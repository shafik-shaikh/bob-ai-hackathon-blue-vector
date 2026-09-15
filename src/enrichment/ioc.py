"""Indicator-of-compromise extraction.

Pulls IPv4/IPv6 addresses, domains, URLs, file hashes, e-mail addresses, CVE
identifiers, user principals and hostnames out of any text, including free
prose in intelligence reports. Intel authors habitually *defang* indicators
(`hxxp://`, `185[.]220[.]101[.]4`, `evil[.]example`), so the extractor refangs
before matching - otherwise an IOC in a report never correlates with the same
IOC in a SIEM event, which defeats the point of ingesting reports at all.

Every extractor is deliberately conservative. A false indicator creates a false
correlation edge, and Signal 1 weights shared indicators heavily.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable

from src.models import Indicator, IndicatorType

# ---------------------------------------------------------------------------
# Refanging
# ---------------------------------------------------------------------------

_REFANG_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"hxxps?://", re.IGNORECASE), lambda m: m.group(0).lower().replace("hxxp", "http")),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[@\]|\[at\]", re.IGNORECASE), "@"),
    (re.compile(r"\[:\]|\[://\]"), "://"),
]


def refang(text: str) -> str:
    for pattern, replacement in _REFANG_RULES:
        text = pattern.sub(replacement, text)  # type: ignore[arg-type]
    return text


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

_IPV4 = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?!\.?\d)")
_IPV6 = re.compile(r"(?<![:\w])((?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4})(?![:\w])", re.IGNORECASE)
_URL = re.compile(r"\b((?:https?|ftp)://[^\s'\"<>)\]]+)", re.IGNORECASE)
_EMAIL = re.compile(r"\b([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})\b", re.IGNORECASE)
_DOMAIN = re.compile(
    r"(?<![\w@/.\\-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}))(?![\w/-])",
    re.IGNORECASE,
)
_CVE = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)
_MAC = re.compile(r"\b((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\b", re.IGNORECASE)
_SHA256 = re.compile(r"\b([a-f0-9]{64})\b", re.IGNORECASE)
_SHA1 = re.compile(r"\b([a-f0-9]{40})\b", re.IGNORECASE)
_MD5 = re.compile(r"\b([a-f0-9]{32})\b", re.IGNORECASE)
# Domain-style user principals: DOMAIN\user, user@domain, or explicit "user=" fields.
_USER_PRINCIPAL = re.compile(r"\b([A-Z][A-Z0-9-]{1,15}\\[a-z][a-z0-9._-]{1,31})\b")
_USER_FIELD = re.compile(r"\b(?:user(?:name)?|account|principal|subject)\s*[=:]\s*['\"]?([A-Za-z][\w.\\$-]{1,63})", re.IGNORECASE)
_HOST_FIELD = re.compile(r"\b(?:host(?:name)?|computer|machine|device)\s*[=:]\s*['\"]?([A-Za-z][\w-]{2,63})", re.IGNORECASE)

# File extensions that look like domains to a regex but are not.
_FILE_EXTENSIONS = {
    "exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "jar", "zip", "rar", "7z", "docm", "docx", "xlsm",
    "xlsx", "pdf", "txt", "log", "json", "csv", "yaml", "yml", "py", "sh", "tmp", "dat", "bin", "iso",
    "lnk", "hta", "scr", "msi", "cab", "gz", "tar", "db", "conf", "cfg", "ini", "xml", "html", "htm",
    "sys", "drv", "local", "internal", "lan", "corp",
}


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def _valid_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    # Version strings like 1.2.3.4 slip through occasionally; drop obvious non-hosts.
    return not (ip.is_multicast or ip.is_unspecified or ip.is_reserved or value.endswith(".0"))


def _valid_ipv6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False


# Conservative TLD allowlist. Dotted tokens such as `Net.WebClient` or
# `System.Management` appear constantly in endpoint telemetry and would
# otherwise become bogus "domains" that correlate unrelated alerts.
_KNOWN_TLDS = {
    "com", "net", "org", "io", "info", "biz", "co", "me", "tv", "cc", "ws", "top", "xyz", "site", "online",
    "club", "pw", "su", "ru", "cn", "uk", "de", "fr", "nl", "eu", "in", "us", "ca", "au", "nz", "br", "jp",
    "kr", "ir", "il", "ua", "pl", "cz", "md", "ro", "se", "no", "fi", "dk", "is", "ch", "at", "be", "es",
    "it", "pt", "gr", "tr", "ae", "sa", "pk", "za", "ng", "ke", "mx", "ar", "cl", "vn", "th", "id", "my",
    "sg", "hk", "tw", "edu", "gov", "mil", "int", "onion", "example", "nz", "zone", "cloud", "app", "dev",
}


def _valid_domain(value: str) -> bool:
    tld = value.rsplit(".", 1)[-1].lower()
    if tld in _FILE_EXTENSIONS or tld not in _KNOWN_TLDS:
        return False
    if _IPV4.fullmatch(value):
        return False
    return True


def _snippet(text: str, start: int, end: int, width: int = 40) -> str:
    left = max(0, start - width)
    right = min(len(text), end + width)
    return ("…" if left > 0 else "") + text[left:right].replace("\n", " ") + ("…" if right < len(text) else "")


def extract_indicators(text: str, *, context_label: str | None = None) -> list[Indicator]:
    """Extract every indicator from a block of text, refanging first.

    Hash matching is ordered longest-first so a SHA-256 is not also reported as
    an MD5 (any 32-hex substring of it would match otherwise).
    """
    if not text:
        return []
    text = refang(text)
    found: dict[tuple[IndicatorType, str], Indicator] = {}
    consumed: list[tuple[int, int]] = []

    def _overlaps(s: int, e: int) -> bool:
        return any(s < ce and e > cs for cs, ce in consumed)

    def _add(kind: IndicatorType, value: str, s: int, e: int) -> None:
        key = (kind, value.strip().lower())
        if key in found:
            return
        ctx = context_label or _snippet(text, s, e)
        found[key] = Indicator(type=kind, value=value, context=ctx)
        consumed.append((s, e))

    for pattern, kind in ((_SHA256, IndicatorType.SHA256), (_SHA1, IndicatorType.SHA1), (_MD5, IndicatorType.MD5)):
        for m in pattern.finditer(text):
            if not _overlaps(m.start(1), m.end(1)):
                _add(kind, m.group(1), m.start(1), m.end(1))

    for m in _CVE.finditer(text):
        _add(IndicatorType.CVE, m.group(1).upper(), m.start(1), m.end(1))

    for m in _MAC.finditer(text):
        _add(IndicatorType.MAC, m.group(1), m.start(1), m.end(1))

    for m in _URL.finditer(text):
        url = m.group(1).rstrip(".,;")
        _add(IndicatorType.URL, url, m.start(1), m.end(1))
        # The host inside a URL is an indicator in its own right.
        host = re.sub(r"^[a-z]+://", "", url, flags=re.IGNORECASE).split("/")[0].split(":")[0]
        if _IPV4.fullmatch(host) and _valid_ipv4(host):
            found.setdefault((IndicatorType.IPV4, host.lower()), Indicator(type=IndicatorType.IPV4, value=host, context=context_label or f"host of {url}"))
        elif _valid_domain(host):
            found.setdefault((IndicatorType.DOMAIN, host.lower()), Indicator(type=IndicatorType.DOMAIN, value=host, context=context_label or f"host of {url}"))

    for m in _EMAIL.finditer(text):
        if not _overlaps(m.start(1), m.end(1)):
            _add(IndicatorType.EMAIL, m.group(1), m.start(1), m.end(1))

    for m in _IPV4.finditer(text):
        if not _overlaps(m.start(1), m.end(1)) and _valid_ipv4(m.group(1)):
            _add(IndicatorType.IPV4, m.group(1), m.start(1), m.end(1))

    for m in _IPV6.finditer(text):
        if not _overlaps(m.start(1), m.end(1)) and _valid_ipv6(m.group(1)):
            _add(IndicatorType.IPV6, m.group(1), m.start(1), m.end(1))

    for m in _DOMAIN.finditer(text):
        if not _overlaps(m.start(1), m.end(1)) and _valid_domain(m.group(1)):
            _add(IndicatorType.DOMAIN, m.group(1), m.start(1), m.end(1))

    for m in _USER_PRINCIPAL.finditer(text):
        _add(IndicatorType.USER, m.group(1), m.start(1), m.end(1))
    for m in _USER_FIELD.finditer(text):
        value = m.group(1)
        if value.lower() not in {"none", "null", "n/a", "unknown", "system"}:
            _add(IndicatorType.USER, value, m.start(1), m.end(1))

    for m in _HOST_FIELD.finditer(text):
        _add(IndicatorType.HOSTNAME, m.group(1), m.start(1), m.end(1))

    return list(found.values())


def merge_indicators(*groups: Iterable[Indicator]) -> list[Indicator]:
    """Union of indicator lists, de-duplicated on (type, value)."""
    seen: dict[tuple[IndicatorType, str], Indicator] = {}
    for group in groups:
        for ind in group:
            seen.setdefault((ind.type, ind.value), ind)
    return list(seen.values())


def is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False
