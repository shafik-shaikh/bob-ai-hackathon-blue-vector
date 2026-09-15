"""Intelligence-report adapter - human-authored prose with a small header.

    === REPORT INTEL-003 ===
    DATE: ...
    SOURCE: ...
    CLASSIFICATION: ...
    PRIORITY: HIGH
    SUBJECT: ...

    <free text, with defanged indicators>

Reports have no asset. What they do have is indicators buried in prose -
refanged by the extractor - and references to sites and hosts by name, which
the asset-adjacency signal treats as "this report mentions that asset".
"""

from __future__ import annotations

import re
from pathlib import Path

from src.ingest.base import finalise_indicators, parse_timestamp, resolve_known_asset, text_indicators
from src.models import Alert, Indicator, IndicatorType, SourceType

_BLOCK = re.compile(
    r"=== REPORT (?P<id>[A-Z0-9-]+) ===\n(?P<header>(?:[A-Z]+: [^\n]*\n)+)\n(?P<body>.*?)(?=\n=== REPORT |\Z)",
    re.DOTALL,
)
_SITE_REF = re.compile(r"\b(SITE-[A-Z]+)\b")
_HOST_REF = re.compile(r"\b([A-Z]{2,6}-(?:[A-Z]{2,6}-)?\d{2,3})\b")  # e.g. PRINT-SRV-01, FIN-WS-042, DC01 is handled below
_DC_REF = re.compile(r"\b(DC0\d)\b")


def parse_intel_block(report_id: str, header: str, body: str) -> Alert:
    fields = {}
    for line in header.strip().splitlines():
        key, _, value = line.partition(": ")
        fields[key.strip().lower()] = value.strip()
    subject = fields.get("subject", "")
    text = f"{subject}. {body.strip()}"

    mentions = [
        Indicator(type=IndicatorType.HOSTNAME, value=m, context="site referenced in report")
        for m in set(_SITE_REF.findall(body))
    ] + [
        Indicator(type=IndicatorType.HOSTNAME, value=m, context="host referenced in report")
        for m in set(_HOST_REF.findall(body)) | set(_DC_REF.findall(body))
        if resolve_known_asset(m) is not None  # "SHA-256" matches the host pattern; the inventory is the filter
    ]
    indicators = finalise_indicators(None, text_indicators(body), mentions)
    return Alert(
        alert_id=report_id,
        source=SourceType.INTEL,
        timestamp=parse_timestamp(fields["date"]),
        raw_text=text,
        source_severity=fields.get("priority"),
        asset=None,
        indicators=indicators,
        raw_payload={"report_id": report_id, **fields, "body": body.strip()},
    )


def load_intel(path: Path) -> list[Alert]:
    content = path.read_text(encoding="utf-8")
    alerts = []
    for m in _BLOCK.finditer(content):
        alerts.append(parse_intel_block(m.group("id"), m.group("header"), m.group("body")))
    return alerts
