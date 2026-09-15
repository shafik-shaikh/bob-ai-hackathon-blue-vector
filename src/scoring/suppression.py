"""False-positive suppression rules.

Each rule encodes a *documented* reason why activity that looks hostile is
expected in this enclave, and returns the evidence it matched on. The
prioritiser combines fired rules into `false_positive_likelihood`, and the
MCP tool `why_deprioritised` reads the same evidence back to the analyst.

Rules are deliberately narrow. A rule that suppresses too much is worse than
no rule: the scanner rule keys on the scanner's own address *and* the
scanning technique, so an attacker who steals the scanner would still be
caught if they did anything other than scan.

Strength is the probability the rule assigns to "benign" when it fires. It is
a judgement, and it is written down here where a reviewer can argue with it.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from src.models import Alert, Incident, IndicatorType, SourceType

# --- Enclave knowledge the rules depend on. In production this would come
# from the CMDB and the change-management system; here it is declared.

AUTHORISED_SCANNERS = {
    "range": ipaddress.ip_network("10.50.1.0/24"),
    "asset_ids": {"SCAN-01"},
    "schedule": "Sundays and Mondays 06:00-06:30 UTC (change CHG-STD-0042, standing approval)",
}
CHANGE_WINDOWS = [
    {
        "ticket": "CHG-2026-0911",
        "summary": "Backup transport agent rollout to BACKUP-01 and FILE-SRV-01",
        "start": datetime(2026, 9, 13, 23, 0, tzinfo=timezone.utc),
        "end": datetime(2026, 9, 14, 2, 0, tzinfo=timezone.utc),
        "accounts": {"corp\\r.tanaka", "corp\\k.olsen"},
        "assets": {"BACKUP-01", "FILE-SRV-01", "ADM-WS-002"},
    },
]
ADMIN_VLAN = ipaddress.ip_network("10.20.10.0/24")
ADMIN_ACCOUNTS = {"corp\\r.tanaka", "corp\\k.olsen"}
SERVICE_ACCOUNT_EXPECTATIONS = {
    # account -> assets it is expected to act on
    "corp\\svc_backup": {"BACKUP-01"},
    "corp\\svc_patch": {"*"},
}
SINKHOLE_RANGE = ipaddress.ip_network("192.0.2.0/24")
INFORMATIONAL_SEVERITIES = {"informational", "info", "debug", "notice", "p4"}
LOW_SEVERITIES = INFORMATIONAL_SEVERITIES | {"low", "p3"}


@dataclass(frozen=True)
class SuppressionRule:
    rule_id: str
    name: str
    rationale: str
    strength: float
    matcher: Callable[[Incident, list[Alert]], str | None]


@dataclass(frozen=True)
class FiredRule:
    rule_id: str
    name: str
    rationale: str
    strength: float
    evidence: str


def _ips(alert: Alert) -> set[str]:
    return {i.value for i in alert.indicators if i.type == IndicatorType.IPV4}


def _in(ip: str, net: ipaddress.IPv4Network) -> bool:
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def _users(alert: Alert) -> set[str]:
    out = {i.value for i in alert.indicators if i.type == IndicatorType.USER}
    if alert.asset and alert.asset.user_principal:
        out.add(alert.asset.user_principal)
    return out


# ---------------------------------------------------------------------------
# Matchers
# ---------------------------------------------------------------------------


def _known_scanner(incident: Incident, alerts: list[Alert]) -> str | None:
    from_scanner = []
    for a in alerts:
        scan_technique = any(t.technique_id in {"T1046", "T1595", "T1595.001", "T1595.002"} for t in a.techniques)
        src_in_range = any(_in(ip, AUTHORISED_SCANNERS["range"]) for ip in _ips(a))
        src_is_scanner = bool(a.asset and a.asset.asset_id in AUTHORISED_SCANNERS["asset_ids"])
        if scan_technique and (src_in_range or src_is_scanner):
            from_scanner.append(a.alert_id)
    if not from_scanner or len(from_scanner) < max(1, int(0.8 * len(alerts))):
        return None
    ips = sorted({ip for a in alerts for ip in _ips(a) if _in(ip, AUTHORISED_SCANNERS["range"])})
    when = min(a.timestamp for a in alerts).strftime("%a %H:%M UTC")
    return (
        f"{len(from_scanner)} of {len(alerts)} alerts are scanning techniques sourced from {', '.join(ips)} "
        f"inside the authorised scanner range {AUTHORISED_SCANNERS['range']} (asset SCAN-01). Activity started {when}, "
        f"matching the standing scan schedule: {AUTHORISED_SCANNERS['schedule']}."
    )


def _maintenance_window(incident: Incident, alerts: list[Alert]) -> str | None:
    for w in CHANGE_WINDOWS:
        inside = [a for a in alerts if w["start"] <= a.timestamp <= w["end"]]
        if len(inside) < len(alerts):
            continue
        accounts = {u for a in alerts for u in _users(a)}
        if not accounts & w["accounts"]:
            continue
        assets = {a.asset.asset_id for a in alerts if a.asset}
        if not assets <= w["assets"]:
            continue
        return (
            f"All {len(alerts)} alerts fall inside change window {w['ticket']} "
            f"({w['start']:%Y-%m-%d %H:%M}–{w['end']:%H:%M} UTC: {w['summary']}), involve approved account(s) "
            f"{', '.join(sorted(accounts & w['accounts']))} and touch only in-scope assets {', '.join(sorted(assets))}."
        )
    return None


def _admin_from_admin_workstation(incident: Incident, alerts: list[Alert]) -> str | None:
    matched = []
    for a in alerts:
        users = _users(a)
        origin_admin_vlan = any(_in(ip, ADMIN_VLAN) for ip in _ips(a)) or bool(a.asset and a.asset.asset_id == "ADM-WS-002")
        if users & ADMIN_ACCOUNTS and origin_admin_vlan:
            matched.append(a.alert_id)
    if len(matched) < max(1, int(0.75 * len(alerts))):
        return None
    return (
        f"{len(matched)} of {len(alerts)} alerts are privileged actions by a designated administrator account "
        f"originating from the admin VLAN {ADMIN_VLAN} (ADM-WS-002), which is the expected origin for such actions."
    )


def _service_account_expected(incident: Incident, alerts: list[Alert]) -> str | None:
    matched = []
    for a in alerts:
        for user in _users(a):
            expected = SERVICE_ACCOUNT_EXPECTATIONS.get(user)
            if expected and a.asset and ("*" in expected or a.asset.asset_id in expected):
                matched.append(f"{user} on {a.asset.asset_id}")
    if len(matched) < len(alerts):
        return None
    return f"Every alert is service-account activity on the asset that account is registered to operate: {', '.join(sorted(set(matched)))}."


def _internet_background(incident: Incident, alerts: list[Alert]) -> str | None:
    denied = [a for a in alerts if a.source == SourceType.SIEM and a.raw_payload.get("rule", {}).get("id") == "FW-0100"]
    if len(denied) < len(alerts):
        return None
    return f"{len(denied)} perimeter deny event(s) with no corresponding accept; internet background radiation blocked at the firewall as designed."


def _sinkhole(incident: Incident, alerts: list[Alert]) -> str | None:
    hits = [a.alert_id for a in alerts if any(_in(ip, SINKHOLE_RANGE) for ip in _ips(a)) and any(t.technique_id.startswith("T1071") for t in a.techniques)]
    if not hits or len(hits) < len(alerts):
        return None
    return f"Beaconing destination is inside the law-enforcement sinkhole range {SINKHOLE_RANGE} (see intel: infrastructure takedown notice); residual traffic from a cleaned host."


def _benign_geo_track(incident: Incident, alerts: list[Alert]) -> str | None:
    if not alerts or any(a.source != SourceType.GEO for a in alerts):
        return None
    reasons = []
    for a in alerts:
        p = a.raw_payload
        notes = str(p.get("notes", "")).lower()
        if p.get("alert_type") == "scheduled_patrol" or "iff valid" in notes or "ads-b valid" in notes:
            reasons.append(f"{a.alert_id}: identified friendly/civil track ({p.get('object_class')})")
        elif float(p.get("confidence", 1)) < 0.5:
            reasons.append(f"{a.alert_id}: sensor confidence {p.get('confidence')} below 0.5")
        elif "authorised list" in notes or "scheduled launch" in notes or "declared voyage" in notes:
            reasons.append(f"{a.alert_id}: matched to authorised movement")
    if len(reasons) < len(alerts):
        return None
    return "; ".join(reasons)


def _informational_only(incident: Incident, alerts: list[Alert]) -> str | None:
    if any((a.source_severity or "").lower() not in INFORMATIONAL_SEVERITIES for a in alerts):
        return None
    if any(t.score >= 0.6 for a in alerts for t in a.techniques):
        return None
    return f"All {len(alerts)} alert(s) carry informational vendor severity and no ATT&CK technique mapped with confidence ≥ 0.6."


def _isolated_low_severity(incident: Incident, alerts: list[Alert]) -> str | None:
    if len(alerts) != 1:
        return None
    a = alerts[0]
    if (a.source_severity or "").lower() not in LOW_SEVERITIES:
        return None
    if a.primary_technique and a.primary_technique.score >= 0.8:
        return None
    return f"Single {a.source.value} alert with vendor severity '{a.source_severity}' and no corroborating alert on any signal."


RULES: list[SuppressionRule] = [
    SuppressionRule("KNOWN_SCANNER_RANGE", "Authorised vulnerability scanner",
                    "Scanning from the registered scanner range on the standing schedule is expected; the IDS marks every scan CRITICAL because it cannot know who is scanning.",
                    0.92, _known_scanner),
    SuppressionRule("MAINTENANCE_WINDOW", "Activity inside an approved change window",
                    "Service installs, remote sessions and scheduled tasks by the change owner on in-scope assets during the ticketed window are the change being executed.",
                    0.80, _maintenance_window),
    SuppressionRule("ADMIN_FROM_ADMIN_WORKSTATION", "Administrator acting from the admin VLAN",
                    "Privileged actions by designated administrators from the privileged-access workstation are the sanctioned path; the same actions from a user workstation would not be suppressed.",
                    0.55, _admin_from_admin_workstation),
    SuppressionRule("SERVICE_ACCOUNT_EXPECTED", "Service account acting on its own system",
                    "Service accounts have a registered scope; activity inside that scope is the job running. Activity outside it (e.g. svc_backup on a finance workstation) is not suppressed.",
                    0.65, _service_account_expected),
    SuppressionRule("INTERNET_BACKGROUND_RADIATION", "Perimeter denies with no accept",
                    "Unsolicited inbound probes blocked at the perimeter are constant and carry no information about compromise.",
                    0.90, _internet_background),
    SuppressionRule("SINKHOLE_DESTINATION", "Beacon to a known sinkhole",
                    "Partner takedown sinkholed the C2 range; beacons to it prove a host was infected once, not that it is controlled now.",
                    0.75, _sinkhole),
    SuppressionRule("BENIGN_GEO_TRACK", "Identified friendly, civil or low-confidence track",
                    "Tracks with valid IFF/ADS-B, matched authorisations, or sensor confidence below 0.5 are routine sensor output.",
                    0.85, _benign_geo_track),
    SuppressionRule("INFORMATIONAL_ONLY", "Informational telemetry with no technique",
                    "Health and audit messages that map to no adversary technique are context, not alerts.",
                    0.70, _informational_only),
    SuppressionRule("ISOLATED_LOW_SEVERITY", "Isolated low-severity alert",
                    "One low-severity alert with no corroboration from any correlation signal is the base rate of the enclave.",
                    0.50, _isolated_low_severity),
]


def evaluate_rules(incident: Incident, alerts: list[Alert]) -> list[FiredRule]:
    fired: list[FiredRule] = []
    for rule in RULES:
        evidence = rule.matcher(incident, alerts)
        if evidence:
            fired.append(FiredRule(rule.rule_id, rule.name, rule.rationale, rule.strength, evidence))
    return fired


def combined_likelihood(fired: list[FiredRule]) -> float:
    """Independent-evidence combination: 1 - Π(1 - strength)."""
    p = 1.0
    for f in fired:
        p *= 1.0 - f.strength
    return round(1.0 - p, 3)


def rule_catalogue() -> list[dict]:
    return [{"rule_id": r.rule_id, "name": r.name, "rationale": r.rationale, "strength": r.strength} for r in RULES]
