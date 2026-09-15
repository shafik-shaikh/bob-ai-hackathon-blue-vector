"""Syslog adapter - RFC 5424 lines from hosts and sensors.

    <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ID param="value" ...] MSG

Severity is recovered from PRI (PRI = facility*8 + severity) and preserved as
the RFC keyword, e.g. "err" or "warning" - not mapped onto the SIEM's words,
because those scales are not comparable and pretending otherwise is the
original problem.
"""

from __future__ import annotations

import re
from pathlib import Path

from src.ingest.base import field_indicator, finalise_indicators, parse_timestamp, resolve_asset, text_indicators
from src.models import Alert, IndicatorType, SourceType

_LINE = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+"
    r"(?P<sd>-|\[.*?\](?:\[.*?\])*)\s*(?P<msg>.*)$"
)
_SD_PARAM = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
SEVERITY_KEYWORDS = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]


def parse_syslog_line(line: str, alert_id: str) -> Alert | None:
    m = _LINE.match(line.strip())
    if not m:
        return None
    pri = int(m.group("pri"))
    severity = SEVERITY_KEYWORDS[pri % 8]
    facility = pri // 8
    params = {k: v.replace('\\"', '"') for k, v in _SD_PARAM.findall(m.group("sd"))} if m.group("sd") != "-" else {}
    host = m.group("host")
    app = m.group("app")
    msg = m.group("msg")
    user = params.get("user")
    asset = resolve_asset(hostname=host, user=user)

    indicators = finalise_indicators(
        asset,
        field_indicator(IndicatorType.USER, user, "sd.user"),
        text_indicators(msg),
    )
    payload = {
        "line": line.rstrip("\n"),
        "pri": pri,
        "facility": facility,
        "severity": severity,
        "timestamp": m.group("ts"),
        "hostname": host,
        "app_name": app,
        "procid": m.group("procid"),
        "msgid": m.group("msgid"),
        "structured_data": params,
        "msg": msg,
    }
    return Alert(
        alert_id=alert_id,
        source=SourceType.SYSLOG,
        timestamp=parse_timestamp(m.group("ts")),
        raw_text=f"{app}: {msg}",
        source_severity=severity,
        asset=asset,
        indicators=indicators,
        raw_payload=payload,
    )


def load_syslog(path: Path) -> list[Alert]:
    alerts: list[Alert] = []
    n = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        n += 1
        alert = parse_syslog_line(line, f"SYS-{n:04d}")
        if alert:
            alerts.append(alert)
    return alerts
