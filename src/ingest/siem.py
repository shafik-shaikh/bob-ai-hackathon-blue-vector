"""SIEM adapter - nested JSON events with vendor severity words."""

from __future__ import annotations

import json
from pathlib import Path

from src.ingest.base import field_indicator, finalise_indicators, parse_timestamp, resolve_asset, text_indicators
from src.models import Alert, IndicatorType, SourceType


def _get(d: dict, *path, default=None):
    for key in path:
        if not isinstance(d, dict) or key not in d:
            return default
        d = d[key]
    return d


def parse_siem_event(event: dict) -> Alert:
    host = _get(event, "host", "name")
    host_ip = _get(event, "host", "ip")
    user = _get(event, "user", "name")
    asset = resolve_asset(hostname=host, ip=host_ip, user=user)

    rule_name = _get(event, "rule", "name", default="")
    message = event.get("message", "")
    category = event.get("category", "")
    raw_text = f"{rule_name}. {message}".strip()
    if category:
        raw_text = f"[{category}] {raw_text}"

    src_ip = _get(event, "source", "ip")
    dst_ip = _get(event, "destination", "ip")
    sha256 = _get(event, "file", "hash", "sha256")
    url = _get(event, "url", "full")

    indicators = finalise_indicators(
        asset,
        field_indicator(IndicatorType.IPV4, src_ip, "source.ip"),
        field_indicator(IndicatorType.IPV4, dst_ip, "destination.ip"),
        field_indicator(IndicatorType.SHA256, sha256, "file.hash.sha256"),
        field_indicator(IndicatorType.URL, url, "url.full"),
        field_indicator(IndicatorType.USER, user, "user.name"),
        text_indicators(message),
    )
    return Alert(
        alert_id=event["event_id"],
        source=SourceType.SIEM,
        timestamp=parse_timestamp(event["@timestamp"]),
        raw_text=raw_text,
        source_severity=event.get("severity"),
        asset=asset,
        indicators=indicators,
        raw_payload=event,
    )


def load_siem(path: Path) -> list[Alert]:
    events = json.loads(path.read_text(encoding="utf-8"))
    return [parse_siem_event(e) for e in events]
