"""Geospatial adapter - flat CSV of sensor tracks with P1-P4 priorities.

A geospatial alert has no host. Its asset is the *site* it concerns, which
the inventory models with the site's network subnet, so a radar track at
SITE-ALPHA and a rogue-AP alert from SITE-ALPHA's wireless controller are
adjacent to the correlation engine even though one is a physical-domain
observation and the other a network one.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path

from src.ingest.base import finalise_indicators, parse_timestamp, resolve_asset, text_indicators
from src.models import Alert, Indicator, IndicatorType, SourceType

# Sensor-fusion feeds cross-reference other tracks in free text
# ("co-located with track TRK-UAS-7731"); those references are indicators.
_TRACK_REF = re.compile(r"\b((?:TRK|EMT)-[A-Z]+-\d+)\b")


def parse_geo_row(row: dict, alert_id: str) -> Alert:
    site = row["site_id"]
    asset = resolve_asset(hostname=site)
    text = (
        f"{row['alert_type'].replace('_', ' ')}: {row['object_class'].replace('_', ' ')} track {row['track_id']} "
        f"near {site} (sensor {row['sensor_id']}, confidence {row['confidence']}). {row['notes']}"
    )
    indicators = finalise_indicators(
        asset,
        [Indicator(type=IndicatorType.HOSTNAME, value=row["track_id"], context="field track_id")],
        [
            Indicator(type=IndicatorType.HOSTNAME, value=t, context="track cross-referenced in notes")
            for t in _TRACK_REF.findall(row["notes"])
        ],
        text_indicators(row["notes"]),
    )
    payload = dict(row)
    for key in ("lat", "lon", "confidence"):
        payload[key] = float(row[key])
    for key in ("speed_kts", "heading_deg"):
        payload[key] = int(float(row[key]))
    return Alert(
        alert_id=alert_id,
        source=SourceType.GEO,
        timestamp=parse_timestamp(row["timestamp_utc"]),
        raw_text=text,
        source_severity=row["priority"],
        asset=asset,
        indicators=indicators,
        raw_payload=payload,
    )


def load_geo(path: Path) -> list[Alert]:
    with path.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    return [parse_geo_row(row, f"GEO-{n:04d}") for n, row in enumerate(rows, start=1)]
