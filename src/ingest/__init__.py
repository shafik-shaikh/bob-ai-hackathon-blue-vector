"""Ingest adapters: four wire formats in, one canonical `Alert` out."""

from __future__ import annotations

from pathlib import Path

from src.ingest.geo import load_geo
from src.ingest.intel import load_intel
from src.ingest.siem import load_siem
from src.ingest.syslog import load_syslog
from src.models import Alert

FEED_FILES = {
    "siem": ("siem.json", load_siem),
    "syslog": ("sensors.syslog", load_syslog),
    "geo": ("geo_tracks.csv", load_geo),
    "intel": ("intel_reports.txt", load_intel),
}


def ingest_feeds(feeds_dir: Path) -> dict[str, list[Alert]]:
    """Run every adapter whose feed file exists. Returns alerts per source."""
    out: dict[str, list[Alert]] = {}
    for source, (filename, loader) in FEED_FILES.items():
        path = feeds_dir / filename
        if path.exists():
            out[source] = loader(path)
    return out


def ingest_all(feeds_dir: Path) -> list[Alert]:
    alerts: list[Alert] = []
    for group in ingest_feeds(feeds_dir).values():
        alerts.extend(group)
    alerts.sort(key=lambda a: a.timestamp)
    return alerts
