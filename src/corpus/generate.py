"""Render the synthetic corpus into four native wire formats.

    python -m src.corpus.generate

Writes `src/corpus/feeds/{siem.json, sensors.syslog, geo_tracks.csv,
intel_reports.txt}` and `src/corpus/ground_truth.json`. Deterministic: the
same seed always produces byte-identical feeds, so the committed files can be
regenerated and diffed.

The four formats are deliberately different from each other - that is the
problem statement. The SIEM speaks nested JSON with vendor severity words, the
sensors speak RFC 5424 syslog with numeric PRI, the geospatial feed is a flat
CSV with P1-P4 priorities, and the intelligence reports are prose with
defanged indicators. The ingest adapters in `src/ingest/` undo all of that.
"""

from __future__ import annotations

import csv
import io
import json
import random
from datetime import datetime, timezone
from pathlib import Path

from src.corpus.noise import generate_noise
from src.corpus.scenarios import SCENARIOS

SEED = 20260915
FEEDS_DIR = Path(__file__).resolve().parent / "feeds"
GROUND_TRUTH_PATH = Path(__file__).resolve().parent / "ground_truth.json"
WINDOW_START = datetime(2026, 9, 13, 0, 0, tzinfo=timezone.utc)
WINDOW_END = datetime(2026, 9, 14, 23, 59, tzinfo=timezone.utc)

# RFC 5424 severity keywords -> numeric level; facility 16 (local0) throughout.
SYSLOG_SEVERITY = {"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warning": 4, "notice": 5, "info": 6, "debug": 7}
FACILITY = 16


def _ts(spec: dict) -> datetime:
    return datetime.strptime(spec["at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _host_ip(host: str) -> str | None:
    from src.corpus.noise import SERVERS, WORKSTATIONS

    for name, ip, *_ in SERVERS + [(w[0], w[1]) for w in WORKSTATIONS]:
        if name.lower() == host.lower():
            return ip
    return None


# ---------------------------------------------------------------------------
# Renderers - one per wire format
# ---------------------------------------------------------------------------


def render_siem(spec: dict, event_id: str) -> dict:
    event: dict = {
        "event_id": event_id,
        "@timestamp": spec["at"],
        "product": "Sentinel-class SIEM (synthetic)",
        "rule": {"id": spec["rule_id"], "name": spec["rule"]},
        "severity": spec["severity"],
        "category": spec["category"],
        "host": {"name": spec["host"], "ip": _host_ip(spec["host"])},
        "message": spec["message"],
    }
    if spec.get("user"):
        event["user"] = {"name": spec["user"]}
    if spec.get("src_ip"):
        event["source"] = {"ip": spec["src_ip"]}
    if spec.get("dst_ip"):
        event["destination"] = {"ip": spec["dst_ip"], **({"port": spec["dst_port"]} if spec.get("dst_port") else {})}
    if spec.get("file") or spec.get("sha256"):
        event["file"] = {"name": spec.get("file"), "hash": {"sha256": spec["sha256"]} if spec.get("sha256") else {}}
    if spec.get("url"):
        event["url"] = {"full": spec["url"]}
    return event


def render_syslog(spec: dict) -> str:
    pri = FACILITY * 8 + SYSLOG_SEVERITY[spec["sev"]]
    sd = f'[aegis@32473 severity="{spec["sev"]}"' + (f' user="{spec["user"]}"' if spec.get("user") else "") + "]"
    return f"<{pri}>1 {spec['at']} {spec['host']} {spec['app']} - - {sd} {spec['msg']}"


GEO_COLUMNS = ["track_id", "timestamp_utc", "sensor_id", "site_id", "lat", "lon", "object_class", "alert_type", "confidence", "priority", "speed_kts", "heading_deg", "notes"]


def render_geo(spec: dict) -> list:
    return [spec["track_id"], spec["at"], spec["sensor"], spec["site"], f"{spec['lat']:.4f}", f"{spec['lon']:.4f}", spec["object_class"],
            spec["alert_type"], f"{spec['confidence']:.2f}", spec["priority"], spec["speed"], spec["heading"], spec["notes"]]


def render_intel(spec: dict, report_id: str) -> str:
    return (
        f"=== REPORT {report_id} ===\n"
        f"DATE: {spec['at']}\n"
        f"SOURCE: {spec['origin']}\n"
        f"CLASSIFICATION: UNCLASSIFIED // SYNTHETIC EXERCISE DATA\n"
        f"PRIORITY: {spec['priority']}\n"
        f"SUBJECT: {spec['subject']}\n\n"
        f"{spec['body']}\n"
    )


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def build(seed: int = SEED) -> tuple[dict[str, str], dict]:
    rng = random.Random(seed)
    specs: list[tuple[dict, str | None]] = []
    for scenario in SCENARIOS:
        for spec in scenario["alerts"]:
            specs.append((spec, scenario["key"]))
    for spec in generate_noise(rng, WINDOW_START, WINDOW_END, siem=190, syslog=210, geo=60):
        specs.append((spec, None))

    # Chronological per source, so IDs are monotonic in time like a real feed.
    by_source: dict[str, list[tuple[dict, str | None]]] = {"siem": [], "syslog": [], "geo": [], "intel": []}
    for spec, key in specs:
        by_source[spec["source"]].append((spec, key))
    for items in by_source.values():
        items.sort(key=lambda it: _ts(it[0]))

    ground_truth: dict[str, list[str]] = {s["key"]: [] for s in SCENARIOS}

    siem_events = []
    for n, (spec, key) in enumerate(by_source["siem"], start=1):
        event_id = f"SIEM-{n:04d}"
        siem_events.append(render_siem(spec, event_id))
        if key:
            ground_truth[key].append(event_id)

    syslog_lines = []
    for n, (spec, key) in enumerate(by_source["syslog"], start=1):
        syslog_lines.append(render_syslog(spec))
        if key:
            ground_truth[key].append(f"SYS-{n:04d}")

    geo_buf = io.StringIO()
    writer = csv.writer(geo_buf, lineterminator="\n")
    writer.writerow(GEO_COLUMNS)
    for n, (spec, key) in enumerate(by_source["geo"], start=1):
        writer.writerow(render_geo(spec))
        if key:
            ground_truth[key].append(f"GEO-{n:04d}")

    intel_blocks = []
    for n, (spec, key) in enumerate(by_source["intel"], start=1):
        report_id = f"INTEL-{n:03d}"
        intel_blocks.append(render_intel(spec, report_id))
        if key:
            ground_truth[key].append(report_id)

    feeds = {
        "siem.json": json.dumps(siem_events, indent=2, ensure_ascii=False) + "\n",
        "sensors.syslog": "\n".join(syslog_lines) + "\n",
        "geo_tracks.csv": geo_buf.getvalue(),
        "intel_reports.txt": "\n".join(intel_blocks),
    }
    truth = {
        "seed": seed,
        "window": {"start": WINDOW_START.isoformat(), "end": WINDOW_END.isoformat()},
        "totals": {k: len(v) for k, v in by_source.items()},
        "scenarios": [
            {
                "key": s["key"],
                "label": s["label"],
                "ambiguous": s["ambiguous"],
                "title": s["title"],
                "expect": s["expect"],
                "alert_ids": ground_truth[s["key"]],
            }
            for s in SCENARIOS
        ],
    }
    return feeds, truth


def main() -> None:
    feeds, truth = build()
    FEEDS_DIR.mkdir(parents=True, exist_ok=True)
    for name, content in feeds.items():
        (FEEDS_DIR / name).write_text(content, encoding="utf-8", newline="\n")
        print(f"[corpus] wrote {name} ({len(content):,} bytes)")
    GROUND_TRUTH_PATH.write_text(json.dumps(truth, indent=2), encoding="utf-8", newline="\n")
    total = sum(truth["totals"].values())
    planted = sum(len(s["alert_ids"]) for s in truth["scenarios"])
    print(f"[corpus] {total} alerts ({truth['totals']}); {planted} planted across {len(truth['scenarios'])} scenarios")


if __name__ == "__main__":
    main()
