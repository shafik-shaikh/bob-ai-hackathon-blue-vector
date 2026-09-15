"""SQLite persistence for AEGIS.

Plain `sqlite3` from the standard library - there is nothing to install and
nothing to provision. Every pipeline stage writes here and both the FastAPI
surface and the MCP server read from here, which is what guarantees that the
console and IBM Bob never disagree about the state of the queue.

Canonical records are stored as JSON documents (the Pydantic models are the
contract) alongside relational side-tables that carry the columns the
correlation pre-filter needs to index: timestamp, asset, indicator value.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from src.config import settings
from src.models import Alert, BlufReport, CorrelationEdge, Incident

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id        TEXT PRIMARY KEY,
    source          TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    asset_id        TEXT,
    source_severity TEXT,
    document        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_asset ON alerts(asset_id);

CREATE TABLE IF NOT EXISTS alert_indicators (
    alert_id        TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    indicator_type  TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    context         TEXT
);
CREATE INDEX IF NOT EXISTS idx_alert_indicators_value ON alert_indicators(indicator_value);
CREATE INDEX IF NOT EXISTS idx_alert_indicators_alert ON alert_indicators(alert_id);

CREATE TABLE IF NOT EXISTS attack_mappings (
    alert_id        TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    technique_id    TEXT NOT NULL,
    technique_name  TEXT NOT NULL,
    tactic          TEXT NOT NULL,
    score           REAL NOT NULL,
    method          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attack_mappings_technique ON attack_mappings(technique_id);
CREATE INDEX IF NOT EXISTS idx_attack_mappings_alert ON attack_mappings(alert_id);

CREATE TABLE IF NOT EXISTS correlation_edges (
    alert_a         TEXT NOT NULL,
    alert_b         TEXT NOT NULL,
    total_weight    REAL NOT NULL,
    document        TEXT NOT NULL,
    PRIMARY KEY (alert_a, alert_b)
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id     TEXT PRIMARY KEY,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    alert_count     INTEGER NOT NULL,
    composite_score REAL,
    document        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_score ON incidents(composite_score);

CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id     TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    alert_id        TEXT NOT NULL,
    PRIMARY KEY (incident_id, alert_id)
);
CREATE INDEX IF NOT EXISTS idx_incident_alerts_alert ON incident_alerts(alert_id);

CREATE TABLE IF NOT EXISTS assets (
    asset_id        TEXT PRIMARY KEY,
    hostname        TEXT,
    ip              TEXT,
    subnet          TEXT,
    role            TEXT,
    criticality     INTEGER NOT NULL,
    rationale       TEXT
);

CREATE TABLE IF NOT EXISTS bluf_reports (
    incident_id     TEXT PRIMARY KEY REFERENCES incidents(incident_id) ON DELETE CASCADE,
    generated_by    TEXT NOT NULL,
    generated_at    TEXT NOT NULL,
    document        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pipeline_runs (
    run_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    summary         TEXT
);
"""


def _connect(path: Path | None = None) -> sqlite3.Connection:
    db_path = path or settings.database_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def connection(path: Path | None = None) -> Iterator[sqlite3.Connection]:
    conn = _connect(path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(path: Path | None = None, *, reset: bool = False) -> Path:
    """Create every table. With `reset=True` the file is removed first."""
    db_path = path or settings.database_path
    if reset and db_path.exists():
        db_path.unlink()
        for suffix in ("-wal", "-shm", "-journal"):
            side = Path(str(db_path) + suffix)
            if side.exists():
                side.unlink()
    with connection(db_path) as conn:
        conn.executescript(SCHEMA)
    return db_path


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


def _dump(model) -> str:
    return model.model_dump_json()


def upsert_alerts(alerts: Iterable[Alert], conn: sqlite3.Connection) -> int:
    """Insert or replace alerts and rebuild their indicator / mapping rows."""
    count = 0
    for alert in alerts:
        conn.execute(
            "INSERT OR REPLACE INTO alerts(alert_id, source, timestamp, asset_id, source_severity, document)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                alert.alert_id,
                alert.source.value,
                alert.timestamp.isoformat(),
                alert.asset.asset_id if alert.asset else None,
                alert.source_severity,
                _dump(alert),
            ),
        )
        conn.execute("DELETE FROM alert_indicators WHERE alert_id = ?", (alert.alert_id,))
        conn.executemany(
            "INSERT INTO alert_indicators(alert_id, indicator_type, indicator_value, context) VALUES (?, ?, ?, ?)",
            [(alert.alert_id, i.type.value, i.value, i.context) for i in alert.indicators],
        )
        conn.execute("DELETE FROM attack_mappings WHERE alert_id = ?", (alert.alert_id,))
        conn.executemany(
            "INSERT INTO attack_mappings(alert_id, technique_id, technique_name, tactic, score, method)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            [
                (alert.alert_id, t.technique_id, t.technique_name, t.tactic.value, t.score, t.method)
                for t in alert.techniques
            ],
        )
        count += 1
    return count


def load_alerts(conn: sqlite3.Connection, *, ids: Iterable[str] | None = None) -> list[Alert]:
    if ids is None:
        rows = conn.execute("SELECT document FROM alerts ORDER BY timestamp").fetchall()
    else:
        id_list = list(ids)
        if not id_list:
            return []
        marks = ",".join("?" for _ in id_list)
        rows = conn.execute(
            f"SELECT document FROM alerts WHERE alert_id IN ({marks}) ORDER BY timestamp", id_list
        ).fetchall()
    return [Alert.model_validate_json(r["document"]) for r in rows]


def get_alert(conn: sqlite3.Connection, alert_id: str) -> Alert | None:
    row = conn.execute("SELECT document FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    return Alert.model_validate_json(row["document"]) if row else None


def alerts_by_technique(conn: sqlite3.Connection, technique_id: str) -> list[str]:
    """Alert IDs mapped to a technique or any of its sub-techniques."""
    rows = conn.execute(
        "SELECT DISTINCT alert_id FROM attack_mappings WHERE technique_id = ? OR technique_id LIKE ?",
        (technique_id.upper(), f"{technique_id.upper()}.%"),
    ).fetchall()
    return [r["alert_id"] for r in rows]


# ---------------------------------------------------------------------------
# Edges and incidents
# ---------------------------------------------------------------------------


def replace_edges(edges: Iterable[CorrelationEdge], conn: sqlite3.Connection) -> int:
    conn.execute("DELETE FROM correlation_edges")
    rows = [(e.alert_a, e.alert_b, e.total_weight, _dump(e)) for e in edges]
    conn.executemany(
        "INSERT OR REPLACE INTO correlation_edges(alert_a, alert_b, total_weight, document) VALUES (?, ?, ?, ?)",
        rows,
    )
    return len(rows)


def load_edges(conn: sqlite3.Connection) -> list[CorrelationEdge]:
    rows = conn.execute("SELECT document FROM correlation_edges").fetchall()
    return [CorrelationEdge.model_validate_json(r["document"]) for r in rows]


def get_edge(conn: sqlite3.Connection, alert_a: str, alert_b: str) -> CorrelationEdge | None:
    row = conn.execute(
        "SELECT document FROM correlation_edges WHERE (alert_a = ? AND alert_b = ?) OR (alert_a = ? AND alert_b = ?)",
        (alert_a, alert_b, alert_b, alert_a),
    ).fetchone()
    return CorrelationEdge.model_validate_json(row["document"]) if row else None


def replace_incidents(incidents: Iterable[Incident], conn: sqlite3.Connection) -> int:
    conn.execute("DELETE FROM incident_alerts")
    conn.execute("DELETE FROM bluf_reports")
    conn.execute("DELETE FROM incidents")
    count = 0
    for inc in incidents:
        conn.execute(
            "INSERT INTO incidents(incident_id, first_seen, last_seen, alert_count, composite_score, document)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                inc.incident_id,
                inc.first_seen.isoformat(),
                inc.last_seen.isoformat(),
                inc.alert_count,
                inc.score.composite if inc.score else None,
                _dump(inc),
            ),
        )
        conn.executemany(
            "INSERT INTO incident_alerts(incident_id, alert_id) VALUES (?, ?)",
            [(inc.incident_id, a) for a in inc.alert_ids],
        )
        count += 1
    return count


def update_incident(inc: Incident, conn: sqlite3.Connection) -> None:
    conn.execute(
        "UPDATE incidents SET composite_score = ?, document = ? WHERE incident_id = ?",
        (inc.score.composite if inc.score else None, _dump(inc), inc.incident_id),
    )


def load_incidents(conn: sqlite3.Connection) -> list[Incident]:
    """All incidents, highest composite score first."""
    rows = conn.execute(
        "SELECT document FROM incidents ORDER BY composite_score DESC, alert_count DESC, first_seen"
    ).fetchall()
    return [Incident.model_validate_json(r["document"]) for r in rows]


def get_incident(conn: sqlite3.Connection, incident_id: str) -> Incident | None:
    row = conn.execute("SELECT document FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
    return Incident.model_validate_json(row["document"]) if row else None


def incident_for_alert(conn: sqlite3.Connection, alert_id: str) -> Incident | None:
    row = conn.execute(
        "SELECT i.document FROM incidents i JOIN incident_alerts ia ON ia.incident_id = i.incident_id"
        " WHERE ia.alert_id = ?",
        (alert_id,),
    ).fetchone()
    return Incident.model_validate_json(row["document"]) if row else None


def queue_position(conn: sqlite3.Connection, incident_id: str) -> int | None:
    """1-based rank of an incident in the priority queue."""
    rows = conn.execute(
        "SELECT incident_id FROM incidents ORDER BY composite_score DESC, alert_count DESC, first_seen"
    ).fetchall()
    for idx, r in enumerate(rows, start=1):
        if r["incident_id"] == incident_id:
            return idx
    return None


# ---------------------------------------------------------------------------
# Assets and BLUF
# ---------------------------------------------------------------------------


def replace_assets(assets: Iterable[dict], conn: sqlite3.Connection) -> int:
    conn.execute("DELETE FROM assets")
    rows = [
        (
            a["asset_id"],
            a.get("hostname"),
            a.get("ip"),
            a.get("subnet"),
            a.get("role"),
            int(a["criticality"]),
            a.get("rationale"),
        )
        for a in assets
    ]
    conn.executemany(
        "INSERT INTO assets(asset_id, hostname, ip, subnet, role, criticality, rationale) VALUES (?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    return len(rows)


def load_assets(conn: sqlite3.Connection) -> dict[str, dict]:
    rows = conn.execute("SELECT * FROM assets").fetchall()
    return {r["asset_id"]: dict(r) for r in rows}


def save_bluf(report: BlufReport, conn: sqlite3.Connection) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO bluf_reports(incident_id, generated_by, generated_at, document) VALUES (?, ?, ?, ?)",
        (report.incident_id, report.generated_by, datetime.now(timezone.utc).isoformat(), _dump(report)),
    )


def get_bluf(conn: sqlite3.Connection, incident_id: str) -> BlufReport | None:
    row = conn.execute("SELECT document FROM bluf_reports WHERE incident_id = ?", (incident_id,)).fetchone()
    return BlufReport.model_validate_json(row["document"]) if row else None


# ---------------------------------------------------------------------------
# Pipeline bookkeeping / stats
# ---------------------------------------------------------------------------


def record_run(summary: dict, conn: sqlite3.Connection) -> None:
    conn.execute(
        "INSERT INTO pipeline_runs(started_at, finished_at, summary) VALUES (?, ?, ?)",
        (summary.get("started_at"), summary.get("finished_at"), json.dumps(summary)),
    )


def last_run(conn: sqlite3.Connection) -> dict | None:
    row = conn.execute("SELECT summary FROM pipeline_runs ORDER BY run_id DESC LIMIT 1").fetchone()
    return json.loads(row["summary"]) if row else None


def stats(conn: sqlite3.Connection) -> dict:
    def one(sql: str) -> int:
        return int(conn.execute(sql).fetchone()[0])

    by_source = {
        r["source"]: r["n"] for r in conn.execute("SELECT source, COUNT(*) AS n FROM alerts GROUP BY source")
    }
    return {
        "alerts": one("SELECT COUNT(*) FROM alerts"),
        "alerts_by_source": by_source,
        "indicators": one("SELECT COUNT(DISTINCT indicator_value) FROM alert_indicators"),
        "attack_mappings": one("SELECT COUNT(*) FROM attack_mappings"),
        "edges": one("SELECT COUNT(*) FROM correlation_edges"),
        "incidents": one("SELECT COUNT(*) FROM incidents"),
        "multi_alert_incidents": one("SELECT COUNT(*) FROM incidents WHERE alert_count > 1"),
        "bluf_reports": one("SELECT COUNT(*) FROM bluf_reports"),
        "last_run": last_run(conn),
    }
