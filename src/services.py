"""Shared query layer used by both the REST API and the MCP server.

Everything IBM Bob can say about the queue and everything the console shows
comes through these functions, reading the same SQLite state. That is the
mechanism behind the claim that "Bob and the UI never disagree".

Functions return plain dicts shaped exactly as `docs/api-contract.md`
describes, so the API layer is a thin FastAPI wrapper and the MCP layer is a
thin text renderer.
"""

from __future__ import annotations

import sqlite3
from collections import Counter
from typing import Any

import networkx as nx

from src.bluf.generator import generate_bluf
from src.bluf.template import render_bluf_text
from src.config import settings
from src.db.store import (
    alerts_by_technique,
    connection,
    get_alert,
    get_bluf,
    get_edge,
    get_incident,
    incident_for_alert,
    load_alerts,
    load_assets,
    load_incidents,
    queue_position,
    save_bluf,
    stats,
)
from src.enrichment.attack_mapper import load_techniques, technique_index
from src.models import Alert, Incident, Tactic
from src.scoring.prioritiser import rationale_line, score_incident
from src.scoring.suppression import RULES, evaluate_rules, rule_catalogue


class NotFound(Exception):
    pass


# ---------------------------------------------------------------------------
# Serialisers
# ---------------------------------------------------------------------------


def alert_view(alert: Alert, incident_id: str | None = None) -> dict:
    d = alert.model_dump(mode="json")
    d["incident_id"] = incident_id
    return d


def _incident_alerts(conn: sqlite3.Connection, inc: Incident) -> list[Alert]:
    return load_alerts(conn, ids=inc.alert_ids)


def incident_title(alerts: list[Alert], fired_ids: list[str]) -> str:
    """A human title built from the kill chain and assets, not from a template file."""
    techs: list[str] = []
    # Reports are context, not events: order the chain by observed activity.
    events = [a for a in alerts if a.source.value != "intel"] or alerts
    for a in sorted(events, key=lambda x: x.timestamp):
        t = a.primary_technique
        if t and t.technique_name not in techs:
            techs.append(t.technique_name)
    assets = sorted({a.asset.asset_id for a in alerts if a.asset})
    where = ", ".join(assets[:2]) + (f" +{len(assets) - 2}" if len(assets) > 2 else "") if assets else "unresolved asset"
    if len(alerts) == 1:
        return f"{techs[0] if techs else alerts[0].raw_text[:60]} on {where}"
    chain = " → ".join(techs[:4]) + (" → …" if len(techs) > 4 else "")
    prefix = "[suppressed] " if fired_ids else ""
    return f"{prefix}{chain or 'Unmapped activity'} on {where}"


def incident_summary(conn: sqlite3.Connection, inc: Incident, rank: int | None, inventory: dict | None = None) -> dict:
    alerts = _incident_alerts(conn, inc)
    inventory = inventory if inventory is not None else load_assets(conn)
    score = inc.score
    if score is None:
        score, _, _ = score_incident(inc, alerts, inventory)
    fired = evaluate_rules(inc, alerts)
    tactics = sorted({a.primary_technique.tactic for a in alerts if a.primary_technique}, key=lambda t: t.chain_position)
    top = max((a.primary_technique for a in alerts if a.primary_technique), key=lambda t: t.score, default=None)
    return {
        "incident_id": inc.incident_id,
        "rank": rank,
        "title": incident_title(alerts, score.suppression_rules_fired),
        "alert_count": inc.alert_count,
        "sources": dict(Counter(a.source.value for a in alerts)),
        "first_seen": inc.first_seen.isoformat(),
        "last_seen": inc.last_seen.isoformat(),
        "assets": sorted({a.asset.asset_id for a in alerts if a.asset}),
        "tactics": [t.value for t in tactics],
        "top_technique": top.model_dump(mode="json") if top else None,
        "vendor_severities": dict(Counter((a.source_severity or "unknown").lower() for a in alerts)),
        "score": score.model_dump(mode="json"),
        "rationale": rationale_line(inc, alerts, score, fired),
        "has_bluf": get_bluf(conn, inc.incident_id) is not None,
    }


# ---------------------------------------------------------------------------
# Queue
# ---------------------------------------------------------------------------


def get_queue(*, limit: int = 50, min_alerts: int = 1, tactic: str | None = None, source: str | None = None, q: str | None = None) -> list[dict]:
    with connection() as conn:
        inventory = load_assets(conn)
        out = []
        for rank, inc in enumerate(load_incidents(conn), start=1):
            if inc.alert_count < min_alerts:
                continue
            summary = incident_summary(conn, inc, rank, inventory)
            if tactic and tactic not in summary["tactics"]:
                continue
            if source and source not in summary["sources"]:
                continue
            if q:
                hay = " ".join([summary["title"], " ".join(summary["assets"]), " ".join(inc.alert_ids), summary["rationale"]]).lower()
                if q.lower() not in hay:
                    continue
            out.append(summary)
            if len(out) >= limit:
                break
        return out


def get_incident_detail(incident_id: str) -> dict:
    with connection() as conn:
        inc = get_incident(conn, incident_id)
        if not inc:
            raise NotFound(f"Unknown incident {incident_id}")
        inventory = load_assets(conn)
        rank = queue_position(conn, incident_id)
        summary = incident_summary(conn, inc, rank, inventory)
        alerts = _incident_alerts(conn, inc)
        _, explanation, _ = score_incident(inc, alerts, inventory)
        chain: dict[str, dict] = {}
        for a in sorted(alerts, key=lambda x: x.timestamp):
            t = a.primary_technique
            if not t:
                continue
            entry = chain.setdefault(
                t.technique_id,
                {"technique_id": t.technique_id, "technique_name": t.technique_name, "tactic": t.tactic.value, "score": t.score, "alert_ids": []},
            )
            entry["alert_ids"].append(a.alert_id)
            entry["score"] = max(entry["score"], t.score)
        attack_chain = sorted(chain.values(), key=lambda e: Tactic(e["tactic"]).chain_position)
        bluf = get_bluf(conn, incident_id)
        return {
            **summary,
            "alerts": [alert_view(a, incident_id) for a in sorted(alerts, key=lambda x: x.timestamp)],
            "edges": [e.model_dump(mode="json") for e in inc.edges],
            "attack_chain": attack_chain,
            "score_explanation": explanation,
            "bluf": bluf.model_dump(mode="json") if bluf else None,
        }


def get_or_create_bluf(incident_id: str, *, use_watsonx: bool = True) -> dict:
    with connection() as conn:
        inc = get_incident(conn, incident_id)
        if not inc:
            raise NotFound(f"Unknown incident {incident_id}")
        report = get_bluf(conn, incident_id)
        if report is None:
            alerts = _incident_alerts(conn, inc)
            fired = evaluate_rules(inc, alerts)
            report = generate_bluf(inc, alerts, fired, use_watsonx=use_watsonx)
            save_bluf(report, conn)
        return report.model_dump(mode="json")


def bluf_text(incident_id: str) -> str:
    from src.models import BlufReport

    return render_bluf_text(BlufReport.model_validate(get_or_create_bluf(incident_id)))


# ---------------------------------------------------------------------------
# Explain
# ---------------------------------------------------------------------------


def _edge_prose(edge: dict) -> str:
    lines = [f"Edge {edge['alert_a']} ↔ {edge['alert_b']} (total weight {edge['total_weight']:.2f}):"]
    for c in edge["contributions"]:
        lines.append(f"  • {c['signal'].replace('_', ' ')} +{c['weight']:.2f}: {c['rationale']}")
    return "\n".join(lines)


def explain_correlation(alert_a: str, alert_b: str) -> dict:
    with connection() as conn:
        a, b = get_alert(conn, alert_a), get_alert(conn, alert_b)
        if not a or not b:
            missing = alert_a if not a else alert_b
            raise NotFound(f"Unknown alert {missing}")
        inc_a, inc_b = incident_for_alert(conn, alert_a), incident_for_alert(conn, alert_b)
        same = bool(inc_a and inc_b and inc_a.incident_id == inc_b.incident_id)
        direct = get_edge(conn, alert_a, alert_b)
        path: list[dict] = []
        if same and inc_a and not direct:
            g = nx.Graph()
            for e in inc_a.edges:
                g.add_edge(e.alert_a, e.alert_b, edge=e)
            try:
                nodes = nx.shortest_path(g, alert_a, alert_b)
                path = [g.edges[nodes[i], nodes[i + 1]]["edge"].model_dump(mode="json") for i in range(len(nodes) - 1)]
            except nx.NetworkXNoPath:
                path = []
        threshold = settings.correlation_threshold
        if direct:
            narrative = (
                f"{alert_a} and {alert_b} are directly linked (weight {direct.total_weight:.2f} ≥ threshold {threshold}). "
                + " ".join(f"{c.signal.value.replace('_', ' ').capitalize()}: {c.rationale}" for c in direct.contributions)
            )
        elif path:
            hops = " → ".join([path[0]["alert_a"] if path[0]["alert_a"] != alert_b else path[0]["alert_b"]] + [
                (e["alert_b"] if e["alert_a"] == prev else e["alert_a"]) for prev, e in zip([alert_a] + [None] * len(path), path)
            ][: len(path)])
            narrative = (
                f"{alert_a} and {alert_b} are in the same incident ({inc_a.incident_id}) but not directly linked; they are connected "
                f"through {len(path)} edge(s). Each hop clears the threshold on its own evidence:\n" + "\n".join(_edge_prose(e) for e in path)
            )
        elif same:
            narrative = f"Both alerts are in {inc_a.incident_id} but no path was found between them (this should not happen; re-run the pipeline)."
        else:
            # Compute what the engine *would* have scored, so the analyst sees why they were kept apart.
            from src.correlation.graph import CorrelationConfig, IndicatorRarity, score_pair

            all_alerts = load_alerts(conn)
            hypothetical = score_pair(a, b, IndicatorRarity(all_alerts), CorrelationConfig())
            narrative = (
                f"{alert_a} ({inc_a.incident_id if inc_a else 'no incident'}) and {alert_b} ({inc_b.incident_id if inc_b else 'no incident'}) "
                f"are NOT in the same incident. Scoring the pair gives {hypothetical.total_weight:.2f}, below the threshold {threshold}. "
                + (" ".join(f"{c.signal.value.replace('_', ' ').capitalize()} +{c.weight:.2f}: {c.rationale}" for c in hypothetical.contributions) or "No signal fired at all.")
            )
            direct = hypothetical if hypothetical.contributions else None
        return {
            "alert_a": alert_a,
            "alert_b": alert_b,
            "same_incident": same,
            "incident_id": inc_a.incident_id if same and inc_a else None,
            "edge": direct.model_dump(mode="json") if direct else None,
            "path": path,
            "narrative": narrative,
        }


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


def list_alerts(*, limit: int = 100, offset: int = 0, source: str | None = None, severity: str | None = None, q: str | None = None) -> dict:
    with connection() as conn:
        alerts = load_alerts(conn)
        alerts.sort(key=lambda a: a.timestamp, reverse=True)
        if source:
            alerts = [a for a in alerts if a.source.value == source]
        if severity:
            alerts = [a for a in alerts if (a.source_severity or "").lower() == severity.lower()]
        if q:
            ql = q.lower()
            alerts = [a for a in alerts if ql in a.raw_text.lower() or ql in a.alert_id.lower() or (a.asset and ql in a.asset.asset_id.lower())]
        total = len(alerts)
        page = alerts[offset : offset + limit]
        items = []
        for a in page:
            inc = incident_for_alert(conn, a.alert_id)
            items.append(alert_view(a, inc.incident_id if inc else None))
        return {"total": total, "items": items}


def get_alert_detail(alert_id: str) -> dict:
    with connection() as conn:
        a = get_alert(conn, alert_id)
        if not a:
            raise NotFound(f"Unknown alert {alert_id}")
        inc = incident_for_alert(conn, alert_id)
        total = stats(conn)["incidents"]
        return {
            **alert_view(a, inc.incident_id if inc else None),
            "queue_position": queue_position(conn, inc.incident_id) if inc else None,
            "total_incidents": total,
        }


def why_deprioritised(alert_id: str) -> dict:
    with connection() as conn:
        a = get_alert(conn, alert_id)
        if not a:
            raise NotFound(f"Unknown alert {alert_id}")
        inc = incident_for_alert(conn, alert_id)
        if not inc:
            raise NotFound(f"{alert_id} is not part of any incident; run the pipeline")
        inventory = load_assets(conn)
        alerts = _incident_alerts(conn, inc)
        score, explanation, fired = score_incident(inc, alerts, inventory)
        pos = queue_position(conn, inc.incident_id)
        total = stats(conn)["incidents"]
        vendor = a.source_severity or "unknown"
        rules = [{"rule_id": f.rule_id, "name": f.name, "rationale": f.rationale, "strength": f.strength, "evidence": f.evidence} for f in fired]
        if fired:
            narrative = (
                f"The {a.source.value} vendor marked {alert_id} '{vendor}'. AEGIS placed its incident {inc.incident_id} at position {pos} of {total} "
                f"(score {score.composite:.1f}/100) because {len(fired)} suppression rule(s) fired, giving a false-positive likelihood of "
                f"{score.false_positive_likelihood:.2f}. "
                + " ".join(f"{f.rule_id} — {f.name}: {f.evidence}" for f in fired)
                + f" Before suppression the four factors were: correlation confidence {score.correlation_confidence:.2f}, asset criticality "
                f"{score.asset_criticality:.2f}, tactic severity {score.tactic_severity:.2f}. What would change this: evidence that the activity "
                f"falls outside the documented expectation (different source address, different account, outside the window, or a technique beyond scanning)."
            )
        else:
            narrative = (
                f"The {a.source.value} vendor marked {alert_id} '{vendor}'. AEGIS placed its incident {inc.incident_id} at position {pos} of {total} "
                f"(score {score.composite:.1f}/100). No suppression rule fired; the position reflects the four factors directly: "
                f"{explanation['correlation_confidence']} {explanation['asset_criticality']} {explanation['tactic_severity']} "
                f"Vendor severity is preserved but deliberately not part of the score."
            )
        return {
            "alert_id": alert_id,
            "vendor_severity": vendor,
            "source": a.source.value,
            "incident_id": inc.incident_id,
            "queue_position": pos,
            "total_incidents": total,
            "score": score.model_dump(mode="json"),
            "score_explanation": explanation,
            "rules_fired": rules,
            "narrative": narrative,
        }


# ---------------------------------------------------------------------------
# Techniques, assets, feeds, stats
# ---------------------------------------------------------------------------


def search_techniques(q: str | None = None, *, limit: int = 40) -> list[dict]:
    with connection() as conn:
        counts = Counter()
        inc_counts: dict[str, set] = {}
        for row in conn.execute(
            "SELECT m.technique_id, m.alert_id, ia.incident_id FROM attack_mappings m"
            " LEFT JOIN incident_alerts ia ON ia.alert_id = m.alert_id WHERE m.score >= 0.5"
        ):
            counts[row["technique_id"]] += 1
            inc_counts.setdefault(row["technique_id"], set()).add(row["incident_id"])
    out = []
    ql = (q or "").lower().strip()
    for t in load_techniques():
        if ql and ql not in t.technique_id.lower() and ql not in t.name.lower():
            continue
        if not ql and counts[t.technique_id] == 0:
            continue
        out.append({
            "technique_id": t.technique_id,
            "name": t.name,
            "tactics": list(t.tactics),
            "url": t.url,
            "alert_count": counts[t.technique_id],
            "incident_count": len({i for i in inc_counts.get(t.technique_id, set()) if i}),
        })
    out.sort(key=lambda d: (-d["alert_count"], d["technique_id"]))
    return out[:limit]


def technique_detail(technique_id: str) -> dict:
    tid = technique_id.upper()
    t = technique_index().get(tid)
    if not t:
        raise NotFound(f"Unknown technique {technique_id}")
    with connection() as conn:
        alert_ids = alerts_by_technique(conn, tid)
        inventory = load_assets(conn)
        incidents = []
        seen = set()
        for rank, inc in enumerate(load_incidents(conn), start=1):
            if inc.incident_id in seen or not set(inc.alert_ids) & set(alert_ids):
                continue
            seen.add(inc.incident_id)
            incidents.append(incident_summary(conn, inc, rank, inventory))
    return {
        "technique": {"technique_id": t.technique_id, "name": t.name, "tactics": list(t.tactics), "url": t.url, "description": t.description[:600]},
        "alert_ids": alert_ids,
        "incidents": incidents,
    }


def list_assets() -> list[dict]:
    with connection() as conn:
        return sorted(load_assets(conn).values(), key=lambda a: (-a["criticality"], a["asset_id"]))


def raw_feeds(lines: int = 40) -> dict:
    out = {}
    for key, name in (("siem", "siem.json"), ("syslog", "sensors.syslog"), ("geo", "geo_tracks.csv"), ("intel", "intel_reports.txt")):
        path = settings.feeds_dir / name
        if path.exists():
            text = path.read_text(encoding="utf-8").splitlines()
            out[key] = "\n".join(text[:lines])
        else:
            out[key] = ""
    return out


def get_stats() -> dict:
    with connection() as conn:
        return stats(conn)


def suppression_rules() -> list[dict]:
    return rule_catalogue()


def health() -> dict:
    with connection() as conn:
        s = stats(conn)
    return {"status": "ok", "alerts": s["alerts"], "incidents": s["incidents"]}
