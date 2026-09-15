"""`python -m src.pipeline.run` - ingest → enrich → correlate → score → brief.

Each stage reads and writes SQLite, so the console and the MCP server see
exactly what this run produced. The stage summary is persisted too and shown
in the console header.
"""

from __future__ import annotations

import argparse
import time
from datetime import datetime, timezone

from src.bluf.generator import generate_bluf
from src.config import settings
from src.correlation.graph import CorrelationConfig, correlate
from src.db.store import (
    connection,
    init_db,
    load_alerts,
    load_assets,
    record_run,
    replace_edges,
    replace_incidents,
    save_bluf,
    update_incident,
    upsert_alerts,
)
from src.enrichment.attack_mapper import attack_version, backend, map_alerts
from src.scoring.prioritiser import score_incident
from src.scoring.suppression import evaluate_rules


def run_pipeline(*, use_watsonx: bool = True, bluf_top_n: int | None = None, verbose: bool = True) -> dict:
    started = datetime.now(timezone.utc)
    summary: dict = {"started_at": started.isoformat()}
    log = print if verbose else (lambda *a, **k: None)
    init_db()

    with connection() as conn:
        alerts = load_alerts(conn)
        inventory = load_assets(conn)
    if not alerts:
        raise SystemExit("No alerts in the database. Run `python -m src.corpus.load` first.")
    log(f"[pipeline] {len(alerts)} alerts loaded")

    # ---- enrichment: ATT&CK mapping (IOC extraction happened at ingest)
    t0 = time.time()
    mappings = map_alerts(alerts)
    with connection() as conn:
        upsert_alerts(alerts, conn)
    summary["attack"] = {"version": attack_version(), "backend": backend().name, "mappings": mappings, "mapped_alerts": sum(1 for a in alerts if a.techniques)}
    log(f"[enrich]   ATT&CK v{attack_version()} ({backend().name}): {mappings} mappings on {summary['attack']['mapped_alerts']} alerts in {time.time() - t0:.1f}s")

    # ---- correlation
    t0 = time.time()
    cfg = CorrelationConfig()
    edges, incidents, info = correlate(alerts, cfg)
    with connection() as conn:
        replace_edges(edges, conn)
        replace_incidents(incidents, conn)
    summary["correlation"] = info
    log(f"[correlate] {info['candidate_pairs']} candidate pairs -> {info['edges_kept']} edges >= {cfg.threshold} -> "
        f"{info['incidents']} incidents ({info['multi_alert_incidents']} multi-alert, largest {info['largest_incident']}) in {time.time() - t0:.1f}s")

    # ---- scoring
    t0 = time.time()
    by_id = {a.alert_id: a for a in alerts}
    suppressed = 0
    with connection() as conn:
        for inc in incidents:
            inc_alerts = [by_id[i] for i in inc.alert_ids]
            breakdown, _, fired = score_incident(inc, inc_alerts, inventory)
            inc.score = breakdown
            suppressed += 1 if fired else 0
            update_incident(inc, conn)
    incidents.sort(key=lambda i: -(i.score.composite if i.score else 0))
    summary["scoring"] = {"scored": len(incidents), "suppressed": suppressed, "top_score": incidents[0].score.composite if incidents else None}
    log(f"[score]    {len(incidents)} incidents scored, {suppressed} with suppression rules fired, in {time.time() - t0:.1f}s")

    # ---- BLUF for the top of the queue
    t0 = time.time()
    n = bluf_top_n or settings.bluf_top_n
    generated = {"template": 0, "watsonx": 0}
    with connection() as conn:
        for inc in incidents[:n]:
            inc_alerts = [by_id[i] for i in inc.alert_ids]
            fired = evaluate_rules(inc, inc_alerts)
            report = generate_bluf(inc, inc_alerts, fired, use_watsonx=use_watsonx)
            save_bluf(report, conn)
            generated[report.generated_by] += 1
    summary["bluf"] = {**generated, "watsonx_configured": settings.watsonx_configured}
    log(f"[bluf]     {sum(generated.values())} briefs ({generated['watsonx']} watsonx, {generated['template']} template) in {time.time() - t0:.1f}s")

    summary["finished_at"] = datetime.now(timezone.utc).isoformat()
    summary["alerts"] = len(alerts)
    with connection() as conn:
        record_run(summary, conn)
    log(f"[pipeline] done. Top of queue: " + ", ".join(f"{i.incident_id} ({i.score.composite:.0f})" for i in incidents[:5]))
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the AEGIS pipeline over the loaded corpus.")
    parser.add_argument("--no-watsonx", action="store_true", help="Skip watsonx even if configured.")
    parser.add_argument("--bluf-top-n", type=int, default=None, help="How many top incidents get a BLUF (default from env).")
    args = parser.parse_args()
    run_pipeline(use_watsonx=not args.no_watsonx, bluf_top_n=args.bluf_top_n)


if __name__ == "__main__":
    main()
