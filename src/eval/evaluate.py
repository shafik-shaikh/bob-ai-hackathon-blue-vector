"""`python -m src.eval.evaluate` - measure the pipeline against ground truth.

Reports, per planted scenario:

* **coverage** - fraction of the scenario's alerts that landed in the
  best-matching incident (recall at alert level);
* **purity** - fraction of that incident's alerts that belong to the scenario
  (precision at alert level);
* **queue position** of the best-matching incident, and whether a benign
  scenario was suppressed below every true positive.

And overall: scenario detection rate, mean queue position of true positives,
suppression success, ATT&CK mapping coverage on planted alerts, and the
fraction of noise alerts that stayed out of multi-alert incidents.

Writes `src/eval/results.json` and prints a Markdown table. The numbers in
the README come from here, not from adjectives.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean

from src.config import settings
from src.db.store import connection, incident_for_alert, load_alerts, load_incidents

RESULTS_PATH = Path(__file__).resolve().parent / "results.json"


def evaluate(*, verbose: bool = True) -> dict:
    truth = json.loads(settings.ground_truth_path.read_text(encoding="utf-8"))
    with connection() as conn:
        incidents = load_incidents(conn)
        alerts = load_alerts(conn)
        inc_of = {}
        for inc in incidents:
            for aid in inc.alert_ids:
                inc_of[aid] = inc
    rank = {inc.incident_id: r for r, inc in enumerate(incidents, start=1)}
    planted = {aid for s in truth["scenarios"] for aid in s["alert_ids"]}
    by_id = {a.alert_id: a for a in alerts}

    rows = []
    for s in truth["scenarios"]:
        ids = s["alert_ids"]
        groups: dict[str, list[str]] = {}
        for aid in ids:
            inc = inc_of.get(aid)
            groups.setdefault(inc.incident_id if inc else "none", []).append(aid)
        best_id = max(groups, key=lambda k: len(groups[k]))
        best = next((i for i in incidents if i.incident_id == best_id), None)
        covered = len(groups[best_id])
        extras = [a for a in (best.alert_ids if best else []) if a not in ids]
        mapped = sum(1 for aid in ids if by_id[aid].primary_technique)
        rows.append({
            "scenario": s["key"],
            "label": s["label"],
            "ambiguous": s["ambiguous"],
            "alerts": len(ids),
            "best_incident": best_id,
            "coverage": round(covered / len(ids), 3),
            "purity": round(covered / (covered + len(extras)), 3) if best else 0.0,
            "fragments": len(groups),
            "missing": [a for k, v in groups.items() if k != best_id for a in v],
            "extras": extras,
            "queue_position": rank.get(best_id),
            "composite": best.score.composite if best and best.score else None,
            "rules_fired": best.score.suppression_rules_fired if best and best.score else [],
            "attack_mapped": f"{mapped}/{len(ids)}",
        })

    tps = [r for r in rows if r["label"] == "true_positive"]
    benign = [r for r in rows if r["label"] == "benign"]
    worst_tp_rank = max(r["queue_position"] for r in tps)
    suppressed_ok = sum(1 for r in benign if r["rules_fired"] and r["queue_position"] > worst_tp_rank)

    noise_in_multi = sum(1 for inc in incidents if inc.alert_count > 1 for a in inc.alert_ids if a not in planted)
    noise_total = len(alerts) - len(planted)

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "correlation_threshold": settings.correlation_threshold,
            "temporal_halflife_seconds": settings.temporal_halflife_seconds,
            "embedding_backend": settings.embedding_backend,
        },
        "alerts": len(alerts),
        "planted_alerts": len(planted),
        "incidents": len(incidents),
        "multi_alert_incidents": sum(1 for i in incidents if i.alert_count > 1),
        "scenarios_detected": sum(1 for r in tps if r["coverage"] >= 0.5),
        "true_positive_scenarios": len(tps),
        "mean_tp_coverage": round(mean(r["coverage"] for r in tps), 3),
        "mean_tp_purity": round(mean(r["purity"] for r in tps), 3),
        "mean_tp_queue_position": round(mean(r["queue_position"] for r in tps), 2),
        "worst_tp_queue_position": worst_tp_rank,
        "benign_scenarios_suppressed_below_all_tps": f"{suppressed_ok}/{len(benign)}",
        "noise_alerts_pulled_into_multi_alert_incidents": f"{noise_in_multi}/{noise_total}",
        "planted_alerts_with_attack_mapping": f"{sum(1 for a in planted if by_id[a].primary_technique)}/{len(planted)}",
        "scenarios": rows,
    }
    RESULTS_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8", newline="\n")

    if verbose:
        print(f"AEGIS evaluation - {len(alerts)} alerts, {len(planted)} planted, threshold {settings.correlation_threshold}\n")
        print("| Scenario | Label | Alerts | Coverage | Purity | Queue pos | Score | Rules fired |")
        print("|---|---|---|---|---|---|---|---|")
        for r in rows:
            print(f"| {r['scenario']} | {r['label']}{' (ambiguous)' if r['ambiguous'] else ''} | {r['alerts']} | {r['coverage']:.2f} | {r['purity']:.2f} | "
                  f"{r['queue_position']} | {r['composite']:.1f} | {', '.join(r['rules_fired']) or '-'} |")
        print()
        for k in ("scenarios_detected", "mean_tp_coverage", "mean_tp_purity", "mean_tp_queue_position", "worst_tp_queue_position",
                  "benign_scenarios_suppressed_below_all_tps", "noise_alerts_pulled_into_multi_alert_incidents", "planted_alerts_with_attack_mapping"):
            print(f"{k:50} {summary[k]}")
        print(f"\nresults written to {RESULTS_PATH}")
    return summary


if __name__ == "__main__":
    evaluate()
