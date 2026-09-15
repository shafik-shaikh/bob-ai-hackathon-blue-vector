"""Four-factor incident prioritisation.

    composite = 100 × (0.35·confidence + 0.30·asset + 0.25·tactic + 0.10·breadth) × (1 − fp)

The factors are kept separate in `ScoreBreakdown` and rendered separately in
the console, because a single number an analyst cannot decompose is a number
an analyst will not trust.

Design decision worth defending: asset criticality carries almost as much
weight as correlation confidence. A medium-confidence incident on a domain
controller *should* outrank a high-confidence one on a print server. Sorting
by confidence alone reproduces the vendor-severity problem this system
exists to fix. Vendor severity is deliberately absent from the formula - it is
preserved on every alert, shown in the console, and never trusted.
"""

from __future__ import annotations

from statistics import mean

from src.correlation.tactics import tactic_depth
from src.models import Alert, Incident, ScoreBreakdown, Tactic
from src.scoring.suppression import FiredRule, combined_likelihood, evaluate_rules

WEIGHTS = {"confidence": 0.35, "asset": 0.30, "tactic": 0.25, "breadth": 0.10}
UNKNOWN_ASSET_CRITICALITY = 2  # of 5


def correlation_confidence(incident: Incident, alerts: list[Alert]) -> tuple[float, str]:
    mapping_scores = [a.primary_technique.score for a in alerts if a.primary_technique]
    mapping = mean(mapping_scores) if mapping_scores else 0.0
    if incident.alert_count == 1:
        value = 0.4 * mapping
        return round(value, 3), f"Single alert, no corroborating edge; confidence rests on its ATT&CK mapping alone ({mapping:.2f})."
    edge_mean = mean(e.total_weight for e in incident.edges) if incident.edges else 0.0
    edge_strength = min(1.0, edge_mean / 0.8)
    value = 0.6 * edge_strength + 0.4 * mapping
    return round(value, 3), (
        f"{len(incident.edges)} correlation edges, mean weight {edge_mean:.2f} (normalised {edge_strength:.2f}); "
        f"mean ATT&CK mapping confidence across {len(mapping_scores)} mapped alerts {mapping:.2f}."
    )


def asset_criticality(alerts: list[Alert], inventory: dict[str, dict]) -> tuple[float, str]:
    best = 0
    best_asset = None
    for a in alerts:
        if not a.asset:
            continue
        rec = inventory.get(a.asset.asset_id)
        crit = int(rec["criticality"]) if rec else UNKNOWN_ASSET_CRITICALITY
        if crit > best:
            best, best_asset = crit, a.asset.asset_id
    if best == 0:
        return 0.2, "No asset resolved (report-only incident); default criticality 1/5."
    rec = inventory.get(best_asset or "", {})
    role = rec.get("role", "unregistered asset")
    return round(best / 5, 3), f"Highest-value asset involved: {best_asset} ({role}), criticality {best}/5."


def tactic_severity(alerts: list[Alert]) -> tuple[float, str]:
    tactics: list[Tactic] = [a.primary_technique.tactic for a in alerts if a.primary_technique]
    if not tactics:
        return 0.0, "No ATT&CK technique mapped."
    depth = tactic_depth(tactics)
    distinct = sorted({t for t in tactics}, key=lambda t: t.chain_position)
    chain = min(1.0, len(distinct) / 5)
    value = 0.7 * depth + 0.3 * chain
    deepest = max(distinct, key=lambda t: t.chain_position)
    return round(value, 3), (
        f"Deepest stage reached: {deepest.value} ({depth:.2f} of kill chain); {len(distinct)} distinct tactic(s) observed "
        f"({' → '.join(t.value for t in distinct)})."
    )


def breadth(alerts: list[Alert]) -> float:
    sources = {a.source for a in alerts}
    return round(0.5 * min(1.0, (len(alerts) - 1) / 6) + 0.5 * min(1.0, (len(sources) - 1) / 3), 3)


def score_incident(incident: Incident, alerts: list[Alert], inventory: dict[str, dict]) -> tuple[ScoreBreakdown, dict[str, str], list[FiredRule]]:
    conf, conf_why = correlation_confidence(incident, alerts)
    asset, asset_why = asset_criticality(alerts, inventory)
    tactic, tactic_why = tactic_severity(alerts)
    spread = breadth(alerts)
    fired = evaluate_rules(incident, alerts)
    fp = combined_likelihood(fired)
    fp_why = (
        "No suppression rule matched."
        if not fired
        else "; ".join(f"{f.rule_id} (strength {f.strength:.2f})" for f in fired)
    )
    base = WEIGHTS["confidence"] * conf + WEIGHTS["asset"] * asset + WEIGHTS["tactic"] * tactic + WEIGHTS["breadth"] * spread
    composite = round(100 * base * (1 - fp), 1)
    breakdown = ScoreBreakdown(
        correlation_confidence=conf,
        asset_criticality=asset,
        tactic_severity=tactic,
        false_positive_likelihood=fp,
        suppression_rules_fired=[f.rule_id for f in fired],
        composite=max(0.0, min(100.0, composite)),
    )
    explanation = {
        "correlation_confidence": conf_why,
        "asset_criticality": asset_why,
        "tactic_severity": tactic_why,
        "false_positive_likelihood": fp_why,
        "breadth": f"{len(alerts)} alert(s) across {len({a.source for a in alerts})} source(s) → breadth {spread:.2f}.",
        "formula": f"100 × (0.35×{conf:.2f} + 0.30×{asset:.2f} + 0.25×{tactic:.2f} + 0.10×{spread:.2f}) × (1 − {fp:.2f}) = {composite}",
    }
    return breakdown, explanation, fired


def rationale_line(incident: Incident, alerts: list[Alert], breakdown: ScoreBreakdown, fired: list[FiredRule]) -> str:
    tactics = [a.primary_technique.tactic for a in alerts if a.primary_technique]
    deepest = max(tactics, key=lambda t: t.chain_position).value if tactics else "no technique"
    assets = sorted({a.asset.asset_id for a in alerts if a.asset})
    if fired:
        return f"Suppressed by {', '.join(f.rule_id for f in fired)}: likely benign despite reaching {deepest}."
    return (
        f"{incident.alert_count} alert(s) reach {deepest} on {', '.join(assets[:3]) or 'unresolved asset'}; "
        f"confidence {breakdown.correlation_confidence:.2f}, asset criticality {breakdown.asset_criticality:.2f}."
    )
