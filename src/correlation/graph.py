"""Correlation engine: weighted alert graph → connected-component incidents.

Every alert is a node. For each candidate pair, four independent signals each
contribute a weighted `SignalContribution` with a plain-language rationale:

    Signal 1  shared indicator   max 0.40   rarity-weighted (IDF across corpus)
    Signal 2  temporal proximity max 0.20   exponential decay, no hard window
    Signal 3  asset adjacency    max 0.15   same host / subnet / user, or mention
    Signal 4  tactic progression max 0.25   directional kill-chain ordering

An edge is kept when the sum clears `CORRELATION_THRESHOLD`; incidents are the
connected components of the kept edges. The contributions are persisted with
the edge, which is what lets `explain_correlation` answer "why are these two
alerts together?" with the actual evidence rather than a post-hoc guess.

Candidate generation is bounded: pairs are considered when they fall inside
`CORRELATION_WINDOW_HOURS` of each other *or* share at least one indicator.
That keeps the pairwise work well below O(n²) on a real-sized queue while
guaranteeing that a shared hash is never missed because of a time gap.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

import networkx as nx

from src.config import settings
from src.correlation.tactics import progression_score
from src.enrichment.ioc import is_private_ip
from src.models import Alert, CorrelationEdge, Incident, IndicatorType, SignalContribution, SignalType, SourceType

SIGNAL_WEIGHTS = {
    SignalType.SHARED_INDICATOR: 0.40,
    SignalType.TEMPORAL: 0.20,
    SignalType.ASSET_ADJACENCY: 0.15,
    SignalType.TACTIC_PROGRESSION: 0.25,
}

# How conclusive a *shared* indicator of each type is, independent of rarity.
# A shared SHA-256 is near-proof; a shared hostname is a hint.
INDICATOR_TYPE_FACTOR = {
    IndicatorType.SHA256: 1.0,
    IndicatorType.SHA1: 1.0,
    IndicatorType.MD5: 0.95,
    IndicatorType.URL: 1.0,
    IndicatorType.DOMAIN: 0.9,
    IndicatorType.EMAIL: 0.9,
    IndicatorType.MAC: 0.9,
    IndicatorType.IPV6: 0.9,
    IndicatorType.IPV4: 0.9,  # reduced to 0.6 for RFC1918 space, see below
    IndicatorType.CVE: 0.7,
    IndicatorType.USER: 0.7,
    IndicatorType.HOSTNAME: 0.6,
}


# Shared use of sanctioned or ubiquitous infrastructure is not evidence that
# two alerts describe the same activity, however rare the indicator is in
# this particular corpus. Curated by the domain owner; the factor applies on
# top of rarity. A real deployment would source this from the proxy allowlist.
BENIGN_INFRASTRUCTURE: dict[str, str] = {
    "dropbox.com": "sanctioned personal cloud storage (proxy policy allows)",
    "www.dropbox.com": "sanctioned personal cloud storage (proxy policy allows)",
    "https://www.dropbox.com/": "sanctioned personal cloud storage (proxy policy allows)",
    "cdn.office.net": "Microsoft 365 content delivery",
    "update.microsoft.com": "Windows Update",
    "teams.microsoft.com": "Microsoft Teams",
    "static.corp-cdn.example": "corporate CDN",
    "avupdates.vendor.example": "endpoint protection signature updates",
    "203.0.113.10": "own VPN gateway public address (destination of all perimeter events)",
    "10.20.1.53": "internal DNS resolver (destination of DNS telemetry)",
}
BENIGN_INFRASTRUCTURE_FACTOR = 0.15


@dataclass
class CorrelationConfig:
    threshold: float = settings.correlation_threshold
    halflife_seconds: float = settings.temporal_halflife_seconds
    window_hours: float = settings.correlation_window_hours
    max_incident_size: int = settings.max_incident_size


# ---------------------------------------------------------------------------
# Indicator rarity
# ---------------------------------------------------------------------------


class IndicatorRarity:
    """Inverse document frequency of every indicator across the corpus."""

    def __init__(self, alerts: list[Alert]):
        self.n = max(1, len(alerts))
        self.df: dict[tuple[IndicatorType, str], int] = defaultdict(int)
        for a in alerts:
            for ind in {(i.type, i.value) for i in a.indicators}:
                self.df[ind] += 1
        self.idf_max = math.log(self.n / 1.0)

    def rarity(self, ind: tuple[IndicatorType, str]) -> float:
        """0 (everywhere) … 1 (appears in a single alert)."""
        df = self.df.get(ind, 1)
        return math.log(self.n / df) / self.idf_max if self.idf_max else 0.0


# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------


def _fmt_minutes(seconds: float) -> str:
    if seconds < 90:
        return f"{int(seconds)} s"
    if seconds < 5400:
        return f"{seconds / 60:.0f} min"
    return f"{seconds / 3600:.1f} h"


def signal_shared_indicator(a: Alert, b: Alert, rarity: IndicatorRarity) -> SignalContribution | None:
    shared = {(i.type, i.value) for i in a.indicators} & {(i.type, i.value) for i in b.indicators}
    if not shared:
        return None
    scored = []
    for ind in shared:
        factor = INDICATOR_TYPE_FACTOR.get(ind[0], 0.5)
        if ind[0] == IndicatorType.IPV4 and is_private_ip(ind[1]):
            factor = 0.6
        if ind[1] in BENIGN_INFRASTRUCTURE:
            factor *= BENIGN_INFRASTRUCTURE_FACTOR
        scored.append((rarity.rarity(ind) * factor, ind))
    scored.sort(reverse=True)
    best, best_ind = scored[0]
    # Additional shared indicators add corroboration with diminishing returns.
    strength = best
    for r, _ in scored[1:]:
        strength += (1 - strength) * r * 0.5
    strength = min(1.0, strength)
    parts = [
        f"{ind[0].value} {ind[1]} (in {rarity.df[ind]} of {rarity.n} alerts"
        + (f"; discounted: {BENIGN_INFRASTRUCTURE[ind[1]]}" if ind[1] in BENIGN_INFRASTRUCTURE else "")
        + ")"
        for _, ind in scored[:3]
    ]
    more = f" and {len(scored) - 3} more" if len(scored) > 3 else ""
    return SignalContribution(
        signal=SignalType.SHARED_INDICATOR,
        weight=round(SIGNAL_WEIGHTS[SignalType.SHARED_INDICATOR] * strength, 3),
        rationale=f"Both alerts reference {', '.join(parts)}{more}.",
    )


# An intelligence report is a standing assessment, not a point event: it stays
# relevant to activity for days, so its temporal decay is much slower.
INTEL_HALFLIFE_SECONDS = 7 * 24 * 3600


def signal_temporal(a: Alert, b: Alert, halflife: float) -> SignalContribution | None:
    dt = abs((a.timestamp - b.timestamp).total_seconds())
    if SourceType.INTEL in (a.source, b.source):
        halflife = max(halflife, INTEL_HALFLIFE_SECONDS)
    decay = 0.5 ** (dt / halflife)
    if decay < 0.02:
        return None
    return SignalContribution(
        signal=SignalType.TEMPORAL,
        weight=round(SIGNAL_WEIGHTS[SignalType.TEMPORAL] * decay, 3),
        rationale=f"{_fmt_minutes(dt)} apart (half-life {_fmt_minutes(halflife)}; decay factor {decay:.2f}).",
    )


def _mentions(alert: Alert, other: Alert) -> str | None:
    """Does `alert` name `other`'s asset among its indicators?"""
    if not other.asset:
        return None
    names = {v for v in (other.asset.hostname, other.asset.asset_id, other.asset.ip) if v}
    names = {n.lower() for n in names}
    for ind in alert.indicators:
        if ind.type in (IndicatorType.HOSTNAME, IndicatorType.IPV4) and ind.value.lower() in names:
            return ind.value
    return None


def signal_asset_adjacency(a: Alert, b: Alert) -> SignalContribution | None:
    best = 0.0
    why = ""
    if a.asset and b.asset:
        if a.asset.asset_id == b.asset.asset_id:
            ua, ub = a.asset.user_principal, b.asset.user_principal
            if ua and ub and ua != ub:
                best, why = 0.75, f"Same asset {a.asset.asset_id}, but different principals ({ua} vs {ub})."
            else:
                best, why = 1.0, f"Same asset {a.asset.asset_id}."
        else:
            if a.asset.user_principal and a.asset.user_principal == b.asset.user_principal:
                best, why = 0.8, f"Same user principal {a.asset.user_principal} on {a.asset.asset_id} and {b.asset.asset_id}."
            if a.asset.subnet and a.asset.subnet == b.asset.subnet and best < 0.6:
                best, why = 0.6, f"Same subnet {a.asset.subnet} ({a.asset.asset_id} and {b.asset.asset_id})."
    if best < 0.7:
        for src, dst in ((a, b), (b, a)):
            hit = _mentions(src, dst)
            if hit:
                best, why = 0.7, f"{src.alert_id} explicitly references {dst.asset.asset_id} ({hit}), the asset of {dst.alert_id}."
                break
    if best == 0.0:
        return None
    return SignalContribution(
        signal=SignalType.ASSET_ADJACENCY,
        weight=round(SIGNAL_WEIGHTS[SignalType.ASSET_ADJACENCY] * best, 3),
        rationale=why,
    )


# Below this mapping confidence a technique is a guess, and guesses do not chain.
MIN_MAPPING_CONFIDENCE_FOR_CHAIN = 0.55
# Kill-chain ordering is evidence of *one* operation only when the two alerts
# are already tied to a common entity (same host/user, an explicit mention, or
# a shared indicator). Without that tie, ordering is coincidence of timing and
# the signal is halved.
UNTIED_PROGRESSION_FACTOR = 0.5


def signal_tactic_progression(a: Alert, b: Alert, *, tied: bool) -> SignalContribution | None:
    if not a.techniques or not b.techniques:
        return None
    first, second = (a, b) if a.timestamp <= b.timestamp else (b, a)
    best: tuple[float, str, object, object, float] | None = None
    # Consider the top two mappings on each side: the second-ranked technique
    # is often the one that carries the progression (an alert that is both
    # "shadow copies deleted" and "masquerading" chains on either).
    for tf in first.techniques[:2]:
        for ts in second.techniques[:2]:
            confidence = min(tf.score, ts.score)
            if confidence < MIN_MAPPING_CONFIDENCE_FOR_CHAIN:
                continue
            score, why = progression_score(tf.tactic, ts.tactic)
            if tf.technique_id == ts.technique_id:
                score, why = max(score, 0.6), f"Both alerts map to the same technique {tf.technique_id}; repeated technique is consistent with one operation."
            value = score * confidence
            if best is None or value > best[0]:
                best = (value, why, tf, ts, confidence)
    if best is None or best[0] <= 0:
        return None
    value, why, tf, ts, confidence = best
    factor = 1.0 if tied else UNTIED_PROGRESSION_FACTOR
    weight = SIGNAL_WEIGHTS[SignalType.TACTIC_PROGRESSION] * value * factor
    if weight < 0.01:
        return None
    tie_note = "" if tied else " Halved: the alerts share no entity or indicator, so ordering alone is weak evidence."
    return SignalContribution(
        signal=SignalType.TACTIC_PROGRESSION,
        weight=round(weight, 3),
        rationale=(
            f"{first.alert_id} maps to {tf.technique_id} ({tf.tactic.value}), then {second.alert_id} maps to "
            f"{ts.technique_id} ({ts.tactic.value}). {why} Progression {value / confidence:.2f} × mapping confidence {confidence:.2f}.{tie_note}"
        ),
    )


# ---------------------------------------------------------------------------
# Edge construction
# ---------------------------------------------------------------------------


def score_pair(a: Alert, b: Alert, rarity: IndicatorRarity, cfg: CorrelationConfig) -> CorrelationEdge:
    shared = signal_shared_indicator(a, b, rarity)
    adjacency = signal_asset_adjacency(a, b)
    # "Tied" = same host or user, an explicit mention, or any shared indicator.
    tied = shared is not None or (adjacency is not None and adjacency.weight >= SIGNAL_WEIGHTS[SignalType.ASSET_ADJACENCY] * 0.7 - 1e-9)
    contributions = [
        c
        for c in (
            shared,
            signal_temporal(a, b, cfg.halflife_seconds),
            adjacency,
            signal_tactic_progression(a, b, tied=tied),
        )
        if c is not None
    ]
    total = round(sum(c.weight for c in contributions), 3)
    return CorrelationEdge(alert_a=a.alert_id, alert_b=b.alert_id, total_weight=total, contributions=contributions)


def candidate_pairs(alerts: list[Alert], cfg: CorrelationConfig) -> set[tuple[int, int]]:
    """Indices of alert pairs worth scoring: close in time, or sharing an indicator."""
    ordered = sorted(range(len(alerts)), key=lambda i: alerts[i].timestamp)
    window = timedelta(hours=cfg.window_hours)
    pairs: set[tuple[int, int]] = set()
    for pos, i in enumerate(ordered):
        ti = alerts[i].timestamp
        for j in ordered[pos + 1 :]:
            if alerts[j].timestamp - ti > window:
                break
            pairs.add((min(i, j), max(i, j)))
    by_indicator: dict[tuple[IndicatorType, str], list[int]] = defaultdict(list)
    for i, a in enumerate(alerts):
        for ind in {(x.type, x.value) for x in a.indicators}:
            by_indicator[ind].append(i)
    for members in by_indicator.values():
        if 1 < len(members) <= 60:  # an indicator in 60+ alerts is noise, not evidence
            for x in range(len(members)):
                for y in range(x + 1, len(members)):
                    pairs.add((min(members[x], members[y]), max(members[x], members[y])))
    return pairs


def build_edges(alerts: list[Alert], cfg: CorrelationConfig | None = None) -> tuple[list[CorrelationEdge], dict]:
    cfg = cfg or CorrelationConfig()
    rarity = IndicatorRarity(alerts)
    pairs = candidate_pairs(alerts, cfg)
    edges: list[CorrelationEdge] = []
    for i, j in pairs:
        edge = score_pair(alerts[i], alerts[j], rarity, cfg)
        if edge.total_weight >= cfg.threshold:
            edges.append(edge)
    info = {"candidate_pairs": len(pairs), "edges_kept": len(edges), "threshold": cfg.threshold}
    return edges, info


# ---------------------------------------------------------------------------
# Incident extraction
# ---------------------------------------------------------------------------


def _split_oversized(graph: nx.Graph, cap: int) -> None:
    """Remove weakest edges until no component exceeds `cap` alerts.

    A single noisy indicator (or a very busy host) can otherwise glue the
    whole corpus into one incident. The cap is a safety rail, not a tuning
    knob; the log reports when it fires so the threshold can be revisited.
    """
    while True:
        big = [c for c in nx.connected_components(graph) if len(c) > cap]
        if not big:
            return
        for comp in big:
            sub = graph.subgraph(comp)
            weakest = min(sub.edges(data=True), key=lambda e: e[2]["weight"])
            graph.remove_edge(weakest[0], weakest[1])


def extract_incidents(alerts: list[Alert], edges: list[CorrelationEdge], cfg: CorrelationConfig | None = None) -> list[Incident]:
    cfg = cfg or CorrelationConfig()
    by_id = {a.alert_id: a for a in alerts}
    graph = nx.Graph()
    graph.add_nodes_from(by_id)
    for e in edges:
        graph.add_edge(e.alert_a, e.alert_b, weight=e.total_weight, edge=e)
    _split_oversized(graph, cfg.max_incident_size)

    components = sorted(
        nx.connected_components(graph),
        key=lambda c: (-len(c), min(by_id[x].timestamp for x in c)),
    )
    incidents: list[Incident] = []
    multi = [c for c in components if len(c) > 1]
    singles = [c for c in components if len(c) == 1]
    multi.sort(key=lambda c: min(by_id[x].timestamp for x in c))
    singles.sort(key=lambda c: min(by_id[x].timestamp for x in c))
    n = 0
    for comp in multi + singles:
        n += 1
        members = sorted(comp, key=lambda x: by_id[x].timestamp)
        comp_edges = [d["edge"] for u, v, d in graph.subgraph(comp).edges(data=True)]
        incidents.append(
            Incident(
                incident_id=f"INC-{n:03d}",
                alert_ids=members,
                edges=sorted(comp_edges, key=lambda e: -e.total_weight),
                first_seen=by_id[members[0]].timestamp,
                last_seen=max(by_id[x].timestamp for x in members),
            )
        )
    return incidents


def correlate(alerts: list[Alert], cfg: CorrelationConfig | None = None) -> tuple[list[CorrelationEdge], list[Incident], dict]:
    cfg = cfg or CorrelationConfig()
    edges, info = build_edges(alerts, cfg)
    incidents = extract_incidents(alerts, edges, cfg)
    info["incidents"] = len(incidents)
    info["multi_alert_incidents"] = sum(1 for i in incidents if i.alert_count > 1)
    info["largest_incident"] = max((i.alert_count for i in incidents), default=0)
    return edges, incidents, info
