"""Deterministic BLUF generation.

This is not a degraded mode. It is the path the demo runs on when watsonx is
unreachable, and it is the structured evidence that the watsonx prompt is
built from when it *is* reachable. Everything in the brief is derived from
persisted incident state, so every sentence can be traced to an alert.

    BOTTOM LINE: one sentence - what happened, to what, how sure
    CONFIDENCE:  High/Medium/Low - what drives it
    ASSESSMENT:  2-3 sentences of narrative
    ATT&CK:      techniques in kill-chain order
    EVIDENCE:    the alerts, with sources and timestamps
    RECOMMENDED: prioritised actions for the next 30 minutes
    GAPS:        what we do not know and what would resolve it
"""

from __future__ import annotations

from collections import Counter

from src.models import Alert, BlufReport, Confidence, Incident, IndicatorType, Tactic, TechniqueMapping
from src.scoring.suppression import FiredRule

# What each stage means to a commander, in plain language.
STAGE_MEANING = {
    Tactic.RECONNAISSANCE: "hostile reconnaissance",
    Tactic.RESOURCE_DEVELOPMENT: "adversary staging of infrastructure",
    Tactic.INITIAL_ACCESS: "an initial intrusion attempt",
    Tactic.EXECUTION: "hostile code execution",
    Tactic.PERSISTENCE: "an established foothold",
    Tactic.PRIVILEGE_ESCALATION: "privilege escalation",
    Tactic.DEFENSE_EVASION: "deliberate evasion of defences",
    Tactic.CREDENTIAL_ACCESS: "credential theft",
    Tactic.DISCOVERY: "internal reconnaissance",
    Tactic.LATERAL_MOVEMENT: "lateral movement between systems",
    Tactic.COLLECTION: "staging of data for theft",
    Tactic.COMMAND_AND_CONTROL: "an active command-and-control channel",
    Tactic.EXFILTRATION: "data exfiltration",
    Tactic.IMPACT: "destructive or disruptive action",
}

# Prioritised actions by the deepest stage reached. Ordered for the next 30 min.
STAGE_ACTIONS = {
    Tactic.IMPACT: [
        "Isolate {assets} from the network now; do not power off (preserve memory).",
        "Confirm backup integrity for {assets} and take BACKUP-01 offline from the domain until verified.",
        "Engage the incident response cell and notify the commander of probable mission impact.",
    ],
    Tactic.EXFILTRATION: [
        "Block {external} at the perimeter and capture full packet data for the session.",
        "Isolate {assets} from the network; preserve host state.",
        "Begin damage assessment: what data left, classification, and downstream notification obligations.",
    ],
    Tactic.COMMAND_AND_CONTROL: [
        "Sinkhole or block {external} at DNS and the perimeter.",
        "Isolate {assets}; collect memory and the persistence artefacts named in the evidence.",
        "Hunt the enclave for the same indicators on other hosts.",
    ],
    Tactic.COLLECTION: [
        "Suspend {users} pending interview; preserve their workstation state.",
        "Review access to the staged data set and revoke where not required.",
        "Check egress logs for the staged archive leaving the network.",
    ],
    Tactic.LATERAL_MOVEMENT: [
        "Disable {users} and reset credentials; invalidate Kerberos tickets on the domain.",
        "Isolate {assets}; review logons from them in the last 24 hours.",
        "Raise the enclave alert state and brief the watch.",
    ],
    Tactic.CREDENTIAL_ACCESS: [
        "Reset credentials for {users} and every account that logged on to {assets} since first_seen.",
        "Isolate {assets}; collect LSASS/NTDS artefacts for forensics.",
        "Assume domain credentials are compromised until the DC audit says otherwise.",
    ],
    Tactic.DISCOVERY: [
        "Disable {users} and terminate their sessions.",
        "Review what was enumerated and which shares were reached.",
        "Enable enhanced auditing on {assets}.",
    ],
    Tactic.PERSISTENCE: [
        "Remove the persistence mechanism named in the evidence on {assets} and isolate the host.",
        "Reset credentials for {users}.",
        "Hunt for the same persistence artefact across the enclave.",
    ],
    Tactic.EXECUTION: [
        "Isolate {assets} and quarantine the executed payload.",
        "Reset credentials for {users}.",
        "Pull the originating email or download from every other mailbox / host.",
    ],
    Tactic.INITIAL_ACCESS: [
        "Block {external} at the perimeter; quarantine the delivery artefact enclave-wide.",
        "Confirm whether {assets} executed anything; isolate if so.",
        "Warn {users} and the wider user population about the lure.",
    ],
    Tactic.RECONNAISSANCE: [
        "Increase sensor coverage on {assets} and log all probes for attribution.",
        "Verify perimeter hardening on the probed services.",
        "Brief the watch; no isolation required yet.",
    ],
}
DEFAULT_ACTIONS = [
    "Review the evidence trail in the console and assign an analyst.",
    "Preserve logs from {assets} for the period first_seen to last_seen.",
]


def _kill_chain(alerts: list[Alert]) -> list[TechniqueMapping]:
    """Distinct primary techniques in kill-chain order (tactic, then time)."""
    seen: dict[str, tuple[int, TechniqueMapping]] = {}
    for a in sorted(alerts, key=lambda x: x.timestamp):
        t = a.primary_technique
        if t and t.technique_id not in seen:
            seen[t.technique_id] = (t.tactic.chain_position, t)
    return [t for _, t in sorted(seen.values(), key=lambda v: v[0])]


def _confidence(incident: Incident, alerts: list[Alert], fired: list[FiredRule]) -> tuple[Confidence, str]:
    score = incident.score
    conf = score.correlation_confidence if score else 0.0
    sources = {a.source.value for a in alerts}
    if fired:
        return Confidence.LOW, (
            f"Suppression rule(s) {', '.join(f.rule_id for f in fired)} matched; the activity has a documented benign explanation."
        )
    if conf >= 0.7 and len(alerts) >= 4 and len(sources) >= 2:
        return Confidence.HIGH, (
            f"{len(alerts)} alerts from {len(sources)} independent sources ({', '.join(sorted(sources))}) linked by "
            f"{len(incident.edges)} evidential edges with mean correlation confidence {conf:.2f}."
        )
    if conf >= 0.45 or (len(alerts) >= 3 and len(sources) >= 2):
        return Confidence.MEDIUM, (
            f"{len(alerts)} alerts from {len(sources)} source(s); correlation confidence {conf:.2f}. "
            "Consistent with one operation but with limited corroboration."
        )
    return Confidence.LOW, f"{len(alerts)} alert(s) from {len(sources)} source(s); correlation confidence {conf:.2f}."


def _externals(alerts: list[Alert]) -> list[str]:
    from src.enrichment.ioc import is_private_ip

    out = []
    for a in alerts:
        for i in a.indicators:
            if i.type in (IndicatorType.DOMAIN, IndicatorType.URL) or (i.type == IndicatorType.IPV4 and not is_private_ip(i.value)):
                if i.value not in out:
                    out.append(i.value)
    return out


def _users(alerts: list[Alert]) -> list[str]:
    users = Counter()
    for a in alerts:
        if a.asset and a.asset.user_principal:
            users[a.asset.user_principal] += 1
        for i in a.indicators:
            if i.type == IndicatorType.USER and "\\" in i.value:
                users[i.value] += 1
    return [u for u, _ in users.most_common(3)]


def _assets(alerts: list[Alert]) -> list[str]:
    return sorted({a.asset.asset_id for a in alerts if a.asset})


def _fmt(ts) -> str:
    return ts.strftime("%d %b %H:%M") + "Z"


def _fill(template: str, *, assets, users, external) -> str:
    return template.format(
        assets=", ".join(assets[:3]) or "the affected host",
        users=", ".join(users) or "the involved accounts",
        external=", ".join(external[:2]) or "the external destination",
    )


def build_template_bluf(incident: Incident, alerts: list[Alert], fired: list[FiredRule]) -> BlufReport:
    alerts = sorted(alerts, key=lambda a: a.timestamp)
    chain = _kill_chain(alerts)
    tactics = [t.tactic for t in chain]
    deepest = max(tactics, key=lambda t: t.chain_position) if tactics else None
    assets = _assets(alerts)
    users = _users(alerts)
    external = _externals(alerts)
    sources = Counter(a.source.value for a in alerts)
    confidence, conf_why = _confidence(incident, alerts, fired)
    span = f"{_fmt(incident.first_seen)}–{_fmt(incident.last_seen)}" if incident.first_seen != incident.last_seen else _fmt(incident.first_seen)

    # ---- bottom line
    if fired:
        bottom = (
            f"Activity on {', '.join(assets[:3]) or 'unresolved assets'} ({len(alerts)} alerts, {span}) is assessed as BENIGN: "
            f"{fired[0].name.lower()} ({fired[0].rule_id}). No action beyond verification required."
        )
    elif deepest:
        bottom = (
            f"{STAGE_MEANING[deepest].capitalize()} on {', '.join(assets[:3]) or 'unresolved assets'}: "
            f"{len(alerts)} correlated alerts across {len(sources)} source(s) ({span}), reaching {deepest.value}; "
            f"assessed with {confidence.value.upper()} confidence."
        )
    else:
        bottom = f"{len(alerts)} alert(s) on {', '.join(assets[:3]) or 'unresolved assets'} ({span}) with no mapped adversary technique; {confidence.value.upper()} confidence."

    # ---- assessment narrative
    steps = []
    intel_ids = [a.alert_id for a in alerts if a.source.value == "intel"]
    for a in alerts:
        t = a.primary_technique
        if not t or a.source.value == "intel":  # reports are context, not events in the sequence
            continue
        who = a.asset.asset_id if a.asset else a.source.value
        steps.append(f"{_fmt(a.timestamp)} {t.technique_name} ({t.technique_id}) on {who}")
    stages = list(dict.fromkeys(t.value for t in tactics))
    if fired:
        assessment = (
            f"The sequence ({'; '.join(steps[:4])}{'; …' if len(steps) > 4 else ''}) is what an intrusion would look like, "
            f"which is why it correlated. {fired[0].evidence} Residual risk: the benign explanation is inferred from schedule and "
            "scope data, not verified with the operator."
        )
    elif steps:
        assessment = (
            f"Activity began at {_fmt(alerts[0].timestamp)} and progressed through {len(stages)} kill-chain stage(s): "
            f"{' → '.join(stages)}. Sequence: {'; '.join(steps[:5])}{'; …' if len(steps) > 5 else ''}. "
            + (f"Corroborated by intelligence reporting {', '.join(intel_ids)}. " if intel_ids else "")
            + (f"External infrastructure involved: {', '.join(external[:3])}. " if external else "")
            + (f"Accounts involved: {', '.join(users)}. " if users else "")
            + f"The alerts were linked by {len(incident.edges)} evidential edge(s); see explain_correlation for any pair."
        )
    else:
        assessment = "Alerts were linked by shared indicators and timing but no ATT&CK technique could be mapped; treat as unclassified activity."

    # ---- evidence
    evidence = [
        f"{a.alert_id} ({a.source.value}, {a.timestamp.strftime('%Y-%m-%dT%H:%MZ')}, vendor severity {a.source_severity or 'n/a'}): "
        f"{a.raw_text[:110].rstrip()}{'…' if len(a.raw_text) > 110 else ''}"
        for a in alerts
    ]

    # ---- recommended actions
    if fired:
        actions = [
            f"Verify with the owner that this was expected: {fired[0].evidence[:140]}",
            "If not confirmed within the watch, re-open at the priority the evidence would otherwise warrant.",
        ]
    else:
        templates = STAGE_ACTIONS.get(deepest, DEFAULT_ACTIONS) if deepest else DEFAULT_ACTIONS
        actions = [_fill(t, assets=assets, users=users, external=external) for t in templates]
        for ind_type in (IndicatorType.SHA256, IndicatorType.MD5):
            hashes = [i.value for a in alerts for i in a.indicators if i.type == ind_type]
            if hashes:
                actions.append(f"Block hash {hashes[0][:16]}… enclave-wide and submit for analysis.")
                break

    # ---- gaps: what would change the assessment
    gaps = []
    present = set(sources)
    if "syslog" not in present:
        gaps.append("No host telemetry (syslog/EDR) in this incident - process-level confirmation is missing.")
    if "siem" not in present:
        gaps.append("No SIEM detections corroborate the host or sensor data.")
    if "intel" not in present:
        gaps.append("No intelligence reporting ties the indicators to a known actor; attribution is not attempted.")
    if not any(a.source == a.source and a.asset and a.asset.criticality for a in alerts):
        pass
    if users and not fired:
        gaps.append(f"Whether {users[0]} was compromised or acting deliberately is not established; interview and logon history would resolve it.")
    hashes = [i.value for a in alerts for i in a.indicators if i.type in (IndicatorType.SHA256, IndicatorType.MD5, IndicatorType.SHA1)]
    if hashes:
        gaps.append(f"Payload {hashes[0][:16]}… has not been analysed; sandbox detonation would confirm capability.")
    if deepest and deepest.chain_position < Tactic.EXFILTRATION.chain_position and not fired:
        gaps.append("No evidence yet of data leaving the network; egress review for the affected hosts would confirm or exclude exfiltration.")
    unmapped = [a.alert_id for a in alerts if not a.primary_technique]
    if unmapped:
        gaps.append(f"{len(unmapped)} alert(s) could not be mapped to an ATT&CK technique ({', '.join(unmapped[:3])}); analyst review needed.")
    if fired:
        gaps.append("The benign explanation relies on schedule/scope records; a confirmation from the change owner would close it.")
    if not gaps:
        gaps.append("No material gaps identified; assessment is bounded by the corpus window.")

    return BlufReport(
        incident_id=incident.incident_id,
        bottom_line=bottom,
        confidence=confidence,
        confidence_rationale=conf_why,
        assessment=assessment,
        attack_chain=chain,
        evidence=evidence,
        recommended_actions=actions,
        gaps=gaps,
        generated_by="template",
    )


def render_bluf_text(report: BlufReport) -> str:
    """Fixed-format text rendering used by the MCP tool and the console copy button."""
    lines = [
        f"BOTTOM LINE: {report.bottom_line}",
        f"CONFIDENCE:  {report.confidence.value} — {report.confidence_rationale}",
        f"ASSESSMENT:  {report.assessment}",
        "ATT&CK:      " + (", ".join(f"{t.technique_id} {t.technique_name} [{t.tactic.value}]" for t in report.attack_chain) or "none mapped"),
        "EVIDENCE:",
        *[f"  - {e}" for e in report.evidence],
        "RECOMMENDED:",
        *[f"  {i}. {a}" for i, a in enumerate(report.recommended_actions, 1)],
        "GAPS:",
        *[f"  - {g}" for g in report.gaps],
        f"(generated by {report.generated_by} for {report.incident_id})",
    ]
    return "\n".join(lines)
