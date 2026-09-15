"""Tactic ordering matrix for correlation Signal 4 (kill-chain progression).

This module encodes *what an intrusion looks like over time*. Two alerts are
more likely to belong to the same activity when the second one's tactic is a
plausible next step from the first one's - Initial Access followed by
Execution, Execution followed by Persistence, Discovery followed by Lateral
Movement. The reverse ordering is possible (attackers loop back) but is weaker
evidence, and some transitions are simply not how intrusions unfold.

Two sources of evidence combine:

1. **Forward distance** in the ATT&CK kill chain. Tactics are declared in
   kill-chain order in `models.Tactic`; a small forward hop scores well, a
   large one less so, a backward hop least of all.
2. **Curated transition table** below. Domain knowledge overrides the pure
   distance model where real intrusions differ from the textbook ordering -
   e.g. Command-and-Control frequently appears immediately after Execution,
   long before Collection, because the implant beacons home first.

Both are visible to the analyst through `explain_correlation`, so a judgement
encoded here is a judgement the analyst can challenge.
"""

from __future__ import annotations

from src.models import Tactic

# Curated plausible transitions. Values are in [0, 1] and express how strongly
# "A then B" resembles a real intrusion. Unlisted pairs fall back to the
# distance model. Each entry carries the reasoning so the table is reviewable.
PLAUSIBLE_TRANSITIONS: dict[tuple[Tactic, Tactic], tuple[float, str]] = {
    (Tactic.RECONNAISSANCE, Tactic.INITIAL_ACCESS): (0.85, "Scanning or phishing-target research precedes an entry attempt."),
    (Tactic.RESOURCE_DEVELOPMENT, Tactic.INITIAL_ACCESS): (0.70, "Infrastructure staged, then used for delivery."),
    (Tactic.INITIAL_ACCESS, Tactic.EXECUTION): (1.00, "The canonical first hop: delivery followed by payload execution."),
    (Tactic.INITIAL_ACCESS, Tactic.PERSISTENCE): (0.80, "Some droppers establish persistence before running the main payload."),
    (Tactic.INITIAL_ACCESS, Tactic.COMMAND_AND_CONTROL): (0.75, "Stagers beacon home immediately after landing."),
    (Tactic.EXECUTION, Tactic.PERSISTENCE): (0.95, "Payload installs a foothold: scheduled task, run key, service."),
    (Tactic.EXECUTION, Tactic.COMMAND_AND_CONTROL): (0.95, "Payload executes and beacons; C2 appears before any later stage."),
    (Tactic.EXECUTION, Tactic.DISCOVERY): (0.85, "Operator lands and enumerates the host."),
    (Tactic.EXECUTION, Tactic.DEFENSE_EVASION): (0.85, "Payload disables or evades controls immediately after running."),
    (Tactic.EXECUTION, Tactic.CREDENTIAL_ACCESS): (0.80, "Credential dumping is typically the next hands-on-keyboard action."),
    (Tactic.PERSISTENCE, Tactic.PRIVILEGE_ESCALATION): (0.85, "Foothold, then elevation."),
    (Tactic.PERSISTENCE, Tactic.COMMAND_AND_CONTROL): (0.80, "Persistent implant re-establishes its channel."),
    (Tactic.PRIVILEGE_ESCALATION, Tactic.CREDENTIAL_ACCESS): (0.95, "Elevation enables LSASS or SAM access."),
    (Tactic.PRIVILEGE_ESCALATION, Tactic.DEFENSE_EVASION): (0.85, "Elevated context used to tamper with defences."),
    (Tactic.DEFENSE_EVASION, Tactic.CREDENTIAL_ACCESS): (0.75, "Controls disabled, then credentials harvested."),
    (Tactic.CREDENTIAL_ACCESS, Tactic.LATERAL_MOVEMENT): (1.00, "Stolen credentials reused against neighbouring hosts."),
    (Tactic.CREDENTIAL_ACCESS, Tactic.DISCOVERY): (0.80, "Harvested credentials used to enumerate further."),
    (Tactic.DISCOVERY, Tactic.LATERAL_MOVEMENT): (0.95, "Enumeration identifies the next target, then movement."),
    (Tactic.DISCOVERY, Tactic.COLLECTION): (0.80, "File-share discovery followed by staging."),
    (Tactic.LATERAL_MOVEMENT, Tactic.CREDENTIAL_ACCESS): (0.85, "Operator lands on the new host and dumps its credentials (LSASS, NTDS on a DC)."),
    (Tactic.LATERAL_MOVEMENT, Tactic.EXECUTION): (0.80, "Movement to a new host is followed by execution there - a loop-back that is legitimate."),
    (Tactic.LATERAL_MOVEMENT, Tactic.DISCOVERY): (0.80, "Re-enumeration on the new host."),
    (Tactic.LATERAL_MOVEMENT, Tactic.COLLECTION): (0.90, "Movement to the host that holds the data, then staging."),
    (Tactic.LATERAL_MOVEMENT, Tactic.PERSISTENCE): (0.75, "Foothold established on the new host."),
    (Tactic.COLLECTION, Tactic.EXFILTRATION): (1.00, "Staged data leaves the network."),
    (Tactic.COLLECTION, Tactic.COMMAND_AND_CONTROL): (0.70, "Staging followed by upload over the existing channel."),
    (Tactic.COMMAND_AND_CONTROL, Tactic.EXFILTRATION): (0.90, "Exfiltration over the C2 channel."),
    (Tactic.COMMAND_AND_CONTROL, Tactic.DISCOVERY): (0.80, "Operator tasking arrives, enumeration follows."),
    (Tactic.COMMAND_AND_CONTROL, Tactic.LATERAL_MOVEMENT): (0.75, "Tasked movement."),
    (Tactic.COMMAND_AND_CONTROL, Tactic.IMPACT): (0.80, "Ransomware detonation is tasked over C2."),
    (Tactic.EXFILTRATION, Tactic.IMPACT): (0.85, "Double-extortion: exfiltrate, then encrypt."),
    (Tactic.DEFENSE_EVASION, Tactic.IMPACT): (0.85, "Shadow-copy deletion and backup tampering precede encryption."),
    (Tactic.LATERAL_MOVEMENT, Tactic.IMPACT): (0.80, "Spread first, detonate everywhere at once."),
}

# Pairs that do not describe a single intrusion in sequence. Kept small and
# explicit; the point is to stop obviously wrong chains, not to be exhaustive.
IMPLAUSIBLE_TRANSITIONS: dict[tuple[Tactic, Tactic], str] = {
    (Tactic.IMPACT, Tactic.RECONNAISSANCE): "Recon after detonation is a new operation, not this one.",
    (Tactic.IMPACT, Tactic.INITIAL_ACCESS): "Entry after detonation is a new operation, not this one.",
    (Tactic.EXFILTRATION, Tactic.INITIAL_ACCESS): "Entry after exfiltration is a new operation.",
    (Tactic.EXFILTRATION, Tactic.RECONNAISSANCE): "Recon after exfiltration is a new operation.",
}


def progression_score(first: Tactic, second: Tactic) -> tuple[float, str]:
    """Score the transition `first -> second` (in time order) in [0, 1].

    Returns the score and a one-line rationale suitable for the evidence trail.
    """
    if (first, second) in IMPLAUSIBLE_TRANSITIONS:
        return 0.0, IMPLAUSIBLE_TRANSITIONS[(first, second)]

    if (first, second) in PLAUSIBLE_TRANSITIONS:
        score, why = PLAUSIBLE_TRANSITIONS[(first, second)]
        return score, f"{first.value} → {second.value} is a curated kill-chain progression: {why}"

    distance = second.chain_position - first.chain_position
    if distance == 0:
        return 0.45, f"Both alerts map to {first.value}; same-stage activity is consistent with one operation but not distinctive."
    if 0 < distance <= 2:
        return 0.70, f"{first.value} → {second.value} is a short forward hop in the kill chain."
    if 2 < distance <= 5:
        return 0.50, f"{first.value} → {second.value} is a forward hop with intermediate stages unobserved."
    if distance > 5:
        return 0.30, f"{first.value} → {second.value} skips most of the kill chain; weak evidence of one operation."
    # Backward transitions: attackers do loop, but it is weaker evidence.
    if -2 <= distance < 0:
        return 0.30, f"{second.value} appears after {first.value}; a short loop-back is plausible but weak evidence."
    return 0.10, f"{second.value} appears well after {first.value} in time but earlier in the kill chain; unlikely to be the same progression."


def tactic_depth(tactics: list[Tactic]) -> float:
    """How far into the kill chain a set of tactics reaches, normalised to [0, 1].

    Used by the prioritiser: an incident that has reached Exfiltration or
    Impact outranks one still at Reconnaissance regardless of alert count.
    """
    if not tactics:
        return 0.0
    deepest = max(t.chain_position for t in tactics)
    return deepest / (len(Tactic) - 1)
