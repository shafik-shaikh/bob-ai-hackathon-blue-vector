# Solution Overview

## Core mechanism

AEGIS reframes alert triage as a **graph problem with an explicit evidence trail**.

Every incoming alert, regardless of source format, becomes a node in a graph. Edges are drawn between
alerts when evidence suggests they describe the same activity, and each edge records *what* evidence
produced it and *how strongly*. Incidents are connected components of that graph above a weight
threshold. Prioritisation then operates on incidents rather than on alerts — which is the level at
which an analyst actually makes decisions.

The consequence of building it this way is that every output is traceable. When AEGIS says two alerts
belong together, it can name the shared SHA-256, the 90-second gap, and the Initial Access → Execution
tactic transition that produced that conclusion. When it ranks an incident third instead of first, it
can decompose the score. This is what makes the system usable in a domain where unexplained machine
judgements are not actionable.

## How it works end to end

**Normalisation.** Four adapters consume SIEM JSON, syslog, geospatial CSV, and free-text intelligence
reports, mapping each into a single canonical `Alert` schema while preserving the raw payload for
provenance. Everything downstream sees one shape.

**Enrichment.** Indicators are extracted from every field including free prose — addresses, hashes,
domains, users, hosts, CVE identifiers. In parallel, alert text is mapped against the MITRE ATT&CK
Enterprise corpus to produce ranked technique candidates with confidence scores.

**Correlation.** Four independent signals contribute weighted edges:

- *Shared indicator*, weighted by rarity. A shared internal DNS resolver is weak evidence; a shared
  file hash is strong. Rarity is computed as inverse document frequency across the corpus, so the
  weighting emerges from the data rather than from a hand-tuned table.
- *Temporal proximity*, as a decay function rather than a fixed window. A hard cutoff is both
  arbitrary and trivially evaded.
- *Asset adjacency* — same host, subnet, or user principal. Catches lateral movement that shares no
  indicators.
- *Tactic chain progression*. If one alert maps to Initial Access and a later alert on the same asset
  maps to Execution or Persistence, the pair scores high, because that ordering is what an intrusion
  looks like. Reverse-ordered pairs score lower.

**Prioritisation.** Incidents are scored across four factors — correlation confidence, asset criticality,
depth reached in the kill chain, and false-positive likelihood from curated suppression patterns. The
factors remain visible in the UI as a decomposition rather than collapsing into an opaque number.

**Briefing.** The top-ranked incidents are rendered into BLUF-format assessments: bottom line, confidence,
assessment, ATT&CK techniques in kill-chain order, evidence, recommended actions, and an explicit
statement of intelligence gaps.

## What makes it different from the naive approach

The naive version of this project groups alerts by shared IP address within a fixed time window and
sorts the result by SIEM severity. AEGIS differs in four specific ways.

**Correlation is evidential, not categorical.** Edges carry weights and reasons. This is what makes
`explain_correlation` answerable.

**Tactic progression is directional.** Most similarity-based approaches treat alert pairs symmetrically.
Encoding kill-chain ordering means the system recognises attack *shape*, not just resemblance.

**Indicator weighting is learned from the corpus.** Rarity-weighted matching avoids the failure where
every alert mentioning the corporate proxy collapses into one enormous incident.

**Priority is consequence-driven.** A medium-confidence incident on a domain controller ranks above a
high-confidence incident on a print server. Sorting by confidence alone reproduces the original problem.

## Key design decisions

*Graph rather than clustering.* Clustering forces every alert into a group and requires choosing k.
Connected components let incident count emerge from the evidence, and let unrelated alerts stay
unrelated.

*Semantic similarity blended with rules for ATT&CK mapping.* Pure similarity on short alert strings is
unreliable. The default backend is a numpy TF-IDF index over the pinned ATT&CK v19.2 corpus (no model
download; a sentence-transformers backend is a one-line switch). Keyword rules pin the telegraphic cases
(`vssadmin delete shadows`), similarity lifts them, and similarity-only matches are capped and never chain
in correlation. Measured accuracy is reported by the evaluation harness rather than asserted.

*BLUF includes a gaps section.* An intelligence product that conceals its own uncertainty is actively
harmful to a commander. The generator is required to state what is not known.

*Deterministic fallback for generation.* If watsonx is unreachable, a template-based BLUF is produced
from the same structured evidence. The system degrades rather than failing.

## User experience

The analyst opens the console to a queue ordered by consequence, not by vendor severity. Selecting an
incident shows the constituent alerts on a timeline, the correlation graph with hoverable edge evidence,
the ATT&CK kill-chain progression, and the BLUF.

Alongside, IBM Bob provides the conversational surface. The analyst asks what to look at first, why two
alerts were linked, for a brief on a given incident, or — most usefully — why something the SIEM marked
critical was ranked low. Bob answers from the live correlation output, not from a summary of it.

## What the evidence says

`python -m src.eval.evaluate` scores the pipeline against the planted ground truth in the shipped corpus
(521 alerts, 8 scenarios). At the shipped configuration every one of the six intrusions ranks in the top
six of 456 incidents with alert-level purity 1.0; both look-alike benign scenarios (a change-window
rollout that resembles persistence plus lateral movement, and an authorised scan the IDS marks
CRITICAL) fall below every intrusion because a documented suppression rule fired; and no noise alert is
pulled into a planted incident. Two planted alerts are missed in the SITE-ALPHA scenario - a HUMINT
report with no technical indicator, and one geo track linked only by time and place - which is the
deliberate cost of refusing to chain alerts on timing alone. Full table: `src/eval/results.json` and the
README.
