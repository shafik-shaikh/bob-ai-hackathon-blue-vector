# AEGIS — Alert Enrichment, Grouping & Intelligence Scoring

**IBM Bob AI Innovation Hackathon 2026 — Problem Statement D2**
Threat Intelligence Correlation & Alert Prioritisation Assistant

---

## 1. The problem in one paragraph

A defence SOC analyst starts a shift with several thousand unread alerts sitting across four or five
consoles that do not talk to each other. The SIEM speaks JSON. The network sensor writes syslog.
The satellite/geospatial feed arrives as CSV. Human-authored intelligence reports arrive as prose.
Nobody can read all of it, so triage happens by whatever sorts to the top — usually severity fields
that every vendor computes differently. The consequence is asymmetric and brutal: chasing a false
positive costs an hour, missing a genuine intrusion costs the mission. And when something real is
found, the commander does not want a log dump — they want a BLUF: what happened, how confident are
we, what do we do in the next thirty minutes.

AEGIS sits between the feeds and the analyst. It normalises everything into one schema, extracts
indicators, maps observed behaviour to MITRE ATT&CK, groups related alerts into incidents, scores
those incidents so the queue is ordered by *consequence* rather than by vendor severity, and lets the
analyst interrogate all of it conversationally through IBM Bob.

---

## 2. What we are actually building

Four capabilities, in dependency order. Each one is demoable on its own, which matters — if we run
out of time, we ship three working things rather than four broken ones.

**C1 — Multi-source ingestion and normalisation.** Four adapters, four wire formats, one canonical
`Alert` record. This is unglamorous and it is the foundation; nothing downstream works without it.

**C2 — ATT&CK mapping.** Every normalised alert gets matched against the MITRE Enterprise technique
corpus, returning ranked technique candidates with confidence scores. Real reference data, not a
lookup table we invented.

**C3 — Correlation into incidents.** Alerts that describe the same activity get grouped. This is the
intellectual core of the project and the part judges will read most carefully.

**C4 — Prioritisation and BLUF generation.** Incidents are scored; the top of the queue gets a
commander-ready BLUF brief. IBM Bob is the delivery surface.

---

## 3. Architecture

```
  SIEM JSON ──┐
  Syslog ─────┤
  Geo CSV ────┼──► Ingest Adapters ──► Canonical Alert ──► Enrichment
  Intel prose ┘        (Samarth)          (SQLite)        (Manan)
                                                               │
                                              ┌────────────────┤
                                              │                │
                                       IOC extraction   ATT&CK mapper
                                         (Het)          (Manan)
                                              │                │
                                              └───────┬────────┘
                                                      ▼
                                          Correlation Engine ──► Incident
                                            (Het + Manan)         graph
                                                      │
                                                      ▼
                                             Priority Scorer
                                                (Het)
                                                      │
                                     ┌────────────────┴──────────────┐
                                     ▼                               ▼
                             MCP Server ──► IBM Bob            FastAPI ──► React UI
                              (Samarth)                        (Samarth)   (Shafik)
```

### Component responsibilities

| Component | Tech | Owner | Responsibility |
|---|---|---|---|
| Ingest adapters | Python, Pydantic | Samarth | Parse four wire formats into canonical schema |
| Alert store | SQLite | Samarth | Persist alerts, incidents, edges, scores |
| IOC extractor | Python, regex + validators | Het | Pull IPs, hashes, domains, users, hosts from any field |
| ATT&CK mapper | sentence-transformers, MITRE CTI | Manan | Rank technique candidates per alert |
| Correlation engine | NetworkX | Het + Manan | Build alert graph, extract connected incidents |
| Priority scorer | Python, weighted model | Het | Rank incidents by consequence, suppress FPs |
| BLUF generator | watsonx.ai / Granite | Manan | Structured commander brief from incident evidence |
| MCP server | Python MCP SDK | Samarth | Expose tools to IBM Bob |
| API | FastAPI | Samarth | REST surface for the UI |
| Analyst console | React + Vite | Shafik | Queue, incident detail, ATT&CK view, BLUF |

---

## 4. The correlation engine — read this carefully

This is the 25-point innovation criterion. The failure mode is obvious and common: three `if`
statements that group alerts sharing a source IP, dressed up in the README as a "correlation engine."
Judges read source code. We need something defensible.

AEGIS treats correlation as **graph construction followed by connected-component extraction**. Every
alert is a node. We draw a weighted edge between two alerts when any of four independent signals
fire, and an incident is a connected component of that graph above a weight threshold.

**Signal 1 — Shared indicator (weight 0.4).** Two alerts reference the same IOC. Weighted by indicator
rarity: a shared internal DNS server IP is near-worthless evidence, a shared SHA-256 is near-conclusive.
Use inverse document frequency across the corpus so this falls out of the data rather than a hand-tuned
table.

**Signal 2 — Temporal proximity (weight 0.2).** Decaying function over the time delta, not a hard
window. Two alerts ninety seconds apart are strong evidence; two alerts six hours apart are weak but
non-zero. A hard cutoff creates an obvious evasion and looks naive in review.

**Signal 3 — Asset adjacency (weight 0.15).** Same host, same subnet, or same user principal. Cheap
to compute, catches lateral movement that shares no indicators.

**Signal 4 — Tactic chain progression (weight 0.25).** This is the differentiator. Using the ATT&CK
mappings from C2, if alert A maps to a technique under *Initial Access* and alert B, shortly after
and on the same asset, maps to *Execution* or *Persistence*, the pair scores high — because that
ordering is what an actual intrusion looks like. Reverse-ordered pairs score lower. We are encoding
kill-chain directionality, not just similarity. **Het owns the tactic ordering matrix; this is where
his domain knowledge becomes code rather than commentary.**

The output is an incident with an explicit evidence trail: which alerts, which edges, which signal
fired on each edge, and with what weight. That trail is what makes `explain_correlation` possible in
Bob, and it is what separates this from a black box.

### Prioritisation

Incidents are scored on four factors, combined and normalised to 0–100:

- **Confidence** — aggregate strength of the correlation edges and the ATT&CK mapping scores.
- **Asset criticality** — from an asset inventory table. A domain controller outranks a print server.
- **Tactic severity** — how deep into the kill chain the incident reaches. *Impact* or *Exfiltration*
  outranks *Reconnaissance*.
- **False-positive likelihood** — a suppression score from known-benign patterns: scheduled scanner
  ranges, maintenance windows, service accounts with expected odd behaviour. Het curates these rules.

Deliberate design decision worth defending in the deck: a high-confidence incident on a low-value
asset should *not* outrank a medium-confidence incident on a domain controller. Sorting by confidence
alone reproduces the exact problem we set out to solve.

---

## 5. IBM Bob integration — the 10-point criterion

The rubric says Bob must be *load-bearing*, not name-dropped. Our test: if Bob is removed, the analyst
loses their primary interface, not a summary paragraph.

We expose an MCP server with these tools:

| Tool | What the analyst asks | What it returns |
|---|---|---|
| `get_priority_queue` | "What should I look at first this shift?" | Top N incidents, ranked, with one-line rationale |
| `explain_correlation` | "Why are alerts 4471 and 4482 the same incident?" | The edge evidence trail in plain language |
| `get_bluf` | "Give me the BLUF for incident 12" | Structured commander brief |
| `why_deprioritised` | "Why is this critical SIEM alert ranked 40th?" | Which suppression rule fired and on what evidence |
| `search_by_technique` | "Show me everything mapped to T1059" | Incidents touching that ATT&CK technique |

`why_deprioritised` is the one to demo. It is the question a sceptical analyst actually asks, it only
has an answer because we kept the evidence trail, and it demonstrates the system reasoning about its
own decisions.

### BLUF format

Fixed structure, generated per incident:

```
BOTTOM LINE: [one sentence — what happened, to what, how sure]
CONFIDENCE:  [High/Medium/Low] — [what drives it]
ASSESSMENT:  [2-3 sentences of narrative]
ATT&CK:      [technique IDs and names observed, in kill-chain order]
EVIDENCE:    [the N alerts, with sources and timestamps]
RECOMMENDED: [prioritised actions for the next 30 minutes]
GAPS:        [what we do not know and what would resolve it]
```

The `GAPS` line matters. An intelligence product that hides its own uncertainty is worse than useless
to a commander, and including it shows the judges we understand the domain.

---

## 6. Role breakdown

### Het — Cybersecurity

Het owns the domain truth of the system. Everything that encodes *what a threat actually looks like*
is his.

**Deliverables**
- The synthetic alert corpus: ~400–600 alerts across four formats, containing 5–8 deliberately planted
  multi-stage attack scenarios plus a realistic volume of benign noise. This is the demo's credibility.
  Scenarios should include at least one that is genuinely ambiguous — the system looking confident about
  everything is a tell.
- Ground-truth labels for the planted scenarios, so we can state real precision/recall numbers in the
  deck instead of adjectives.
- IOC extraction module: IPs (v4/v6), domains, URLs, MD5/SHA-1/SHA-256, email addresses, user
  principals, hostnames, CVE IDs. Must handle indicators embedded in free prose, not just structured
  fields.
- The tactic ordering matrix for correlation Signal 4 — which ATT&CK tactic transitions are plausible
  progressions and which are not.
- False-positive suppression rules with documented rationale per rule.
- Asset criticality inventory.
- Review of the BLUF outputs for operational realism. He is the one who says "no commander would accept
  this."

**Owns in repo:** `src/corpus/`, `src/enrichment/ioc.py`, `src/correlation/tactics.py`,
`src/scoring/suppression.py`, `docs/problem-statement.md`

---

### Manan — AI/ML

Manan owns everything between a normalised alert and a technique mapping, plus the language generation.

**Deliverables**
- MITRE ATT&CK ingestion: pull Enterprise STIX 2.1 from `github.com/mitre/cti`, parse techniques,
  sub-techniques, tactics, and descriptions into a queryable local store. Pin the version — do not
  fetch live at demo time.
- Technique mapping: embed alert text (sentence-transformers, `all-MiniLM-L6-v2` is fast and adequate)
  against technique descriptions, return top-k with cosine scores and a calibrated confidence. Blend
  with keyword/rule signals where the embedding is weak — pure semantic similarity on short alert
  strings underperforms, and saying so honestly in the docs is better than pretending otherwise.
- Edge weight computation for the correlation graph, including the IDF-based indicator rarity model.
- Graph assembly and connected-component extraction (NetworkX), with the threshold tuned against Het's
  ground truth.
- BLUF generation via watsonx.ai — prompt engineering, structured output enforcement, and a
  deterministic fallback template for when the model is unreachable. **Build the fallback early.** A
  demo that dies because an API call timed out is the worst possible outcome.
- Evaluation harness: precision, recall, and mean queue position of true incidents against ground truth.

**Owns in repo:** `src/enrichment/attack_mapper.py`, `src/correlation/graph.py`, `src/bluf/`,
`src/eval/`, `docs/solution-overview.md`

---

### Shafik — Frontend

Shafik owns the analyst console. Judges see this before they read any code — it carries disproportionate
weight for the effort involved.

**Deliverables**
- **Triage queue** — incidents ranked by priority score, with source badges, alert count, top ATT&CK
  technique, and score. Sortable, filterable by tactic and source. This is the landing view.
- **Incident detail** — the constituent alerts in timeline order, the correlation graph rendered
  visually (nodes = alerts, edge thickness = weight), and the evidence trail on edge hover. The graph
  view is the screenshot that will end up on the title slide.
- **ATT&CK view** — observed techniques laid out against the kill chain, showing how far the intrusion
  progressed.
- **BLUF panel** — the generated brief, copy-to-clipboard, and a clear provenance line showing it was
  generated from N alerts across M sources.
- **Score breakdown** — the four scoring factors as a visible decomposition, not a single number. If an
  analyst cannot see why something ranked where it did, they will not trust the ranking.
- At least three clean screenshots for `demo/screenshots/`.

**Constraints:** React + Vite, dark theme (every SOC console is dark; a light theme will read as
unfamiliar to anyone in the domain). Do not build authentication, user settings, or an onboarding flow.
Zero points available there.

**Owns in repo:** `src/frontend/`, `demo/screenshots/`

---

### Samarth — Backend + Database

Samarth owns the spine. If ingestion or the API is shaky, nobody else's work is visible.

**Deliverables**
- Canonical `Alert` schema in Pydantic — the contract every other component depends on. **Freeze this
  in the first two hours and circulate it.** Schema churn at hour twenty is how teams lose a night.
- Four ingest adapters: SIEM JSON, syslog (RFC 5424-ish), geospatial CSV, and free-text intel report.
  Each maps its native fields to the canonical schema and preserves the raw payload for provenance.
- SQLite schema: `alerts`, `incidents`, `incident_alerts`, `correlation_edges`, `attack_mappings`,
  `assets`, `bluf_reports`. Index on timestamp, asset, and indicator for correlation query performance.
- FastAPI endpoints: `/ingest`, `/alerts`, `/incidents`, `/incidents/{id}`, `/incidents/{id}/bluf`,
  `/techniques`.
- The MCP server exposing the five Bob tools. This is the 10-point integration — it is Samarth's
  responsibility to make sure it is genuinely wired to the correlation output and not returning
  canned data.
- A one-command seed script (`scripts/demo.py`) that creates the SQLite database, loads the corpus and
  runs the full pipeline. A judge must be able to go from clone to running system in under five minutes,
  with no database server to install.
- `.env.example` covering every variable the code reads.

**Owns in repo:** `src/ingest/`, `src/db/`, `src/api/`, `src/mcp_server/`, `docs/setup-guide.md`,
`docs/architecture.md`

---

## 7. Interfaces between roles

These are the contracts. Agree them before anyone writes implementation code.

| Boundary | Contract | Frozen by |
|---|---|---|
| Het → Samarth | Corpus file formats and directory layout | Hour 2 |
| Samarth → Manan | Canonical `Alert` Pydantic model | Hour 2 |
| Manan → Het | `TechniqueMapping{technique_id, tactic, score}` | Hour 4 |
| Het → Manan | Tactic ordering matrix as a dict | Hour 4 |
| Manan → Samarth | `Incident` and `CorrelationEdge` models | Hour 6 |
| Samarth → Shafik | OpenAPI schema from FastAPI `/docs` | Hour 6 |

Shafik should build against a static JSON fixture matching the agreed schema from hour one. Waiting
for a live API to start the UI is the standard way a frontend ends up unfinished.

---

## 8. Scope discipline

**In scope:** four ingest formats, ATT&CK mapping, four-signal correlation, four-factor prioritisation,
BLUF generation, five MCP tools, analyst console.

**Explicitly out of scope — put these in `known_limitations`, do not build them:** live feed ingestion,
threat actor attribution, automated response actions, multi-tenancy, authentication, historical trend
analytics, model fine-tuning, alert deduplication across time windows longer than the corpus.

The guide states plainly that honest limitations are respected and overclaiming is penalised when the
code does not match. A short accurate capability list beats a long aspirational one.

---

## 9. Demo narrative

Five minutes, one continuous run. No slides inside the video.

1. Show the four raw feeds in their native formats, side by side and deliberately unreadable. Establish
   the problem viscerally.
2. Run the pipeline. Show the queue populate — several hundred alerts collapsing into a handful of
   incidents.
3. Open the top incident. Walk the correlation graph. Hover an edge, show the evidence trail.
4. Show the ATT&CK kill-chain view — the intrusion's actual progression.
5. Switch to IBM Bob. Ask "what should I look at first?" Then `explain_correlation` on two alerts. Then
   `get_bluf`.
6. The closer: find a SIEM alert marked CRITICAL by the vendor that AEGIS ranked low, and ask Bob why.
   It answers with the suppression rule and its evidence. That single exchange demonstrates ingestion,
   correlation, scoring, provenance, and Bob integration in one breath.

Record this more than once. The first take is always too slow.

---

## 10. Risks

| Risk | Mitigation |
|---|---|
| watsonx unreachable during demo | Deterministic BLUF template fallback, built on day one |
| Embedding mapping quality is poor | Blend with keyword rules; report honest accuracy rather than hiding it |
| Correlation over-merges into one giant incident | Tune threshold against ground truth; cap component size |
| Corpus feels synthetic | Het models it on real alert structures; include ambiguous and benign cases |
| Frontend blocked on backend | Static fixtures from hour one |
| Schema churn late in the build | Freeze canonical `Alert` at hour two |
