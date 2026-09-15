# AEGIS — Alert Enrichment, Grouping & Intelligence Scoring

**IBM Bob AI Innovation Hackathon 2026 — Problem Statement D2: Threat Intelligence Correlation & Alert Prioritisation Assistant**

Turning thousands of incompatible alerts into a handful of explainable, ranked incidents — and a
commander-ready BLUF.

---

## Team — Blue Vector

| Member | Role |
|---|---|
| **Het Khatusuriya** (lead) | Cybersecurity — corpus, IOC extraction, tactic ordering, suppression rules |
| **Manan Modi** | AI/ML — ATT&CK mapping, correlation graph, BLUF generation, evaluation |
| **Mohammad Safik** | Frontend — analyst console, correlation graph view, BLUF panel |
| **Samarth Bhalala** | Backend & Database — ingestion, schema, API, MCP server |

**Track:** AI

## Problem Statement

Defence SOC analysts face thousands of daily alerts across SIEM platforms, network sensors, geospatial
feeds, and written intelligence reports — each in a different format with an incompatible severity
scale. Triage defaults to vendor severity fields that know nothing about the asset involved or about
what else is happening around them. Real multi-stage intrusions fragment into individually unremarkable
alerts across separate consoles, while false positives consume roughly half of all analyst time.

## Solution

AEGIS normalises every source into one schema, maps alerts onto MITRE ATT&CK, and builds a weighted
graph in which incidents emerge as connected components. Edges carry their evidence, so every grouping
and every ranking can be explained. IBM Bob is the analyst's interface into that evidence trail.

## Key Features

- **Four-format ingestion** — SIEM JSON, syslog, geospatial CSV, and free-text intelligence reports
  normalised into a single canonical `Alert`, with raw payloads preserved for provenance.
- **ATT&CK mapping** — embedding-based matching against the official MITRE Enterprise STIX 2.1 corpus,
  blended with keyword signals, returning ranked techniques with confidence scores.
- **Graph correlation** — four weighted signals: rarity-weighted shared indicators, temporal decay,
  asset adjacency, and directional kill-chain tactic progression.
- **Consequence-based prioritisation** — correlation confidence, asset criticality, kill-chain depth,
  and false-positive likelihood, with the decomposition visible to the analyst.
- **IBM Bob integration** — five MCP tools including `explain_correlation` and `why_deprioritised`,
  answering from live correlation state.
- **BLUF briefs** — structured commander assessments that state their own intelligence gaps.

## Tech Stack

**Languages:** Python 3.10+, TypeScript
**Backend:** FastAPI, Pydantic, SQLAlchemy
**Database:** SQLite (via SQLAlchemy)
**ML:** sentence-transformers, NetworkX
**Frontend:** React, Vite
**IBM:** IBM Bob (MCP), watsonx.ai Granite
**Reference data:** MITRE ATT&CK Enterprise STIX 2.1

## How to Run

```bash
git clone https://github.com/het-khatusuriya/bob-ai-hackathon-blue-vector.git
cd bob-ai-hackathon-blue-vector

python -m venv .venv && source .venv/bin/activate
pip install -r src/requirements.txt
cp src/.env.example .env

python -m src.db.init
python -m src.corpus.load
python -m src.pipeline.run

uvicorn src.api.main:app --port 8000        # terminal 1
cd src/frontend && npm install && npm run dev # terminal 2
```

Open `http://localhost:5173`. Full instructions, including IBM Bob MCP registration and a
troubleshooting table, are in [docs/setup-guide.md](docs/setup-guide.md).

## Demo

- **Video:** see [demo/demo-video-link.txt](demo/demo-video-link.txt)
- **Live demo:** see [demo/live-demo-url.txt](demo/live-demo-url.txt)
- **Screenshots:** [demo/screenshots/](demo/screenshots/)

## Documentation

- [Problem statement](docs/problem-statement.md)
- [Solution overview](docs/solution-overview.md)
- [Architecture](docs/architecture.md)
- [Setup guide](docs/setup-guide.md)

## Known Limitations

Stated plainly, because overclaiming is worse than a short honest list.

- **The corpus is synthetic.** Alerts are modelled on real formats and contain deliberately planted
  multi-stage scenarios with ground-truth labels, but no real network telemetry was used.
- **Batch, not streaming.** The pipeline runs over a bounded corpus. There is no live feed ingestion.
- **ATT&CK mapping is imperfect on short alerts.** Semantic similarity degrades on terse strings; we
  blend in keyword signals and report measured accuracy in `src/eval/` rather than asserting it.
- **Correlation thresholds are tuned to this corpus.** A different alert distribution would need
  retuning. The threshold is exposed as a configuration variable for exactly this reason.
- **No threat actor attribution.** We map to techniques, not to named adversary groups.
- **No automated response.** The MCP server is deliberately read-only — acting automatically on a
  probabilistic assessment is not something we would recommend in this domain.
- **No authentication or multi-tenancy.** Out of scope for the hackathon build.

## What We're Most Proud Of

**The evidence trail.** Most AI triage tools produce a ranking and ask you to trust it. AEGIS records
why every edge was drawn and what every score is composed of, then exposes that through IBM Bob in
natural language. The clearest demonstration is `why_deprioritised`: point at an alert the SIEM marked
CRITICAL that AEGIS ranked fortieth, and it will name the suppression rule, the evidence behind it, and
what would change its mind.

That capability only exists because correlation was built as an evidential graph from the start rather
than as a similarity score with an explanation bolted on afterwards. In a defence context, an analyst
who cannot see the reasoning will not act on the output — so explainability was treated as a
requirement, not a feature.

Start with `src/correlation/` if you want to read the strongest work.
