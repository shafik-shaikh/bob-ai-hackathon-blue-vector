# Source Code — AEGIS

All AEGIS source lives here. The layout follows the pipeline stages, so the directory order below is
also the order data moves through the system.

```
src/
├── models.py            ← Canonical contracts. START HERE.
├── config.py            ← Every environment variable, read in one place
├── services.py          ← Shared query layer used by the API and the MCP server
├── requirements.txt     ← Pinned Python dependencies (numpy/networkx/fastapi/mcp; nothing heavy)
├── .env.example         ← Every environment variable, documented
│
├── corpus/              ← Synthetic corpus: scenarios.py (planted attacks), noise.py, generate.py,
│                           feeds/ (the four wire formats), ground_truth.json, asset_inventory.json
├── ingest/              ← Four adapters: siem.py, syslog.py, geo.py, intel.py → canonical Alert
├── db/                  ← SQLite schema and persistence (store.py), `python -m src.db.init`
├── data/attack/         ← MITRE ATT&CK Enterprise v19.2, extracted from the official STIX bundle
│
├── enrichment/          ← ioc.py (indicator extraction, refanging), attack_mapper.py (TF-IDF + rules)
├── correlation/         ← graph.py (four signals, edges, components), tactics.py (kill-chain matrix)
├── scoring/             ← prioritiser.py (four factors), suppression.py (nine documented rules)
├── bluf/                ← template.py (deterministic brief), watsonx_client.py (optional refinement)
│
├── pipeline/            ← run.py orchestrates enrich → correlate → score → brief
├── api/                 ← FastAPI (main.py) - REST contract + serves the console
├── mcp_server/          ← server.py - six read-only MCP tools for IBM Bob
├── eval/                ← evaluate.py + results.json - measured against ground truth
└── frontend/static/     ← Analyst console: index.html, app.js, graph.js, styles.css (no build step)
```

Tests live in `../tests/`; `../scripts/demo.py` is the one-command run.

## Read this first

`models.py` is the contract every other module depends on. It is deliberately free of internal imports.
Two details in it are load-bearing:

- **`Tactic` declaration order is kill-chain order.** Correlation Signal 4 scores a tactic transition by
  position in this enum.
- **`Indicator` values are lower-cased on validation.** The same hash arrives upper-case from one feed and
  lower-case from another; without normalisation those alerts never correlate.

Then read, in order: `correlation/graph.py` (the four signals and why each is bounded the way it is),
`correlation/tactics.py` (the domain knowledge as code), `scoring/suppression.py` (why a vendor-critical
alert can be deprioritised defensibly), `bluf/template.py` (the brief), `mcp_server/server.py` (what Bob
can ask).

## Ownership

| Area | Owner |
|---|---|
| `corpus/`, `enrichment/ioc.py`, `correlation/tactics.py`, `scoring/suppression.py` | Het Khatusuriya |
| `enrichment/attack_mapper.py`, `correlation/graph.py`, `bluf/`, `eval/` | Manan Modi |
| `frontend/` | Mohammad Safik |
| `ingest/`, `db/`, `api/`, `mcp_server/`, `services.py` | Samarth Bhalala |

## Conventions

- `.env` is gitignored. Never commit real credentials; `.env.example` carries placeholders and documents
  every variable `config.py` reads.
- The database is SQLite via the standard library. No server, no ORM.
- The MCP server is read-only by design. It exposes no tool capable of mutating state or acting on an
  asset.
- Windows terminals: set `PYTHONIOENCODING=utf-8` if the pipeline log's arrows fail to print.
