# Source Code — AEGIS

All AEGIS source lives here. The layout follows the pipeline stages, so the
directory order below is also the order data moves through the system.

## Layout

```
src/
├── models.py          ← Canonical contracts. START HERE.
├── requirements.txt   ← Pinned Python dependencies
├── .env.example       ← Every environment variable, documented
│
├── ingest/            ← Four adapters: SIEM JSON, syslog, geo CSV, intel prose
├── db/                ← SQLAlchemy models, session handling, schema init
├── corpus/            ← Synthetic alert corpus + ground-truth labels
│
├── enrichment/        ← IOC extraction, MITRE ATT&CK technique mapping
├── correlation/       ← Weighted alert graph, tactic ordering, incident extraction
├── scoring/           ← Four-factor prioritisation, suppression rules
├── bluf/              ← Commander brief generation (watsonx + template fallback)
│
├── pipeline/          ← Orchestrates ingest → enrich → correlate → score → brief
├── api/               ← FastAPI REST surface for the console
├── mcp_server/        ← MCP tools exposed to IBM Bob
├── eval/              ← Precision/recall harness against ground truth
└── frontend/          ← React + Vite analyst console
```

## Read this first

`models.py` is the contract every other module depends on. It is deliberately
free of internal imports so all four workstreams can build against it in
parallel without circular dependencies.

Two details in it are load-bearing and easy to break by accident:

- **`Tactic` declaration order is kill-chain order.** Correlation Signal 4 scores
  a tactic transition by the forward distance between two enum members, so
  reordering them silently changes correlation behaviour.
- **`Indicator` values are lower-cased on validation.** The same file hash
  arrives uppercase from one feed and lowercase from another; without
  normalisation those two alerts never correlate.

## Ownership

| Directory | Owner |
|---|---|
| `corpus/`, `enrichment/ioc.py`, `correlation/tactics.py`, `scoring/suppression.py` | Het Khatusuriya |
| `enrichment/attack_mapper.py`, `correlation/graph.py`, `bluf/`, `eval/` | Manan Modi |
| `frontend/` | Mohammad Safik |
| `ingest/`, `db/`, `api/`, `mcp_server/` | Samarth Bhalala |

## Conventions

- `.env` is gitignored. Never commit real credentials — `.env.example` carries
  dummy values and documents every variable the code reads.
- The database is SQLite via SQLAlchemy. There is no server to provision, which
  keeps the setup guide to three commands.
- The MCP server is read-only by design. It exposes no tool capable of mutating
  state or acting on an asset.
