# Setup Guide

Written for someone who has never seen this repository. Every step is explicit.

## Prerequisites

| Requirement | Version | Check with |
|---|---|---|
| Python | 3.10+ | `python --version` |
| Node.js | 18+ | `node --version` |
| Git | any | `git --version` |

No database server is required. AEGIS uses SQLite, which ships with Python.

An IBM watsonx.ai account is optional. Without credentials the system falls back to deterministic
BLUF generation and remains fully demoable.

## 1. Clone

```bash
git clone https://github.com/het-khatusuriya/bob-ai-hackathon-blue-vector.git
cd bob-ai-hackathon-blue-vector
```

## 2. Python environment

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r src/requirements.txt
```

## 3. Environment variables

```bash
cp src/.env.example .env
```

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | No | SQLAlchemy URL. Defaults to `sqlite:///aegis.db` in the repo root. |
| `WATSONX_API_KEY` | No | watsonx.ai key. Omit to use template BLUF fallback. |
| `WATSONX_PROJECT_ID` | No | watsonx project identifier. |
| `WATSONX_URL` | No | Regional endpoint, e.g. `https://eu-gb.ml.cloud.ibm.com`. |
| `EMBEDDING_MODEL` | No | Defaults to `all-MiniLM-L6-v2`. |
| `CORRELATION_THRESHOLD` | No | Edge weight cutoff. Defaults to `0.45`. |
| `API_PORT` | No | Defaults to `8000`. |

## 4. Initialise and seed

```bash
python -m src.db.init          # creates tables
python -m src.corpus.load      # loads the synthetic alert corpus
python -m src.pipeline.run     # ingest -> enrich -> correlate -> score -> brief
```

The pipeline prints a per-stage summary. Expect roughly: several hundred alerts ingested, a few hundred
ATT&CK mappings, a few hundred correlation edges, and a low double-digit number of incidents.

The first run downloads the embedding model (~90 MB) and the MITRE ATT&CK STIX bundle. Subsequent runs
use the cache.

## 5. Start the API

```bash
uvicorn src.api.main:app --reload --port 8000
```

Interactive API docs: `http://localhost:8000/docs`

## 6. Start the frontend

In a second terminal:

```bash
cd src/frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

## 7. Connect IBM Bob

Register the MCP server with your Bob configuration:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "python",
      "args": ["-m", "src.mcp_server.server"],
      "cwd": "/absolute/path/to/bob-ai-hackathon-blue-vector"
    }
  }
}
```

Then ask Bob:

```
What should I look at first this shift?
Why are alerts A-4471 and A-4482 part of the same incident?
Give me the BLUF for incident 12.
Why was A-4503 deprioritised?
```

## Verifying it works

| Check | Expected |
|---|---|
| `curl localhost:8000/health` | `{"status":"ok"}` |
| `curl localhost:8000/incidents` | JSON array of scored incidents |
| Frontend queue | Incidents ranked, highest score first |
| Incident detail | Correlation graph renders with hoverable edges |
| Bob `get_priority_queue` | Ranked incidents matching the UI order |

If the UI queue and Bob's answer disagree, the pipeline was re-run without refreshing one of them.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `unable to open database file` | Wrong working directory | Run commands from the repo root |
| `relation "alerts" does not exist` | Tables not created | `python -m src.db.init` |
| Empty queue after pipeline | Corpus not loaded | `python -m src.corpus.load` |
| BLUF returns template text | No watsonx credentials | Expected fallback; set the three watsonx vars |
| Embedding download stalls | Network restriction | Pre-download to `~/.cache/huggingface` |
| One giant incident | Threshold too low | Raise `CORRELATION_THRESHOLD` toward `0.6` |
| Every alert its own incident | Threshold too high | Lower toward `0.35` |
| Frontend CORS errors | API on non-default port | Update `VITE_API_URL` in `src/frontend/.env` |

## One-command run

```bash
python scripts/demo.py
```

Initialises the database, seeds the corpus, runs the full pipeline, and starts both the API and the
frontend. No infrastructure to provision.
