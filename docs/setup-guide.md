# Setup Guide

Written for someone who has never seen this repository. Every step is explicit and was run on a clean
Windows 11 machine and in Git Bash before submission.

## Prerequisites

| Requirement | Version | Check with |
|---|---|---|
| Python | 3.10 or newer | `python --version` |
| Git | any | `git --version` |

That is all. No Node.js, no database server, no model download. The console is plain HTML/JS served by
the API process; the store is SQLite from the Python standard library; ATT&CK mapping uses a numpy
TF-IDF index built in under a second from the committed MITRE corpus.

An IBM watsonx.ai account is optional. Without credentials the BLUF generator uses the deterministic
template, which is the path the demo runs on.

## 1. Clone

```bash
git clone https://github.com/het-khatusuriya/bob-ai-hackathon-blue-vector.git
cd bob-ai-hackathon-blue-vector
```

## 2. Python environment

```bash
python -m venv .venv
source .venv/bin/activate        # Windows PowerShell: .venv\Scripts\Activate.ps1   cmd: .venv\Scripts\activate
pip install -r src/requirements.txt
```

## 3. Environment variables

```bash
cp src/.env.example .env         # Windows: copy src\.env.example .env
```

Every variable is optional; the defaults run the demo. All of them are read in `src/config.py`.

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite:///aegis.db` | SQLite file in the repo root. |
| `WATSONX_API_KEY`, `WATSONX_PROJECT_ID` | placeholders | Set both (and `pip install ibm-watsonx-ai`) to let Granite rewrite BLUF narrative fields. |
| `WATSONX_URL` | `https://eu-gb.ml.cloud.ibm.com` | Regional endpoint. |
| `WATSONX_MODEL_ID` | `ibm/granite-3-8b-instruct` | Model used for BLUF refinement. |
| `BLUF_TOP_N` | `10` | How many top incidents get a brief during the pipeline run (others are generated on demand). |
| `EMBEDDING_BACKEND` | `tfidf` | `sbert` uses sentence-transformers if installed. |
| `ATTACK_MAPPING_FLOOR` | `0.35` | Minimum mapping confidence retained. |
| `ATTACK_TOP_K` | `3` | Technique candidates kept per alert. |
| `CORRELATION_THRESHOLD` | `0.45` | Edge weight cutoff. |
| `TEMPORAL_HALFLIFE_SECONDS` | `3600` | Temporal decay half-life. |
| `CORRELATION_WINDOW_HOURS` | `24` | Pre-filter window for pairwise comparison. |
| `MAX_INCIDENT_SIZE` | `40` | Safety cap on incident size. |
| `API_HOST`, `API_PORT` | `127.0.0.1`, `8000` | Where the API and console listen. |

## 4. One command

```bash
python scripts/demo.py
```

This creates the database, ingests the four feeds, runs the pipeline, prints the evaluation table, and
serves the console on <http://localhost:8000>. About ten seconds end to end on a laptop. Ctrl+C stops it.

### Or step by step

```bash
python -m src.db.init --reset     # create tables
python -m src.corpus.load         # four adapters -> canonical alerts in SQLite
python -m src.pipeline.run        # ATT&CK mapping -> correlation -> scoring -> BLUF
python -m src.eval.evaluate       # precision/recall/queue position vs ground truth
uvicorn src.api.main:app --port 8000
```

Expected pipeline output (numbers will match exactly; the corpus is deterministic):

```
[pipeline] 521 alerts loaded
[enrich]   ATT&CK v19.2 (tfidf): 491 mappings on 252 alerts in 1.2s
[correlate] 103993 candidate pairs -> 148 edges >= 0.45 -> 456 incidents (24 multi-alert, largest 12) in 1.7s
[score]    456 incidents scored, 419 with suppression rules fired, in 0.1s
[bluf]     10 briefs (0 watsonx, 10 template) in 0.0s
[pipeline] done. Top of queue: INC-014 (90), INC-017 (87), INC-010 (84), INC-001 (82), INC-024 (76)
```

To regenerate the synthetic corpus from its scenario definitions: `python -m src.corpus.generate`
(byte-identical output; the seed is fixed).

## 5. The console

Open <http://localhost:8000>.

| View | What it shows |
|---|---|
| Triage queue | Incidents ranked by composite score with the four-factor bar, source badges, top technique, deepest tactic, vendor severities. Singletons hidden by default. |
| Incident | Kill-chain strip, score decomposition with explanations, alert timeline, correlation graph (hover an edge for the evidence trail), pairwise "explain", BLUF panel. |
| Alerts | Every normalised alert; click one → "Why is this ranked here?" |
| Raw feeds | The four native formats side by side. |
| ATT&CK | Search techniques, see which incidents touch them. |

Interactive API documentation: <http://localhost:8000/docs>. The contract is in `docs/api-contract.md`.

## 6. Connect IBM Bob

AEGIS exposes an MCP server over stdio. Add it to Bob's MCP configuration (Bob → Settings → MCP
servers, or the `mcp_settings.json` file Bob uses; see bob.ibm.com/docs/ide for the exact location on
your build):

```json
{
  "mcpServers": {
    "aegis": {
      "command": "/absolute/path/to/bob-ai-hackathon-blue-vector/.venv/bin/python",
      "args": ["-m", "src.mcp_server.server"],
      "cwd": "/absolute/path/to/bob-ai-hackathon-blue-vector"
    }
  }
}
```

On Windows use the venv's `.venv\\Scripts\\python.exe` as the command. The server needs the database
that `scripts/demo.py` or `src.pipeline.run` produced; it reads the same SQLite file the console reads.

Then ask Bob, in Agent or Ask mode:

```
What should I look at first this shift?
Why are SIEM-0146 and SYS-0161 part of the same incident?
Give me the BLUF for INC-017.
The SIEM marked SIEM-0121 critical. Why is it ranked so low?
Show me everything mapped to T1059.
Walk me through INC-014.
```

Bob calls `get_priority_queue`, `explain_correlation`, `get_bluf`, `why_deprioritised`,
`search_by_technique` and `get_incident`. All six are read-only.

To verify the server without Bob:

```bash
python - <<'EOF'
import json, subprocess, sys
p = subprocess.Popen([sys.executable, "-m", "src.mcp_server.server"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
send = lambda o: (p.stdin.write(json.dumps(o) + "\n"), p.stdin.flush())
send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}); p.stdout.readline()
send({"jsonrpc":"2.0","method":"notifications/initialized"})
send({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"why_deprioritised","arguments":{"alert_id":"SIEM-0121"}}})
print(json.loads(p.stdout.readline())["result"]["content"][0]["text"][:500])
EOF
```

## 7. Tests

```bash
pytest -q          # 14 tests: IOC extraction, adapters, mapping, tactic ordering, end-to-end ground truth
```

## Verifying it works

| Check | Expected |
|---|---|
| `curl localhost:8000/health` | `{"status":"ok","alerts":521,"incidents":456}` |
| `curl "localhost:8000/incidents?min_alerts=2&limit=3"` | INC-014, INC-017, INC-010 with scores ≈ 90, 87, 84 |
| `curl localhost:8000/alerts/SIEM-0121/why-deprioritised` | rule `KNOWN_SCANNER_RANGE`, queue position > 100 |
| Console queue | Same order as the API |
| Bob `get_priority_queue` | Same incidents as the console |

If the UI and Bob disagree, one of them is reading a database from a different `DATABASE_URL`.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'src'` | Commands run from the wrong directory | Run everything from the repo root |
| `No alerts in the database` | Corpus not loaded | `python -m src.corpus.load` |
| `unable to open database file` | Relative `DATABASE_URL` from another cwd | Run from the repo root or use an absolute path |
| `UnicodeEncodeError` on Windows console | cp1252 terminal | `set PYTHONIOENCODING=utf-8` (or use Windows Terminal) |
| Console shows "MOCK DATA" badge | Opened `index.html` from disk, or API not running | Open <http://localhost:8000> with the API up |
| BLUF says `generated by template` | No watsonx credentials, or SDK not installed | Expected. Set the three `WATSONX_*` vars and `pip install ibm-watsonx-ai` |
| Bob does not list the tools | Wrong `cwd` or interpreter in MCP config | Use the venv interpreter and the repo root as `cwd` |
| One giant incident | Threshold too low for your data | Raise `CORRELATION_THRESHOLD` toward 0.55 |
| Every alert its own incident | Threshold too high | Lower toward 0.40 |
| Port 8000 in use | Another service | `python scripts/demo.py --port 8010` |
