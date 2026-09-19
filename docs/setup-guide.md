# Setup Guide

This walks through running SIEM ML Predictor from a clean clone, with nothing assumed.

## Prerequisites

| Tool | Version | Check |
|---|---|---|
| Python | 3.10+ | `python --version` |
| pip | any recent | `pip --version` |
| Git | any recent (only to clone) | `git --version` |

No accounts, API keys, GPUs, or external services are required. The trained model is already
committed to the repo, so there's nothing to download to run the app (retraining is optional —
see the end of this guide).

## Environment variables

None are required. `src/.env.example` documents two optional overrides (`HOST`, `PORT`) for the
dev server if you don't want to pass `--port` on the command line; there is nothing to fill in.

## Install

```bash
git clone <this-repo-url>
cd <repo-folder>/src
python -m venv .venv
```

Activate the virtual environment:

```bash
# macOS / Linux
source .venv/bin/activate

# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Windows (cmd / Git Bash)
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Run

```bash
uvicorn app.main:app --port 8000
```

Open **http://localhost:8000** in a browser.

## Verify it's working

1. `curl http://localhost:8000/api/health` should return
   `{"status":"ok","model_loaded":true}`.
2. `curl http://localhost:8000/api/model` should return the model's metadata (algorithm, tree
   count, threshold, evaluation numbers).
3. In the browser, click **"Try sample with labels"** — the 7-step walkthrough should play
   automatically, followed by a full statistics dashboard (precision/recall/ROC-AUC/etc.).
4. Upload one of the other files in `src/samples/` (e.g. `sample_unlabelled.csv`) and confirm
   scores are produced without ground-truth metrics.

## Run the tests

```bash
cd src                       # if not already there
pip install -r requirements-dev.txt
pytest
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `error while attempting to bind on address ... only one usage of each socket address` (Windows) or `Address already in use` (macOS/Linux) | Something else is already listening on that port | Run on a different port: `uvicorn app.main:app --port 8001` |
| `ModuleNotFoundError: No module named 'app'` when running `pytest` or `python -m train.train` | Command run from the repo root instead of `src/` | `cd src` first — these are run as `app.*`/`train.*` packages rooted at `src/` |
| `model_loaded: false` from `/api/health`, or a 500 error on predict | `src/models/model.json` or `meta.json` missing | Confirm both files exist under `src/models/`; if you deleted them, retrain (below) or re-clone |
| Upload rejected with "This file is not network-flow data" | The uploaded file isn't in the UNSW-NB15/Argus/Zeek flow layout the model expects | Try one of the files in `src/samples/` first to confirm the app works, then check your file has flow-style columns (`dur, sbytes, dbytes, sttl, proto, service, state, ct_*`, …) |
| `pip install` fails building `pyarrow` or `xgboost` from source | Python version too new/old, or missing platform wheels | Use Python 3.10–3.12 on a common platform (Windows/macOS/Linux x86-64 or arm64); these packages ship prebuilt wheels for those |

## Optional: retrain the model

Not required to run or evaluate the app — the trained model already ships in the repo.

```bash
cd src
pip install -r requirements-dev.txt
python -m train.train          # downloads ~230 MB (Hugging Face Mouwiya/UNSW-NB15) into data/, ~1 min
python -m train.make_samples   # regenerates samples/ from the held-out capture
```
