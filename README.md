# SIEM ML Predictor

## Team — Blue Vector

| Member | Role |
|---|---|
| **Het Khatusuriya** (lead) | [Khatusuriyahet@gmail.com](mailto:Khatusuriyahet@gmail.com) |
| **Samarth Bhalala** | [samarthbhalala@gmail.com](mailto:samarthbhalala@gmail.com) |
| **Manan Modi** | [22ce068@charusat.edu.in](mailto:22ce068@charusat.edu.in) |
| **Mohammad Safik** | [25pgce026@charusat.edu.in](mailto:25pgce026@charusat.edu.in) |

**Track:** AI

## Problem Statement

Analysts triaging network-flow exports either have to trust a black-box ML verdict or spend
hours manually correlating fields across thousands of events to work out what's actually worth
reviewing. Most ML-based triage tools return a single score with no visibility into *why* an
event was flagged, which features drove it, or how reliable the model is once traffic looks
different from what it was trained on. See [`docs/problem-statement.md`](docs/problem-statement.md)
for the full write-up.

## Solution

Upload a file of network events; a pre-trained XGBoost model scores every event and the page
shows the ML statistics — nothing else, no accounts, no case management. A 7-step animated
walkthrough plays first, built from real numbers measured on the actual run (columns matched,
features built, the score growing tree by tree, the threshold decision, why the top event was
flagged). Full details in [`docs/solution-overview.md`](docs/solution-overview.md).

## Key Features

- Upload CSV/Parquet/JSON/NDJSON flow exports up to 300 MB / 2M rows, with case-insensitive column matching and alias resolution for the UNSW-NB15 / Argus / Zeek flow layout
- 7-step animated walkthrough of a real scored event, with every number measured from that run
- Per-event explanations via XGBoost's exact tree contributions (not an approximation)
- Full detection statistics when a `label`/`attack_cat` column is present — precision, recall, F1, ROC-AUC, PR-AUC, ROC/PR curves, confusion matrix, per-attack-type detection rate, with a live threshold slider
- Unlabelled-mode triage view — score distribution, flagged-event breakdown by protocol/service/source/port/time, and ranked top suspicious events with reasons
- CSV export of every prediction (original columns plus `ml_score` and `ml_flag`)

## Tech Stack

- **Backend:** Python, FastAPI, Uvicorn
- **ML:** XGBoost (gradient-boosted trees), scikit-learn, pandas, NumPy, PyArrow
- **Frontend:** Single-page vanilla HTML/CSS/JS (no external UI libraries), served directly by FastAPI's `StaticFiles`
- **Data:** [UNSW-NB15](https://huggingface.co/datasets/Mouwiya/UNSW-NB15) (Moustafa & Slay, UNSW Canberra Cyber)
- **Testing:** pytest

## How to Run

```bash
cd src
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --port 8000                     # open http://localhost:8000
```

The trained model (`src/models/model.json`, `meta.json`) ships in the repo, so this works
immediately — click "Try sample with labels" for a full result. Full prerequisites,
troubleshooting and retraining instructions: [`docs/setup-guide.md`](docs/setup-guide.md).

## Demo

- **Video:** see [`demo/demo-video-link.txt`](demo/demo-video-link.txt)
- **Live demo:** see [`demo/live-demo-url.txt`](demo/live-demo-url.txt)
- **Screenshots:** [`demo/screenshots/`](demo/screenshots/)

## Known Limitations

- **No IBM Bob integration yet.** This build is a standalone FastAPI app; it does not currently
  call IBM Bob or watsonx.ai. The natural extension point is an MCP server around
  `src/app/model.py`'s `Predictor` (score + explain), so an analyst could ask Bob to triage a
  file or explain a specific flagged event conversationally — see
  [`docs/architecture.md`](docs/architecture.md) for how that would slot in.
- **Flow data only.** The model is trained on network-flow features (UNSW-NB15 / Argus / Zeek
  layout: `dur, sbytes, dbytes, sttl, proto, service, state, ct_*`, …). It does not read raw
  syslog/CEF log text — a flow-feature model can't score free text, and no suitable
  labelled SIEM-log dataset was found to train a text model instead.
- **Lab-generated training data.** UNSW-NB15 is a 2015 testbed capture with generated attacks.
  It's unusually easy — a model using only the source TTL field alone reaches ROC-AUC 0.983 —
  so real-network precision/recall will likely be lower than the 97%/96% measured on the
  held-out capture. The app's "About the model" tab shows this caveat to the user.
- **Fuzzers are the weak spot** — 53% recall on the held-out capture, versus >90% for every
  other attack category.
- Scores are a triage aid, ranking events for an analyst to review — not a verdict.

## What We're Most Proud Of

The walkthrough (`src/app/story.py` + `src/app/static/story.js`) isn't a canned animation —
every number in the 7 steps (columns matched, feature values, the score after each of the 43
trees, why the threshold sits where it does, which features pushed the top event's score up) is
computed live from the model's own XGBoost tree contributions on the file the analyst just
uploaded. It turns "trust the score" into "see exactly how the score was built," which is the
actual gap we set out to close — see [`docs/solution-overview.md`](docs/solution-overview.md).
