# src/ layout

All source code for the SIEM ML Predictor lives here. Nothing outside `src/`
is required to run the app.

```
src/
├── app/                 FastAPI application
│   ├── main.py          routes: POST /api/predict, GET /api/model, samples, CSV download
│   ├── features.py      column schema, aliases, feature building (37 flow features)
│   ├── ingest.py        reads CSV/Parquet/JSON/NDJSON, parses labels
│   ├── model.py         loads the trained XGBoost model, scores rows, explains top events
│   ├── stats.py         metrics (precision/recall/F1/ROC-AUC/PR-AUC) and traffic summaries
│   ├── story.py         data behind the 7-step animated walkthrough
│   └── static/          single-page UI (app.js dashboard, story.js walkthrough) — no
│                        external JS/CSS libraries, served directly by FastAPI
├── models/              model.json + meta.json — the trained model, committed to the repo
├── samples/             sample flow files used by the UI's "try a sample" buttons
├── train/               training + sample-generation scripts (train.py, make_samples.py)
├── tests/               pytest suite
├── data/                (gitignored) raw UNSW-NB15 parquet, downloaded by train/train.py
├── requirements.txt     runtime dependencies
├── requirements-dev.txt dev/test-only dependencies (pytest)
└── .env.example         see below — the app takes no required configuration
```

Run it (from the repo root):

```bash
cd src
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --port 8000
```

Full instructions, prerequisites and troubleshooting: [`../docs/setup-guide.md`](../docs/setup-guide.md).
