# Solution Overview

## The core mechanism

The app is a single request/response cycle: `POST /api/predict` takes an uploaded file and
returns everything the UI shows. Under the hood, three things happen in order:

1. **Ingest & align** (`app/ingest.py`, `app/features.py`) — the file (CSV, Parquet, JSON or
   NDJSON, headered or the original headerless UNSW-NB15 layout) is parsed, columns are
   normalised (case-insensitive, aliases resolved — e.g. `Sload` → `sload`, `Dst_IP` →
   `dstip`), and coverage against the model's 37 expected flow features is measured. Anything
   below 40% coverage is rejected with a message naming what's missing, rather than silently
   producing a meaningless score.
2. **Score** (`app/model.py`) — the pre-trained XGBoost booster (`models/model.json`) scores
   every row. Scores are ranked, and rows above the threshold (default: the value that
   maximised F1 on a validation slice at training time, in `meta.json`) are flagged.
3. **Explain** (`app/story.py`, `app/stats.py`) — instead of returning just a score, the app
   pulls XGBoost's **exact tree contribution values** (`pred_contribs=True`, the same mechanism
   as SHAP for tree ensembles, not an approximation) for the top-ranked event, and the running
   log-odds after each of the model's 43 trees. That's the entire data behind the 7-step
   walkthrough — every number shown ("tree 12 pushed the score from 0.31 to 0.44 because
   `sttl=254`") is read directly off the model that just scored the file, not scripted.

## What makes it different from naive alternatives

A naive version of this tool would be: run inference, return a score column, done. That gives
an analyst a number with no way to sanity-check it. The design choice here is to treat
**explainability and calibration as first-class outputs**, not an add-on:

- The walkthrough isn't a generic "how gradient boosting works" animation — it's built from the
  contribution values of the one event that scored highest *in this file*, so it's always a
  real explanation of a real decision.
- When ground truth (`label` or `attack_cat`) is present, the app computes full detection
  metrics (precision/recall/F1/ROC-AUC/PR-AUC/confusion matrix/per-category recall) live, with
  a threshold slider, instead of quoting a single fixed number from the model card.
- The "About the model" tab surfaces the model's own weak spots (TTL-field sensitivity, the
  Fuzzers category's low recall, the gap between the 2015 UNSW-NB15 lab and real traffic)
  rather than only the metrics that make it look good.

## Key design decisions

- **No accounts, no database, no case management.** The scope is deliberately narrow: upload a
  file, get scored statistics. Anything stateful (case tracking, alert queues) is a different
  product and would dilute the one thing this tool does well.
- **Flow features only, no IPs/ports/timestamps as model inputs.** These fields identify the
  *testbed*, not the *behaviour* — including them would inflate benchmark accuracy without
  producing a model that generalises to a different network. They're still shown to the
  analyst for context, just not used for scoring.
- **A single pre-trained model ships in the repo.** Retraining is available (`python -m
  train.train`) but not required — the point of the demo is to be usable in under a minute
  with zero external accounts or API keys.

## What the user experience looks like

1. Analyst opens the page and either uploads a file or clicks "Try sample with labels."
2. The 7-step walkthrough plays automatically: data received → columns matched → features
   built → the score growing tree by tree → the threshold decision → why the top event was
   flagged → the final result. This takes a few seconds and is the same for every file size —
   it's built from one event's trace, not the whole dataset.
3. "Full statistics" is one click away: score distribution, flagged-event breakdown by
   protocol/service/source/port/time, ranked top suspicious events with their reasons, and (if
   labelled) the full metrics suite with a live threshold slider.
4. The analyst downloads the CSV (original columns + `ml_score` + `ml_flag`) to take back into
   their existing workflow.
