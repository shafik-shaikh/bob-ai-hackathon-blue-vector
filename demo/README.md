# Demo

- `https://drive.google.com/file/d/1zF6hK2qVPdhFz1sbz10QSmDdW3MgYt80/view?usp=sharing` — link to a 3–5 minute walkthrough video (TODO: record and add the URL).
- `live-demo-url.txt` — link to a deployed instance, or `NOT DEPLOYED`.
- `screenshots/` — screenshots of the running app, captured from a real local run
  (Playwright against `uvicorn app.main:app`, not mocked):
  1. `01-upload-home.png` — the upload screen (drag-and-drop or sample buttons)
  2. `02-walkthrough-step.png` — step 1 of the 7-step animated walkthrough, after uploading `samples/sample_labelled.csv`
  3. `03-full-statistics.png` — the full statistics dashboard: precision/recall/F1/ROC-AUC/PR-AUC, score distribution, confusion matrix, ROC and PR curves, with the live threshold slider
  4. `04-detection-metrics.png` — detection rate per attack category, flagged events over time, and flag rate by protocol/service/source
  5. `05-about-the-model.png` — the "About the model" tab: held-out evaluation numbers, recall by attack type, feature importance, and the TTL-field ablation study
