# Screenshots

Captured from the running console (`python scripts/demo.py`) at 1440×900 against the committed corpus.

| File | What it shows |
|---|---|
| `01-triage-queue.png` | The landing view: 24 multi-alert incidents ranked by consequence. Four-factor score bars, source badges, top technique, deepest tactic, assets, vendor severities preserved on the right. |
| `02-incident-correlation-graph.png` | INC-014 (phishing → C2 → DC01 credential theft → exfiltration): kill-chain strip, score decomposition with explanations, and the force-directed correlation graph with edge weights. Hovering an edge shows the evidence trail. |
| `03-why-deprioritised.png` | The demo closer: SIEM-0121 is vendor-CRITICAL; AEGIS ranks it 136 of 456 because `KNOWN_SCANNER_RANGE` fired, with the evidence and the score breakdown. This is the same answer IBM Bob gives via `why_deprioritised`. |
| `04-raw-feeds.png` | The four native formats side by side — the problem before AEGIS. |
| `05-site-alpha-incident.png` | INC-017: geospatial tracks, RF sensor, wireless controller, NAC and OT alerts joined into one physical/cyber incident reaching *impact*. |
