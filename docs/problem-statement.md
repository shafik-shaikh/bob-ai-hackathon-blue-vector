# Problem Statement

## Who is affected

SOC analysts and incident responders who receive network-flow exports (from Argus, Zeek, a
firewall, or a NetFlow collector feeding a SIEM) and have to decide, quickly, which of
thousands of events are worth a human's attention. This is the same audience any commercial
"ML-assisted triage" SIEM feature targets — the difference is what happens after the model
produces a score.

## Why existing solutions don't solve it

Most ML-scored triage tools give the analyst a single number per event and stop there:

- **The score is a black box.** The analyst has no way to see which fields drove it, so they
  either rubber-stamp high scores (alert fatigue in the other direction — trusting a model they
  can't inspect) or ignore the model and go back to manual correlation, which defeats the point
  of having it.
- **No visibility into model reliability.** A vendor's marketing page quotes a headline
  accuracy number from their own test set. It rarely says how that number was measured, on what
  data, or how it degrades on traffic that looks different from training data — so analysts
  can't calibrate how much to trust it.
- **Threshold is fixed.** A single cutoff baked into the product doesn't fit every analyst's
  risk tolerance or every network's base rate of attacks.

## Quantified pain

Precision and recall both move a lot with the base rate of attacks in the traffic, which is
exactly the kind of thing a black-box score hides. On the same trained model:

| Test slice | Attack rate | Precision | Recall |
|---|---|---|---|
| Held-out capture (`sample_labelled.csv`) | 27% | ~97% | ~96% |
| Realistic capture (`sample_realistic_3pct_attacks.csv`) | 2.6% | ~74% | (recall holds, false positives climb) |

A model that looks excellent on a 27%-attack test set looks meaningfully worse — still useful,
but worse — on a 2.6%-attack network, which is closer to real traffic. A tool that only reports
the first number is misleading an analyst who will actually see the second.

## Why this matters now

ML-based detection is being bolted onto more SIEM pipelines every year, largely because the
volume of flow data has outgrown what analysts can review by hand. If that layer isn't
explainable and honestly benchmarked, teams either over-trust it (missed attacks explained away
as "the model said it was fine") or under-trust it (ignore it, and the volume problem is back).
Making the score's provenance and its real accuracy visible — rather than asserted — is what
turns an ML score from a liability into an actual triage aid.
