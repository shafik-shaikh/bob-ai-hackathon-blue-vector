"""Train the flow-level malicious/benign model on UNSW-NB15 and write models/model.json + meta.json.

Data: the raw UNSW-NB15 flows (with IPs/ports/timestamps), as parquet on Hugging Face
(Mouwiya/UNSW-NB15). Part 0 (earlier capture) trains; part 1 (later capture, different attack mix)
is held out and only used to report the numbers shown in the app.

    python -m train.train                       # downloads ~230 MB to data/ on first run
    python -m train.train --part0 a.parquet --part1 b.parquet
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.request
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb

from app.features import CATEGORICAL, build_features, normalise_columns
from app.ingest import parse_labels
from app.stats import evaluate

ROOT = Path(__file__).resolve().parent.parent
BASE = "https://huggingface.co/datasets/Mouwiya/UNSW-NB15/resolve/main/data/"
PARTS = {"part0": "train-00000-of-00002.parquet", "part1": "train-00001-of-00002.parquet"}
VOCAB_SIZE = 15


def fetch(name: str) -> Path:
    path = ROOT / "data" / name
    if not path.exists():
        path.parent.mkdir(exist_ok=True)
        print(f"downloading {name} ...")
        urllib.request.urlretrieve(BASE + name, path)
    return path


def load(path: Path) -> pd.DataFrame:
    df = normalise_columns(pd.read_parquet(path))
    return df.sort_values("stime", kind="stable").reset_index(drop=True)


def _ablation(X: pd.DataFrame, y: np.ndarray, Xt: pd.DataFrame, yt: np.ndarray) -> list[dict]:
    """How much of the score is one artefact-prone feature? Small models, same held-out capture."""
    from sklearn.metrics import average_precision_score, roc_auc_score

    ttl = ["sttl", "dttl", "ct_state_ttl"]
    variants = {
        "source TTL only": ["sttl"],
        "TTL features only": ttl,
        "everything except TTL features": [c for c in X.columns if c not in ttl],
    }
    rows = []
    for name, cols in variants.items():
        small = xgb.XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1, subsample=0.8,
                                  colsample_bytree=0.8, tree_method="hist", n_jobs=4, random_state=7)
        small.fit(X[cols], y)
        s = small.predict_proba(Xt[cols])[:, 1]
        rows.append({"variant": name, "roc_auc": float(roc_auc_score(yt, s)), "pr_auc": float(average_precision_score(yt, s))})
    return rows


def _priority_bands(threshold: float, sv: np.ndarray, yv: np.ndarray, st: np.ndarray, yt: np.ndarray) -> list[dict]:
    """Review tiers by score, with how often each tier was a real attack on data the model was not fit on.

    Validation (the slice after the training rows, 1.4% attacks) is closest to a real network's base
    rate; the held-out capture (20% attacks) is shown alongside so the range is visible.
    """
    tiers = [("Critical", 0.9, 1.01), ("High", threshold, 0.9), ("Watch", 0.3, threshold), ("Low", 0.0, 0.3)]
    rows = []
    for name, lo, hi in tiers:
        row = {"tier": name, "min": round(lo, 4), "max": min(round(hi, 4), 1.0)}
        for tag, s, y in (("valid", sv, yv), ("test", st, yt)):
            mask = (s >= lo) & (s < hi)
            row[f"n_{tag}"] = int(mask.sum())
            row[f"attack_share_{tag}"] = float(y[mask].mean()) if mask.any() else None
            row[f"catches_{tag}"] = float(y[mask].sum() / y.sum())
        rows.append(row)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--part0", type=Path)
    ap.add_argument("--part1", type=Path)
    args = ap.parse_args()

    train_df = load(args.part0 or fetch(PARTS["part0"]))
    test_df = load(args.part1 or fetch(PARTS["part1"]))

    vocab = {
        c: [v for v in train_df[c].astype(str).str.strip().str.lower().value_counts().index[:VOCAB_SIZE]]
        for c in CATEGORICAL
    }
    X, _ = build_features(train_df, vocab)
    y, _ = parse_labels(train_df)
    Xt, _ = build_features(test_df, vocab)
    yt, cat_t = parse_labels(test_df)

    # Time-ordered split: fit on the first 80% of part 0, tune the threshold on the last 20%.
    cut = int(len(X) * 0.8)
    model = xgb.XGBClassifier(
        n_estimators=600, max_depth=6, learning_rate=0.08, subsample=0.8, colsample_bytree=0.8,
        min_child_weight=3, tree_method="hist", eval_metric="aucpr", early_stopping_rounds=30,
        n_jobs=4, random_state=7,
    )
    started = time.time()
    model.fit(X.iloc[:cut], y[:cut], eval_set=[(X.iloc[cut:], y[cut:])], verbose=False)
    print(f"trained in {time.time() - started:.0f}s, best_iteration={model.best_iteration}")

    score_valid = model.predict_proba(X.iloc[cut:])[:, 1]
    score_test = model.predict_proba(Xt)[:, 1]
    valid = evaluate(y[cut:], score_valid)
    threshold = valid["best_f1_threshold"]
    test = evaluate(yt, score_test, threshold=threshold, category=cat_t)
    priority = _priority_bands(threshold, score_valid, y[cut:], score_test, yt)

    ablation = _ablation(X, y, Xt, yt)

    # Keep only the trees up to the best iteration: the raw Booster would otherwise also use the
    # extra early-stopping rounds, and the threshold below was tuned without them.
    booster = model.get_booster()[: model.best_iteration + 1]
    gain = booster.get_score(importance_type="total_gain")
    total = sum(gain.values()) or 1.0
    importance = sorted(({"feature": k, "share": v / total} for k, v in gain.items()), key=lambda r: -r["share"])[:15]

    meta = {
        "name": "UNSW-NB15 flow classifier",
        "algorithm": "XGBoost (gradient-boosted trees)",
        "trained_at": time.strftime("%Y-%m-%d"),
        "data_source": "UNSW-NB15 (Moustafa & Slay, UNSW Canberra) via huggingface.co/datasets/Mouwiya/UNSW-NB15",
        "train_rows": int(cut), "train_attack_rate": float(np.mean(y[:cut])),
        "validation_rows": int(len(X) - cut), "test_rows": int(len(Xt)),
        "test_attack_rate": float(np.nanmean(yt)),
        "trees": booster.num_boosted_rounds(), "max_depth": model.get_params()["max_depth"],
        "threshold": threshold, "threshold_rule": "maximises F1 on the validation slice",
        "vocab": vocab, "features": list(X.columns),
        "test": test, "feature_importance": importance, "ablation": ablation, "priority_bands": priority,
        "caveats": [
            "UNSW-NB15 is a lab testbed (2015) with synthetic attack traffic. Separation is unusually clean "
            "(see ablation), so expect lower precision/recall on a real network.",
            "The held-out capture is a later window with a different attack mix (mostly Generic).",
            "Trained on flow records, not syslog/CEF text. Input files must use flow-style columns.",
        ],
    }
    (ROOT / "models").mkdir(exist_ok=True)
    booster.save_model(str(ROOT / "models" / "model.json"))
    (ROOT / "models" / "meta.json").write_text(json.dumps(meta, indent=2))
    print(json.dumps({k: test[k] for k in ("roc_auc", "pr_auc", "precision", "recall", "f1")}, indent=2))
    print("per-category recall:", json.dumps(test.get("by_category"), indent=1))


if __name__ == "__main__":
    main()
