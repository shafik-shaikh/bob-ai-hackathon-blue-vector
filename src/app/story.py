"""The 'what just happened' data behind the step-by-step walkthrough.

Everything here is measured from the real run (the uploaded rows, the real trees), not illustrated:
the growth of the score tree by tree, and the per-feature push, come straight from XGBoost.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import xgboost as xgb

from .features import CATEGORICAL, NUMERIC, feature_label
from .ingest import ReadInfo
from .model import Predictor, _fmt

PREVIEW_FIELDS = ["srcip", "sport", "dstip", "dsport", "proto", "service", "state", "dur", "sbytes", "dbytes"]
DISPLAY_ONLY = ["srcip", "sport", "dstip", "stime", "ltime", "stcpb", "dtcpb", "attack_cat", "label"]
SHOWN_PARTS = 6


def _sigmoid(x: float) -> float:
    return float(1.0 / (1.0 + np.exp(-x)))


def _vector(predictor: Predictor, X: pd.DataFrame, i: int) -> list[dict]:
    row = X.iloc[i]
    out = []
    for name in predictor.features:
        group = name.split("=", 1)[0] if "=" in name else "numeric"
        out.append({"n": name, "g": group, "v": None if not np.isfinite(row[name]) else float(row[name])})
    return out


def _trace(predictor: Predictor, X: pd.DataFrame, i: int) -> list[float]:
    """Running log-odds of one event after 1, 2, ... N trees."""
    d = xgb.DMatrix(X.iloc[[i]], feature_names=predictor.features)
    return [round(float(predictor.booster.predict(d, output_margin=True, iteration_range=(0, k))[0]), 3)
            for k in range(1, predictor.booster.num_boosted_rounds() + 1)]


def _explain(predictor: Predictor, X: pd.DataFrame, i: int) -> dict:
    d = xgb.DMatrix(X.iloc[[i]], feature_names=predictor.features)
    contribs = predictor.booster.predict(d, pred_contribs=True)[0]
    bias, pushes = float(contribs[-1]), contribs[:-1]
    order = np.argsort(-np.abs(pushes))
    shown = order[:SHOWN_PARTS]
    values = X.iloc[i].to_numpy()
    parts = [{"feature": feature_label(predictor.features[j]), "value": _fmt(values[j]), "push": round(float(pushes[j]), 3)}
             for j in shown]
    other = float(pushes[order[SHOWN_PARTS:]].sum())
    logit = bias + float(pushes.sum())
    return {"bias": round(bias, 3), "parts": parts, "other": round(other, 3), "logit": round(logit, 3),
            "start_prob": _sigmoid(bias), "prob": _sigmoid(logit)}


def _event(df: pd.DataFrame, i: int, scores: np.ndarray, labels, category) -> dict:
    ev = {"row": int(i) + 1, "score": round(float(scores[i]), 4)}
    for f in PREVIEW_FIELDS:
        if f in df.columns:
            ev[f] = str(df.at[i, f])
    if labels is not None and np.isfinite(labels[i]):
        ev["label"] = int(labels[i])
    if category is not None:
        ev["attack_cat"] = str(category.iloc[i])
    return ev


def build_story(predictor: Predictor, df: pd.DataFrame, X: pd.DataFrame, scores: np.ndarray, labels, category,
                info: ReadInfo, missing: list[str], size_bytes: int, threshold: float) -> dict:
    top_i, low_i = int(np.argmax(scores)), int(np.argmin(scores))
    found = [c for c in NUMERIC if c not in missing]
    groups = {"numeric": len(NUMERIC)} | {c: sum(f.startswith(c + "=") for f in predictor.features) for c in CATEGORICAL}
    preview_cols = [c for c in PREVIEW_FIELDS if c in df.columns]
    return {
        "input": {
            "format": info.format, "headerless": info.headerless, "bytes": size_bytes, "rows": int(len(df)),
            "columns": info.columns_in, "labelled": labels is not None,
            "preview_cols": preview_cols, "preview": [{c: str(df.at[i, c]) for c in preview_cols} for i in range(min(6, len(df)))],
        },
        "mapping": {
            "found": found, "missing": [c for c in NUMERIC if c in missing],
            "categorical_found": [c for c in CATEGORICAL if c not in missing], "renamed": info.renamed,
            "display_only": [c for c in DISPLAY_ONLY if c in df.columns],
        },
        "features": {"count": len(predictor.features), "groups": groups, "vector": _vector(predictor, X, top_i)},
        "model": {"algorithm": predictor.meta["algorithm"], "trees": predictor.booster.num_boosted_rounds(),
                  "max_depth": predictor.meta.get("max_depth"), "threshold": threshold},
        "attack": _event(df, top_i, scores, labels, category) | {"trace": _trace(predictor, X, top_i)},
        "normal": _event(df, low_i, scores, labels, category) | {"trace": _trace(predictor, X, low_i)},
        "explain": _explain(predictor, X, top_i),
    }
