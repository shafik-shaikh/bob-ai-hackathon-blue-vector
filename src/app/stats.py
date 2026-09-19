"""ML statistics: supervised metrics when labels exist, score/traffic summaries always."""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_curve, roc_auc_score, average_precision_score, roc_curve

BINS = 100


def _curve(x: np.ndarray, y: np.ndarray, points: int = 80) -> list[list[float]]:
    if len(x) > points:
        keep = np.unique(np.linspace(0, len(x) - 1, points).astype(int))
        x, y = x[keep], y[keep]
    return [[round(float(a), 4), round(float(b), 4)] for a, b in zip(x, y)]


def _confusion(y: np.ndarray, flag: np.ndarray) -> dict[str, int]:
    return {
        "tp": int(np.sum(flag & (y == 1))), "fp": int(np.sum(flag & (y == 0))),
        "tn": int(np.sum(~flag & (y == 0))), "fn": int(np.sum(~flag & (y == 1))),
    }


def _rates(c: dict[str, int]) -> dict[str, float]:
    tp, fp, tn, fn = c["tp"], c["fp"], c["tn"], c["fn"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "precision": precision, "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "accuracy": (tp + tn) / max(tp + fp + tn + fn, 1),
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
    }


def score_histogram(scores: np.ndarray) -> list[int]:
    return np.bincount(np.minimum((scores * BINS).astype(int), BINS - 1), minlength=BINS).tolist()


def evaluate(y: np.ndarray, scores: np.ndarray, threshold: float | None = None,
             category: pd.Series | None = None) -> dict:
    """Metrics for rows whose label is known. Returns {"note": ...} when only one class is present."""
    known = np.isfinite(y)
    y, scores = y[known].astype(int), scores[known]
    out: dict = {"n": int(len(y)), "positives": int(y.sum()), "prevalence": float(y.mean()) if len(y) else 0.0}
    if len(y) == 0 or y.min() == y.max():
        out["note"] = "Labels contain a single class, so ROC-AUC/PR-AUC are undefined."
        return out

    prec, rec, thr = precision_recall_curve(y, scores)
    f1 = 2 * prec[:-1] * rec[:-1] / np.maximum(prec[:-1] + rec[:-1], 1e-12)
    best = float(thr[int(np.argmax(f1))])
    used = best if threshold is None else threshold
    fpr, tpr, _ = roc_curve(y, scores)

    confusion = _confusion(y, scores >= used)
    out |= {
        "roc_auc": float(roc_auc_score(y, scores)), "pr_auc": float(average_precision_score(y, scores)),
        "threshold": used, "best_f1_threshold": best, "confusion": confusion, **_rates(confusion),
        "roc_curve": _curve(fpr, tpr), "pr_curve": _curve(rec[:-1], prec[:-1]),
        "hist_pos": score_histogram(scores[y == 1]), "hist_neg": score_histogram(scores[y == 0]),
        "threshold_table": [
            {"threshold": t, **_rates(c), **c}
            for t in (0.1, 0.25, 0.5, 0.75, 0.9) for c in [_confusion(y, scores >= t)]
        ],
    }
    if category is not None:
        cat = category.to_numpy()[known]
        rows = []
        for name in sorted(set(cat[y == 1])):
            mask = cat == name
            rows.append({"category": str(name), "count": int(mask.sum()),
                         "detected": int(np.sum(scores[mask] >= used)),
                         "recall": float(np.mean(scores[mask] >= used))})
        out["by_category"] = sorted(rows, key=lambda r: -r["count"])
    return out


def _breakdown(df: pd.DataFrame, flag: np.ndarray, column: str, top: int = 8) -> list[dict]:
    if column not in df.columns:
        return []
    frame = pd.DataFrame({"k": df[column].astype(str).str.strip(), "f": flag})
    grouped = frame.groupby("k")["f"].agg(["size", "sum"]).sort_values(["sum", "size"], ascending=False).head(top)
    return [{"value": k, "events": int(r["size"]), "flagged": int(r["sum"]),
             "rate": float(r["sum"] / r["size"])} for k, r in grouped.iterrows()]


def summarise(df: pd.DataFrame, scores: np.ndarray, threshold: float) -> dict:
    """Score distribution and where the flagged traffic sits. Works without any labels."""
    flag = scores >= threshold
    out = {
        "events": int(len(df)), "flagged": int(flag.sum()), "flag_rate": float(flag.mean()),
        "mean_score": float(scores.mean()), "hist_all": score_histogram(scores),
        "by_proto": _breakdown(df, flag, "proto"), "by_service": _breakdown(df, flag, "service"),
        "top_sources": [r for r in _breakdown(df[flag], flag[flag], "srcip", 8)],
        "top_ports": [r for r in _breakdown(df[flag], flag[flag], "dsport", 8)],
        "timeline": [],
    }
    for key in ("top_sources", "top_ports"):
        for row in out[key]:  # within the flagged subset the rate is meaningless; report counts only
            row.pop("rate", None)
            row.pop("events", None)
    if "stime" in df.columns:
        t = pd.to_numeric(df["stime"], errors="coerce")
        if t.notna().sum() > 1 and t.max() > t.min():
            edges = np.linspace(t.min(), t.max(), 41)
            bucket = np.clip(np.digitize(t.fillna(t.min()), edges) - 1, 0, 39)
            total = np.bincount(bucket, minlength=40)
            hit = np.bincount(bucket, weights=flag.astype(float), minlength=40)
            out["timeline"] = [{"t": float(edges[i]), "events": int(total[i]), "flagged": int(hit[i])} for i in range(40)]
    return out
