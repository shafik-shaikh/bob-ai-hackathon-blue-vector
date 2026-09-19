"""Load the pre-trained model, score events and explain the top ones."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb

from .features import build_features, feature_label

MODELS = Path(__file__).resolve().parent.parent / "models"


class Predictor:
    def __init__(self, directory: Path = MODELS):
        self.meta = json.loads((directory / "meta.json").read_text())
        self.booster = xgb.Booster()
        self.booster.load_model(str(directory / "model.json"))
        self.features: list[str] = self.meta["features"]

    @property
    def threshold(self) -> float:
        return float(self.meta["threshold"])

    def featurize(self, df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
        X, missing = build_features(df, self.meta["vocab"])
        return X[self.features], missing

    def score(self, X: pd.DataFrame) -> np.ndarray:
        return self.booster.predict(xgb.DMatrix(X, feature_names=self.features))

    def explain(self, X: pd.DataFrame, top: int = 3) -> list[list[dict]]:
        """Per-row top features pushing the score up (XGBoost's exact tree contributions, log-odds)."""
        contribs = self.booster.predict(xgb.DMatrix(X, feature_names=self.features), pred_contribs=True)[:, :-1]
        values = X.to_numpy()
        reasons = []
        for row, vals in zip(contribs, values):
            order = np.argsort(-row)[:top]
            reasons.append([
                {"feature": feature_label(self.features[i]), "value": _fmt(vals[i]), "push": round(float(row[i]), 2)}
                for i in order if row[i] > 0
            ])
        return reasons


def _fmt(value: float) -> str:
    if not np.isfinite(value):
        return "missing"
    return str(int(value)) if float(value).is_integer() else f"{value:.4g}"


@lru_cache(maxsize=1)
def get_predictor() -> Predictor:
    return Predictor()
