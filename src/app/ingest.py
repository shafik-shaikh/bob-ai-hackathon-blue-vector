"""Read an uploaded event file (CSV / Parquet / JSON / NDJSON) and pull out the optional ground truth."""

from __future__ import annotations

import io
import json
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from .features import ALIASES, NUMERIC, RAW_COLUMNS, normalise_columns

MAX_ROWS = 2_000_000
_BENIGN = {"normal", "benign", "0", "false", "no", "none", "legit", "legitimate", "-", ""}


class IngestError(ValueError):
    """The file cannot be turned into a table of events."""


@dataclass
class ReadInfo:
    """What happened while reading the file; feeds the step-by-step walkthrough in the UI."""

    format: str = "CSV"
    headerless: bool = False
    columns_in: int = 0
    renamed: list[dict] = field(default_factory=list)


def read_events(data: bytes, filename: str) -> pd.DataFrame:
    return read_with_info(data, filename)[0]


def read_with_info(data: bytes, filename: str) -> tuple[pd.DataFrame, ReadInfo]:
    name = filename.lower()
    info = ReadInfo()
    try:
        if name.endswith(".parquet"):
            df, info.format = pd.read_parquet(io.BytesIO(data)), "Parquet"
        elif name.endswith((".json", ".ndjson", ".jsonl")):
            df, info.format = _read_json(data)
        else:
            df, info.headerless = _read_csv(data)
    except IngestError:
        raise
    except Exception as exc:  # pandas/pyarrow raise many unrelated types on malformed input
        raise IngestError(f"could not parse '{filename}': {exc}") from exc
    if df.empty:
        raise IngestError("the file has no rows")
    if len(df) > MAX_ROWS:
        raise IngestError(f"{len(df):,} rows is over the {MAX_ROWS:,}-row limit; split the file")
    info.columns_in = len(df.columns)
    keys = {str(c).strip().lower().replace(" ", "_"): str(c) for c in df.columns}
    info.renamed = [{"from": orig, "to": ALIASES[k]} for k, orig in keys.items()
                    if k in ALIASES and ALIASES[k] not in keys]
    return normalise_columns(df).reset_index(drop=True), info


def _read_csv(data: bytes) -> tuple[pd.DataFrame, bool]:
    df = pd.read_csv(io.BytesIO(data), encoding="utf-8-sig", low_memory=False, skipinitialspace=True)
    known = {str(c).strip().lower() for c in df.columns}
    # The original UNSW-NB15 files ship without a header row: the first data row was read as names.
    if "dur" not in known and "sbytes" not in known and len(df.columns) == len(RAW_COLUMNS):
        df = pd.read_csv(io.BytesIO(data), header=None, names=RAW_COLUMNS, encoding="utf-8-sig", low_memory=False)
        return df, True
    return df, False


def _read_json(data: bytes) -> tuple[pd.DataFrame, str]:
    text = data.decode("utf-8-sig").strip()
    if text.startswith("["):
        return pd.json_normalize(json.loads(text)), "JSON array"
    return pd.json_normalize([json.loads(line) for line in text.splitlines() if line.strip()]), "NDJSON"


def parse_labels(df: pd.DataFrame) -> tuple[np.ndarray | None, pd.Series | None]:
    """Return (label array with NaN for unknown, attack category) or (None, None) if no truth is present."""
    category = None
    if "attack_cat" in df.columns:
        category = df["attack_cat"].astype("string").str.strip().replace({"Backdoors": "Backdoor"})
        category = category.fillna("Normal").replace({"": "Normal"})
    if "label" in df.columns:
        labels = _label_from_column(df["label"])
        if np.isfinite(labels).any():
            return labels, category
    if category is not None:
        return (~category.str.lower().isin(_BENIGN)).to_numpy(dtype="float64"), category
    return None, None


def _label_from_column(series: pd.Series) -> np.ndarray:
    numeric = pd.to_numeric(series, errors="coerce")
    if numeric.notna().mean() > 0.9:
        return (numeric > 0).where(numeric.notna()).to_numpy(dtype="float64")
    text = series.astype("string").str.strip().str.lower()
    out = (~text.isin(_BENIGN)).astype("float64").where(text.notna())
    return out.to_numpy(dtype="float64")


def coverage(df: pd.DataFrame) -> float:
    """Share of the model's numeric input columns present in the file."""
    return sum(c in df.columns for c in NUMERIC) / len(NUMERIC)
