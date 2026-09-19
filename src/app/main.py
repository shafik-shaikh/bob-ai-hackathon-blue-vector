"""Upload a SIEM/flow export -> pre-trained model scores every event -> ML statistics."""

from __future__ import annotations

import tempfile
import time
import uuid
from collections import OrderedDict
from pathlib import Path

import numpy as np
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .features import NUMERIC
from .ingest import IngestError, coverage, parse_labels, read_with_info
from .model import get_predictor
from .stats import evaluate, summarise
from .story import build_story

ROOT = Path(__file__).resolve().parent.parent
STATIC = Path(__file__).resolve().parent / "static"
SAMPLES = ROOT / "samples"
MAX_BYTES = 300 * 1024 * 1024
MIN_COVERAGE = 0.4
TOP_N = 100
ID_FIELDS = ["srcip", "sport", "dstip", "dsport", "proto", "service", "state"]

app = FastAPI(title="SIEM ML Predictor", version="1.0.0")
_exports: "OrderedDict[str, Path]" = OrderedDict()  # last few prediction CSVs, keyed by result id
_export_dir = Path(tempfile.mkdtemp(prefix="siem-ml-"))


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "model_loaded": (ROOT / "models" / "model.json").exists()}


@app.get("/api/model")
def model_info() -> dict:
    return get_predictor().meta


@app.get("/api/samples")
def list_samples() -> list[dict]:
    return [{"name": p.name, "size_kb": p.stat().st_size // 1024, "has_labels": "unlabelled" not in p.name}
            for p in sorted(SAMPLES.glob("*.csv"))]


@app.get("/api/samples/{name}")
def download_sample(name: str) -> FileResponse:
    path = SAMPLES / Path(name).name
    if not path.is_file():
        raise HTTPException(404, "no such sample")
    return FileResponse(path, media_type="text/csv", filename=path.name)


@app.post("/api/predict/sample/{name}")
def predict_sample(name: str, threshold: float | None = Form(None)) -> dict:
    path = SAMPLES / Path(name).name
    if not path.is_file():
        raise HTTPException(404, "no such sample")
    return _run(path.read_bytes(), path.name, threshold)


@app.post("/api/predict")
def predict(file: UploadFile = File(...), threshold: float | None = Form(None)) -> dict:
    data = file.file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(413, f"file is over {MAX_BYTES // 1024 // 1024} MB")
    return _run(data, file.filename or "upload", threshold)


@app.get("/api/results/{result_id}/predictions.csv")
def download_predictions(result_id: str) -> FileResponse:
    path = _exports.get(result_id)
    if path is None or not path.exists():
        raise HTTPException(404, "result expired; upload the file again")
    return FileResponse(path, media_type="text/csv", filename="predictions.csv")


def _run(data: bytes, filename: str, threshold: float | None) -> dict:
    started = time.time()
    predictor = get_predictor()
    threshold = predictor.threshold if threshold is None else float(np.clip(threshold, 0.0, 1.0))
    try:
        df, info = read_with_info(data, filename)
    except IngestError as exc:
        raise HTTPException(422, str(exc)) from exc
    share = coverage(df)
    if share < MIN_COVERAGE:
        seen = ", ".join(map(str, list(df.columns)[:12])) + (" …" if len(df.columns) > 12 else "")
        raise HTTPException(422, (
            f"This file is not network-flow data: only {round(share * len(NUMERIC))} of the {len(NUMERIC)} columns "
            f"the model needs were found (e.g. dur, sbytes, sttl, proto, service). "
            f"Your file has {len(df.columns)} columns: {seen}. "
            "Use a flow export in the UNSW-NB15 layout, or click 'Try sample with labels'."))

    X, missing = predictor.featurize(df)
    scores = predictor.score(X)
    flag = scores >= threshold
    labels, category = parse_labels(df)

    order = np.argsort(-scores)[:TOP_N]
    reasons = predictor.explain(X.iloc[order])
    top = []
    for rank, i in enumerate(order):
        row = {"row": int(i) + 1, "score": round(float(scores[i]), 4), "reasons": reasons[rank]}
        for field in ID_FIELDS:
            if field in df.columns:
                row[field] = str(df.at[i, field])
        if labels is not None and np.isfinite(labels[i]):
            row["label"] = int(labels[i])
        if category is not None:
            row["attack_cat"] = str(category.iloc[i])
        top.append(row)

    result_id = uuid.uuid4().hex[:12]
    export = df.assign(ml_score=np.round(scores, 5), ml_flag=flag.astype(int))
    path = _export_dir / f"{result_id}.csv"
    export.to_csv(path, index=False)
    _exports[result_id] = path
    while len(_exports) > 5:
        _, old = _exports.popitem(last=False)
        old.unlink(missing_ok=True)

    warnings = []
    if share < 0.9:
        warnings.append(f"{len(missing)} expected columns are missing; the model treats them as unknown, "
                        "so scores may be less reliable.")
    return {
        "id": result_id, "filename": filename, "rows": int(len(df)), "threshold": threshold,
        "default_threshold": predictor.threshold, "labelled": labels is not None,
        "columns": {"found": len(NUMERIC) - sum(m in NUMERIC for m in missing), "expected": len(NUMERIC),
                    "missing": [m for m in missing if m in NUMERIC]},
        "summary": summarise(df, scores, threshold),
        "metrics": evaluate(labels, scores, threshold=threshold, category=category) if labels is not None else None,
        "story": build_story(predictor, df, X, scores, labels, category, info, missing, len(data), threshold),
        "top": top, "warnings": warnings, "seconds": round(time.time() - started, 2),
    }


@app.exception_handler(Exception)
async def unexpected(_, exc: Exception) -> JSONResponse:
    return JSONResponse({"detail": f"unexpected error: {exc.__class__.__name__}: {exc}"}, status_code=500)


app.mount("/", StaticFiles(directory=STATIC, html=True), name="static")
