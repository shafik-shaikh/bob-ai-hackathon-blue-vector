import io
import json

import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient

from app.features import NUMERIC, normalise_columns
from app.ingest import IngestError, parse_labels, read_events
from app.main import app
from app.stats import evaluate

client = TestClient(app)


def _flows(n=6):
    row = {c: 1 for c in NUMERIC}
    row |= {"proto": "tcp", "service": "http", "state": "FIN", "srcip": "10.0.0.1", "dstip": "10.0.0.2", "stime": 1_400_000_000}
    return pd.DataFrame([row] * n)


def test_column_aliases_and_case():
    df = normalise_columns(pd.DataFrame({"Sload": [1], "smean": [2], "Dst_IP": [3], "Label": [1]}))
    assert list(df.columns) == ["sload", "smeansz", "dstip", "label"]


def test_headerless_unsw_csv_is_read():
    from app.features import RAW_COLUMNS

    line = ",".join(["59.166.0.0", "1390", "149.171.126.6", "0x000b", "udp", "CON"] + ["1"] * 43) + "\n"
    df = read_events(line.encode() * 3, "UNSW-NB15_1.csv")
    assert len(df) == 3 and list(df.columns) == RAW_COLUMNS
    assert df.loc[0, "dsport"] == "0x000b"


@pytest.mark.parametrize("values,expected", [([0, 1, 1], [0, 1, 1]), (["Normal", "Exploits", "benign"], [0, 1, 0])])
def test_label_parsing(values, expected):
    labels, _ = parse_labels(pd.DataFrame({"label": values}))
    assert labels.tolist() == expected


def test_labels_fall_back_to_attack_cat():
    labels, cat = parse_labels(pd.DataFrame({"attack_cat": ["Normal", " Fuzzers", "Backdoors", None]}))
    assert labels.tolist() == [0, 1, 1, 0]
    assert cat.tolist() == ["Normal", "Fuzzers", "Backdoor", "Normal"]


def test_evaluate_matches_known_case():
    y = np.array([0, 0, 1, 1, 1.0])
    s = np.array([0.1, 0.6, 0.4, 0.8, 0.9])
    m = evaluate(y, s, threshold=0.5)
    assert m["confusion"] == {"tp": 2, "fp": 1, "tn": 1, "fn": 1}
    assert m["roc_auc"] == pytest.approx(5 / 6)


def test_single_class_labels_do_not_crash():
    assert "note" in evaluate(np.array([1.0, 1.0]), np.array([0.2, 0.9]))


def test_model_meta_is_served():
    meta = client.get("/api/model").json()
    assert 0 < meta["threshold"] < 1 and meta["test"]["roc_auc"] > 0.5 and meta["ablation"]


def test_predict_unlabelled_csv():
    body = _flows().to_csv(index=False).encode()
    r = client.post("/api/predict", files={"file": ("flows.csv", body)})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["rows"] == 6 and j["metrics"] is None and len(j["top"]) == 6
    assert all(0 <= t["score"] <= 1 for t in j["top"])


def test_predict_json_and_ndjson_and_labels():
    df = _flows(4).assign(label=[0, 1, 0, 1])
    nd = "\n".join(json.dumps(r) for r in df.to_dict("records")).encode()
    r = client.post("/api/predict", files={"file": ("f.ndjson", nd)})
    assert r.status_code == 200 and r.json()["labelled"] is True
    assert r.json()["metrics"]["positives"] == 2


def test_prediction_csv_download_roundtrip():
    j = client.post("/api/predict", files={"file": ("f.csv", _flows().to_csv(index=False).encode())}).json()
    text = client.get(f"/api/results/{j['id']}/predictions.csv").text
    out = pd.read_csv(io.StringIO(text))
    assert {"ml_score", "ml_flag"} <= set(out.columns) and len(out) == 6


def test_rejects_non_flow_file():
    r = client.post("/api/predict", files={"file": ("x.csv", b"user,action\nbob,login\n")})
    detail = r.json()["detail"]
    assert r.status_code == 422 and "not network-flow data" in detail and "user, action" in detail


def test_rejects_garbage_and_empty():
    assert client.post("/api/predict", files={"file": ("x.json", b"{not json")}).status_code == 422
    assert client.post("/api/predict", files={"file": ("x.csv", b"a,b\n")}).status_code == 422


def test_sample_endpoint_and_path_traversal():
    j = client.post("/api/predict/sample/sample_labelled.csv").json()
    assert j["metrics"]["roc_auc"] > 0.95
    assert client.get("/api/samples/..%2Fmodels%2Fmeta.json").status_code == 404


def test_uploaded_html_is_not_interpreted_server_side():
    df = _flows(2).assign(srcip="<script>alert(1)</script>")
    j = client.post("/api/predict", files={"file": ("f.csv", df.to_csv(index=False).encode())}).json()
    assert j["top"][0]["srcip"] == "<script>alert(1)</script>"  # returned verbatim; the UI escapes on render


def test_saved_model_uses_only_the_validated_trees():
    from app.model import get_predictor

    predictor = get_predictor()
    assert predictor.booster.num_boosted_rounds() == predictor.meta["trees"]


def test_walkthrough_story_numbers_agree_with_the_score():
    """The tree-by-tree curve, the per-feature pushes and the reported score are the same number."""
    j = client.post("/api/predict/sample/sample_labelled.csv").json()
    s = j["story"]
    logit = s["attack"]["trace"][-1]
    assert len(s["attack"]["trace"]) == s["model"]["trees"] == j["story"]["model"]["trees"]
    assert 1 / (1 + np.exp(-logit)) == pytest.approx(s["attack"]["score"], abs=1e-3)
    parts = s["explain"]["bias"] + sum(p["push"] for p in s["explain"]["parts"]) + s["explain"]["other"]
    assert parts == pytest.approx(logit, abs=0.02)
    assert s["features"]["count"] == len(s["features"]["vector"]) == 83
    assert s["mapping"]["missing"] == [] and s["input"]["labelled"] is True


def test_story_reports_headerless_and_format():
    j = client.post("/api/predict/sample/sample_headerless_raw.csv").json()
    assert j["story"]["input"]["headerless"] is True and j["story"]["input"]["columns"] == 49
    assert client.post("/api/predict/sample/sample_flows.ndjson").json()["story"]["input"]["format"] == "NDJSON"
