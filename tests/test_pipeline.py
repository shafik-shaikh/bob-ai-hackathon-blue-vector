"""End-to-end and unit tests for AEGIS. Run with `pytest`.

The end-to-end tests build a throwaway database from the committed corpus,
so they double as a check that the setup guide's commands work.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
os.environ.setdefault("DATABASE_URL", f"sqlite:///{(REPO / 'aegis-test.db').as_posix()}")

from src.corpus.load import load_corpus  # noqa: E402
from src.correlation.tactics import progression_score  # noqa: E402
from src.db.store import connection, init_db, load_incidents  # noqa: E402
from src.enrichment.attack_mapper import map_alert  # noqa: E402
from src.enrichment.ioc import extract_indicators, refang  # noqa: E402
from src.ingest.syslog import parse_syslog_line  # noqa: E402
from src.models import Alert, IndicatorType, SourceType, Tactic  # noqa: E402
from src.pipeline.run import run_pipeline  # noqa: E402
from src import services  # noqa: E402


# ---------------------------------------------------------------------------
# Unit: IOC extraction
# ---------------------------------------------------------------------------


def test_refang_and_extract_from_prose():
    text = (
        "Beacon to hxxp://update-cdn[.]ravensky[.]net/gate.php from 10.20.14.42. "
        "Payload SHA-256 9c7e2b1a5d4f3e2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c, CVE-2023-22518, "
        "BSSID 3c:22:fb:9a:11:07, user=CORP\\j.okafor."
    )
    assert refang("185[.]220[.]101[.]4") == "185.220.101.4"
    found = {(i.type, i.value) for i in extract_indicators(text)}
    assert (IndicatorType.URL, "http://update-cdn.ravensky.net/gate.php") in found
    assert (IndicatorType.DOMAIN, "update-cdn.ravensky.net") in found
    assert (IndicatorType.IPV4, "10.20.14.42") in found  # followed by a full stop
    assert (IndicatorType.SHA256, "9c7e2b1a5d4f3e2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c") in found
    assert (IndicatorType.CVE, "cve-2023-22518") in found
    assert (IndicatorType.MAC, "3c:22:fb:9a:11:07") in found
    assert (IndicatorType.USER, "corp\\j.okafor") in found
    # No bogus domains from dotted tokens.
    assert not any(t == IndicatorType.DOMAIN and v == "j.okafor" for t, v in found)


def test_sha256_not_reported_as_md5():
    h = "a" * 64
    kinds = [i.type for i in extract_indicators(f"hash {h}")]
    assert kinds == [IndicatorType.SHA256]


# ---------------------------------------------------------------------------
# Unit: syslog adapter
# ---------------------------------------------------------------------------


def test_syslog_rfc5424_parse():
    line = '<131>1 2026-09-14T10:52:41Z dc01 sysmon - - [aegis@32473 severity="err" user="CORP\\svc_backup"] EventID=1 ProcessCreate Image=ntdsutil.exe'
    a = parse_syslog_line(line, "SYS-0001")
    assert a is not None
    assert a.source == SourceType.SYSLOG
    assert a.source_severity == "err"
    assert a.asset and a.asset.asset_id == "DC01" and a.asset.user_principal == "corp\\svc_backup"
    assert a.raw_payload["facility"] == 16


# ---------------------------------------------------------------------------
# Unit: ATT&CK mapping and tactic ordering
# ---------------------------------------------------------------------------


def _alert(text: str) -> Alert:
    from datetime import datetime, timezone

    return Alert(alert_id="X-1", source=SourceType.SIEM, timestamp=datetime.now(timezone.utc), raw_text=text)


@pytest.mark.parametrize(
    "text,expected",
    [
        ("vssadmin.exe delete shadows /all /quiet executed", "T1490"),
        ("powershell.exe -nop -w hidden -enc SQBFAFgA", "T1059.001"),
        ("ntdsutil.exe ac i ntds ifm create full", "T1003.003"),
        ("ET SCAN Nmap SYN scan detected", "T1046"),
        ("Rogue AP detected: evil-twin deauthentication frames", "T1557"),
    ],
)
def test_keyword_mapping(text, expected):
    mappings = map_alert(_alert(text))
    assert mappings and mappings[0].technique_id == expected
    assert mappings[0].score >= 0.8


def test_progression_is_directional():
    forward, _ = progression_score(Tactic.INITIAL_ACCESS, Tactic.EXECUTION)
    backward, _ = progression_score(Tactic.EXECUTION, Tactic.INITIAL_ACCESS)
    assert forward > backward
    impossible, _ = progression_score(Tactic.IMPACT, Tactic.INITIAL_ACCESS)
    assert impossible == 0.0


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def built_state():
    init_db(reset=True)
    load_corpus(verbose=False)
    summary = run_pipeline(use_watsonx=False, verbose=False)
    yield summary


def test_pipeline_produces_ranked_incidents(built_state):
    with connection() as conn:
        incidents = load_incidents(conn)
    assert len(incidents) > 100
    scores = [i.score.composite for i in incidents]
    assert scores == sorted(scores, reverse=True)
    assert incidents[0].alert_count >= 5


def test_ground_truth_scenarios_surface(built_state):
    import json

    from src.config import settings

    truth = json.loads(settings.ground_truth_path.read_text(encoding="utf-8"))
    queue = services.get_queue(limit=500, min_alerts=1)
    rank_of = {}
    for row in queue:
        for aid in services.get_incident_detail(row["incident_id"])["alerts"]:
            rank_of[aid["alert_id"]] = row["rank"]
    tp_ranks = []
    benign_ranks = []
    for s in truth["scenarios"]:
        ranks = [rank_of[a] for a in s["alert_ids"] if a in rank_of]
        best = min(ranks)
        (tp_ranks if s["label"] == "true_positive" else benign_ranks).append(best)
    assert max(tp_ranks) <= 10, f"a true positive fell out of the top 10: {tp_ranks}"
    assert min(benign_ranks) > max(tp_ranks), "a benign scenario outranked a true positive"


def test_why_deprioritised_names_the_rule(built_state):
    # The vendor-CRITICAL scanner alert is the demo closer.
    with connection() as conn:
        row = conn.execute(
            "SELECT alert_id FROM alerts WHERE source_severity = 'critical' AND document LIKE '%Nmap SYN scan%' LIMIT 1"
        ).fetchone()
    assert row is not None
    answer = services.why_deprioritised(row["alert_id"])
    assert "KNOWN_SCANNER_RANGE" in [r["rule_id"] for r in answer["rules_fired"]]
    assert answer["queue_position"] > 50
    assert "10.50.1.10" in answer["narrative"]


def test_explain_correlation_returns_evidence(built_state):
    top = services.get_queue(limit=1, min_alerts=2)[0]
    detail = services.get_incident_detail(top["incident_id"])
    edge = detail["edges"][0]
    answer = services.explain_correlation(edge["alert_a"], edge["alert_b"])
    assert answer["same_incident"] is True
    assert answer["edge"] and answer["edge"]["contributions"]
    assert all(c["rationale"] for c in answer["edge"]["contributions"])


def test_bluf_has_gaps_and_evidence(built_state):
    top = services.get_queue(limit=1, min_alerts=2)[0]
    bluf = services.get_or_create_bluf(top["incident_id"], use_watsonx=False)
    assert bluf["gaps"], "a BLUF without a GAPS section is not allowed"
    assert len(bluf["evidence"]) == top["alert_count"]
    assert bluf["confidence"] in {"High", "Medium", "Low"}
