"""The eval only scores a run whose proof bundle replays."""

from pathlib import Path

import pytest

from sealroom import conflict
from sealroom import eval as ev
from sealroom.flow import local_check

from test_engine import FakeTEE

CASE = Path(__file__).resolve().parents[2] / "eval" / "small"
SCORE_KEYS = {"precision", "recall", "true_positives", "false_positives", "missed", "recall_by_relationship"}


@pytest.fixture
def tee(monkeypatch):
    t = FakeTEE()
    monkeypatch.setattr(conflict, "complete", t.complete)
    monkeypatch.setattr(ev, "verify_model", lambda name: t.model)
    return t


def test_verified_run_is_scored(tee):
    res = ev.evaluate(CASE, "fake/model", log=lambda *_: None)
    run = res["runs"][0]
    assert res["verified"] and res["unverified_runs"] == []
    assert run["verified"] is True
    assert SCORE_KEYS <= run.keys()


@pytest.mark.parametrize("tamper", ["verdict", "response"])
def test_failed_replay_reports_no_score(tee, monkeypatch, tamper):
    def tampered(*a, **kw):
        r = local_check(*a, **kw)
        b = r["bundle"]
        if tamper == "verdict":
            b["verdict"]["pairs"].append({"i": 0, "j": 0, "relationship": "same_entity", "confidence": 1.0, "source": "enclave"})
            b["verdict_hash"] = conflict.sha256_hex(conflict.canonical(b["verdict"]))
        else:
            assert len(b["calls"]) > 1
            b["calls"][0]["response_b64"] = b["calls"][1]["response_b64"]
        return r

    monkeypatch.setattr(ev, "local_check", tampered)
    res = ev.evaluate(CASE, "fake/model", runs=2, log=lambda *_: None)
    assert res["verified"] is False
    assert res["unverified_runs"] == [0, 1]
    for run in res["runs"]:
        assert run["verified"] is False
        assert run["replay_failures"]
        assert not (SCORE_KEYS & run.keys()), "an unverified run must carry no score"
