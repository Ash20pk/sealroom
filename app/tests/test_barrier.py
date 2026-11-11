from dataclasses import asdict

import pytest

from sealroom.barrier import Policy, Session, policy_from_verdict, verify_log


def test_screen_blocks_person():
    p = Policy()
    p.screen("jane", "client:halverson")
    s = Session("jane", p)
    assert not s.decide("doc1", ["client:halverson"]).allowed
    assert s.decide("doc2", ["client:lumenra"]).allowed
    assert Session("raj", p).decide("doc1", ["client:halverson"]).allowed


def test_wall_closes_other_side_after_exposure():
    p = Policy()
    p.wall("client:brightwater", "client:oduya")
    s = Session("raj", p)
    assert s.decide("a", ["client:oduya"]).allowed
    d = s.decide("b", ["client:brightwater"])
    assert not d.allowed and "wall" in d.reason
    assert Session("raj", p).decide("b", ["client:brightwater"]).allowed  # fresh session


def test_unlabelled_refused_and_refused_reads_do_not_expose():
    p = Policy()
    p.wall("x", "y")
    s = Session("raj", p)
    assert not s.decide("memo", []).allowed
    p.screen("raj", "x")
    assert not s.decide("d", ["x"]).allowed
    assert "x" not in s.seen
    assert s.decide("e", ["y"]).allowed


def test_log_chain_detects_tampering():
    p = Policy()
    p.screen("jane", "c:a")
    s = Session("jane", p)
    for i, l in enumerate(["c:a", "c:b", "c:a"]):
        s.decide(f"d{i}", [l])
    log = [asdict(d) for d in s.log]
    assert verify_log(log) == s.head
    log[0]["allowed"] = True
    with pytest.raises(ValueError):
        verify_log(log)


def test_policy_from_verdict():
    v = {"conflicts": [{"existing": "Orrin Biologics"}, {"existing": "Harbinger Foods"}]}
    p = policy_from_verdict(v, "jane", lambda n: "client:" + n.split()[0].lower())
    assert p.screens["jane"] == {"client:orrin", "client:harbinger"}
