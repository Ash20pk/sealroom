"""The agent sees one fixed refusal for every refused read, whatever the reason,
and its decision log chains to the root that gets sealed."""

import json
from dataclasses import asdict

from nacl.signing import SigningKey

from sealroom import agent
from sealroom.attest import VerifiedModel
from sealroom.e2ee import decrypt_as_model
from sealroom.nearai import SignedCompletion
from sealroom.room import REFUSAL, Policy, Session, verify_log

LIBRARY = {
    "open": {"id": "open", "title": "Lumenra brief", "labels": ["client:lumenra"], "text": "Lumenra renewal terms."},
    "screened": {"id": "screened", "title": "Halverson memo", "labels": ["client:halverson"], "text": "Halverson strategy."},
    "walled": {"id": "walled", "title": "Brightwater file", "labels": ["client:brightwater"], "text": "Brightwater pricing."},
    "unlabelled": {"id": "unlabelled", "title": "Misc note", "labels": [], "text": "Unclassified."},
}
# Opens the wall's first side, then hits a screen, the wall, an unlabelled doc and a missing id.
READS = ["open", "screened", "walled", "unlabelled", "no-such-doc"]


def test_every_refusal_reads_the_same_and_the_log_chains(monkeypatch):
    key = SigningKey.generate()
    model = VerifiedModel("fake/model", bytes(key.verify_key).hex(), bytes(SigningKey.generate().verify_key).hex(),
                          "ab" * 32, "UpToDate", "00" * 32, b"{}")
    seen_by_model: list[str] = []

    def complete(model, msgs, reader, max_tokens=800):
        if len(msgs) > 2:  # the reply to the previous read, as the model receives it
            seen_by_model.append(decrypt_as_model(key, msgs[-1]["content"]))
        step = (len(msgs) - 2) // 2
        action = {"action": "read", "id": READS[step]} if step < len(READS) else {"action": "answer", "text": "done"}
        return SignedCompletion(f"c{step}", json.dumps(action), "", "", "", "", "", "provider_tee")

    monkeypatch.setattr(agent, "complete", complete)
    p = Policy()
    p.screen("jane", "client:halverson")
    p.wall("client:lumenra", "client:brightwater")
    s = Session("jane", p)
    run = agent.run("brief me", s, LIBRARY, model, max_steps=len(READS) + 1)

    assert run.answer == "done"
    assert len(seen_by_model) == len(READS)
    assert "Lumenra renewal terms." in seen_by_model[0]
    refused = seen_by_model[1:]
    assert refused == [REFUSAL] * len(refused), "every refusal must be byte-identical"
    for doc in ("Halverson", "Brightwater", "Unclassified"):
        assert not any(doc in r for r in refused)

    # Screen, wall and unlabelled have different reasons, which only reviewers see.
    # A missing id is refused like unlabelled material, so the agent can't tell
    # "does not exist" from "exists but closed".
    reasons = [d.reason for d in s.log[1:]]
    assert len(set(reasons[:3])) == 3
    assert reasons[2] == reasons[3]
    assert not any(d.allowed for d in s.log[1:])
    assert verify_log([asdict(d) for d in s.log]) == s.head
