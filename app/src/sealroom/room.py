"""Sealroom access rules for AI agents, with a tamper-evident decision log.

Two kinds of rule:
  screen  a person may not reach material labelled with certain clients
          (created automatically from a conflict check's verdict)
  wall    two labels may never meet in one agent session: once a session has
          seen one side, the other side is closed to it

Every read is decided before the tool runs. Unlabelled material is refused.
The agent always gets the same refusal text, whatever the reason, so it can't
probe for which clients the firm acts for. Reasons are kept for reviewers.

Each decision is appended to a hash chain; the final head is the session's
log root, which is sealed on NEAR.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field

REFUSAL = "Access to this material is not available in this session."
GENESIS = "0" * 64


def _h(prev: str, entry: dict) -> str:
    return hashlib.sha256(bytes.fromhex(prev) + json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass
class Policy:
    screens: dict[str, set[str]] = field(default_factory=dict)  # person -> labels they may not reach
    walls: list[tuple[str, str]] = field(default_factory=list)  # label pairs that may not meet

    def screen(self, person: str, label: str) -> None:
        self.screens.setdefault(person, set()).add(label)

    def wall(self, a: str, b: str) -> None:
        if (a, b) not in self.walls and (b, a) not in self.walls:
            self.walls.append((a, b))

    def to_json(self) -> dict:
        return {"screens": {p: sorted(l) for p, l in self.screens.items()}, "walls": [list(w) for w in self.walls]}


@dataclass
class Decision:
    seq: int
    at: float
    person: str
    resource: str
    labels: list[str]
    allowed: bool
    reason: str  # reviewer-only
    hash: str = ""


class Session:
    def __init__(self, person: str, policy: Policy, session_id: str | None = None):
        self.id = session_id or uuid.uuid4().hex[:16]
        self.person = person
        self.policy = policy
        self.seen: set[str] = set()
        self.log: list[Decision] = []
        self.head = GENESIS

    def _reason(self, labels: list[str]) -> str | None:
        if not labels:
            return "unlabelled material is closed until someone classifies it"
        screened = self.policy.screens.get(self.person, set())
        for l in labels:
            if l in screened:
                return f"{self.person} is screened from {l}"
        for a, b in self.policy.walls:
            for mine, other in ((a, b), (b, a)):
                if other in labels and mine in self.seen:
                    return f"session has seen {mine}; wall {a} | {b}"
        if any(a in labels and b in labels for a, b in self.policy.walls):
            return "material carries both sides of a wall"
        return None

    def decide(self, resource: str, labels: list[str]) -> Decision:
        reason = self._reason(labels)
        d = Decision(
            seq=len(self.log),
            at=round(time.time(), 3),
            person=self.person,
            resource=resource,
            labels=sorted(labels),
            allowed=reason is None,
            reason=reason or "no Sealroom rule applies",
        )
        entry = asdict(d)
        entry.pop("hash")
        d.hash = self.head = _h(self.head, entry)
        self.log.append(d)
        if d.allowed:
            self.seen.update(labels)
        return d

    @property
    def blocked(self) -> int:
        return sum(not d.allowed for d in self.log)


def verify_log(log: list[dict]) -> str:
    """Recompute the chain from a decision log export; returns the root."""
    head = GENESIS
    for d in log:
        entry = {k: v for k, v in d.items() if k != "hash"}
        head = _h(head, entry)
        if d["hash"] != head:
            raise ValueError(f"log broken at decision {d['seq']}")
    return head


def policy_hash(policy: Policy) -> str:
    return hashlib.sha256(json.dumps(policy.to_json(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def policy_from_verdict(named_pairs: list[dict], person: str, label_of) -> Policy:
    """Turn a conflict check into screens: the incoming person is screened
    from every existing party they conflict with (named_verdict() output)."""
    p = Policy()
    for c in named_pairs:
        p.screen(person, label_of(c["existing"]["name"]))
    return p
