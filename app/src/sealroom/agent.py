"""A research agent for a law firm, working inside the Sealroom.

The agent is a NEAR account registered by the firm, owned by one member and
pinned to a model and to the hash of this prompt. A member must sign each
session it runs. Every model call goes to a NEAR AI TEE with end-to-end encryption, so neither
the gateway nor we as operators can read the firm's documents in transit.
Every document read is decided by the Sealroom session before any content
reaches the model. The session's decision log is sealed on NEAR at the end.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .attest import VerifiedModel
from .room import REFUSAL, Session
from .e2ee import ClientKey, encrypt_to
from .nearai import complete

SYSTEM = """You are a research assistant at a law firm. You can read documents from the firm's
library to answer the user's question. Reply with JSON only, one action per turn:
  {"action": "read", "id": "<document id>"}
  {"action": "answer", "text": "<your answer>"}
Some documents may be unavailable to this session. If a read is refused, do not retry it and do not
speculate about why; work with what you have, and say plainly if you could not find the answer.
Library:
"""

# Registered on NEAR with the agent; a session run with any other prompt cannot be sealed.
PROMPT_HASH = hashlib.sha256(SYSTEM.encode()).hexdigest()


@dataclass
class Turn:
    action: dict
    chat_id: str
    request_sha256: str
    response_sha256: str
    signature: str
    signing_address: str
    decision: dict | None = None


@dataclass
class AgentRun:
    session_id: str
    person: str
    question: str
    answer: str = ""
    turns: list[Turn] = field(default_factory=list)

    def to_json(self) -> dict:
        return asdict(self)


def load_library(path: Path) -> dict[str, dict]:
    return {d["id"]: d for d in json.loads(Path(path).read_text())}


def run(question: str, session: Session, library: dict[str, dict], model: VerifiedModel, max_steps: int = 6, on_step=None) -> AgentRun:
    catalog = "\n".join(f"- {d['id']}: {d['title']}" for d in library.values())
    reader = ClientKey.generate()
    key = model.signing_key
    msgs = [
        {"role": "system", "content": encrypt_to(key, SYSTEM + catalog)},
        {"role": "user", "content": encrypt_to(key, question)},
    ]
    out = AgentRun(session_id=session.id, person=session.person, question=question)
    for _ in range(max_steps):
        c = complete(model, msgs, reader, max_tokens=800)
        try:
            action = json.loads(c.content.strip().strip("`").removeprefix("json").strip())
        except json.JSONDecodeError:
            action = {"action": "answer", "text": c.content.strip()}
        turn = Turn(action, c.chat_id, c.request_sha256, c.response_sha256, c.signature, c.signing_address)
        out.turns.append(turn)
        msgs.append({"role": "assistant", "content": encrypt_to(key, json.dumps(action))})

        if action.get("action") == "read":
            doc = library.get(str(action.get("id")))
            d = session.decide(str(action.get("id")), doc["labels"] if doc else [])
            turn.decision = asdict(d)
            body = f"Document {doc['id']}: {doc['title']}\n\n{doc['text']}" if (d.allowed and doc) else REFUSAL
            msgs.append({"role": "user", "content": encrypt_to(key, body)})
            if on_step:
                on_step(turn)
            continue
        out.answer = str(action.get("text", ""))
        if on_step:
            on_step(turn)
        return out
    out.answer = "(stopped after the step limit)"
    return out
