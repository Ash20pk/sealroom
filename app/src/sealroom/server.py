"""Local web app for Sealroom.

The browser seals each firm's list itself (libsodium, in the page), so this
server only ever receives ciphertext envelopes. It verifies attestation, relays
the sealed request, checks the TEE signature and writes the record to NEAR.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from nacl.signing import VerifyKey
from pydantic import BaseModel

from . import chain
from .agent import load_library, run
from .attest import verify_model
from .barrier import Policy, Session, policy_from_verdict, verify_log
from .conflict import canonical, check

ROOT = Path(__file__).resolve().parents[3]
WEB = ROOT / "web"
DEMO = ROOT / "demo"
STATE = ROOT / ".state"
STATE.mkdir(exist_ok=True)
MODEL = os.environ.get("SEALROOM_MODEL", "z-ai/glm-5.3-flash")
FIRMS = {
    "incoming": os.environ.get("SEALROOM_FIRM_INCOMING", "sr-firm-north-64716.testnet"),
    "existing": os.environ.get("SEALROOM_FIRM_EXISTING", "sr-firm-south-64716.testnet"),
}

app = FastAPI(title="Sealroom")
_attest = {"at": 0.0, "model": None}


def attested(fresh: bool = False):
    if fresh or not _attest["model"] or time.time() - _attest["at"] > 300:
        _attest["model"] = verify_model(MODEL)
        _attest["at"] = time.time()
    return _attest["model"]


def _err(e: Exception) -> HTTPException:
    msg = str(e)
    if "402" in msg or "spending limit" in msg:
        msg = "NEAR AI Cloud has no credit on this key. Add credit at cloud.near.ai, then try again."
    return HTTPException(502, msg)


@app.get("/api/config")
def config():
    return {
        "model": MODEL,
        "contract": chain.CONTRACT,
        "explorer": chain.EXPLORER,
        "firms": {side: {"account": acct, "name": chain.view("firm_name", {"account_id": acct})} for side, acct in FIRMS.items()},
    }


@app.get("/api/attest")
def attest(fresh: bool = False):
    try:
        m = attested(fresh)
    except Exception as e:  # noqa: BLE001
        raise _err(e)
    return {**m.to_json(), "checks": [
        "Intel signed the TDX quotes for the gateway and the model",
        "The quote binds the model's key and our fresh nonce",
        "TDX debug mode is off",
    ]}


class CheckIn(BaseModel):
    incoming: dict
    existing: dict


@app.post("/api/check")
def run_check(body: CheckIn):
    try:
        m = attested()
        r = check(body.incoming, body.existing, m)
        c = r.completion
        res = chain.call(
            body.existing["firm"],
            "record_check",
            {
                "counterparty": body.incoming["firm"],
                "requester_commitment": body.existing["commitment"],
                "counterparty_commitment": body.incoming["commitment"],
                "verdict_hash": r.verdict_hash,
                "conflicts_found": len(r.verdict["conflicts"]),
                "attestation": {
                    "model": m.model, "chat_id": c.chat_id, "signed_text": c.signed_text,
                    "signature": c.signature, "signing_address": c.signing_address, "report_hash": m.report_sha256,
                },
            },
        )
    except Exception as e:  # noqa: BLE001
        raise _err(e)
    check_id = res["return"]
    record = {
        "check_id": check_id, "verdict": r.verdict, "verdict_hash": r.verdict_hash,
        "completion": c.to_json(), "tx": res["tx"], "tx_url": chain.tx_url(res["tx"]),
    }
    (STATE / f"check-{check_id}.json").write_text(json.dumps(record, indent=2))
    (STATE / "latest-check.json").write_text(json.dumps(record, indent=2))
    return record


@app.get("/api/check/{check_id}/verify")
def verify_check(check_id: int):
    rec = chain.view("get_check", {"id": check_id})
    if not rec:
        raise HTTPException(404, f"No check #{check_id} on {chain.CONTRACT}.")
    att = rec["attestation"]
    steps = []
    try:
        VerifyKey(bytes.fromhex(att["signing_address"])).verify(
            att["signed_text"].encode(), bytes.fromhex(att["signature"].removeprefix("0x")))
        steps.append({"ok": True, "text": "The TEE's signature over the request and response hashes is valid"})
    except Exception:  # noqa: BLE001
        steps.append({"ok": False, "text": "The signature does not verify"})
    live = attested(fresh=True)
    same = att["signing_address"].lower() in (live.signing_key.lower(), live.gateway_key.lower())
    steps.append({"ok": same, "text": "The signer is the key an attested TEE holds right now" if same
                  else "The signer differs from today's attested key (keys rotate when the model is redeployed)"})
    local = STATE / f"check-{check_id}.json"
    if local.exists():
        v = json.loads(local.read_text())["verdict"]
        import hashlib
        ok = hashlib.sha256(canonical(v)).hexdigest() == rec["verdict_hash"]
        steps.append({"ok": ok, "text": "The verdict we hold matches the hash on NEAR" if ok else "The verdict we hold does NOT match the hash on NEAR"})
    return {"record": rec, "steps": steps}


class AgentIn(BaseModel):
    person: str
    question: str
    use_verdict: bool = True
    walls: list[str] = []
    seal: bool = True


@app.post("/api/agent")
def agent(body: AgentIn):
    labels = json.loads((DEMO / "labels.json").read_text())
    policy = Policy()
    latest = STATE / "latest-check.json"
    if body.use_verdict and latest.exists():
        policy = policy_from_verdict(json.loads(latest.read_text())["verdict"], body.person,
                                     lambda n: labels.get(n, "client:" + n.lower().split()[0]))
    for w in body.walls:
        a, b = w.split("|")
        policy.wall(a.strip(), b.strip())
    session = Session(body.person, policy)
    q: queue.Queue = queue.Queue()

    def work():
        try:
            m = attested()
            q.put({"type": "start", "session_id": session.id, "policy": policy.to_json(), "model": m.model})
            r = run(body.question, session, load_library(DEMO / "library.json"), m,
                    on_step=lambda t: q.put({"type": "step", "turn": asdict(t)}))
            export = {"run": r.to_json(), "policy": policy.to_json(), "log": [asdict(d) for d in session.log], "log_root": session.head}
            if body.seal and session.log:
                res = chain.call(FIRMS["existing"], "seal_session", {
                    "session_id": session.id, "log_root": session.head,
                    "decisions": len(session.log), "blocked": session.blocked})
                export["chain"] = {"tx": res["tx"], "url": chain.tx_url(res["tx"])}
            (STATE / f"session-{session.id}.json").write_text(json.dumps(export, indent=2))
            q.put({"type": "done", "answer": r.answer, "log_root": session.head, "chain": export.get("chain"),
                   "decisions": len(session.log), "blocked": session.blocked})
        except Exception as e:  # noqa: BLE001
            q.put({"type": "error", "message": _err(e).detail})
        q.put(None)

    threading.Thread(target=work, daemon=True).start()

    def stream():
        while (item := q.get()) is not None:
            yield f"data: {json.dumps(item)}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.get("/api/session/{session_id}/verify")
def verify_session(session_id: str):
    rec = chain.view("get_session", {"session_id": session_id})
    if not rec:
        raise HTTPException(404, f"Session {session_id} is not sealed on {chain.CONTRACT}.")
    local = STATE / f"session-{session_id}.json"
    steps = []
    if local.exists():
        exp = json.loads(local.read_text())
        try:
            root = verify_log(exp["log"])
            steps.append({"ok": True, "text": f"Each of the {len(exp['log'])} decisions chains to the next"})
            ok = root == rec["log_root"]
            steps.append({"ok": ok, "text": "The log root matches the one sealed on NEAR" if ok else "The log root does NOT match NEAR"})
        except ValueError as e:
            steps.append({"ok": False, "text": str(e)})
    else:
        steps.append({"ok": False, "text": "We don't hold this session's log locally, so only the on-chain seal is shown"})
    return {"record": rec, "steps": steps}


@app.get("/demo/{name}")
def demo_file(name: str):
    if name not in {"partner_incoming.csv", "firm_existing.csv"}:
        raise HTTPException(404)
    return FileResponse(DEMO / name)


app.mount("/", StaticFiles(directory=WEB, html=True), name="web")


def main() -> None:
    import uvicorn

    uvicorn.run("sealroom.server:app", host="127.0.0.1", port=int(os.environ.get("PORT", 4410)))
