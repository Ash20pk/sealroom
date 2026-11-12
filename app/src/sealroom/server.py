"""Local web app for Sealroom: the orchestrator.

What this server holds: ciphertexts, blinded points, entry NUMBERS, signatures.
What it never holds: a party name before both firms disclose a match, or a
firm's or member's private key (they sign in the browser).

Every firm message is checked against the firm's key registered on NEAR before
it is accepted. The agent will not start without a member's signature, and it
seals its session from its own NEAR account with a key that can do nothing else.

DEMO NOTE: this page plays both firms and the lawyers, so /api/demo/identity
hands the browser their keys from .state/identity. The server code never signs
with them; in production each key lives on its owner's device.
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
from pydantic import BaseModel

from . import bundle, chain, conflict
from .agent import PROMPT_HASH, load_library, run
from .attest import verify_model
from .identity import session_message, sha256_hex, verify
from .room import Policy, Session, policy_from_verdict, policy_hash, verify_log

ROOT = Path(__file__).resolve().parents[3]
WEB = ROOT / "web"
DEMO = ROOT / "demo"
STATE = ROOT / ".state"
IDENTITY = STATE / "identity"
STATE.mkdir(exist_ok=True)
MODEL = os.environ.get("SEALROOM_MODEL", "z-ai/glm-5.3-flash")
FIRMS = {
    "incoming": os.environ.get("SEALROOM_FIRM_INCOMING", "sr-firm-north-64716.testnet"),
    "existing": os.environ.get("SEALROOM_FIRM_EXISTING", "sr-firm-south-64716.testnet"),
}
AGENT = os.environ.get("SEALROOM_AGENT", f"research.{FIRMS['existing']}")
MEMBERS = [f"jane.{FIRMS['existing']}", f"marcus.{FIRMS['existing']}"]

app = FastAPI(title="Sealroom")
_attest = {"at": 0.0, "model": None}
rooms: dict[str, dict] = {}  # check_ref -> state of an open check
pending: dict[str, dict] = {}  # session_id -> prepared agent session


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


def _room(ref: str) -> dict:
    r = rooms.get(ref)
    if not r:
        raise HTTPException(404, "No such open check. Start again.")
    return r


@app.get("/api/config")
def config():
    def firm(acct):
        f = chain.view("get_firm", {"account_id": acct}) or {}
        return {"account": acct, "name": f.get("name"), "key": f.get("key"), "url": chain.account_url(acct)}

    members = []
    for m in MEMBERS:
        got = chain.view("get_member", {"account_id": m})
        if got:
            members.append({"account": m, **got, "url": chain.account_url(m)})
    agent = chain.view("get_agent", {"account_id": AGENT})
    return {
        "model": MODEL,
        "contract": chain.CONTRACT,
        "operator": chain.OPERATOR,
        "explorer": chain.EXPLORER,
        "firms": {side: firm(acct) for side, acct in FIRMS.items()},
        "members": members,
        "agent": {"account": AGENT, **(agent or {}), "url": chain.account_url(AGENT),
                  "prompt_matches": bool(agent) and agent["prompt_hash"] == PROMPT_HASH},
        "engine": {"name": conflict.ENGINE, "instructions_hash": conflict.INSTRUCTIONS_HASH},
    }


@app.get("/api/demo/identity/{account}")
def demo_identity(account: str):
    """Demo only: the page plays the firms and lawyers. Never serves the agent's or operator's keys."""
    if account not in (*FIRMS.values(), *MEMBERS):
        raise HTTPException(404, "Not a demo firm or member.")
    p = IDENTITY / f"{account}.json"
    if not p.exists():
        raise HTTPException(404, "Run `sealroom setup` first.")
    return json.loads(p.read_text())


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


# ---------------------------------------------------------------- conflict check


class OpenIn(BaseModel):
    incoming_count: int
    existing_count: int


@app.post("/api/check/open")
def open_check(body: OpenIn):
    ref = os.urandom(16).hex()
    keys = chain.firm_keys(*FIRMS.values())
    rooms[ref] = {"ref": ref, "chunk": conflict.plan_chunk(body.incoming_count, body.existing_count), "keys": keys,
                  "envelopes": {}, "psi": {}, "opened": time.time()}
    return {"check_ref": ref, "chunk": rooms[ref]["chunk"], "contract": chain.CONTRACT, "firms": FIRMS, "keys": keys}


class EnvelopeIn(BaseModel):
    envelope: dict


@app.post("/api/check/{ref}/envelope")
def post_envelope(ref: str, body: EnvelopeIn):
    r, env = _room(ref), body.envelope
    side = env.get("side")
    if side not in FIRMS or env.get("firm") != FIRMS[side] or env.get("check_ref") != ref:
        raise HTTPException(400, "Envelope is for another firm, side or check.")
    other = FIRMS["existing" if side == "incoming" else "incoming"]
    if env.get("counterparty") != other or env.get("chunk") != r["chunk"]:
        raise HTTPException(400, "Envelope names the wrong counterparty or chunk size.")
    try:
        conflict.check_envelope(env, r["keys"][env["firm"]], chain.CONTRACT)
    except ValueError as e:
        raise HTTPException(400, str(e))
    r["envelopes"][side] = env
    return {"accepted": True, "signed_by": env["firm"]}


@app.get("/api/check/{ref}/envelope/{side}")
def get_envelope(ref: str, side: str):
    """What the other firm needs for the exact-match step: the blinded set and the signed hashes."""
    env = _room(ref)["envelopes"].get(side)
    if not env:
        raise HTTPException(404, "That firm has not sealed yet.")
    return {k: env[k] for k in ("firm", "side", "counterparty", "check_ref", "commitment", "ciphertext_hash", "psi_blinded", "psi_hash", "signature")}


class PsiIn(BaseModel):
    kind: str  # incoming_doubled | existing_doubled | incoming_index | existing_index
    message: dict


@app.post("/api/check/{ref}/psi")
def post_psi(ref: str, body: PsiIn):
    r = _room(ref)
    if body.kind not in ("incoming_doubled", "existing_doubled", "incoming_index", "existing_index"):
        raise HTTPException(400, "Unknown exact-match message.")
    r["psi"][body.kind] = body.message
    return {"accepted": True}


@app.get("/api/check/{ref}/psi")
def get_psi(ref: str):
    return _room(ref)["psi"]


@app.post("/api/check/{ref}/run")
def run_check(ref: str):
    r = _room(ref)
    inc, ext = r["envelopes"].get("incoming"), r["envelopes"].get("existing")
    if not inc or not ext or len(r["psi"]) != 4:
        raise HTTPException(400, "Both firms must seal and finish the exact-match step first.")
    try:
        exact = conflict.exact_pairs(r["psi"], inc, ext, r["keys"], ref)
        m = attested()
        res = conflict.run_check(inc, ext, m, exact)
        b = bundle.build(chain.CONTRACT, res, inc, ext, r["psi"], r["keys"])
        rec = chain.call(chain.OPERATOR, "record_check", bundle.onchain_args(b), gas="300 Tgas")
    except Exception as e:  # noqa: BLE001
        raise _err(e)
    b["check_id"] = int(rec["return"])
    b["tx"] = rec["tx"]
    r["bundle"] = b
    (STATE / f"bundle-{b['check_id']}.json").write_text(json.dumps(b))
    return {"check_id": b["check_id"], "tx": rec["tx"], "tx_url": chain.tx_url(rec["tx"]), "verdict": res.verdict,
            "verdict_hash": res.verdict_hash,
            "calls": [{"chat_id": c.completion.chat_id, "signer": c.completion.signing_address} for c in res.calls]}


class RevealIn(BaseModel):
    side: str
    reveal: dict


@app.post("/api/check/{ref}/reveal")
def post_reveal(ref: str, body: RevealIn):
    r = _room(ref)
    b = r.get("bundle")
    if not b:
        raise HTTPException(400, "No verdict yet.")
    if body.side not in FIRMS:
        raise HTTPException(400, "Unknown side.")
    b.setdefault("reveals", {})[body.side] = body.reveal
    if len(b["reveals"]) < 2:
        return {"waiting": True}
    try:
        named = conflict.named_verdict(b["verdict"], b["reveals"], r["keys"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    (STATE / f"bundle-{b['check_id']}.json").write_text(json.dumps(b))
    (STATE / "latest-check.json").write_text(json.dumps({"check_id": b["check_id"], "named": named}))
    rooms.pop(ref, None)
    return {"named": named, "check_id": b["check_id"]}


@app.get("/api/check/{check_id}/bundle")
def get_bundle(check_id: int):
    p = STATE / f"bundle-{check_id}.json"
    if not p.exists():
        raise HTTPException(404, "We don't hold that bundle.")
    return FileResponse(p, media_type="application/json", filename=f"sealroom-check-{check_id}.json")


@app.get("/api/check/{check_id}/verify")
def verify_check(check_id: int):
    rec = chain.view("get_check", {"id": check_id})
    if not rec:
        raise HTTPException(404, f"No check #{check_id} on {chain.CONTRACT}.")
    steps = [{"ok": True, "text": f"NEAR accepted this record only after verifying both firms' signatures and {rec['calls']} TEE signature(s)"}]
    p = STATE / f"bundle-{check_id}.json"
    if p.exists():
        b = json.loads(p.read_text())
        keys = chain.firm_keys(rec["incoming"]["firm"], rec["existing"]["firm"])
        try:
            steps += bundle.verify(b, onchain=rec, firm_keys=keys).steps
        except Exception as e:  # noqa: BLE001
            steps.append({"ok": False, "text": f"Replay failed: {e}"})
    else:
        steps.append({"ok": False, "text": "We don't hold this check's proof bundle, so only the on-chain record is shown"})
    return {"record": rec, "steps": steps}


# ---------------------------------------------------------------- agent


class PrepareIn(BaseModel):
    member: str
    question: str
    use_verdict: bool = True
    walls: list[str] = []


@app.post("/api/agent/prepare")
def agent_prepare(body: PrepareIn):
    """Build the session the member is asked to sign: who, which agent, which question, which rules."""
    m = chain.view("get_member", {"account_id": body.member})
    if not m or not m["active"]:
        raise HTTPException(400, f"{body.member} is not an active member on {chain.CONTRACT}.")
    labels = json.loads((DEMO / "labels.json").read_text())
    policy = Policy()
    latest = STATE / "latest-check.json"
    if body.use_verdict and latest.exists():
        policy = policy_from_verdict(json.loads(latest.read_text())["named"], body.member,
                                     lambda n: labels.get(n, "client:" + n.lower().split()[0]))
    for w in body.walls:
        a, b = w.split("|")
        policy.wall(a.strip(), b.strip())
    session = Session(body.member, policy)
    q, p = sha256_hex(body.question), policy_hash(policy)
    pending[session.id] = {"session": session, "question": body.question, "member": m, "account": body.member, "q": q, "p": p}
    return {"session_id": session.id, "agent": AGENT, "policy": policy.to_json(), "policy_hash": p, "question_hash": q,
            "message": session_message(chain.CONTRACT, AGENT, session.id, q, p)}


class RunIn(BaseModel):
    session_id: str
    authorization: str
    seal: bool = True


@app.post("/api/agent/run")
def agent_run(body: RunIn):
    ps = pending.pop(body.session_id, None)
    if not ps:
        raise HTTPException(404, "Prepare the session first.")
    session: Session = ps["session"]
    msg = session_message(chain.CONTRACT, AGENT, session.id, ps["q"], ps["p"])
    if not verify(ps["member"]["key"], msg, body.authorization):
        raise HTTPException(403, f"That signature is not from {ps['account']}'s registered key. The agent will not start.")
    agent = chain.view("get_agent", {"account_id": AGENT})
    if not agent or not agent["active"] or agent["firm"] != ps["member"]["firm"]:
        raise HTTPException(403, "The agent is not active for this member's firm.")
    if agent["prompt_hash"] != PROMPT_HASH:
        raise HTTPException(409, "The agent's registered prompt differs from the running code; refusing to run.")
    q: queue.Queue = queue.Queue()

    def work():
        try:
            m = attested()
            if m.model != agent["model"]:
                raise RuntimeError(f"The agent is registered to run {agent['model']}, not {m.model}.")
            q.put({"type": "start", "session_id": session.id, "policy": session.policy.to_json(), "model": m.model,
                   "member": ps["account"], "member_name": ps["member"]["name"], "agent": AGENT})
            r = run(ps["question"], session, load_library(DEMO / "library.json"), m,
                    on_step=lambda t: q.put({"type": "step", "turn": asdict(t)}))
            export = {"run": r.to_json(), "agent": AGENT, "member": ps["account"], "policy": session.policy.to_json(),
                      "policy_hash": ps["p"], "question_hash": ps["q"], "authorization": body.authorization,
                      "log": [asdict(d) for d in session.log], "log_root": session.head}
            if body.seal and session.log:
                res = chain.call(AGENT, "seal_session", {
                    "session_id": session.id, "member": ps["account"], "log_root": session.head, "decisions": len(session.log),
                    "blocked": session.blocked, "policy_hash": ps["p"], "question_hash": ps["q"], "model": m.model,
                    "prompt_hash": PROMPT_HASH, "authorization": body.authorization})
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
    m = chain.view("get_member", {"account_id": rec["member"]}) or {}
    steps = [{"ok": True, "text": f"Sealed by agent {rec['agent']} from its own account; NEAR checked {m.get('name', rec['member'])}'s signature and the agent's registered model and prompt"}]
    local = STATE / f"session-{session_id}.json"
    if local.exists():
        exp = json.loads(local.read_text())
        try:
            root = verify_log(exp["log"])
            steps.append({"ok": True, "text": f"Each of the {len(exp['log'])} decisions chains to the next"})
            ok = root == rec["log_root"]
            steps.append({"ok": ok, "text": "The log root matches the one sealed on NEAR" if ok else "The log root does NOT match NEAR"})
            same_q = sha256_hex(exp["run"]["question"]) == rec["question_hash"]
            steps.append({"ok": same_q, "text": "The question in the log is the one the member signed" if same_q else "The question differs from what the member signed"})
        except ValueError as e:
            steps.append({"ok": False, "text": str(e)})
    else:
        steps.append({"ok": False, "text": "We don't hold this session's log locally, so only the on-chain seal is shown"})
    return {"record": rec, "member": m, "steps": steps}


@app.get("/demo/{name}")
def demo_file(name: str):
    if name not in {"partner_incoming.csv", "firm_existing.csv"}:
        raise HTTPException(404)
    return FileResponse(DEMO / name)


app.mount("/", StaticFiles(directory=WEB, html=True), name="web")


def main() -> None:
    import uvicorn

    uvicorn.run("sealroom.server:app", host="127.0.0.1", port=int(os.environ.get("PORT", 4410)))
