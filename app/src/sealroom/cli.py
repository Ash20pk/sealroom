"""sealroom CLI.

  sealroom attest                          verify the model TEE, print what was checked
  sealroom setup                           deploy the contract and register firms, members, agent (testnet)
  sealroom whoami ACCOUNT                  show a firm, member or agent as registered on NEAR
  sealroom check IN.csv EX.csv --incoming-firm F --existing-firm F [--record]
                                           run a full check on one machine, playing both firms
  sealroom verify CHECK_ID [--bundle B]    anyone: re-check an on-chain record and replay its proof bundle
  sealroom verify-bundle B                 replay a proof bundle (and compare with NEAR if it names a check)
  sealroom prove CHECK_ID LIST.csv SECRET.json   a firm proves which list it submitted
  sealroom agent --member M --question Q   run the research agent; the member signs, the agent seals
  sealroom verify-session SESSION.json     re-check a session log against NEAR
  sealroom eval CASE_DIR                   measure precision and recall on a labelled case
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from dataclasses import asdict
from pathlib import Path

from . import bundle, chain, conflict
from .attest import verify_model
from .identity import Identity

DEFAULT_MODEL = os.environ.get("SEALROOM_MODEL", "z-ai/glm-5.3-flash")
ROOT = Path(__file__).resolve().parents[3]
STATE = Path(os.environ.get("SEALROOM_STATE", ROOT / ".state"))
IDENTITY = STATE / "identity"
FIRM_IN = os.environ.get("SEALROOM_FIRM_INCOMING", "sr-firm-north-64716.testnet")
FIRM_EX = os.environ.get("SEALROOM_FIRM_EXISTING", "sr-firm-south-64716.testnet")
AGENT = os.environ.get("SEALROOM_AGENT", f"research.{FIRM_EX}")


def _p(msg: str) -> None:
    print(msg, file=sys.stderr)


def identity(account: str) -> Identity:
    p = IDENTITY / f"{account}.json"
    if not p.exists():
        sys.exit(f"no local key for {account} in {IDENTITY} (run `sealroom setup`, or use your own identity file)")
    return Identity.load(p)


def cmd_attest(a) -> None:
    m = verify_model(a.model)
    _p(f"✓ Intel TDX quote verified for gateway and {m.model} (TCB {m.tcb_status})")
    _p("✓ quote binds the model's encryption/signing key and our fresh nonce; debug mode off")
    print(json.dumps(m.to_json(), indent=2))


def cmd_setup(a) -> None:
    from . import setup

    ex = FIRM_EX
    setup.run(IDENTITY, operator=chain.OPERATOR, contract=chain.CONTRACT, wasm=ROOT / "contract/target/near/sealroom.wasm",
              firms={FIRM_IN: a.incoming_name, ex: a.existing_name},
              members=[{"account": f"jane.{ex}", "firm": ex, "name": "Jane Okafor"},
                       {"account": f"marcus.{ex}", "firm": ex, "name": "Marcus Reid"}],
              agent={"account": AGENT, "firm": ex, "owner": f"marcus.{ex}", "name": "Southwell research agent", "model": a.model},
              log=_p)


def cmd_whoami(a) -> None:
    for kind in ("firm", "member", "agent"):
        got = chain.view(f"get_{kind}", {"account_id": a.account})
        if got:
            print(json.dumps({"account": a.account, "kind": kind, **got}, indent=2))
            return
    sys.exit(f"{a.account} is not registered on {chain.CONTRACT}")


def cmd_check(a) -> None:
    from .flow import local_check

    inc, ext = identity(a.incoming_firm), identity(a.existing_firm)
    keys = chain.firm_keys(inc.account, ext.account)
    for who in (inc, ext):
        if keys[who.account] != who.public:
            sys.exit(f"local key for {who.account} is not the key registered on NEAR")
    m = verify_model(a.model)
    _p(f"✓ attested {m.model}; model key {m.signing_key[:12]}…")
    r = local_check(conflict.load_parties(Path(a.incoming)), conflict.load_parties(Path(a.existing)), inc, ext, m,
                    keys=keys, record=a.record, log=lambda s: _p("  " + s))
    out = Path(a.out or STATE / f"bundle-{r.get('check_id', 'local')}.json")
    out.write_text(json.dumps(r["bundle"], indent=2))
    for side, sec in r["secrets"].items():
        (out.parent / f"{out.stem}.{side}.secret.json").write_text(json.dumps(sec, indent=2))
    _p(f"→ proof bundle {out}")
    for n in r["named"]:
        print(f"{n['severity']:6} {n['relationship']:17} {n['confidence']:.2f} {n['source']:7} {n['incoming']['name']}  <->  {n['existing']['name']}")
    if not r["named"]:
        print("no conflicts")


def _print_report(rep) -> None:
    for s in rep.steps:
        _p(("✓ " if s["ok"] else "✗ ") + s["text"])


def cmd_verify(a) -> None:
    rec = chain.view("get_check", {"id": int(a.check_id)})
    if not rec:
        sys.exit(f"no check #{a.check_id} on {chain.CONTRACT}")
    _p(f"✓ check #{a.check_id} on {chain.CONTRACT}: both firm signatures and {rec['calls']} TEE signature(s) were verified by the contract when it was recorded")
    if a.bundle:
        b = json.loads(Path(a.bundle).read_text())
        keys = chain.firm_keys(rec["incoming"]["firm"], rec["existing"]["firm"])
        rep = bundle.verify(b, onchain=rec, firm_keys=keys)
        _print_report(rep)
        print(json.dumps(rec, indent=2))
        sys.exit(0 if rep.passed else 1)
    print(json.dumps(rec, indent=2))


def cmd_verify_bundle(a) -> None:
    b = json.loads(Path(a.bundle).read_text())
    rec, keys = None, None
    if b.get("check_id") is not None and b.get("contract") == chain.CONTRACT:
        rec = chain.view("get_check", {"id": b["check_id"]})
        e = b["envelopes"]
        keys = chain.firm_keys(e["incoming"]["firm"], e["existing"]["firm"])
    rep = bundle.verify(b, onchain=rec, firm_keys=keys, check_attestation=not a.offline)
    _print_report(rep)
    sys.exit(0 if rep.passed else 1)


def cmd_prove(a) -> None:
    rec = chain.view("get_check", {"id": int(a.check_id)})
    secret = json.loads(Path(a.secret).read_text())
    c = conflict.commitment(secret["salt"], conflict.load_parties(Path(a.list)))
    hit = c in (rec["incoming"]["commitment"], rec["existing"]["commitment"])
    _p(("✓ this list is exactly what " if hit else "✗ this list is NOT what ") + f"{secret['firm']} submitted in check #{a.check_id}")
    sys.exit(0 if hit else 1)


def cmd_agent(a) -> None:
    from .agent import PROMPT_HASH, load_library, run
    from .identity import session_message, sha256_hex, verify
    from .room import Policy, Session, policy_from_verdict, policy_hash

    member = identity(a.member)
    reg = chain.view("get_member", {"account_id": member.account})
    agent = chain.view("get_agent", {"account_id": a.agent})
    if not reg or not reg["active"] or reg["key"] != member.public:
        sys.exit(f"{member.account} is not an active member with this key")
    if not agent or not agent["active"] or agent["firm"] != reg["firm"]:
        sys.exit(f"{a.agent} is not an active agent of {reg['firm']}")
    if agent["prompt_hash"] != PROMPT_HASH:
        sys.exit("this agent's registered prompt differs from the code's prompt; refusing to run")

    labels = json.loads(Path(a.labels).read_text()) if a.labels else {}
    policy = Policy()
    if a.bundle:
        b = json.loads(Path(a.bundle).read_text())
        keys = chain.firm_keys(b["verdict"]["incoming"]["firm"], b["verdict"]["existing"]["firm"])
        named = conflict.named_verdict(b["verdict"], b["reveals"], keys)
        policy = policy_from_verdict(named, member.account, lambda n: labels.get(n, "client:" + n.lower().split()[0]))
        _p(f"screens for {member.account}: {sorted(policy.screens.get(member.account, []))}")
    for w in a.wall or []:
        x, y = w.split("|")
        policy.wall(x.strip(), y.strip())

    session = Session(member.account, policy)
    q_hash, p_hash = sha256_hex(a.question), policy_hash(policy)
    auth = member.sign(session_message(chain.CONTRACT, a.agent, session.id, q_hash, p_hash))
    assert verify(reg["key"], session_message(chain.CONTRACT, a.agent, session.id, q_hash, p_hash), auth)
    _p(f"✓ {reg['name']} ({member.account}) signed session {session.id} for agent {a.agent}")
    m = verify_model(agent["model"])
    _p(f"✓ attested {m.model}, the model {a.agent} is registered to run")

    def step(t):
        act = t.action
        if act.get("action") == "read":
            d = t.decision
            _p(f"  read {str(act.get('id')):8} -> {'ALLOW' if d['allowed'] else 'BLOCK'}   [reviewer: {d['reason']}]   tee-signed {t.chat_id[:14]}…")
        else:
            _p("  answer")

    r = run(a.question, session, load_library(Path(a.library)), m, on_step=step)
    print(r.answer)
    export = {"run": r.to_json(), "agent": a.agent, "member": member.account, "policy": policy.to_json(), "policy_hash": p_hash,
              "question_hash": q_hash, "authorization": auth, "log": [asdict(d) for d in session.log], "log_root": session.head}
    if a.seal and session.log:
        res = chain.call(a.agent, "seal_session", {
            "session_id": session.id, "member": member.account, "log_root": session.head, "decisions": len(session.log),
            "blocked": session.blocked, "policy_hash": p_hash, "question_hash": q_hash, "model": m.model,
            "prompt_hash": PROMPT_HASH, "authorization": auth})
        export["chain"] = {"contract": chain.CONTRACT, "tx": res["tx"], "url": chain.tx_url(res["tx"])}
        _p(f"✓ {a.agent} sealed the session on NEAR with its scoped key: {chain.tx_url(res['tx'])}")
    out = Path(a.out or STATE / f"session-{session.id}.json")
    out.write_text(json.dumps(export, indent=2))
    _p(f"→ {out}")


def cmd_verify_session(a) -> None:
    from .identity import session_message, sha256_hex, verify
    from .room import verify_log

    exp = json.loads(Path(a.export).read_text())
    root = verify_log(exp["log"])
    rec = chain.view("get_session", {"session_id": exp["run"]["session_id"]})
    if not rec:
        sys.exit("session not sealed on chain")
    ok = rec["log_root"] == root and rec["decisions"] == len(exp["log"])
    _p(("✓ decision log matches the root sealed on NEAR" if ok else "✗ decision log does NOT match the sealed root") + f" ({len(exp['log'])} decisions, {rec['blocked']} blocked)")
    m = chain.view("get_member", {"account_id": rec["member"]})
    signed = verify(m["key"], session_message(chain.CONTRACT, rec["agent"], rec["session_id"], rec["question_hash"], rec["policy_hash"]), exp["authorization"])
    same_q = sha256_hex(exp["run"]["question"]) == rec["question_hash"]
    _p(("✓" if signed else "✗") + f" {m['name']} ({rec['member']}) signed this session; sealed by agent {rec['agent']}")
    _p(("✓" if same_q else "✗") + " the question in the log is the one the member signed")
    sys.exit(0 if ok and signed and same_q else 1)


def cmd_eval(a) -> None:
    from .eval import evaluate

    res = evaluate(Path(a.case), a.model, runs=a.runs, log=_p)
    print(json.dumps(res, indent=2))
    if a.out:
        Path(a.out).write_text(json.dumps(res, indent=2))


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="sealroom")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("attest").set_defaults(fn=cmd_attest)
    s = sub.add_parser("setup")
    s.add_argument("--incoming-name", default="Northgate & Pryce LLP")
    s.add_argument("--existing-name", default="Southwell Carrow LLP")
    s.set_defaults(fn=cmd_setup)
    w = sub.add_parser("whoami")
    w.add_argument("account")
    w.set_defaults(fn=cmd_whoami)
    c = sub.add_parser("check")
    c.add_argument("incoming")
    c.add_argument("existing")
    c.add_argument("--incoming-firm", default=FIRM_IN)
    c.add_argument("--existing-firm", default=FIRM_EX)
    c.add_argument("--record", action="store_true", help="record on NEAR (signed by the operator)")
    c.add_argument("--out")
    c.set_defaults(fn=cmd_check)
    v = sub.add_parser("verify")
    v.add_argument("check_id")
    v.add_argument("--bundle", help="proof bundle to replay against the record")
    v.set_defaults(fn=cmd_verify)
    vb = sub.add_parser("verify-bundle")
    vb.add_argument("bundle")
    vb.add_argument("--offline", action="store_true", help="skip re-verifying the Intel quote (no network)")
    vb.set_defaults(fn=cmd_verify_bundle)
    p = sub.add_parser("prove")
    p.add_argument("check_id")
    p.add_argument("list")
    p.add_argument("secret")
    p.set_defaults(fn=cmd_prove)
    g = sub.add_parser("agent", help="run the research agent inside the Sealroom")
    g.add_argument("--member", required=True, help="member account starting the session")
    g.add_argument("--agent", default=AGENT)
    g.add_argument("--question", required=True)
    g.add_argument("--library", default=str(ROOT / "demo/library.json"))
    g.add_argument("--labels", default=str(ROOT / "demo/labels.json"))
    g.add_argument("--bundle", help="proof bundle of a check; its conflicts become screens for the member")
    g.add_argument("--wall", action="append", help='"label-a | label-b"')
    g.add_argument("--no-seal", dest="seal", action="store_false")
    g.add_argument("--out")
    g.set_defaults(fn=cmd_agent)
    vs = sub.add_parser("verify-session")
    vs.add_argument("export")
    vs.set_defaults(fn=cmd_verify_session)
    e = sub.add_parser("eval")
    e.add_argument("case", help="directory with incoming.csv, existing.csv, truth.json")
    e.add_argument("--runs", type=int, default=1)
    e.add_argument("--out")
    e.set_defaults(fn=cmd_eval)
    a = ap.parse_args(argv)
    t = time.time()
    a.fn(a)
    _p(f"({time.time() - t:.1f}s)")


if __name__ == "__main__":
    main()
