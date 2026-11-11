"""sealroom CLI.

  sealroom attest                      check the model TEE, print what was verified
  sealroom seal  --firm F --side S LIST.csv   encrypt a list (run by each firm)
  sealroom check INCOMING.env.json EXISTING.env.json [--record-as ACCOUNT]
  sealroom verify CHECK_ID             anyone: re-check an on-chain record
  sealroom prove CHECK_ID LIST.csv SECRET.json   a firm proves which list it submitted
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

from nacl.signing import VerifyKey

from . import chain
from .attest import verify_model
from .conflict import check, commitment, load_parties, seal

DEFAULT_MODEL = os.environ.get("SEALROOM_MODEL", "z-ai/glm-5.3-flash")


def _p(msg: str) -> None:
    print(msg, file=sys.stderr)


def cmd_attest(a) -> None:
    m = verify_model(a.model)
    _p(f"✓ Intel TDX quote verified for gateway and {m.model} (TCB {m.tcb_status})")
    _p("✓ quote binds the model's encryption/signing key and our fresh nonce")
    print(json.dumps(m.to_json(), indent=2))


def cmd_seal(a) -> None:
    parties = load_parties(Path(a.list))
    m = verify_model(a.model)
    _p(f"✓ attested {m.model}; encrypting {len(parties)} entries to its TEE key {m.signing_key[:12]}…")
    s = seal(a.firm, a.side, parties, m)
    out = Path(a.out or f"{a.firm}.{a.side}")
    out.with_suffix(".envelope.json").write_text(json.dumps(s.envelope, indent=2))
    out.with_suffix(".secret.json").write_text(json.dumps(s.secret, indent=2))
    _p(f"→ {out.with_suffix('.envelope.json')}  (send this to the orchestrator)")
    _p(f"→ {out.with_suffix('.secret.json')}    (keep this; it proves what you submitted)")


def cmd_check(a) -> None:
    inc = json.loads(Path(a.incoming).read_text())
    ext = json.loads(Path(a.existing).read_text())
    m = verify_model(inc["model"])
    _p(f"✓ re-attested {m.model}; both envelopes target key {m.signing_key[:12]}…")
    _p("  sending sealed request (this process cannot read either list)…")
    r = check(inc, ext, m)
    c = r.completion
    _p(f"✓ TEE signature verified ({c.signature_kind or 'unknown'} kind) over request {c.request_sha256[:12]}… response {c.response_sha256[:12]}…")
    _p(f"  {len(r.verdict['conflicts'])} conflict(s) found")
    record = {"verdict": r.verdict, "verdict_hash": r.verdict_hash, "completion": c.to_json(), "attestation": m.to_json()}
    if a.record_as:
        res = chain.call(
            a.record_as,
            "record_check",
            {
                "counterparty": ext["firm"] if a.record_as == inc["firm"] else inc["firm"],
                "requester_commitment": inc["commitment"] if a.record_as == inc["firm"] else ext["commitment"],
                "counterparty_commitment": ext["commitment"] if a.record_as == inc["firm"] else inc["commitment"],
                "verdict_hash": r.verdict_hash,
                "conflicts_found": len(r.verdict["conflicts"]),
                "attestation": {
                    "model": m.model,
                    "chat_id": c.chat_id,
                    "signed_text": c.signed_text,
                    "signature": c.signature,
                    "signing_address": c.signing_address,
                    "report_hash": m.report_sha256,
                },
            },
        )
        record["chain"] = {"contract": chain.CONTRACT, "check_id": res["return"], "tx": res["tx"], "url": chain.tx_url(res["tx"])}
        _p(f"✓ anchored on NEAR as check #{res['return']}: {chain.tx_url(res['tx'])}")
    out = Path(a.out or "verdict.json")
    out.write_text(json.dumps(record, indent=2))
    _p(f"→ {out}")
    print(json.dumps(r.verdict, indent=2))


def cmd_verify(a) -> None:
    rec = chain.view("get_check", {"id": int(a.check_id)})
    if not rec:
        sys.exit(f"no check #{a.check_id} on {chain.CONTRACT}")
    att = rec["attestation"]
    ok = True
    try:
        VerifyKey(bytes.fromhex(att["signing_address"])).verify(
            att["signed_text"].encode(), bytes.fromhex(att["signature"].removeprefix("0x"))
        )
        _p("✓ TEE signature over the recorded request/response hashes is valid")
    except Exception:
        ok = False
        _p("✗ signature does not verify")
    live = verify_model(att["model"])
    if att["signing_address"].lower() in (live.signing_key.lower(), live.gateway_key.lower()):
        _p(f"✓ signer is the key a freshly attested {att['model']} TEE holds right now")
    else:
        _p("! signer differs from today's attested key (keys rotate on redeploy); compare with the report hash on record")
    if a.verdict:
        v = json.loads(Path(a.verdict).read_text())["verdict"]
        from .conflict import canonical

        h = hashlib.sha256(canonical(v)).hexdigest()
        same = h == rec["verdict_hash"]
        ok &= same
        _p(("✓" if same else "✗") + " verdict file matches the on-chain verdict hash")
    print(json.dumps(rec, indent=2))
    sys.exit(0 if ok else 1)


def cmd_prove(a) -> None:
    rec = chain.view("get_check", {"id": int(a.check_id)})
    secret = json.loads(Path(a.secret).read_text())
    c = commitment(secret["salt"], load_parties(Path(a.list)))
    hit = c in (rec["requester_commitment"], rec["counterparty_commitment"])
    _p(("✓ this list is exactly what " if hit else "✗ this list is NOT what ") + f"{secret['firm']} submitted in check #{a.check_id}")
    sys.exit(0 if hit else 1)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="sealroom")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("attest").set_defaults(fn=cmd_attest)
    s = sub.add_parser("seal")
    s.add_argument("--firm", required=True, help="the firm's NEAR account")
    s.add_argument("--side", required=True, choices=["incoming", "existing"])
    s.add_argument("--out")
    s.add_argument("list")
    s.set_defaults(fn=cmd_seal)
    c = sub.add_parser("check")
    c.add_argument("incoming")
    c.add_argument("existing")
    c.add_argument("--record-as", help="NEAR account that signs the on-chain record")
    c.add_argument("--out")
    c.set_defaults(fn=cmd_check)
    v = sub.add_parser("verify")
    v.add_argument("check_id")
    v.add_argument("--verdict", help="verdict.json to compare with the on-chain hash")
    v.set_defaults(fn=cmd_verify)
    p = sub.add_parser("prove")
    p.add_argument("check_id")
    p.add_argument("list")
    p.add_argument("secret")
    p.set_defaults(fn=cmd_prove)
    a = ap.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
