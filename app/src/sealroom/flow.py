"""A whole conflict check on one machine, playing both firms (CLI and eval).

The web app runs the same steps with each firm's work done in the browser and
only signed, sealed messages passing through the server.
"""

from __future__ import annotations

import os

from . import bundle, chain, conflict
from .attest import VerifiedModel
from .identity import Identity


def local_check(incoming: list[dict], existing: list[dict], inc_id: Identity, ext_id: Identity, model: VerifiedModel, *,
                contract: str | None = None, keys: dict[str, str] | None = None, record: bool = False, log=lambda *_: None) -> dict:
    contract = contract or chain.CONTRACT
    keys = keys or {inc_id.account: inc_id.public, ext_id.account: ext_id.public}
    check_ref = os.urandom(16).hex()
    chunk = conflict.plan_chunk(len(incoming), len(existing))

    si = conflict.seal(inc_id.account, "incoming", incoming, model, chunk)
    se = conflict.seal(ext_id.account, "existing", existing, model, chunk)
    conflict.sign_envelope(si.envelope, inc_id, contract, check_ref, ext_id.account)
    conflict.sign_envelope(se.envelope, ext_id, contract, check_ref, inc_id.account)
    for env in (si.envelope, se.envelope):
        conflict.check_envelope(env, keys[env["firm"]], contract)
    log(f"both lists sealed and signed (chunk {chunk}: {len(si.envelope['ciphertexts'])}×{len(se.envelope['ciphertexts'])} chunk pairs)")

    d_inc = conflict.psi_double(se, si.envelope, ext_id, check_ref)
    d_ext = conflict.psi_double(si, se.envelope, inc_id, check_ref)
    transcript = {
        "incoming_doubled": d_inc,
        "existing_doubled": d_ext,
        "incoming_index": conflict.psi_index(si, d_inc, inc_id, check_ref),
        "existing_index": conflict.psi_index(se, d_ext, ext_id, check_ref),
    }
    exact = conflict.exact_pairs(transcript, si.envelope, se.envelope, keys, check_ref)
    log(f"exact tier: {len(exact)} match(es) by private set intersection")

    r = conflict.run_check(si.envelope, se.envelope, model, exact)
    log(f"enclave tier: {r.verdict['calls']} signed call(s), {len(r.verdict['pairs'])} pair(s) in the verdict"
        + (" (TRUNCATED: some replies stayed full)" if r.verdict["truncated"] else ""))
    b = bundle.build(contract, r, si.envelope, se.envelope, transcript, keys)
    b["reveals"] = {
        "incoming": conflict.reveal(si, [p["i"] for p in r.verdict["pairs"]], inc_id, check_ref),
        "existing": conflict.reveal(se, [p["j"] for p in r.verdict["pairs"]], ext_id, check_ref),
    }
    named = conflict.named_verdict(r.verdict, b["reveals"], keys)
    out = {"bundle": b, "named": named, "secrets": {"incoming": si.secret, "existing": se.secret}}
    if record:
        res = chain.call(chain.OPERATOR, "record_check", bundle.onchain_args(b), gas="300 Tgas", contract=contract)
        out["check_id"] = int(res["return"]) if res["return"] else None
        out["tx"] = res["tx"]
        b["check_id"] = out["check_id"]
        log(f"recorded on NEAR as check #{out['check_id']}: {chain.tx_url(res['tx'])}")
    return out
