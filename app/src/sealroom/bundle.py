"""Proof bundles: everything needed to re-derive a verdict from signed evidence.

A bundle is safe to give to both firms and to a regulator. It holds ciphertexts
(only the TEE could read them), the messages the orchestrator itself wrote
(disclosed with their encryption randomness), the TEE's raw responses and the
key they were encrypted to, the signed exact-match transcript, and the raw
attestation report.

verify() replays it:
  1. the attestation report: Intel-signed quotes binding the model and gateway keys
  2. both envelopes: hashes, and signatures by each firm's registered key
  3. the exact-match tier, recomputed from the signed PSI transcript
  4. every model call: the request rebuilt byte for byte, the TEE signature
     over sha256(request) and sha256(response), the response decrypted and
     re-validated against the chunks that call was shown
  5. the verdict re-derived from 3 and 4, and its hash
  6. optionally, the on-chain record: same envelopes, same verdict hash, same calls
"""

from __future__ import annotations

import base64
import hashlib
import json

from . import conflict
from .e2ee import ClientKey, encrypt_to
from .identity import sha256_hex, verify as verify_sig
from .nearai import expected_signed_text, request_body

VERSION = "sealroom-bundle/1"


def build(contract: str, r: conflict.CheckResult, incoming: dict, existing: dict, transcript: dict, keys: dict[str, str]) -> dict:
    m = r.model
    return {
        "version": VERSION,
        "contract": contract,
        "check_ref": incoming["check_ref"],
        "engine": {
            "name": conflict.ENGINE,
            "model": m.model,
            "model_key": m.signing_key,
            "gateway_key": m.gateway_key,
            "report_hash": m.report_sha256,
            "report_nonce": m.nonce,
            "report_b64": base64.b64encode(m.report_raw).decode(),
            "instructions": conflict.INSTRUCTIONS,
            "instructions_hash": conflict.INSTRUCTIONS_HASH,
            "max_tokens": conflict.MAX_TOKENS,
        },
        "firm_keys": keys,
        "envelopes": {"incoming": incoming, "existing": existing},
        "exact_transcript": transcript,
        "reader_seed": r.reader_seed,
        "calls": [
            {
                "incoming_chunk": c.incoming_chunk,
                "existing_chunk": c.existing_chunk,
                "messages": c.messages,
                "chat_id": c.completion.chat_id,
                "response_b64": base64.b64encode(c.completion.raw).decode(),
                "signed_text": c.completion.signed_text,
                "signature": c.completion.signature,
                "signing_address": c.completion.signing_address,
                "signature_kind": c.completion.signature_kind,
            }
            for c in r.calls
        ],
        "verdict": r.verdict,
        "verdict_hash": r.verdict_hash,
    }


def onchain_args(b: dict) -> dict:
    """The record_check arguments this bundle implies."""
    def env(e):
        return {k: e[k] for k in ("firm", "commitment", "ciphertext_hash", "psi_hash", "signature")}

    e = b["engine"]
    return {
        "check_ref": b["check_ref"],
        "incoming": env(b["envelopes"]["incoming"]),
        "existing": env(b["envelopes"]["existing"]),
        "verdict_hash": b["verdict_hash"],
        "conflicts_found": len(b["verdict"]["pairs"]),
        "exact_matches": b["verdict"]["exact_matches"],
        "truncated": b["verdict"]["truncated"],
        "engine": {k: e[k] for k in ("model", "model_key", "gateway_key", "report_hash", "instructions_hash")},
        "calls": [{"signed_text": c["signed_text"], "signature": c["signature"], "signer": c["signing_address"]} for c in b["calls"]],
    }


def calls_root(b: dict) -> str:
    return hashlib.sha256(b"".join(c["signed_text"].encode() + b"\n" for c in b["calls"])).hexdigest()


class Report:
    def __init__(self):
        self.steps: list[dict] = []

    def ok(self, text: str) -> None:
        self.steps.append({"ok": True, "text": text})

    def bad(self, text: str) -> None:
        self.steps.append({"ok": False, "text": text})

    @property
    def passed(self) -> bool:
        return all(s["ok"] for s in self.steps)


def verify(b: dict, *, onchain: dict | None = None, firm_keys: dict[str, str] | None = None, check_attestation: bool = True) -> Report:
    """Replay a bundle. firm_keys: keys read from the contract (preferred over the bundle's copy)."""
    rep = Report()
    if b.get("version") != VERSION:
        rep.bad(f"unknown bundle version {b.get('version')}")
        return rep
    e = b["engine"]
    keys = firm_keys or b["firm_keys"]
    inc, ext = b["envelopes"]["incoming"], b["envelopes"]["existing"]

    # 1. attestation
    raw_report = base64.b64decode(e["report_b64"])
    if hashlib.sha256(raw_report).hexdigest() != e["report_hash"]:
        rep.bad("The attestation report does not match its hash")
    elif check_attestation:
        from .attest import AttestationError, check_report

        try:
            m = check_report(e["model"], raw_report, e["report_nonce"])
            same = m.signing_key.lower() == e["model_key"].lower() and m.gateway_key.lower() == e["gateway_key"].lower()
            (rep.ok if same else rep.bad)(
                "Intel signed the TDX quotes, and they bind the model and gateway keys used here" if same
                else "The attested keys differ from the keys this check used")
        except AttestationError as err:
            rep.bad(f"Attestation report did not verify: {err}")
    else:
        rep.ok("The attestation report matches its hash (quote not re-verified)")
    if sha256_hex(e["instructions"]) != e["instructions_hash"]:
        rep.bad("The instructions do not match their hash")

    # 2. envelopes
    try:
        for env in (inc, ext):
            conflict.check_envelope(env, keys[env["firm"]], b["contract"])
            if env["check_ref"] != b["check_ref"] or env["model_key"] != e["model_key"]:
                raise ValueError(f"{env['firm']}'s envelope is for another check or model key")
        if inc["counterparty"] != ext["firm"] or ext["counterparty"] != inc["firm"]:
            raise ValueError("the envelopes do not name each other as counterparty")
        rep.ok(f"Both firms signed their sealed lists with their registered keys ({inc['firm']}, {ext['firm']})")
    except (ValueError, KeyError) as err:
        rep.bad(str(err))
        return rep

    # 3. exact tier
    try:
        exact = conflict.exact_pairs(b["exact_transcript"], inc, ext, keys, b["check_ref"])
        rep.ok(f"The exact-match transcript is signed by both firms and yields {len(exact)} exact match(es)")
    except (ValueError, KeyError) as err:
        rep.bad(f"Exact-match transcript: {err}")
        return rep

    # 4. every call
    reader = ClientKey.from_seed(b["reader_seed"])
    allowed = {e["model_key"].lower(), e["gateway_key"].lower()}
    got_pairs, bad_calls = [], []
    for n, c in enumerate(b["calls"]):
        try:
            msgs = []
            for m in c["messages"]:
                ref = m["ref"]
                if ref == "instructions":
                    if m.get("plaintext", e["instructions"]) != e["instructions"]:
                        raise ValueError("instructions differ from the hashed instructions")
                    ct = encrypt_to(e["model_key"], e["instructions"], eph_secret=m["eph_secret"], nonce=m["nonce"])
                elif ref.startswith("incoming:"):
                    ct = inc["ciphertexts"][int(ref.split(":")[1])]
                elif ref.startswith("existing:"):
                    ct = ext["ciphertexts"][int(ref.split(":")[1])]
                elif ref == "disclosed":
                    ct = encrypt_to(e["model_key"], m["plaintext"], eph_secret=m["eph_secret"], nonce=m["nonce"])
                else:
                    raise ValueError(f"unknown message ref {ref}")
                msgs.append({"role": m["role"], "content": ct})
            req_h = hashlib.sha256(request_body(e["model"], msgs, e["max_tokens"])).hexdigest()
            raw = base64.b64decode(c["response_b64"])
            resp_h = hashlib.sha256(raw).hexdigest()
            if c["signed_text"] != expected_signed_text(c["signature_kind"], c["signed_text"], e["model"], req_h, resp_h):
                raise ValueError("the TEE signed different request/response bytes")
            if c["signing_address"].lower().removeprefix("0x") not in allowed:
                raise ValueError("signed by a key that is not the attested model or gateway")
            if not verify_sig(c["signing_address"], c["signed_text"], c["signature"].removeprefix("0x")):
                raise ValueError("TEE signature is invalid")
            msg = json.loads(raw)["choices"][0]["message"]
            content = reader.decrypt(msg["content"]) if msg.get("content") else ""
            ci, ce = inc["chunk"], ext["chunk"]
            a, bb = c["incoming_chunk"], c["existing_chunk"]
            got_pairs.append(conflict.parse_pairs(content, range(a * ci, min((a + 1) * ci, inc["count"])),
                                                  range(bb * ce, min((bb + 1) * ce, ext["count"]))))
        except Exception as err:  # noqa: BLE001
            bad_calls.append(f"call {n}: {err}")
    if bad_calls:
        for x in bad_calls:
            rep.bad(x)
        return rep
    rep.ok(f"All {len(b['calls'])} enclave calls rebuilt byte for byte; every TEE signature checks out")

    # 5. verdict
    pairs = conflict.merge(got_pairs, exact)
    chunks_in, chunks_ex = len(inc["ciphertexts"]), len(ext["ciphertexts"])
    covered = {(c["incoming_chunk"], c["existing_chunk"]) for c in b["calls"]}
    full = len(covered) == chunks_in * chunks_ex
    # Re-derive truncation from the call sequence rather than trusting the claim.
    saturated = False
    by_pair: dict[tuple[int, int], list[list[dict]]] = {}
    for c, got in zip(b["calls"], got_pairs):
        by_pair.setdefault((c["incoming_chunk"], c["existing_chunk"]), []).append(got)
    for seq in by_pair.values():
        seen: set = set()
        for got in seq[:-1]:
            seen |= {(p["i"], p["j"]) for p in got}
        last = seq[-1]
        new = {(p["i"], p["j"]) for p in last} - seen
        if len(last) >= conflict.PER_CALL_CAP and new:
            saturated = True
    truncated = saturated or not full
    verdict = conflict.build_verdict(b["check_ref"], inc, ext, pairs, exact, truncated, len(b["calls"]))
    h = conflict.sha256_hex(conflict.canonical(verdict))
    if h == b["verdict_hash"] and verdict == b["verdict"]:
        rep.ok(f"The verdict re-derives exactly from the signed responses ({len(pairs)} pair(s))")
    else:
        rep.bad("The verdict does NOT follow from the signed responses")
    (rep.ok if full else rep.bad)(
        f"Every chunk pair was checked ({chunks_in}×{chunks_ex})" if full else f"Only {len(covered)} of {chunks_in * chunks_ex} chunk pairs were checked")
    if saturated:
        rep.bad("Some replies stayed full after continuing; there may be more pairs than reported")

    # 6. chain
    if onchain is not None:
        want = onchain_args(b)
        same = (
            onchain["verdict_hash"] == want["verdict_hash"]
            and onchain["check_ref"] == want["check_ref"]
            and all(onchain[s][k] == want[s][k] for s in ("incoming", "existing") for k in ("firm", "commitment", "ciphertext_hash", "psi_hash"))
            and onchain["calls"] == len(want["calls"])
            and onchain["calls_root"] == calls_root(b)
            and onchain["engine"]["instructions_hash"] == want["engine"]["instructions_hash"]
        )
        (rep.ok if same else rep.bad)(
            "The record on NEAR matches this bundle: same lists, same calls, same verdict hash" if same
            else "The record on NEAR does NOT match this bundle")
    return rep
