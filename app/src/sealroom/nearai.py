"""Encrypted, signed chat completions against NEAR AI Cloud.

The orchestrator never sees plaintext party data: every message arrives already
encrypted to the attested model key. It only holds the key the response is
encrypted to, and it keeps the exact request and response bytes so the TEE's
signature over them can be checked and anchored on NEAR.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass

import httpx
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .attest import BASE, VerifiedModel
from .e2ee import ClientKey


class SignatureError(Exception):
    pass


@dataclass
class SignedCompletion:
    chat_id: str
    content: str  # decrypted assistant content
    request_sha256: str
    response_sha256: str
    signed_text: str
    signature: str
    signing_address: str
    signature_kind: str
    body: bytes = b""  # exact request bytes sent
    raw: bytes = b""  # exact response bytes received

    def to_json(self) -> dict:
        d = asdict(self)
        d.pop("body"), d.pop("raw")
        return d


def api_key() -> str:
    key = os.environ.get("NEARAI_API_KEY", "")
    if not key.startswith("sk-"):
        raise RuntimeError("set NEARAI_API_KEY (an sk-... key from cloud.near.ai)")
    return key


def request_body(model: str, encrypted_messages: list[dict], max_tokens: int) -> bytes:
    """The exact bytes sent. Rebuilt byte for byte by the proof-bundle verifier."""
    return json.dumps(
        {
            "model": model,
            "messages": encrypted_messages,
            "stream": False,
            "temperature": 0,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        },
        separators=(",", ":"),
    ).encode()


def complete(
    model: VerifiedModel,
    encrypted_messages: list[dict],
    reader: ClientKey,
    *,
    max_tokens: int = 2000,
    timeout: float = 180,
) -> SignedCompletion:
    """Send pre-encrypted messages; decrypt the reply; fetch and check the TEE signature."""
    body = request_body(model.model, encrypted_messages, max_tokens)
    headers = {
        "Authorization": f"Bearer {api_key()}",
        "Content-Type": "application/json",
        "Accept-Encoding": "identity",
        "X-Signing-Algo": "ed25519",
        "X-Client-Pub-Key": reader.public_hex,
        "X-Model-Pub-Key": model.signing_key,
        "X-Encryption-Version": "2",
        "x-no-aliasing": "true",
    }
    r = httpx.post(f"{BASE}/chat/completions", content=body, headers=headers, timeout=timeout)
    if r.status_code >= 400:
        raise RuntimeError(f"NEAR AI {r.status_code}: {r.text[:500]}")
    raw = r.content
    resp = json.loads(raw)
    msg = resp["choices"][0]["message"]
    content = reader.decrypt(msg["content"]) if msg.get("content") else ""

    req_h = hashlib.sha256(body).hexdigest()
    resp_h = hashlib.sha256(raw).hexdigest()
    sig = _fetch_signature(resp["id"])
    _check_signature(sig, model, req_h, resp_h)
    return SignedCompletion(
        chat_id=resp["id"],
        content=content,
        request_sha256=req_h,
        response_sha256=resp_h,
        signed_text=sig["text"],
        signature=sig["signature"],
        signing_address=sig["signing_address"],
        signature_kind=sig.get("signature_kind", ""),
        body=body,
        raw=raw,
    )


def _fetch_signature(chat_id: str, attempts: int = 10) -> dict:
    for i in range(attempts):
        r = httpx.get(
            f"{BASE}/signature/{chat_id}",
            params={"signing_algo": "ed25519"},
            headers={"Authorization": f"Bearer {api_key()}"},
            timeout=30,
        )
        if r.status_code == 200 and "signature" in r.json():
            return r.json()
        time.sleep(min(1.5 * (i + 1), 5))
    raise SignatureError(f"no signature for {chat_id} (last status {r.status_code}: {r.text[:200]})")


def expected_signed_text(kind: str, signed_text: str, model: str, req_h: str, resp_h: str) -> str:
    if kind == "provider_tee" or signed_text.count(":") >= 2:
        return f"{model}:{req_h}:{resp_h}"
    return f"{req_h}:{resp_h}"


def _check_signature(sig: dict, model: VerifiedModel, req_h: str, resp_h: str) -> None:
    kind = sig.get("signature_kind", "")
    if kind == "provider_tee" or sig["text"].count(":") >= 2:
        expected = f"{model.model}:{req_h}:{resp_h}"
        if sig["signing_address"].lower() != model.signing_key.lower():
            raise SignatureError("signature is not from the attested model key")
    else:
        expected = f"{req_h}:{resp_h}"
        if sig["signing_address"].lower() != model.gateway_key.lower():
            raise SignatureError("gateway signature is not from the attested gateway key")
    if sig["text"] != expected:
        raise SignatureError(f"signed text does not match our bytes:\n  got  {sig['text']}\n  want {expected}")
    try:
        VerifyKey(bytes.fromhex(sig["signing_address"])).verify(
            sig["text"].encode(), bytes.fromhex(sig["signature"].removeprefix("0x"))
        )
    except BadSignatureError as e:
        raise SignatureError("ed25519 signature is invalid") from e
