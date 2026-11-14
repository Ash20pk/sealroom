"""Fetch and check NEAR AI Cloud attestation before anything is encrypted.

What we check, per report (gateway and every model candidate):
  1. Intel's signature over the TDX quote (dcap-qvl, Intel PCS collateral).
  2. report_data[0:32] is the signing key, zero-padded: the key we encrypt to
     and later verify signatures with lives inside this TEE.
  3. report_data[32:64] is our fresh nonce, so the report is not a replay.
  4. TDX debug mode is off.
  5. RTMR0-3 replay from the event log to the values in the signed quote. The
     RTMR3 events are recomputed from their payloads, so the compose-hash and
     app-id events are bound to the quote; then compose-hash must equal
     sha256(app_compose) and both must match the report's info block. That ties
     the exact docker compose (image digests included) to the attested TEE.
  6. Model only: the NVIDIA GPU evidence goes to NVIDIA's attestation service
     (NRAS). We verify the returned ES384 tokens against NVIDIA's published
     keys, and require an overall pass, a pass per GPU, and our nonce in every
     token.

Not checked here: the GPU evidence carries our nonce but is not bound to the
TDX quote by a hash, so "these GPUs sit behind that CVM" rests on NEAR AI's
deployment. See the README.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
from dataclasses import asdict, dataclass, field

import dcap_qvl
import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

BASE = "https://cloud-api.near.ai/v1"
INTEL_PCS = "https://api.trustedservices.intel.com"
NRAS = "https://nras.attestation.nvidia.com"

# TDX quote v4: 48-byte header, then the TD report body. Offsets in the body.
_HDR = 48
_TD_ATTRIBUTES = _HDR + 120
_REPORT_DATA = _HDR + 520
_RTMR0 = _HDR + 328  # four 48-byte RTMRs follow mrtd/mrconfigid/mrowner/mrownerconfig


class AttestationError(Exception):
    pass


@dataclass
class VerifiedModel:
    model: str
    signing_key: str  # Ed25519 public key, hex; also the E2EE recipient key
    gateway_key: str  # Ed25519 key of the attested gateway (signs streamed / gateway-kind responses)
    nonce: str
    tcb_status: str
    report_sha256: str  # sha256 of the raw report JSON we verified
    report_raw: bytes = b""  # the report itself, so anyone can re-verify it later
    compose_hashes: list[str] = field(default_factory=list)  # each model instance's app_compose sha256, bound to its quote via RTMR3
    gpu_status: str = ""  # "verified" (NRAS passed for every GPU) or "skipped"

    def to_json(self) -> dict:
        d = asdict(self)
        d.pop("report_raw")
        return d


def _check_quote(quote_hex: str, signing_key_hex: str, nonce: str, pccs_url: str | None) -> str:
    quote = bytes.fromhex(quote_hex)
    rd = quote[_REPORT_DATA : _REPORT_DATA + 64]
    if rd[:32].hex() != signing_key_hex.lower().ljust(64, "0"):
        raise AttestationError("quote report_data does not bind the signing key")
    if rd[32:].hex() != nonce:
        raise AttestationError("quote report_data does not carry our nonce (stale or replayed report)")
    if quote[_TD_ATTRIBUTES] & 0x01:
        raise AttestationError("TDX debug mode is on")
    try:
        verified = asyncio.run(dcap_qvl.get_collateral_and_verify(quote, pccs_url))
    except Exception as e:  # noqa: BLE001 - surface the verifier's reason
        raise AttestationError(f"Intel quote verification failed: {e}") from e
    if verified.status not in ("UpToDate", "SWHardeningNeeded", "ConfigurationAndSWHardeningNeeded"):
        raise AttestationError(f"TCB status not acceptable: {verified.status}")
    return verified.status


def _rtmrs(quote: bytes) -> list[bytes]:
    return [quote[_RTMR0 + 48 * i : _RTMR0 + 48 * (i + 1)] for i in range(4)]


def _event_digest(e: dict) -> bytes:
    """dstack runtime events (RTMR3) are logged without a digest; it is
    sha384(event_type as u32 LE || ":" || name || ":" || payload)."""
    data = e["event_type"].to_bytes(4, "little") + b":" + e["event"].encode() + b":" + bytes.fromhex(e["event_payload"])
    return hashlib.sha384(data).digest()


def check_event_log(entry: dict) -> dict:
    """Replay the event log against the quote's RTMRs, and tie compose-hash and
    app-id (RTMR3) to the report's info block. Returns the RTMR3 events."""
    quote = bytes.fromhex(entry["intel_quote"])
    log = entry.get("event_log")
    if isinstance(log, str):
        log = json.loads(log)
    if not log:
        raise AttestationError("report has no event log")
    events: dict[str, str] = {}
    for imr, want in enumerate(_rtmrs(quote)):
        m = b"\0" * 48
        for e in log:
            if e["imr"] != imr:
                continue
            if imr == 3:
                d = _event_digest(e)
                if e.get("digest") and bytes.fromhex(e["digest"]) != d:
                    raise AttestationError(f"RTMR3 event {e['event']!r} digest does not match its payload")
                events[e["event"]] = e["event_payload"]
            else:
                d = bytes.fromhex(e["digest"])
            m = hashlib.sha384(m + d).digest()
        if m != want:
            raise AttestationError(f"event log does not replay to RTMR{imr} in the quote")

    info = entry.get("info") or {}
    tcb = info.get("tcb_info") or {}
    if isinstance(tcb, str):
        tcb = json.loads(tcb)
    compose = events.get("compose-hash")
    if not compose:
        raise AttestationError("RTMR3 has no compose-hash event")
    app_compose = tcb.get("app_compose")
    if app_compose is None or hashlib.sha256(app_compose.encode()).hexdigest() != compose:
        raise AttestationError("app_compose does not hash to the compose-hash in RTMR3")
    for key, ev in (("compose_hash", "compose-hash"), ("app_id", "app-id"), ("os_image_hash", "os-image-hash")):
        claimed = info.get(key) or tcb.get(key)
        if claimed is not None and claimed.lower() != events.get(ev, "").lower():
            raise AttestationError(f"report info {key} differs from the {ev} event in RTMR3")
    return events


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _jwt_claims(token: str, jwks: dict) -> dict:
    """Verify an ES384 JWT against a JWKS (EC P-384 keys) and return its claims."""
    h, p, sig = token.split(".")
    header = json.loads(_b64url(h))
    if header.get("alg") != "ES384":
        raise AttestationError(f"NRAS token uses {header.get('alg')}, expected ES384")
    jwk = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
    if jwk is None or jwk.get("crv") != "P-384":
        raise AttestationError("NRAS token is signed by a key NVIDIA does not publish")
    pub = ec.EllipticCurvePublicNumbers(
        int.from_bytes(_b64url(jwk["x"]), "big"), int.from_bytes(_b64url(jwk["y"]), "big"), ec.SECP384R1()
    ).public_key()
    raw = _b64url(sig)
    if len(raw) != 96:
        raise AttestationError("NRAS token signature is malformed")
    der = encode_dss_signature(int.from_bytes(raw[:48], "big"), int.from_bytes(raw[48:], "big"))
    try:
        pub.verify(der, f"{h}.{p}".encode(), ec.ECDSA(hashes.SHA384()))
    except InvalidSignature as e:
        raise AttestationError("NRAS token signature does not verify") from e
    return json.loads(_b64url(p))


def check_gpu(nvidia_payload: str | dict, nonce: str, *, nras_url: str = NRAS, timeout: float = 60) -> int:
    """Have NVIDIA's NRAS appraise the GPU evidence, and verify its answer.
    Returns the number of GPUs that passed."""
    payload = json.loads(nvidia_payload) if isinstance(nvidia_payload, str) else nvidia_payload
    if str(payload.get("nonce", "")).lower() != nonce:
        raise AttestationError("GPU evidence does not carry our nonce")
    if not payload.get("evidence_list"):
        raise AttestationError("GPU evidence list is empty")
    try:
        r = httpx.post(f"{nras_url}/v3/attest/gpu", json=payload, timeout=timeout)
        r.raise_for_status()
        jwks = httpx.get(f"{nras_url}/.well-known/jwks.json", timeout=timeout).json()
        overall, per_gpu = r.json()
    except AttestationError:
        raise
    except Exception as e:  # noqa: BLE001
        raise AttestationError(f"NVIDIA attestation service failed: {e}") from e
    if overall[0] != "JWT":
        raise AttestationError("NRAS returned no platform token")
    claims = _jwt_claims(overall[1], jwks)
    if claims.get("x-nvidia-overall-att-result") is not True:
        raise AttestationError("NVIDIA did not pass the GPU attestation")
    if claims.get("eat_nonce", "").lower() != nonce:
        raise AttestationError("NRAS platform token is not for our nonce")
    if not per_gpu or len(per_gpu) != len(payload["evidence_list"]):
        raise AttestationError("NRAS did not return a token for every GPU")
    for gpu, token in per_gpu.items():
        c = _jwt_claims(token, jwks)
        if c.get("measres") != "success" or c.get("x-nvidia-gpu-attestation-report-nonce-match") is not True:
            raise AttestationError(f"{gpu} failed NVIDIA attestation")
        if c.get("eat_nonce", "").lower() != nonce:
            raise AttestationError(f"{gpu} token is not for our nonce")
    return len(per_gpu)


def verify_model(model: str, *, pccs_url: str | None = INTEL_PCS, timeout: float = 60) -> VerifiedModel:
    nonce = os.urandom(32).hex()
    r = httpx.get(
        f"{BASE}/attestation/report",
        params={"model": model, "provider": "near", "signing_algo": "ed25519", "nonce": nonce},
        headers={"x-no-aliasing": "true"},
        timeout=timeout,
    )
    r.raise_for_status()
    return check_report(model, r.content, nonce, pccs_url=pccs_url)


def check_report(model: str, raw: bytes, nonce: str, *, pccs_url: str | None = INTEL_PCS,
                 nras_url: str | None = NRAS) -> VerifiedModel:
    """Verify a raw attestation report. Used live, and offline by anyone re-checking a proof bundle.
    nras_url=None skips the NVIDIA GPU check (gpu_status "skipped")."""
    report = json.loads(raw)

    gw = report["gateway_attestation"]
    _check_quote(gw["intel_quote"], gw["signing_address"], nonce, pccs_url)
    check_event_log(gw)

    candidates = report.get("model_attestations") or []
    if not candidates:
        raise AttestationError(f"no TEE attestation available for {model}")
    keys = set()
    status = ""
    composes: set[str] = set()
    gpu_status = "skipped"
    for c in candidates:
        if c.get("signing_algo") != "ed25519":
            raise AttestationError("model candidate is not ed25519")
        status = _check_quote(c["intel_quote"], c["signing_public_key"], nonce, pccs_url)
        ev = check_event_log(c)
        composes.add(ev["compose-hash"])
        if nras_url is not None:
            if not c.get("nvidia_payload"):
                raise AttestationError("model candidate has no GPU evidence")
            check_gpu(c["nvidia_payload"], nonce, nras_url=nras_url)
            gpu_status = "verified"
        keys.add(c["signing_public_key"])
    if len(keys) != 1:
        # Instances of one model share a key; more than one means we can't pin.
        raise AttestationError(f"model reports carry {len(keys)} different keys; refusing to pick")
    return VerifiedModel(
        model=model,
        signing_key=keys.pop(),
        gateway_key=gw["signing_address"],
        nonce=nonce,
        tcb_status=status,
        report_sha256=hashlib.sha256(raw).hexdigest(),
        report_raw=raw,
        compose_hashes=sorted(composes),
        gpu_status=gpu_status,
    )
