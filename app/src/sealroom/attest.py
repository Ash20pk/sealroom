"""Fetch and check NEAR AI Cloud attestation before anything is encrypted.

What we check, per report (gateway and every model candidate):
  1. Intel's signature over the TDX quote (dcap-qvl, Intel PCS collateral).
  2. report_data[0:32] is the signing key, zero-padded: the key we encrypt to
     and later verify signatures with lives inside this TEE.
  3. report_data[32:64] is our fresh nonce, so the report is not a replay.
  4. TDX debug mode is off.

Not checked here (documented in the README): RTMR3 event-log replay against
app_compose, and the NVIDIA GPU attestation via NRAS.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from dataclasses import asdict, dataclass

import dcap_qvl
import httpx

BASE = "https://cloud-api.near.ai/v1"
INTEL_PCS = "https://api.trustedservices.intel.com"

# TDX quote v4: 48-byte header, then the TD report body. Offsets in the body.
_HDR = 48
_TD_ATTRIBUTES = _HDR + 120
_REPORT_DATA = _HDR + 520


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

    def to_json(self) -> dict:
        return asdict(self)


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


def verify_model(model: str, *, pccs_url: str | None = INTEL_PCS, timeout: float = 60) -> VerifiedModel:
    nonce = os.urandom(32).hex()
    r = httpx.get(
        f"{BASE}/attestation/report",
        params={"model": model, "provider": "near", "signing_algo": "ed25519", "nonce": nonce},
        headers={"x-no-aliasing": "true"},
        timeout=timeout,
    )
    r.raise_for_status()
    raw = r.content
    report = json.loads(raw)

    gw = report["gateway_attestation"]
    _check_quote(gw["intel_quote"], gw["signing_address"], nonce, pccs_url)

    candidates = report.get("model_attestations") or []
    if not candidates:
        raise AttestationError(f"no TEE attestation available for {model}")
    keys = set()
    status = ""
    for c in candidates:
        if c.get("signing_algo") != "ed25519":
            raise AttestationError("model candidate is not ed25519")
        status = _check_quote(c["intel_quote"], c["signing_public_key"], nonce, pccs_url)
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
    )
