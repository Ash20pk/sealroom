"""Attestation checks that don't need the network: the RTMR replay runs on a
real NEAR AI Cloud model report (tests/fixtures), and the NRAS token checks run
against a local P-384 key standing in for NVIDIA's."""

import base64
import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from sealroom import attest
from sealroom.attest import AttestationError, check_event_log, check_gpu

REPORT = json.loads((Path(__file__).parent / "fixtures" / "model_attestation.json").read_text())
NONCE = "ab" * 32


def test_event_log_replays_to_quote_rtmrs():
    ev = check_event_log(copy.deepcopy(REPORT))
    assert ev["compose-hash"] == REPORT["info"]["compose_hash"]
    assert ev["app-id"] == REPORT["info"]["app_id"]


def test_tampered_rtmr3_event_is_caught():
    r = copy.deepcopy(REPORT)
    e = next(e for e in r["event_log"] if e["event"] == "compose-hash")
    e["event_payload"] = "00" * 32
    with pytest.raises(AttestationError, match="RTMR3"):
        check_event_log(r)


def test_app_compose_must_match_compose_hash():
    r = copy.deepcopy(REPORT)
    r["info"]["tcb_info"]["app_compose"] += " "
    with pytest.raises(AttestationError, match="app_compose"):
        check_event_log(r)


def test_info_block_must_match_rtmr3():
    r = copy.deepcopy(REPORT)
    r["info"]["app_id"] = "00" * 20
    with pytest.raises(AttestationError, match="app_id"):
        check_event_log(r)


# ---------------------------------------------------------------- NVIDIA NRAS

KEY = ec.generate_private_key(ec.SECP384R1())


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _jwks(key=KEY, kid="k1"):
    n = key.public_key().public_numbers()
    return {"keys": [{"kty": "EC", "crv": "P-384", "kid": kid, "x": _b64(n.x.to_bytes(48, "big")), "y": _b64(n.y.to_bytes(48, "big"))}]}


def _jwt(claims: dict, key=KEY, kid="k1") -> str:
    h = _b64(json.dumps({"alg": "ES384", "kid": kid}).encode())
    p = _b64(json.dumps(claims).encode())
    r, s = decode_dss_signature(key.sign(f"{h}.{p}".encode(), ec.ECDSA(hashes.SHA384())))
    return f"{h}.{p}.{_b64(r.to_bytes(48, 'big') + s.to_bytes(48, 'big'))}"


def _gpu_ok(nonce=NONCE):
    return {"measres": "success", "x-nvidia-gpu-attestation-report-nonce-match": True, "eat_nonce": nonce}


class _Resp:
    def __init__(self, data):
        self.data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self.data


def _nras(monkeypatch, overall: dict, gpus: dict, *, sign_key=KEY):
    answer = [["JWT", _jwt(overall, sign_key)], {g: _jwt(c, sign_key) for g, c in gpus.items()}]
    monkeypatch.setattr(attest.httpx, "post", lambda *a, **k: _Resp(answer))
    monkeypatch.setattr(attest.httpx, "get", lambda *a, **k: _Resp(_jwks()))


PAYLOAD = {"nonce": NONCE, "arch": "HOPPER", "evidence_list": [{"evidence": "e0", "certificate": "c0"}, {"evidence": "e1", "certificate": "c1"}]}
PASS = {"x-nvidia-overall-att-result": True, "eat_nonce": NONCE}


def test_gpu_check_passes_on_signed_nras_answer(monkeypatch):
    _nras(monkeypatch, PASS, {"GPU-0": _gpu_ok(), "GPU-1": _gpu_ok()})
    assert check_gpu(json.dumps(PAYLOAD), NONCE) == 2


def test_gpu_evidence_for_another_nonce_is_refused(monkeypatch):
    _nras(monkeypatch, PASS, {"GPU-0": _gpu_ok(), "GPU-1": _gpu_ok()})
    with pytest.raises(AttestationError, match="nonce"):
        check_gpu(PAYLOAD, "cd" * 32)


def test_nras_token_from_unknown_key_is_refused(monkeypatch):
    _nras(monkeypatch, PASS, {"GPU-0": _gpu_ok(), "GPU-1": _gpu_ok()}, sign_key=ec.generate_private_key(ec.SECP384R1()))
    with pytest.raises(AttestationError, match="signature"):
        check_gpu(PAYLOAD, NONCE)


def test_failed_gpu_is_refused(monkeypatch):
    _nras(monkeypatch, PASS, {"GPU-0": _gpu_ok(), "GPU-1": {**_gpu_ok(), "measres": "fail"}})
    with pytest.raises(AttestationError, match="GPU-1"):
        check_gpu(PAYLOAD, NONCE)


def test_missing_gpu_token_is_refused(monkeypatch):
    _nras(monkeypatch, PASS, {"GPU-0": _gpu_ok()})
    with pytest.raises(AttestationError, match="every GPU"):
        check_gpu(PAYLOAD, NONCE)
