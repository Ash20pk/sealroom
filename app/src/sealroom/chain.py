"""Thin wrapper over near-cli-rs for the Sealroom contract.

Signing uses the legacy keychain (~/.near-credentials), so keys never pass
through this code.
"""

from __future__ import annotations

import json
import os
import re
import subprocess

import httpx

CONTRACT = os.environ.get("SEALROOM_CONTRACT", "v2.sealroom-64716.testnet")
OPERATOR = os.environ.get("SEALROOM_OPERATOR", "sealroom-64716.testnet")
NETWORK = os.environ.get("SEALROOM_NETWORK", "testnet")
CONNECTION = os.environ.get("SEALROOM_CONNECTION", "testnet-fastnear")
RPC = os.environ.get("SEALROOM_RPC", "https://test.rpc.fastnear.com")
EXPLORER = "https://testnet.nearblocks.io" if NETWORK == "testnet" else "https://nearblocks.io"


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def near(*args: str, timeout: int = 240) -> tuple[str, str]:
    """Run near-cli-rs non-interactively; returns (stdout, combined output). Raises on failure."""
    p = subprocess.run(["near", *args], capture_output=True, text=True, timeout=timeout)
    out = _ANSI.sub("", p.stdout + p.stderr)
    if p.returncode != 0:
        raise RuntimeError(f"near {' '.join(args[:3])} failed:\n{out[-3000:]}")
    return _ANSI.sub("", p.stdout).strip(), out


def _refusal(out: str, signer: str) -> str | None:
    """The contract logs "sealroom: <reason>" before it panics, because some nearcore
    releases report guest panics as a bare `unreachable` trap. Fetch that log."""
    tx = re.search(r"Transaction ID:\s*(\w+)", out)
    if not tx:
        return None
    try:
        r = httpx.post(RPC, json={"jsonrpc": "2.0", "id": 1, "method": "tx",
                                  "params": {"tx_hash": tx.group(1), "sender_account_id": signer, "wait_until": "FINAL"}}, timeout=30).json()
        logs = [l for o in r["result"]["receipts_outcome"] for l in o["outcome"]["logs"] if l.startswith("sealroom: ")]
        return logs[-1].removeprefix("sealroom: ") if logs else None
    except Exception:  # noqa: BLE001
        return None


def call(signer: str, method: str, args: dict, gas: str = "100 Tgas", contract: str | None = None) -> dict:
    try:
        stdout, out = near(
            "contract", "call-function", "as-transaction", contract or CONTRACT, method,
            "json-args", json.dumps(args), "prepaid-gas", gas, "attached-deposit", "0 NEAR",
            "sign-as", signer, "network-config", CONNECTION, "sign-with-legacy-keychain", "send",
        )
    except RuntimeError as e:
        reason = _refusal(str(e), signer)
        if reason:
            raise RuntimeError(f"NEAR refused {method}: {reason}") from None
        raise
    if "succeeded" not in out:
        raise RuntimeError(f"{method} failed:\n{out[-1500:]}")
    tx = re.search(r"Transaction ID:\s*(\w+)", out)
    return {"tx": tx.group(1) if tx else None, "return": stdout or None}


def view(method: str, args: dict, contract: str | None = None):
    import base64

    r = httpx.post(
        RPC,
        json={
            "jsonrpc": "2.0", "id": 1, "method": "query",
            "params": {
                "request_type": "call_function", "finality": "final", "account_id": contract or CONTRACT,
                "method_name": method, "args_base64": base64.b64encode(json.dumps(args).encode()).decode(),
            },
        },
        timeout=30,
    ).json()
    if "error" in r or "error" in r.get("result", {}):
        raise RuntimeError(f"view {method} failed: {r}")
    return json.loads(bytes(r["result"]["result"]).decode() or "null")


def tx_url(tx: str | None) -> str | None:
    return f"{EXPLORER}/txns/{tx}" if tx else None


def firm_keys(*accounts: str) -> dict[str, str]:
    """Each firm's registered sealing key, read from the contract."""
    out = {}
    for a in accounts:
        f = view("get_firm", {"account_id": a})
        if not f:
            raise RuntimeError(f"{a} is not a registered firm on {CONTRACT}")
        out[a] = f["key"]
    return out


def account_url(account: str) -> str:
    return f"{EXPLORER}/address/{account}"
