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

CONTRACT = os.environ.get("SEALROOM_CONTRACT", "sealroom-64716.testnet")
NETWORK = os.environ.get("SEALROOM_NETWORK", "testnet")
CONNECTION = os.environ.get("SEALROOM_CONNECTION", "testnet-fastnear")
RPC = os.environ.get("SEALROOM_RPC", "https://test.rpc.fastnear.com")
EXPLORER = "https://testnet.nearblocks.io" if NETWORK == "testnet" else "https://nearblocks.io"


def call(signer: str, method: str, args: dict, gas: str = "50 Tgas") -> dict:
    cmd = [
        "near", "contract", "call-function", "as-transaction", CONTRACT, method,
        "json-args", json.dumps(args), "prepaid-gas", gas, "attached-deposit", "0 NEAR",
        "sign-as", signer, "network-config", CONNECTION, "sign-with-legacy-keychain", "send",
    ]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    ansi = re.compile(r"\x1b\[[0-9;]*m")
    out = ansi.sub("", p.stdout + p.stderr)
    if p.returncode != 0 or "succeeded" not in out:
        raise RuntimeError(f"{method} failed:\n{out[-1500:]}")
    tx = re.search(r"Transaction ID:\s*(\w+)", out)
    ret = ansi.sub("", p.stdout).strip() or None  # near-cli prints only the return value on stdout
    return {"tx": tx.group(1) if tx else None, "return": ret}


def view(method: str, args: dict):
    import base64

    r = httpx.post(
        RPC,
        json={
            "jsonrpc": "2.0", "id": 1, "method": "query",
            "params": {
                "request_type": "call_function", "finality": "final", "account_id": CONTRACT,
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
