"""One-time testnet setup: contract, firms, members, agent.

  contract  <name>.<operator> is created and the contract deployed, operator = <operator>
  firms     each firm registers its name and a fresh ed25519 sealing key
  members   real NEAR sub-accounts of their firm, created with the member's own key,
            then registered by the firm with that same key
  agent     a sub-account of its firm whose ONLY key is a function-call key that
            can call seal_session on the Sealroom contract and nothing else

Private keys go to .state/identity/<account>.json (gitignored). In production each
of those files lives on its owner's device; here one machine plays every role.
Every step is idempotent: re-running skips what already exists.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import chain
from .agent import PROMPT_HASH
from .identity import Identity

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def near_public(identity: Identity) -> str:
    return "ed25519:" + b58(bytes.fromhex(identity.public))


def exists(account: str) -> bool:
    try:
        chain.near("account", "view-account-summary", account, "network-config", chain.CONNECTION, "now")
        return True
    except RuntimeError:
        return False


def load_or_new(state: Path, account: str, role: str, name: str) -> Identity:
    p = state / f"{account}.json"
    if p.exists():
        return Identity.load(p)
    i = Identity.generate(account, role, name)
    i.save(p)
    return i


def run(state: Path, *, operator: str, contract: str, wasm: Path, firms: dict[str, str], members: list[dict],
        agent: dict, log=print) -> dict:
    """firms: {account: display name}; members: [{account, firm, name}]; agent: {account, firm, owner, name, model}"""
    state.mkdir(parents=True, exist_ok=True)
    if not exists(contract):
        chain.near("account", "create-account", "fund-myself", contract, "3 NEAR", "autogenerate-new-keypair",
                   "save-to-legacy-keychain", "sign-as", operator, "network-config", chain.CONNECTION,
                   "sign-with-legacy-keychain", "send")
        chain.near("contract", "deploy", contract, "use-file", str(wasm), "with-init-call", "new",
                   "json-args", json.dumps({"operator": operator}), "prepaid-gas", "100 Tgas", "attached-deposit", "0 NEAR",
                   "network-config", chain.CONNECTION, "sign-with-legacy-keychain", "send")
        log(f"deployed {contract} (operator {operator})")

    for account, name in firms.items():
        ident = load_or_new(state, account, "firm", name)
        f = chain.view("get_firm", {"account_id": account}, contract)
        if not f or f["key"] != ident.public:
            chain.call(account, "register_firm", {"name": name, "key": ident.public}, contract=contract)
            log(f"registered firm {account} with sealing key {ident.public[:12]}…")

    for m in members:
        ident = load_or_new(state, m["account"], "member", m["name"])
        if not exists(m["account"]):
            chain.near("account", "create-account", "fund-myself", m["account"], "0.1 NEAR", "use-manually-provided-public-key",
                       near_public(ident), "sign-as", m["firm"], "network-config", chain.CONNECTION,
                       "sign-with-legacy-keychain", "send")
            log(f"created member account {m['account']} with the member's own key")
        got = chain.view("get_member", {"account_id": m["account"]}, contract)
        if not got or got["key"] != ident.public or not got["active"]:
            chain.call(m["firm"], "add_member", {"member": m["account"], "name": m["name"], "key": ident.public}, contract=contract)
            log(f"registered member {m['account']} under {m['firm']}")

    a = agent
    if not exists(a["account"]):
        # Create with a temporary full-access key, add the scoped key, then delete the full-access key.
        chain.near("account", "create-account", "fund-myself", a["account"], "0.5 NEAR", "autogenerate-new-keypair",
                   "save-to-legacy-keychain", "sign-as", a["firm"], "network-config", chain.CONNECTION,
                   "sign-with-legacy-keychain", "send")
        full = json.loads((Path.home() / ".near-credentials" / chain.NETWORK / f"{a['account']}.json").read_text())["public_key"]
        chain.near("account", "add-key", a["account"], "grant-function-call-access", "--allowance", "0.5 NEAR",
                   "--contract-account-id", contract, "--function-names", "seal_session", "autogenerate-new-keypair",
                   "save-to-legacy-keychain", "network-config", chain.CONNECTION, "sign-with-legacy-keychain", "send")
        chain.near("account", "delete-keys", a["account"], "public-keys", full, "network-config", chain.CONNECTION,
                   "sign-with-legacy-keychain", "send")
        # The legacy keychain signs with <account>.json: point it at the scoped key, set the dead one aside.
        creds = Path.home() / ".near-credentials" / chain.NETWORK
        main = creds / f"{a['account']}.json"
        main.rename(main.with_name(main.name + ".deleted-on-chain"))
        dead = creds / a["account"] / (full.replace(":", "_") + ".json")
        if dead.exists():
            dead.rename(dead.with_name(dead.name + ".deleted-on-chain"))
        scoped = next(p for p in (creds / a["account"]).glob("ed25519_*.json"))
        main.write_text(scoped.read_text())
        main.chmod(0o600)
        log(f"created agent {a['account']}: its only key can call seal_session on {contract}")
    got = chain.view("get_agent", {"account_id": a["account"]}, contract)
    if not got or got["prompt_hash"] != PROMPT_HASH or got["model"] != a["model"] or not got["active"]:
        chain.call(a["firm"], "register_agent", {"agent": a["account"], "owner": a["owner"], "name": a["name"],
                                                 "model": a["model"], "prompt_hash": PROMPT_HASH}, contract=contract)
        log(f"registered agent {a['account']} (owner {a['owner']}, model {a['model']}, prompt {PROMPT_HASH[:12]}…)")
    return {"contract": contract, "operator": operator, "firms": list(firms), "members": [m["account"] for m in members], "agent": a["account"]}
