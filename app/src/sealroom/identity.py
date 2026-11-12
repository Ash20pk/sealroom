"""Who is who in a Sealroom check or session, and the exact texts they sign.

Every party has an ed25519 key registered on the Sealroom contract:
  firm    signs its envelope for one check (contract verifies it)
  member  signs each agent session they start (contract verifies it)
  agent   a NEAR account; it seals its own sessions with a key scoped to the contract

The message formats are mirrored byte for byte in contract/src/lib.rs and web/app.js.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


def envelope_message(contract: str, check_ref: str, side: str, counterparty: str, firm: str,
                     commitment: str, ciphertext_hash: str, psi_hash: str) -> str:
    return f"sealroom/envelope/v1|{contract}|{check_ref}|{firm}|{side}|{counterparty}|{commitment}|{ciphertext_hash}|{psi_hash}"


def session_message(contract: str, agent: str, session_id: str, question_hash: str, policy_hash: str) -> str:
    return f"sealroom/session/v1|{contract}|{agent}|{session_id}|{question_hash}|{policy_hash}"


def psi_message(check_ref: str, firm: str, step: str, payload_hash: str) -> str:
    """Off-chain: a firm's signed exact-match message (double-blinded set, or its matched indices)."""
    return f"sealroom/psi/v1|{check_ref}|{firm}|{step}|{payload_hash}"


def reveal_message(check_ref: str, firm: str, reveal_hash: str) -> str:
    """Off-chain: a firm discloses its own matched entries to the other firm."""
    return f"sealroom/reveal/v1|{check_ref}|{firm}|{reveal_hash}"


def sha256_hex(data: bytes | str) -> str:
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def verify(public_hex: str, message: str, signature_hex: str) -> bool:
    try:
        VerifyKey(bytes.fromhex(public_hex.removeprefix("0x"))).verify(message.encode(), bytes.fromhex(signature_hex))
        return True
    except (BadSignatureError, ValueError):
        return False


@dataclass
class Identity:
    """A local signing identity. In production this key lives on the party's own device."""

    account: str
    role: str  # firm | member | agent
    name: str
    seed: str  # 32-byte ed25519 seed, hex

    @classmethod
    def generate(cls, account: str, role: str, name: str) -> "Identity":
        return cls(account, role, name, os.urandom(32).hex())

    @classmethod
    def load(cls, path: Path) -> "Identity":
        d = json.loads(Path(path).read_text())
        return cls(d["account"], d["role"], d["name"], d["seed"])

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.__dict__, indent=2))
        path.chmod(0o600)

    @property
    def _key(self) -> SigningKey:
        return SigningKey(bytes.fromhex(self.seed))

    @property
    def public(self) -> str:
        return bytes(self._key.verify_key).hex()

    def sign(self, message: str) -> str:
        return self._key.sign(message.encode()).signature.hex()
