"""End-to-end encryption to a NEAR AI Cloud model TEE (protocol v2).

X25519 ECDH with a fresh ephemeral key per field, HKDF-SHA256 (no salt,
info "ed25519_encryption", 32 bytes), XChaCha20-Poly1305 with a 24-byte nonce.
Wire format, hex: ephemeral_pub(32) || nonce(24) || ciphertext+tag.

Every field carries its own ephemeral key, so two firms can each encrypt their
own message to the model key without sharing anything with each other or with
the orchestrator that relays the request.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl import bindings as nb
from nacl.public import PrivateKey
from nacl.signing import SigningKey

INFO = b"ed25519_encryption"


def _kdf(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO).derive(shared)


def model_x25519(model_ed25519_pub_hex: str) -> bytes:
    return nb.crypto_sign_ed25519_pk_to_curve25519(bytes.fromhex(model_ed25519_pub_hex))


def encrypt_to(model_ed25519_pub_hex: str, plaintext: str) -> str:
    """Encrypt one field so only the holder of the model key can read it."""
    eph = PrivateKey.generate()
    shared = nb.crypto_scalarmult(bytes(eph), model_x25519(model_ed25519_pub_hex))
    key = _kdf(shared)
    nonce = os.urandom(24)
    ct = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext.encode(), None, nonce, key)
    return (bytes(eph.public_key) + nonce + ct).hex()


@dataclass
class ClientKey:
    """The key a response is encrypted to. Ed25519 on the wire, X25519 for ECDH."""

    signing: SigningKey

    @classmethod
    def generate(cls) -> "ClientKey":
        return cls(SigningKey.generate())

    @property
    def public_hex(self) -> str:
        return bytes(self.signing.verify_key).hex()

    def _x25519_secret(self) -> bytes:
        sk64 = bytes(self.signing) + bytes(self.signing.verify_key)
        return nb.crypto_sign_ed25519_sk_to_curve25519(sk64)

    def decrypt(self, hex_blob: str) -> str:
        raw = bytes.fromhex(hex_blob)
        eph, nonce, ct = raw[:32], raw[32:56], raw[56:]
        key = _kdf(nb.crypto_scalarmult(self._x25519_secret(), eph))
        return nb.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, None, nonce, key).decode()


def decrypt_as_model(model_signing: SigningKey, hex_blob: str) -> str:
    """Test helper: decrypt a field the way the model TEE would."""
    return ClientKey(model_signing).decrypt(hex_blob)
