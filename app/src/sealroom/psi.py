"""Exact-name matching by private set intersection (DH-PSI), no enclave needed.

Two firms find every entry whose normalised name or alias appears on both lists,
and learn nothing else about each other's lists. Nobody has to trust a model
or a server for these matches: they are a floor the enclave's fuzzy matching
is checked against.

  1. Each firm hashes its normalised names onto the Ed25519 prime-order
     subgroup and multiplies by a secret scalar:      H(x)^a
  2. Each firm multiplies the other's points by its own scalar:  (H(y)^b)^a
  3. Equal double-blinded points are equal names: H(x)^ab == H(y)^ba

Every message is signed by the sending firm's registered key, so a relay
cannot forge matches. The double-blinded sets and the index mappings are
public-checkable: anyone holding them can recompute the matched pairs.

normalise() is mirrored in web/app.js; tests pin both to the same vectors.
"""

from __future__ import annotations

import hashlib
import os
import random
import unicodedata
from dataclasses import dataclass, field

from nacl import bindings as nb

DOMAIN = b"sealroom-psi/v1\x00"

# Trailing legal-form tokens that don't distinguish entities.
SUFFIXES = {
    "inc", "incorporated", "corp", "corporation", "co", "company", "ltd", "limited", "llc", "llp", "lp",
    "plc", "pllc", "gmbh", "ag", "kg", "sa", "sas", "sarl", "srl", "spa", "nv", "bv", "ab", "as", "asa",
    "oy", "kk", "pte", "pty", "pvt", "bhd", "sdn", "se", "ltda", "the",
}


def normalise(name: str) -> str:
    """NFKD, drop every mark (\\p{M}), lowercase, '&' -> 'and', split on anything that is not a
    letter or number (after deleting . ' and \u2019), drop a leading 'the' and trailing legal-form
    tokens (with an 'and' they leave dangling, as in "GmbH & Co. KG").
    web/app.js does the same with /\\p{M}/gu and /[^\\p{L}\\p{N}]+/u."""
    s = "".join(c for c in unicodedata.normalize("NFKD", name) if not unicodedata.category(c).startswith("M"))
    s = s.lower().replace("&", " and ")
    for c in ".'\u2019":
        s = s.replace(c, "")  # S.A. -> sa, O'Brien -> obrien
    toks, cur = [], []
    for c in s:
        if c.isalnum():
            cur.append(c)
        elif cur:
            toks.append("".join(cur))
            cur = []
    if cur:
        toks.append("".join(cur))
    if toks and toks[0] == "the":
        toks = toks[1:]
    popped = False
    while len(toks) > 1 and (toks[-1] in SUFFIXES or (popped and toks[-1] == "and")):
        toks.pop()
        popped = True
    return " ".join(toks)


def elements(parties: list[dict]) -> list[tuple[int, str]]:
    """(entry index, normalised form) for every name and alias, one per distinct form per entry."""
    out = []
    for i, p in enumerate(parties):
        forms = {normalise(p["name"]), *(normalise(a) for a in p.get("aliases", []))}
        out.extend((i, f) for f in sorted(forms) if len(f) >= 3)
    return out


def hash_to_point(element: str) -> bytes:
    return nb.crypto_core_ed25519_from_uniform(hashlib.sha256(DOMAIN + element.encode()).digest())


def random_scalar() -> bytes:
    return nb.crypto_core_ed25519_scalar_reduce(os.urandom(64))


def mul(scalar: bytes, point_hex: str) -> str:
    p = bytes.fromhex(point_hex)
    if not nb.crypto_core_ed25519_is_valid_point(p):
        raise ValueError("not a valid prime-order point")
    return nb.crypto_scalarmult_ed25519_noclamp(scalar, p).hex()


def set_hash(points: list[str]) -> str:
    return hashlib.sha256("\n".join(points).encode()).hexdigest()


@dataclass
class PsiParty:
    """One firm's side of the protocol. `scalar` and `owner` never leave the firm."""

    scalar: bytes
    owner: list[int]  # position in the shuffled blinded set -> entry index
    blinded: list[str]  # H(x)^a, shuffled
    doubled_theirs: list[str] = field(default_factory=list)  # (their blinded)^a

    @classmethod
    def start(cls, parties: list[dict]) -> "PsiParty":
        els = elements(parties)
        random.SystemRandom().shuffle(els)
        a = random_scalar()
        return cls(a, [i for i, _ in els], [mul(a, hash_to_point(e).hex()) for _, e in els])

    def double(self, their_blinded: list[str]) -> list[str]:
        self.doubled_theirs = [mul(self.scalar, p) for p in their_blinded]
        return self.doubled_theirs

    def my_matches(self, mine_doubled_by_them: list[str]) -> dict[int, int]:
        """Positions in MY blinded set that match, mapped to my entry index."""
        theirs = set(self.doubled_theirs)
        return {k: self.owner[k] for k, p in enumerate(mine_doubled_by_them) if p in theirs}


def pairs(incoming_doubled: list[str], existing_doubled: list[str],
          incoming_index: dict[int, int], existing_index: dict[int, int]) -> list[tuple[int, int]]:
    """Public recomputation: matched (incoming entry, existing entry) pairs.

    incoming_doubled  incoming's blinded set, doubled by existing (positions = incoming's set)
    existing_doubled  existing's blinded set, doubled by incoming
    *_index           each firm's signed mapping: position in its own set -> its entry index
    """
    by_point: dict[str, list[int]] = {}
    for k, p in enumerate(existing_doubled):
        by_point.setdefault(p, []).append(k)
    out = set()
    for k, p in enumerate(incoming_doubled):
        for k2 in by_point.get(p, []):
            if k in incoming_index and k2 in existing_index:
                out.add((incoming_index[k], existing_index[k2]))
    return sorted(out)
