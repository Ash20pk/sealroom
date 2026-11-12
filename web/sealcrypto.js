// Sealroom's browser crypto. Mirrors app/src/sealroom/{e2ee,psi,identity,conflict}.py;
// web/interop.test.mjs runs it under Node against the Python implementation.
let sodium;
export function useSodium(s) { sodium = s; }

const enc = new TextEncoder();
export const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
export const unhex = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));


export function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
  return JSON.stringify(v);
}
export const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", typeof bytes === "string" ? enc.encode(bytes) : bytes));
export const sha256hex = async (x) => hex(await sha256(x));

export async function hkdf(shared) {
  const k = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: enc.encode("ed25519_encryption") }, k, 256);
  return new Uint8Array(bits);
}

// NEAR AI E2EE v2: X25519 + HKDF-SHA256 + XChaCha20-Poly1305, fresh ephemeral key per field.
export async function encryptTo(modelKeyHex, text) {
  const modelX = sodium.crypto_sign_ed25519_pk_to_curve25519(unhex(modelKeyHex));
  const eph = sodium.crypto_box_keypair();
  const key = await hkdf(sodium.crypto_scalarmult(eph.privateKey, modelX));
  const nonce = sodium.randombytes_buf(24);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(enc.encode(text), null, null, nonce, key);
  const out = new Uint8Array(32 + 24 + ct.length);
  out.set(eph.publicKey, 0); out.set(nonce, 32); out.set(ct, 56);
  return hex(out);
}

export const verifySig = (pkHex, msg, sigHex) => { try { return sodium.crypto_sign_verify_detached(unhex(sigHex), enc.encode(msg), unhex(pkHex)); } catch { return false; } };
export const envelopeMessage = (contract, ref, side, counterparty, e) =>
  `sealroom/envelope/v1|${contract}|${ref}|${e.firm}|${side}|${counterparty}|${e.commitment}|${e.ciphertext_hash}|${e.psi_hash}`;
export const psiMessage = (ref, firm, step, h) => `sealroom/psi/v1|${ref}|${firm}|${step}|${h}`;
export const revealMessage = (ref, firm, h) => `sealroom/reveal/v1|${ref}|${firm}|${h}`;

/* exact tier: DH-PSI over the Ed25519 prime-order group; mirrors app/src/sealroom/psi.py */
const SUFFIXES = new Set(("inc incorporated corp corporation co company ltd limited llc llp lp plc pllc gmbh ag kg sa sas sarl srl spa " +
  "nv bv ab as asa oy kk pte pty pvt bhd sdn se ltda the").split(" "));
export function normalise(name) {
  let s = name.normalize("NFKD").replace(/\p{M}/gu, "").toLowerCase().replace(/&/g, " and ").replace(/[.'’]/g, "");
  let toks = s.split(/[^\p{L}\p{N}]+/u).filter(Boolean);
  if (toks[0] === "the") toks = toks.slice(1);
  let popped = false;
  while (toks.length > 1 && (SUFFIXES.has(toks.at(-1)) || (popped && toks.at(-1) === "and"))) { toks.pop(); popped = true; }
  return toks.join(" ");
}
export function elements(parties) {
  const out = [];
  parties.forEach((p, i) => {
    const forms = [...new Set([normalise(p.name), ...p.aliases.map(normalise)])].sort();
    forms.filter((f) => [...f].length >= 3).forEach((f) => out.push([i, f]));
  });
  return out;
}
const DOMAIN = enc.encode("sealroom-psi/v1\0");
export async function hashToPoint(el) {
  const b = enc.encode(el), m = new Uint8Array(DOMAIN.length + b.length);
  m.set(DOMAIN); m.set(b, DOMAIN.length);
  return sodium.crypto_core_ed25519_from_uniform(await sha256(m));
}
export const mul = (scalar, pointHex) => {
  const p = unhex(pointHex);
  if (!sodium.crypto_core_ed25519_is_valid_point(p)) throw new Error("invalid point in exact-match set");
  return hex(sodium.crypto_scalarmult_ed25519_noclamp(scalar, p));
};
export const setHash = (points) => sha256hex(points.join("\n"));

export async function psiStart(parties) {
  const els = elements(parties);
  for (let i = els.length - 1; i > 0; i--) { const j = sodium.randombytes_uniform(i + 1); [els[i], els[j]] = [els[j], els[i]]; }
  const scalar = sodium.crypto_core_ed25519_scalar_reduce(sodium.randombytes_buf(64));
  const blinded = [];
  for (const [, e] of els) blinded.push(hex(sodium.crypto_scalarmult_ed25519_noclamp(scalar, await hashToPoint(e))));
  return { scalar, owner: els.map(([i]) => i), blinded };
}

