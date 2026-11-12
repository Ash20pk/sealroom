// Runs web/sealcrypto.js under Node for app/tests/test_interop.py.
// Reads vectors on stdin, prints what the browser code computes for them.
import _sodium from "libsodium-wrappers-sumo";
import * as sc from "./sealcrypto.js";

await _sodium.ready;
sc.useSodium(_sodium);
const v = JSON.parse(await new Promise((r) => { let s = ""; process.stdin.on("data", (d) => (s += d)); process.stdin.on("end", () => r(s)); }));
const party = await sc.psiStart(v.parties);
const out = {
  normalised: v.names.map(sc.normalise),
  elements: sc.elements(v.parties),
  points: await Promise.all(v.elements.map(async (e) => sc.hex(await sc.hashToPoint(e)))),
  canonical: sc.canonical(v.object),
  set_hash: await sc.setHash(v.points_for_hash),
  envelope_message: sc.envelopeMessage(...v.envelope_args),
  verify: sc.verifySig(v.sig.public, v.sig.message, v.sig.signature),
  // JS side of a PSI run: Python doubles these, JS doubles Python's, Python intersects.
  psi: { blinded: party.blinded, owner: party.owner, doubled_python: v.python_blinded.map((p) => sc.mul(party.scalar, p)) },
};
process.stdout.write(JSON.stringify(out));
