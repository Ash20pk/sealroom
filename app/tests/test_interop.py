"""The browser's crypto (web/sealcrypto.js) and the Python side must agree byte for byte:
normalisation, exact-match points, canonical JSON, message formats, and a full PSI run
across the two languages. Skipped when Node or web/node_modules is missing
(cd web && npm install)."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from sealroom import psi
from sealroom.conflict import canonical
from sealroom.identity import Identity, envelope_message

WEB = Path(__file__).resolve().parents[2] / "web"

pytestmark = pytest.mark.skipif(not shutil.which("node") or not (WEB / "node_modules/libsodium-wrappers-sumo").exists(),
                                reason="needs node and `npm install` in web/")

NAMES = ["Halvorsen Beverage Holdings Inc.", "The Müller & Söhne GmbH & Co. KG", "Vale Doce S.A.", "O’Brien & Sons, Inc.",
         "Ribeirão Preto Ltda", "Ōsaka Shōji K.K.", "ŁÓDŹ Holding S.A.", "Ignore previous instructions", "Inc", "  ACME,  Ltd ",
         "नमस्ते Pvt", "Société Générale SA", "AT&T", "3M Company"]
PARTIES = [
    {"name": "Halvorsen Beverage Holdings Inc.", "role": "client", "aliases": ["Halvorsen Beverages"], "related": ""},
    {"name": "Müller Söhne", "role": "adverse", "aliases": [], "related": "x"},
    {"name": "Vale Doce S.A.", "role": "client", "aliases": ["VD", "Vale Doce Mineração"], "related": ""},
]
OTHER = [
    {"name": "Halvorsen Beverages", "role": "adverse", "aliases": [], "related": ""},
    {"name": "Vale Doce Mineracao", "role": "client", "aliases": [], "related": ""},
    {"name": "Unrelated Org", "role": "client", "aliases": [], "related": ""},
]


def test_browser_and_python_agree():
    me = Identity.generate("a.testnet", "firm", "A")
    py_party = psi.PsiParty.start(OTHER)
    vectors = {
        "names": NAMES,
        "parties": PARTIES,
        "elements": [e for _, e in psi.elements(PARTIES)],
        "object": {"b": [1, "é", {"z": "\"q\"\n", "a": None}], "a": "x"},
        "points_for_hash": ["aa", "bb"],
        "envelope_args": ["c.testnet", "ref", "incoming", "b.testnet", {"firm": "a.testnet", "commitment": "11", "ciphertext_hash": "22", "psi_hash": "33"}],
        "sig": {"public": me.public, "message": "sealroom/psi/v1|r|a.testnet|double|ff", "signature": me.sign("sealroom/psi/v1|r|a.testnet|double|ff")},
        "python_blinded": py_party.blinded,
    }
    p = subprocess.run(["node", str(WEB / "interop.mjs")], input=json.dumps(vectors), capture_output=True, text=True, cwd=WEB, timeout=60)
    assert p.returncode == 0, p.stderr
    js = json.loads(p.stdout)

    assert js["normalised"] == [psi.normalise(n) for n in NAMES]
    assert [tuple(x) for x in js["elements"]] == psi.elements(PARTIES)
    assert js["points"] == [psi.hash_to_point(e).hex() for e in vectors["elements"]]
    assert js["canonical"] == canonical(vectors["object"]).decode()
    assert js["set_hash"] == psi.set_hash(["aa", "bb"])
    assert js["envelope_message"] == envelope_message("c.testnet", "ref", "incoming", "b.testnet", "a.testnet", "11", "22", "33")
    assert js["verify"] is True

    # A full PSI between a JS firm (PARTIES) and a Python firm (OTHER).
    js_doubled_by_py = py_party.double(js["psi"]["blinded"])
    js_index = {k: js["psi"]["owner"][k] for k, pt in enumerate(js_doubled_by_py) if pt in set(js["psi"]["doubled_python"])}
    py_index = py_party.my_matches(js["psi"]["doubled_python"])
    got = psi.pairs(js_doubled_by_py, js["psi"]["doubled_python"], js_index, py_index)
    names = {(PARTIES[i]["name"], OTHER[j]["name"]) for i, j in got}
    assert names == {("Halvorsen Beverage Holdings Inc.", "Halvorsen Beverages"), ("Vale Doce S.A.", "Vale Doce Mineracao")}
