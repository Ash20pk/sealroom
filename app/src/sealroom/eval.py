"""Precision and recall of the full engine on a labelled case (eval/<case>/).

Runs exactly what production runs (sealing, signed envelopes, exact tier by
PSI, every chunk pair through the attested model, proof bundle) with throwaway
firm identities and no chain writes, then scores the named verdict against
truth.json. Each run's proof bundle is replayed too, so a score is only
reported for a verdict that verifies.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path

from . import bundle, conflict
from .attest import verify_model
from .flow import local_check
from .identity import Identity


def _score(named: list[dict], truth: dict) -> dict:
    want = {(p["incoming"], p["existing"]): p for p in truth["pairs"]}
    negatives = {(n["incoming"], n["existing"]) for n in truth.get("hard_negatives", [])}
    got = {(n["incoming"]["name"], n["existing"]["name"]): n for n in named}
    tp = [k for k in got if k in want]
    fp = [k for k in got if k not in want]
    fn = [k for k in want if k not in got]
    by_rel = Counter(want[k]["relationship"] for k in want)
    hit_rel = Counter(want[k]["relationship"] for k in tp)
    by_diff = Counter(want[k].get("difficulty", "?") for k in want)
    hit_diff = Counter(want[k].get("difficulty", "?") for k in tp)
    exact_only = {k for k, n in got.items() if n["source"] == "exact"}
    return {
        "truth": len(want),
        "predicted": len(got),
        "true_positives": len(tp),
        "precision": round(len(tp) / len(got), 3) if got else 1.0,
        "recall": round(len(tp) / len(want), 3) if want else 1.0,
        "recall_by_relationship": {r: f"{hit_rel[r]}/{by_rel[r]}" for r in sorted(by_rel)},
        "recall_by_difficulty": {d: f"{hit_diff[d]}/{by_diff[d]}" for d in sorted(by_diff)},
        "relationship_correct": sum(1 for k in tp if got[k]["relationship"] == want[k]["relationship"]),
        "hard_negatives_flagged": sorted(f"{a} <-> {b}" for a, b in fp if (a, b) in negatives),
        "false_positives": sorted(f"{a} <-> {b}" for a, b in fp),
        "missed": sorted(f"{a} <-> {b} ({want[(a, b)]['relationship']})" for a, b in fn),
        "found_only_by_exact_tier": len(exact_only & set(tp)),
    }


def evaluate(case: Path, model_name: str, runs: int = 1, log=print) -> dict:
    inc = conflict.load_parties(case / "incoming.csv")
    ext = conflict.load_parties(case / "existing.csv")
    truth = json.loads((case / "truth.json").read_text())
    model = verify_model(model_name)
    log(f"{case.name}: {len(inc)} × {len(ext)} entries, {len(truth['pairs'])} true pairs; model {model.model}")
    out = []
    for n in range(runs):
        a = Identity.generate("eval-incoming.testnet", "firm", "A")
        b = Identity.generate("eval-existing.testnet", "firm", "B")
        t = time.time()
        r = local_check(inc, ext, a, b, model, contract="eval.local", log=lambda s: log("  " + s))
        rep = bundle.verify(r["bundle"], check_attestation=False)
        s = _score(r["named"], truth)
        s.update(run=n, seconds=round(time.time() - t, 1), calls=r["bundle"]["verdict"]["calls"],
                 truncated=r["bundle"]["verdict"]["truncated"], bundle_verifies=rep.passed)
        log(f"  run {n}: precision {s['precision']}, recall {s['recall']} ({s['true_positives']}/{s['truth']}), "
            f"{len(s['false_positives'])} false positive(s), bundle {'verifies' if rep.passed else 'FAILS'}")
        out.append(s)
    return {"case": case.name, "model": model.model, "engine": conflict.ENGINE, "runs": out}
