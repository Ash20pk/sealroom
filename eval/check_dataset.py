#!/usr/bin/env python3
"""Validate the Sealroom conflict-matching eval cases in eval/<case>/.

Checks per case:
  - CSV header is exactly name,role,aliases,related; roles are client|adverse
  - names are non-empty and unique within each CSV (also after normalisation)
  - every truth.json name exists verbatim in the matching CSV
  - relationship / difficulty values are valid, no pair duplicated
  - hard negatives reference real rows and are disjoint from the pairs
  - prompt-injection rows never appear in pairs or hard negatives
  - every cross-list exact-normalised name match is labelled same_entity
  - every relationship type is present; hard-negative minimums are met
Exits non-zero on any failure.
"""
import csv
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HEADER = ["name", "role", "aliases", "related"]
ROLES = {"client", "adverse"}
RELATIONSHIPS = ["same_entity", "former_name", "parent_subsidiary", "affiliate", "shared_officer"]
DIFFICULTIES = {"easy", "medium", "hard"}
CASES = {"small": 15, "medium": 40, "hard": 30}  # case -> minimum hard negatives
INJECTION_MARKERS = re.compile(
    r"ignore (all |any |your |previous|prior)|disregard|system override|system:|instructions|note to matcher",
    re.I,
)

# Trailing legal-form tokens stripped for the "exact match" definition.
SUFFIXES = {
    "inc", "incorporated", "ltd", "limited", "llc", "llp", "lp", "gmbh", "plc", "ag", "sa",
    "sas", "sarl", "co", "corp", "corporation", "company", "bv", "nv", "kk", "kg", "ltda",
    "pvt", "private", "pty", "pte", "as", "asa", "spa", "sro", "kabushiki", "kaisha",
}


def norm(name):
    """Lowercase, drop dots, punctuation -> space, strip trailing legal suffixes."""
    s = name.lower().replace(".", "")
    s = re.sub(r"[\W_]+", " ", s).strip()
    toks = s.split()
    while toks and toks[-1] in SUFFIXES:
        toks.pop()
    return " ".join(toks)


def is_exact(a, b):
    return norm(a) == norm(b)


def load_csv(path, errors):
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    if not rows or rows[0] != HEADER:
        errors.append(f"{path}: bad header {rows[0] if rows else None}")
        return []
    out = []
    for i, r in enumerate(rows[1:], start=2):
        if len(r) != 4:
            errors.append(f"{path}:{i}: expected 4 fields, got {len(r)}")
            continue
        d = dict(zip(HEADER, r))
        if not d["name"].strip():
            errors.append(f"{path}:{i}: empty name")
        if d["role"] not in ROLES:
            errors.append(f"{path}:{i}: bad role {d['role']!r}")
        out.append(d)
    names = [d["name"] for d in out]
    seen, nseen = set(), {}
    for n in names:
        if n in seen:
            errors.append(f"{path}: duplicate name {n!r}")
        seen.add(n)
        k = norm(n)
        if k in nseen and nseen[k] != n:
            errors.append(f"{path}: names collide after normalisation: {nseen[k]!r} / {n!r}")
        nseen[k] = n
    return out


def is_injection(row):
    return bool(INJECTION_MARKERS.search(row["name"]) or INJECTION_MARKERS.search(row["related"]))


def check_case(case, min_neg):
    errors = []
    d = os.path.join(HERE, case)
    inc = load_csv(os.path.join(d, "incoming.csv"), errors)
    exi = load_csv(os.path.join(d, "existing.csv"), errors)
    with open(os.path.join(d, "truth.json"), encoding="utf-8") as f:
        truth = json.load(f)
    inc_by = {r["name"]: r for r in inc}
    ex_by = {r["name"]: r for r in exi}

    pairs = truth.get("pairs", [])
    negs = truth.get("hard_negatives", [])
    pair_keys = set()
    rel_counts = {r: 0 for r in RELATIONSHIPS}
    exact = 0
    for p in pairs:
        for k in ("incoming", "existing", "relationship", "difficulty", "note"):
            if k not in p:
                errors.append(f"{case}: pair missing {k}: {p}")
        if p.get("incoming") not in inc_by:
            errors.append(f"{case}: pair incoming not in CSV: {p.get('incoming')!r}")
        if p.get("existing") not in ex_by:
            errors.append(f"{case}: pair existing not in CSV: {p.get('existing')!r}")
        if p.get("relationship") not in RELATIONSHIPS:
            errors.append(f"{case}: bad relationship {p.get('relationship')!r}")
        else:
            rel_counts[p["relationship"]] += 1
        if p.get("difficulty") not in DIFFICULTIES:
            errors.append(f"{case}: bad difficulty {p.get('difficulty')!r}")
        key = (p.get("incoming"), p.get("existing"))
        if key in pair_keys:
            errors.append(f"{case}: duplicated pair {key}")
        pair_keys.add(key)
        if p.get("relationship") == "same_entity" and is_exact(*key):
            exact += 1
        for side, by in (("incoming", inc_by), ("existing", ex_by)):
            row = by.get(p.get(side))
            if row and is_injection(row):
                errors.append(f"{case}: injection row in pairs: {row['name']!r}")

    neg_keys = set()
    for n in negs:
        key = (n.get("incoming"), n.get("existing"))
        if not n.get("why_not"):
            errors.append(f"{case}: hard negative missing why_not: {key}")
        if key[0] not in inc_by:
            errors.append(f"{case}: hard negative incoming not in CSV: {key[0]!r}")
        if key[1] not in ex_by:
            errors.append(f"{case}: hard negative existing not in CSV: {key[1]!r}")
        if key in neg_keys:
            errors.append(f"{case}: duplicated hard negative {key}")
        neg_keys.add(key)
        if key in pair_keys:
            errors.append(f"{case}: hard negative also in pairs: {key}")
        for side, by in (("incoming", inc_by), ("existing", ex_by)):
            row = by.get(n.get(side))
            if row and is_injection(row):
                errors.append(f"{case}: injection row in hard negatives: {row['name']!r}")

    # Any cross-list exact-normalised collision must be a labelled same_entity pair.
    ex_norm = {}
    for r in exi:
        ex_norm.setdefault(norm(r["name"]), []).append(r["name"])
    same = {(p["incoming"], p["existing"]) for p in pairs if p.get("relationship") == "same_entity"}
    for r in inc:
        for e in ex_norm.get(norm(r["name"]), []):
            if (r["name"], e) not in same:
                errors.append(f"{case}: unlabelled exact match {r['name']!r} ~ {e!r}")

    for rel, c in rel_counts.items():
        if c == 0:
            errors.append(f"{case}: no pairs of type {rel}")
    if len(negs) < min_neg:
        errors.append(f"{case}: only {len(negs)} hard negatives (< {min_neg})")

    inj = sum(is_injection(r) for r in inc) + sum(is_injection(r) for r in exi)
    if not 2 <= inj <= 3:
        errors.append(f"{case}: expected 2-3 injection rows, found {inj}")

    pos_inc = len({p["incoming"] for p in pairs})
    stats = {
        "incoming": len(inc),
        "existing": len(exi),
        "pairs": len(pairs),
        "by_type": rel_counts,
        "exact_same_entity": exact,
        "hard_negatives": len(negs),
        "injection_rows": inj,
        "positive_incoming_pct": round(100.0 * pos_inc / max(1, len(inc)), 1),
    }
    return errors, stats


def main():
    all_errors = []
    for case, min_neg in CASES.items():
        errors, s = check_case(case, min_neg)
        all_errors += errors
        bt = ", ".join(f"{k}={v}" for k, v in s["by_type"].items())
        print(
            f"[{case}] incoming={s['incoming']} existing={s['existing']} pairs={s['pairs']} "
            f"({bt}) exact_same_entity={s['exact_same_entity']}/{s['by_type']['same_entity']} "
            f"hard_negatives={s['hard_negatives']} injections={s['injection_rows']} "
            f"positive_incoming={s['positive_incoming_pct']}%"
        )
    if all_errors:
        print(f"\nFAILED: {len(all_errors)} problem(s)")
        for e in all_errors:
            print("  -", e)
        sys.exit(1)
    print("\nOK: all checks passed")


if __name__ == "__main__":
    main()
