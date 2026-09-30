"""Recompute the headline E1 numbers from the published summary.

The raw E1 file is 52 MB and is not in the repository. This reads the
reduction that is, and prints the four numbers the paper quotes, so the main
claim can be checked without trusting the write-up.

    python verify_e1.py

Expected output, which is what the paper reports:

    clean pairs      7267
    arm A blocked    1156  (15.91%)
    arm B blocked    1445  (19.88%)
    McNemar b : c    298 : 9
"""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path

SUMMARY = Path("results/differential/e1_summary.json")

# What the paper reports. Kept here so a drift in the data is a failure rather
# than a quietly different number.
EXPECTED = {"clean": 7267, "a_blocked": 1156, "b_blocked": 1445, "b": 298, "c": 9}


def exact_mcnemar(b: int, c: int) -> float:
    """Two-sided exact test on the discordant pairs.

    The chi-square form is not usable here: c is single digit, which is
    exactly where the approximation fails.
    """
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def main() -> int:
    if not SUMMARY.exists():
        print(f"missing {SUMMARY}", file=sys.stderr)
        return 2

    data = json.loads(SUMMARY.read_text(encoding="utf-8"))
    rows = data["rows"]

    # An errored arm is missing data, not an outcome. Pairs where either arm
    # errored are excluded from the paired test and the exclusion is reported.
    clean = [r for r in rows
             if r["outcome_A"] != "error" and r["outcome_B"] != "error"]

    a_blocked = sum(1 for r in clean if r["outcome_A"] == "blocked")
    b_blocked = sum(1 for r in clean if r["outcome_B"] == "blocked")
    b = sum(1 for r in clean
            if r["outcome_A"] != "blocked" and r["outcome_B"] == "blocked")
    c = sum(1 for r in clean
            if r["outcome_A"] == "blocked" and r["outcome_B"] != "blocked")

    n = len(clean)
    print(f"arms              A = {data['arms']['A']}")
    print(f"                  B = {data['arms']['B']}")
    print(f"origins probed    {len(rows)}")
    print(f"clean pairs       {n}")
    print(f"excluded          {len(rows) - n}  (at least one arm errored)")
    print(f"arm A blocked     {a_blocked}  ({100 * a_blocked / n:.2f}%)")
    print(f"arm B blocked     {b_blocked}  ({100 * b_blocked / n:.2f}%)")
    print(f"paired difference +{100 * (b_blocked - a_blocked) / n:.2f} pp")
    print(f"McNemar b : c     {b} : {c}")
    print(f"exact p           {exact_mcnemar(b, c):.3g}")

    got = {"clean": n, "a_blocked": a_blocked, "b_blocked": b_blocked,
           "b": b, "c": c}
    bad = {k: (v, EXPECTED[k]) for k, v in got.items() if v != EXPECTED[k]}
    if bad:
        print("\nMISMATCH against the published figures:")
        for k, (g, e) in bad.items():
            print(f"  {k}: got {g}, paper says {e}")
        return 1
    print("\nmatches the published figures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
