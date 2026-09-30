"""Paired analysis of E7.

The run prints per-arm counts, which is enough to see the shape but not enough
to claim a difference. Every arm was sent to the same origin in the same
session with the order randomised, so the arms are paired and the right test
is McNemar's, exactly as in E1.

Three questions, each a specific pair:

  A vs E   does the full protocol block more than nothing?          (sanity)
  A vs B   does the identity header alone block more than nothing?
  B vs E   is the identity header alone WEAKER than the full set?
  C vs E   is the metadata header alone weaker than the full set?
  B vs C   is identity a weaker trigger than metadata?

The last is the interesting one. `Signature-Input` carries no identity and no
proof - only which components are covered and a key identifier. If it is a
stronger trigger than `Signature-Agent`, which carries the operator's URL, then
whatever is matching is not reading identity at all.

Reads existing results. Sends no traffic.

    python decompose_analyze.py
"""
from __future__ import annotations

import glob
import json
from math import comb

ARMS = ["A none", "B agent only", "C input only", "D proof no agent",
        "E full valid"]


def mcnemar(rows, x, y):
    """Exact two-sided McNemar on blocked/not-blocked between two arms."""
    b = sum(1 for r in rows if r[x] != "blocked" and r[y] == "blocked")
    c = sum(1 for r in rows if r[x] == "blocked" and r[y] != "blocked")
    n = b + c
    if not n:
        return b, c, 1.0
    k = min(b, c)
    return b, c, min(1.0, 2 * sum(comb(n, i) for i in range(k + 1)) / (2 ** n))


def wilson(k, n, z=1.96):
    if not n:
        return 0.0, 0.0
    from math import sqrt
    p = k / n
    d = 1 + z * z / n
    centre = p + z * z / (2 * n)
    m = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (centre - m) / d), min(1.0, (centre + m) / d)


def main():
    files = sorted(glob.glob("results/decompose/decompose_*.json"))
    if not files:
        print("no decompose results")
        return 1
    d = json.load(open(files[-1], encoding="utf-8"))
    rows = d["rows"]
    clean = [r for r in rows if all(r.get(a) not in (None, "error")
                                    for a in ARMS)]
    print("file   : " + files[-1])
    print("origins: %d   all arms clean: %d (%.1f%%)"
          % (len(rows), len(clean), 100 * len(clean) / len(rows) if rows else 0))
    if not clean:
        return 1

    n = len(clean)
    print()
    print("=" * 72)
    print("BLOCK RATE BY ARM")
    print("=" * 72)
    print("  %-22s %7s %9s   %s" % ("arm", "blocked", "rate", "95% CI"))
    counts = {}
    for a in ARMS:
        k = sum(1 for r in clean if r[a] == "blocked")
        counts[a] = k
        lo, hi = wilson(k, n)
        print("  %-22s %7d %8.2f%%   %.2f%%-%.2f%%"
              % (a, k, 100 * k / n, 100 * lo, 100 * hi))

    print()
    print("=" * 72)
    print("PAIRED COMPARISONS  (McNemar exact, same origins)")
    print("=" * 72)
    pairs = [("A none", "E full valid", "does the protocol block at all?"),
             ("A none", "B agent only", "identity header alone vs nothing"),
             ("A none", "C input only", "metadata header alone vs nothing"),
             ("B agent only", "E full valid", "is identity alone weaker?"),
             ("C input only", "E full valid", "is metadata alone weaker?"),
             ("D proof no agent", "E full valid", "does removing identity matter?"),
             ("B agent only", "C input only", "identity vs metadata")]
    for x, y, q in pairs:
        b, c, p = mcnemar(clean, x, y)
        print("  %-40s b=%-4d c=%-4d p=%.4g" % (q, b, c, p))
        print("      %s -> %s" % (x, y))

    print()
    print("=" * 72)
    print("READING")
    print("=" * 72)
    a, b_, c_, dd, e = (counts[k] for k in ARMS)
    print("  Every arm below carries ONLY our own identity and our own key.")
    print()
    if e:
        print("  Signature-Agent alone reproduces %.1f%% of the full effect."
              % (100 * b_ / e))
        print("  Signature-Input alone reproduces %.1f%%." % (100 * c_ / e))
        print("  Signature+Input, no identity, reproduces %.1f%%."
              % (100 * dd / e))
    print("  Baseline with no protocol headers: %.2f%% (%d/%d)."
          % (100 * a / n, a, n))
    print()
    _, _, p_bc = mcnemar(clean, "B agent only", "C input only")
    if c_ > b_ and p_bc < 0.05:
        print("  The METADATA header is a significantly stronger trigger than")
        print("  the IDENTITY header (p=%.3g). Signature-Input carries no" % p_bc)
        print("  operator URL and no proof - only covered components and a key")
        print("  identifier. Whatever matches is therefore not reading identity.")
    elif p_bc >= 0.05:
        print("  Identity and metadata headers are indistinguishable as")
        print("  triggers (p=%.3g). Any one protocol header name suffices." % p_bc)
    print()
    print("  Compare E1b's decoy arm: headers of the same shape and size with")
    print("  unrelated names blocked 5 of 94 (5.3%), against 88 of 94 (93.6%)")
    print("  for Web Bot Auth names carrying garbage. The trigger is the NAMES,")
    print("  not header novelty, and one name is enough.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
