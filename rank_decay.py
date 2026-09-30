"""Deployment density as a function of site rank.

The pilot's job is not to produce a hit rate. A hit rate from the top 5,000 of
Tranco says almost nothing about the web, because the head of the list is
enriched for exactly the companies that would deploy this first. The question
that decides whether a full census is worth running is different:

    does density decay with rank, and how fast?

If it falls off a cliff by rank 50,000, the population lives in the head and a
million-host scan buys you a long tail of zeroes. If it decays slowly, the tail
holds most of the population and the full census is the study.

Joins scan output back to the Tranco ranking and reports density per rank
bucket over the *resolvable* denominator, since infrastructure domains with no
apex record can never host a directory.

    python rank_decay.py --scan results/scans/scan_<stamp>.jsonl
"""
from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path


def wilson(k: int, n: int, z: float = 1.96):
    if n == 0:
        return (0.0, 0.0)
    p, d = k / n, 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def load_ranks(path: Path) -> dict:
    ranks = {}
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for row in csv.reader(fh):
            if len(row) >= 2 and row[0].strip().isdigit():
                ranks[row[1].strip().lower()] = int(row[0])
    return ranks


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scan", required=True)
    ap.add_argument("--hosts", default="tranco.csv")
    ap.add_argument("--buckets", type=int, default=10)
    args = ap.parse_args()

    ranks = load_ranks(Path(args.hosts))
    records = []
    with open(args.scan, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            rank = ranks.get(rec["host"].lower())
            if rank:
                rec["rank"] = rank
                records.append(rec)

    if not records:
        print("no scan records could be matched to a rank")
        return

    records.sort(key=lambda r: r["rank"])
    top = max(r["rank"] for r in records)
    size = max(1, math.ceil(top / args.buckets))

    print(f"\n{Path(args.scan).name}")
    print(f"  {len(records)} records spanning ranks 1-{top}")
    print(f"  {args.buckets} buckets of {size}")
    print()

    header = f"{'rank range':<18} {'scanned':>8} {'resolvable':>11} {'found':>6} {'density':>9}  {'95% CI':<18} plot"
    print(header)
    print("-" * len(header))

    total_found = total_resolvable = 0
    for b in range(args.buckets):
        lo, hi = b * size + 1, (b + 1) * size
        chunk = [r for r in records if lo <= r["rank"] <= hi]
        if not chunk:
            continue
        resolvable = [r for r in chunk if r["error"] != "dns"]
        found = [r for r in chunk if r["ok"]]
        n, k = len(resolvable), len(found)
        total_found += k
        total_resolvable += n
        density = k / n if n else 0.0
        clo, chi = wilson(k, n)
        bar = "#" * min(40, int(density * 4000))
        print(f"{lo:>7}-{hi:<10} {len(chunk):>8} {n:>11} {k:>6} "
              f"{density:>8.4%}  [{clo:.4%}, {chi:.4%}]  {bar}")

    print("-" * len(header))
    overall = total_found / total_resolvable if total_resolvable else 0
    olo, ohi = wilson(total_found, total_resolvable)
    print(f"{'overall':<18} {len(records):>8} {total_resolvable:>11} "
          f"{total_found:>6} {overall:>8.4%}  [{olo:.4%}, {ohi:.4%}]")

    print("\nhits, by rank")
    for r in [x for x in records if x["ok"]]:
        declared = "card" if r.get("declared") else "bare JWKS - no declarations"
        print(f"  {r['rank']:>7}  {r['host']:<38} {r['shape']:<12} {declared}")

    print("\nProjection to 1M is extrapolation, not measurement. Density in the")
    print("head of the list is not evidence about the tail; the decay curve above")
    print("is what tells you whether the tail is worth scanning.")
    if total_found < 10:
        print("\nToo few hits to fit a decay curve. Widen the pilot before deciding")
        print("on the full census - a handful of hits cannot distinguish a steep")
        print("decay from a flat one.")


if __name__ == "__main__":
    main()
