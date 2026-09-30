"""Consolidate every census run into one population, with ranks and decay.

The scans accumulated across several sessions with resumes, so the raw files
overlap: `builtwith.com` appears three times in one of them. Counting records
rather than distinct hosts would inflate both the numerator and the
denominator, and the duplicates are not evenly distributed, so it would
inflate them unequally.

This deduplicates by host, restores the Tranco rank each host was drawn from
(the scan rows do not carry it), and reports density by rank decade with
Wilson intervals. It also fits the decay only if there are enough points to
fit, and says so plainly when there are not.

Reads existing results. Sends no traffic.

    python census_consolidate.py
"""
from __future__ import annotations

import glob
import json
import math
from collections import Counter
from pathlib import Path


def wilson(k, n, z=1.96):
    """Wilson score interval. Correct at the small proportions we have here,
    where the normal approximation would produce negative lower bounds."""
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (c - m) / d), min(1.0, (c + m) / d)


def load_ranks():
    """host -> best (lowest) Tranco rank."""
    ranks = {}
    p = Path("tranco.csv")
    if not p.exists():
        return ranks
    with p.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.strip().split(",")
            if len(parts) >= 2:
                try:
                    r = int(parts[0])
                except ValueError:
                    continue
                h = parts[1].strip().lower()
                if h and (h not in ranks or r < ranks[h]):
                    ranks[h] = r
    return ranks


def main():
    files = sorted(glob.glob("results/scans/scan_*.jsonl")) + \
            sorted(glob.glob("results/pilot/scan_*.jsonl"))
    if not files:
        print("no scan files")
        return 1

    # Deduplicate by host. A later observation supersedes an earlier one, but
    # a hit is never overwritten by a miss: a directory that was found once is
    # evidence it exists, and a later transient failure does not unfind it.
    best = {}
    dupes = 0
    per_file = Counter()
    for f in files:
        with open(f, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                h = (r.get("host") or "").lower()
                if not h:
                    continue
                per_file[f] += 1
                if h in best:
                    dupes += 1
                    if best[h].get("ok") and not r.get("ok"):
                        continue
                best[h] = r

    print("scan files:")
    for f in files:
        print("  %-52s %7d rows" % (f[-52:], per_file[f]))
    print()
    print("total rows          : %d" % sum(per_file.values()))
    print("duplicate host rows : %d" % dupes)
    print("DISTINCT HOSTS      : %d" % len(best))

    ranks = load_ranks()
    print("tranco ranks loaded : %d" % len(ranks))

    rows = list(best.values())
    resolvable = [r for r in rows if r.get("error") != "dns"]
    hits = [r for r in rows if r.get("ok")]
    print()
    print("resolvable          : %d" % len(resolvable))
    print("directories found   : %d" % len(hits))
    lo, hi = wilson(len(hits), len(resolvable))
    print("density             : %.4f%%  (95%% CI %.4f%%-%.4f%%)"
          % (100 * len(hits) / len(resolvable), 100 * lo, 100 * hi))

    print()
    print("=" * 72)
    print("THE OPERATORS")
    print("=" * 72)
    print("  %-6s %-28s %-6s %s" % ("rank", "host", "keys", "media type"))
    for r in sorted(hits, key=lambda x: ranks.get(x["host"].lower(), 10 ** 9)):
        h = r["host"].lower()
        print("  %-6s %-28s %-6s %s"
              % (ranks.get(h, "?"), h[:28], r.get("key_count", "?"),
                 str(r.get("content_type") or r.get("media_type") or "")[:34]))

    print()
    print("=" * 72)
    print("DENSITY BY RANK DECADE")
    print("=" * 72)
    # Log-spaced buckets: deployment is expected to concentrate at the head,
    # and equal-width buckets would put almost every host in one cell.
    bounds = [(1, 1000), (1001, 5000), (5001, 10000), (10001, 25000),
              (25001, 50000), (50001, 100000), (100001, 10 ** 9)]
    print("  %-18s %10s %8s %9s %s" % ("rank range", "resolvable", "found",
                                       "density", "95% CI"))
    pts = []
    for lo_r, hi_r in bounds:
        sub = [r for r in resolvable
               if lo_r <= ranks.get(r["host"].lower(), 10 ** 9) <= hi_r]
        if not sub:
            continue
        k = sum(1 for r in sub if r.get("ok"))
        a, b = wilson(k, len(sub))
        label = "%d-%d" % (lo_r, hi_r) if hi_r < 10 ** 9 else "%d+" % lo_r
        print("  %-18s %10d %8d %8.3f%%  %.3f%%-%.3f%%"
              % (label, len(sub), k, 100 * k / len(sub), 100 * a, 100 * b))
        if k:
            pts.append((math.sqrt(lo_r * min(hi_r, 10 ** 6)), k / len(sub)))

    print()
    print("=" * 72)
    print("DECAY")
    print("=" * 72)
    nonzero = len(pts)
    if nonzero < 4:
        print("  %d non-empty buckets. Too few to fit a decay curve, and a fit"
              % nonzero)
        print("  on this many points would be a decoration rather than a")
        print("  result. Report the table.")
    else:
        # log density ~ a + b*log rank, least squares on the non-zero buckets
        xs = [math.log10(x) for x, _ in pts]
        ys = [math.log10(y) for _, y in pts]
        n = len(xs)
        mx, my = sum(xs) / n, sum(ys) / n
        sxx = sum((x - mx) ** 2 for x in xs)
        sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
        if sxx == 0:
            print("  degenerate fit")
        else:
            b = sxy / sxx
            a = my - b * mx
            ss_t = sum((y - my) ** 2 for y in ys)
            ss_r = sum((y - (a + b * x)) ** 2 for x, y in zip(xs, ys))
            r2 = 1 - ss_r / ss_t if ss_t else float("nan")
            print("  log10(density) = %.3f %+.3f * log10(rank)" % (a, b))
            print("  slope %.3f  ->  density falls %.1fx per decade of rank"
                  % (b, 10 ** (-b)))
            print("  R^2 = %.3f  on %d buckets" % (r2, n))
            if r2 < 0.5:
                print("  Weak fit. Report the table and the slope as indicative,")
                print("  not as a law.")

    print()
    print("=" * 72)
    print("NON-RESPONSE")
    print("=" * 72)
    errs = Counter(r.get("error") or ("ok" if r.get("ok") else
                                      "http_" + str(r.get("status")))
                   for r in rows)
    for k, v in errs.most_common(12):
        print("  %-26s %7d  %5.1f%%" % (str(k)[:26], v, 100 * v / len(rows)))

    out = {"distinct_hosts": len(best), "resolvable": len(resolvable),
           "found": len(hits),
           "operators": sorted({r["host"].lower() for r in hits})}
    Path("results/census_consolidated.json").write_text(
        json.dumps(out, indent=2), encoding="utf-8")
    print()
    print("written: results/census_consolidated.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
