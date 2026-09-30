"""E1c - what changes in the response body when a request is signed?

The headline result counts outcome transitions: served -> blocked. That is the
coarsest possible view of a response. Every observation in the E1 stream also
carries `bytes` and `latency_ms`, which were recorded but never analysed.

Two questions the outcome codes cannot answer:

  1. Among origins that served BOTH arms, does the signed arm get a
     *different response*? A systematically smaller body would mean silent
     degradation - content withheld from declared agents without any status
     code saying so. That is invisible to every outcome-based measurement,
     including ours until now.

  2. Does signing cost latency? A signed request that is routed through an
     extra verification path should be measurably slower.

Both are within-origin comparisons on the same pairs, so origin heterogeneity
(page size varies enormously across the web) cancels out.

Reads existing results. Sends no traffic.

    python content_diff.py
    python content_diff.py --stream results/differential/e1_stream_XXX.jsonl
"""
from __future__ import annotations

import argparse
import glob
import json
import statistics
from collections import Counter
from math import comb, sqrt


def sign_test(pairs):
    """Exact two-sided sign test on (a, b) pairs. Ties dropped."""
    pos = sum(1 for a, b in pairs if b > a)
    neg = sum(1 for a, b in pairs if b < a)
    n = pos + neg
    if not n:
        return pos, neg, 1.0
    k = min(pos, neg)
    p = min(1.0, 2 * sum(comb(n, i) for i in range(k + 1)) / (2 ** n))
    return pos, neg, p


def wilcoxon_z(pairs):
    """Normal-approximation Wilcoxon signed-rank. Reported alongside the sign
    test because the sign test ignores magnitude and n here is large."""
    d = [b - a for a, b in pairs if b != a]
    if len(d) < 10:
        return None, None
    ranks = sorted(range(len(d)), key=lambda i: abs(d[i]))
    r = [0.0] * len(d)
    i = 0
    while i < len(ranks):
        j = i
        while j + 1 < len(ranks) and abs(d[ranks[j + 1]]) == abs(d[ranks[i]]):
            j += 1
        avg = (i + j) / 2 + 1
        for k in range(i, j + 1):
            r[ranks[k]] = avg
        i = j + 1
    w_pos = sum(r[i] for i in range(len(d)) if d[i] > 0)
    n = len(d)
    mu = n * (n + 1) / 4
    sd = sqrt(n * (n + 1) * (2 * n + 1) / 24)
    if sd == 0:
        return None, None
    z = (w_pos - mu) / sd
    # two-sided normal tail
    p = 2 * (1 - 0.5 * (1 + _erf(abs(z) / sqrt(2))))
    return z, max(p, 0.0)


def _erf(x):
    # Abramowitz-Stegun 7.1.26
    s = 1 if x >= 0 else -1
    x = abs(x)
    t = 1 / (1 + 0.3275911 * x)
    y = 1 - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741)
              * t - 0.284496736) * t + 0.254829592) * t * 2.718281828459045 ** (-x * x)
    return s * y


def vals_of(obs, field):
    """Every repetition's value for one arm, missing ones dropped.

    Deliberately NOT collapsed to a median. With two repetitions the median
    is the mean, so a single flaky fetch halves the number and manufactures
    an apparent 50% shrinkage. That artifact produced five false positives
    on the first pass of this analysis; the fix is to keep the repetitions
    apart and demand consistency instead of averaging over it.
    """
    return [o[field] for o in obs if o.get(field) is not None]


def median_of(obs, field):
    vals = vals_of(obs, field)
    return statistics.median(vals) if vals else None


def real_2xx(o):
    """A 2xx that actually carried a document.

    `202 Accepted` with a zero-length body is not a served page - it is an
    acknowledgement. The outcome coder scores any 2xx as `served`, which is
    right for transitions and wrong for content comparison.
    """
    return (o.get("status") is not None and 200 <= o["status"] < 300
            and (o.get("bytes") or 0) > 0)


def cdn_of(row):
    for o in row.get("A", []) + row.get("B", []):
        h = o.get("bot_headers") or {}
        if "cf-ray" in h or "cf-mitigated" in h:
            return "Cloudflare"
        srv = (h.get("server") or "").lower()
        if "cloudflare" in srv:
            return "Cloudflare"
        if "akamai" in srv:
            return "Akamai"
    return "other"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stream", default=None)
    ap.add_argument("--min-bytes", type=int, default=512,
                    help="ignore pairs where both bodies are tiny; a 12-byte "
                         "difference on a 40-byte body is noise, not content")
    ap.add_argument("--tol", type=float, default=0.02,
                    help="fractional size change below which a pair counts as "
                         "unchanged (pages carry nonces, timestamps, ads)")
    args = ap.parse_args()

    path = args.stream
    if not path:
        cands = sorted(glob.glob("results/differential/e1_stream_*.jsonl"),
                       key=lambda p: len(open(p, "rb").read(1)) and p)
        cands = sorted(glob.glob("results/differential/e1_stream_*.jsonl"))
        if not cands:
            print("no E1 stream found")
            return 1
        path = max(cands, key=lambda p: __import__("os").path.getsize(p))
    print("stream: " + path)

    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    print("records: " + str(len(rows)))

    # The population for this question is narrower than for the headline
    # result: both arms must have been SERVED. A blocked arm's body is a
    # block page, and comparing its size to a real page measures nothing.
    served = [r for r in rows
              if r.get("outcome_A") == "served" and r.get("outcome_B") == "served"]
    print("both arms served: " + str(len(served)))

    size_pairs, lat_pairs, per_host = [], [], []
    for r in served:
        # content comparison uses only observations that carried a document
        ga = [o for o in r["A"] if real_2xx(o)]
        gb = [o for o in r["B"] if real_2xx(o)]
        sa = median_of(ga, "bytes") if ga else None
        sb = median_of(gb, "bytes") if gb else None
        la, lb = median_of(r["A"], "latency_ms"), median_of(r["B"], "latency_ms")
        if sa is not None and sb is not None and max(sa, sb) >= args.min_bytes:
            size_pairs.append((sa, sb))
            per_host.append((r["host"], sa, sb, cdn_of(r)))
        if la is not None and lb is not None:
            lat_pairs.append((la, lb))

    print()
    print("=" * 66)
    print("RESPONSE SIZE  (both arms served, body >= %d bytes)" % args.min_bytes)
    print("=" * 66)
    print("comparable pairs: " + str(len(size_pairs)))
    if size_pairs:
        # Classify by fractional change, not raw bytes: a 2KB swing means
        # something different on a 5KB page than on a 2MB one.
        smaller = bigger = same = 0
        for a, b in size_pairs:
            frac = (b - a) / a if a else 0.0
            if frac < -args.tol:
                smaller += 1
            elif frac > args.tol:
                bigger += 1
            else:
                same += 1
        n = len(size_pairs)
        print("  signed body SMALLER by >%.0f%%  : %d  (%.1f%%)"
              % (args.tol * 100, smaller, 100 * smaller / n))
        print("  signed body LARGER  by >%.0f%%  : %d  (%.1f%%)"
              % (args.tol * 100, bigger, 100 * bigger / n))
        print("  within +/-%.0f%%              : %d  (%.1f%%)"
              % (args.tol * 100, same, 100 * same / n))
        pos, neg, p = sign_test(size_pairs)
        print("  sign test  larger=%d smaller=%d  p=%.4g" % (pos, neg, p))
        z, pw = wilcoxon_z(size_pairs)
        if z is not None:
            print("  wilcoxon   z=%+.2f  p=%.4g" % (z, pw))
        print("  median A=%d  median B=%d bytes"
              % (statistics.median(a for a, _ in size_pairs),
                 statistics.median(b for _, b in size_pairs)))

    # ------------------------------------------------------------------
    # Consistent silent degradation.
    #
    # An origin counts only if EVERY signed repetition is less than half of
    # EVERY unsigned repetition, and every observation involved is a 2xx that
    # actually carried bytes. That rules out both the averaging artifact and
    # pages that are simply nondeterministic between fetches - several origins
    # vary their own unsigned arm by an order of magnitude.
    print()
    print("=" * 66)
    print("CONSISTENT SILENT DEGRADATION")
    print("  (max signed < 50% of min unsigned, across all repetitions)")
    print("=" * 66)
    degraded, flaky = [], 0
    for r in served:
        av = [o["bytes"] for o in r["A"] if real_2xx(o)]
        bv = [o["bytes"] for o in r["B"] if real_2xx(o)]
        if len(av) < 2 or len(bv) < 2:
            continue
        if min(av) < args.min_bytes:
            continue
        # an origin whose own unsigned arm swings this wide tells us nothing
        if max(av) > 3 * min(av):
            flaky += 1
            continue
        if max(bv) < 0.5 * min(av):
            degraded.append((r["host"], av, bv, cdn_of(r)))
    print("  origins meeting the rule : %d" % len(degraded))
    print("  excluded, unsigned arm itself unstable : %d" % flaky)
    for h, av, bv, c in sorted(degraded, key=lambda t: max(t[2]) / min(t[1])):
        print("    %-28s unsigned %s  signed %s  %s"
              % (h[:28], av, bv, c))
    if degraded:
        print()
        print("  These origins return HTTP 200 with a near-empty body to the")
        print("  signed request, twice, while serving the full page to the")
        print("  unsigned one, twice. A refusal that no status code records.")
        print("  Outcome-based measurement - including our own headline")
        print("  result - cannot see this. It is a floor, not an estimate.")

    print()
    print("=" * 66)
    print("LATENCY  (both arms served)")
    print("=" * 66)
    print("comparable pairs: " + str(len(lat_pairs)))
    if lat_pairs:
        pos, neg, p = sign_test(lat_pairs)
        print("  signed SLOWER: %d   signed FASTER: %d   sign test p=%.4g"
              % (pos, neg, p))
        print("  median A=%.0f ms  median B=%.0f ms"
              % (statistics.median(a for a, _ in lat_pairs),
                 statistics.median(b for _, b in lat_pairs)))
        deltas = sorted(b - a for a, b in lat_pairs)
        print("  median paired delta: %+.0f ms" % statistics.median(deltas))
        z, pw = wilcoxon_z(lat_pairs)
        if z is not None:
            print("  wilcoxon   z=%+.2f  p=%.4g" % (z, pw))

    print()
    print("=" * 66)
    print("READING")
    print("=" * 66)
    if size_pairs:
        pos, neg, p = sign_test(size_pairs)
        n = len(size_pairs)
        if p < 0.01 and neg > pos:
            print("  Among origins that served BOTH arms, the signed response is")
            print("  systematically SMALLER. Some origins degrade content for")
            print("  declared agents without ever returning an error status - a")
            print("  form of refusal invisible to outcome-based measurement.")
        elif p < 0.01 and pos > neg:
            print("  Signed responses are systematically LARGER. Check whether")
            print("  this is a challenge/interstitial page rather than content.")
        else:
            print("  No systematic size difference among served pairs (p=%.3g)."
                  % p)
            print("  Origins that serve a signed request serve it the same content.")
            print("  This MATTERS: it means the effect measured in E1 is a clean")
            print("  binary - admitted or refused - with no hidden middle ground")
            print("  of quiet degradation. The refusal is honest.")
    print()
    print("  Caveat: body size is a proxy for content. Two pages of identical")
    print("  length can differ entirely, and dynamic pages vary between any two")
    print("  fetches. The %.0f%% tolerance absorbs ordinary variation but this"
          % (args.tol * 100))
    print("  cannot detect a same-size substitution.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
