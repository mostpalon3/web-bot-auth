"""E9 - is it an exact match on the registered header name?

E7 established that `Signature-Input` alone reproduces the full effect: not
the identity, not the proof, just that header. It did not establish how
precisely the name is matched, and the answer changes what the finding means.

  exact match     a literal deny-list entry keyed on the registered name.
                  The protocol's own header has been added to a bot
                  signature list.

  fuzzy match     anything signature-shaped trips it, and the finding is
                  about header heuristics rather than about Web Bot Auth.

Four arms, same origins, order randomised:

  A  nothing                                        control
  B  Signature-Input          the registered name   known ~97%
  C  X-Signature-Input        prefixed              not the registered name
  D  Signature-Inputs         one character added   near-miss

All four carry identical values where a value is sent, so the only thing
varying between B, C and D is the spelling of the header name.

If C and D fall to baseline while B stays at ceiling, the trigger is a literal
string. If they stay high, it is a heuristic and E7's reading needs softening.

    python nearmiss.py --contact you@x.org --info-url https://study/
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from collections import Counter, defaultdict
from math import comb
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402

from wba.keys import SigningKey  # noqa: E402
from wba.signature import Request, SigParams, sign  # noqa: E402

OUT = Path("results/nearmiss")
CHALLENGE = ("just a moment", "checking your browser", "attention required",
             "cf_chl_opt", "verifying you are human")

ARMS = ["A none", "B Signature-Input", "C X-Signature-Input",
        "D Signature-Inputs"]


def classify(resp):
    if resp is None:
        return "error"
    if resp.status_code in (401, 403):
        return "blocked"
    if resp.status_code == 429:
        return "rate_limited"
    if resp.status_code == 402:
        return "payment_required"
    if 200 <= resp.status_code < 300:
        if "html" in resp.headers.get("Content-Type", "").lower():
            if any(m in resp.text[:8000].lower() for m in CHALLENGE):
                return "challenged"
        return "served"
    return "http_" + str(resp.status_code)


def mcnemar(rows, x, y):
    b = sum(1 for r in rows if r[x] != "blocked" and r[y] == "blocked")
    c = sum(1 for r in rows if r[x] == "blocked" and r[y] != "blocked")
    n = b + c
    if not n:
        return b, c, 1.0
    k = min(b, c)
    return b, c, min(1.0, 2 * sum(comb(n, i) for i in range(k + 1)) / (2 ** n))


def build(arm, key, url, agent):
    if arm == "A none":
        return {}
    hdr = '"' + agent + '"'
    full = sign(key, Request("GET", url, {"Signature-Agent": hdr}),
                SigParams.fresh(key.thumbprint()))
    value = full["Signature-Input"]        # identical value in all three arms
    if arm == "B Signature-Input":
        return {"Signature-Input": value}
    if arm == "C X-Signature-Input":
        return {"X-Signature-Input": value}
    return {"Signature-Inputs": value}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hosts", default="blockers.txt")
    ap.add_argument("--limit", type=int, default=150)
    ap.add_argument("--contact", required=True)
    ap.add_argument("--info-url", required=True)
    ap.add_argument("--agent",
                    default="https://wba-probe.aniksaha4049.workers.dev")
    ap.add_argument("--delay", type=float, default=0.9)
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--seed", type=int, default=20260914)
    args = ap.parse_args()

    if "@" not in args.contact or not args.info_url.startswith("https://"):
        print("--contact must be monitored, --info-url an https page")
        return 1

    key = SigningKey.from_pem("keys/research.pem")
    hosts = [h.strip() for h in
             Path(args.hosts).read_text(encoding="utf-8").splitlines()
             if h.strip() and not h.startswith("#")][:args.limit]

    session = requests.Session()
    session.headers["User-Agent"] = (
        "wba-nearmiss/0.1 (+" + args.info_url + "; academic measurement; "
        "four requests per origin; contact: " + args.contact + ")")

    rng = random.Random(args.seed)
    print("origins %d, arms %d, requests %d"
          % (len(hosts), len(ARMS), len(hosts) * len(ARMS)))
    print("Ctrl+C within 10 seconds to abort.")
    time.sleep(10)

    rows, counts = [], defaultdict(Counter)
    for i, host in enumerate(hosts, 1):
        url = "https://" + host + "/"
        rec = {"host": host}
        order = ARMS[:]
        rng.shuffle(order)
        for arm in order:
            try:
                resp = session.get(url, headers=build(arm, key, url, args.agent),
                                   timeout=args.timeout, allow_redirects=True)
            except requests.RequestException:
                resp = None
            rec[arm] = classify(resp)
            counts[arm][rec[arm]] += 1
            time.sleep(args.delay)
        rows.append(rec)
        if i % 25 == 0 or i == len(hosts):
            print("  %4d/%d  %s" % (i, len(hosts),
                                    {a: counts[a]["blocked"] for a in ARMS}))

    OUT.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    (OUT / ("nearmiss_" + stamp + ".json")).write_text(
        json.dumps({"collected_utc": stamp, "rows": rows}, indent=2),
        encoding="utf-8")

    clean = [r for r in rows if all(r.get(a) != "error" for a in ARMS)]
    print()
    print("=" * 66)
    print("BLOCK RATE BY HEADER NAME  (%d origins clean on all arms)" % len(clean))
    print("=" * 66)
    res = {}
    for a in ARMS:
        k = sum(1 for r in clean if r[a] == "blocked")
        res[a] = k
        print("  %-24s %4d / %d   %6.2f%%"
              % (a, k, len(clean), 100 * k / len(clean) if clean else 0))

    if clean:
        print()
        print("  paired comparisons")
        for x, y in (("A none", "B Signature-Input"),
                     ("A none", "C X-Signature-Input"),
                     ("A none", "D Signature-Inputs"),
                     ("C X-Signature-Input", "B Signature-Input"),
                     ("D Signature-Inputs", "B Signature-Input")):
            b, c, p = mcnemar(clean, x, y)
            print("    %-24s -> %-22s b=%-4d c=%-4d p=%.4g" % (x, y, b, c, p))

        print()
        print("=" * 66)
        print("READING")
        print("=" * 66)
        n = len(clean)
        a_, b_, c_, d_ = (res[k] for k in ARMS)
        near_baseline = (c_ <= a_ * 2 + 3) and (d_ <= a_ * 2 + 3)
        if b_ > 0.5 * n and near_baseline:
            print("  EXACT MATCH. The registered name blocks at %.1f%%; a prefixed"
                  % (100 * b_ / n))
            print("  name blocks at %.1f%% and a one-character variant at %.1f%%,"
                  % (100 * c_ / n, 100 * d_ / n))
            print("  both at the %.1f%% baseline." % (100 * a_ / n))
            print()
            print("  The trigger is a literal deny-list entry keyed on the")
            print("  protocol's registered header name. Not a heuristic, not")
            print("  anything signature-shaped: that exact string. The header")
            print("  the specification defines has been added to a bot")
            print("  signature list.")
        elif c_ > 0.5 * n or d_ > 0.5 * n:
            print("  NOT an exact match. Variant spellings also block, so the")
            print("  trigger is a heuristic over signature-shaped headers and")
            print("  E7's reading must be softened accordingly. Report this.")
        else:
            print("  Mixed. Report the table.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
