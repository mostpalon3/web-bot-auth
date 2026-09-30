"""E5 - what does the tollbooth charge?

E1d established that every origin answering a signed request with HTTP 402 is
a People Inc. brand. The price was not recoverable: `crawler-price` was not in
E1's captured header set.

Cloudflare's pay-per-crawl carries the price in response headers on the 402.
As far as we can establish, no measurement of actual deployed prices has been
published - the mechanism is new. So capture EVERY response header on the 402,
not a whitelist, and report the distribution.

One request per origin, signed, serially. Roughly two dozen requests.

Also probes the unsigned arm at the same origins, because the finding under
test is a *difference*: the anonymous client is served while the declared one
is charged. Reconfirming that here, with full headers, makes the tollbooth
section self-contained rather than a cross-reference into E1.

    python tollbooth.py --contact you@example.org --info-url https://study/
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402

from wba.keys import SigningKey  # noqa: E402
from wba.signature import Request, SigParams, sign  # noqa: E402

OUT = Path("results/tollbooth")

# The 20 identified in E1d, plus the three that charge both arms as controls:
# if those behave identically here, the instrument is reading prices, not
# reading a signature effect that does not exist.
SIGNED_ONLY = [
    "allrecipes.com", "bhg.com", "eatingwell.com", "ew.com", "foodandwine.com",
    "health.com", "investopedia.com", "lifewire.com", "marthastewart.com",
    "people.com", "realsimple.com", "seriouseats.com", "southernliving.com",
    "thebalancemoney.com", "thespruce.com", "thoughtco.com",
    "travelandleisure.com", "treehugger.com", "verywellhealth.com",
    "verywellmind.com",
]
BOTH_ARMS = ["telegraph.co.uk", "allhen.online", "mintmanga.one"]

# Header names that plausibly carry a price or payment instruction. Matched
# loosely because the mechanism is new and the spelling is not settled.
PRICE_HINT = re.compile(
    r"crawler|price|pay|payment|402|toll|charge|cost|billing|micropay",
    re.I)


def signed_headers(key, url, agent):
    hdr = '"' + agent + '"'
    req = Request("GET", url, {"Signature-Agent": hdr})
    h = sign(key, req, SigParams.fresh(key.thumbprint()))
    h["Signature-Agent"] = hdr
    return h


def probe(session, url, headers, timeout):
    try:
        r = session.get(url, headers=headers, timeout=timeout,
                        allow_redirects=True)
    except requests.RequestException as e:
        return {"error": type(e).__name__}
    return {
        "status": r.status_code,
        "headers": dict(r.headers),          # everything, not a whitelist
        "bytes": len(r.content),
        "body_head": r.text[:600] if r.status_code == 402 else None,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--contact", required=True)
    ap.add_argument("--info-url", required=True)
    ap.add_argument("--agent",
                    default="https://wba-probe.aniksaha4049.workers.dev")
    ap.add_argument("--delay", type=float, default=1.5)
    ap.add_argument("--timeout", type=float, default=15.0)
    args = ap.parse_args()

    if "@" not in args.contact or not args.info_url.startswith("https://"):
        print("--contact must be a monitored address, --info-url an https page")
        return 1

    key = SigningKey.from_pem("keys/research.pem")
    session = requests.Session()
    session.headers["User-Agent"] = (
        "wba-tollbooth/0.1 (+" + args.info_url + "; academic measurement of "
        "pay-per-crawl pricing; two requests per origin; contact: "
        + args.contact + ")")

    hosts = [(h, "signed_only") for h in SIGNED_ONLY] + \
            [(h, "both_arms") for h in BOTH_ARMS]

    print("probing " + str(len(hosts)) + " origins, unsigned then signed")
    print()
    rows = []
    for host, group in hosts:
        url = "https://" + host + "/"
        a = probe(session, url, {}, args.timeout)
        time.sleep(args.delay)
        b = probe(session, url, signed_headers(key, url, args.agent),
                  args.timeout)
        time.sleep(args.delay)
        rows.append({"host": host, "group": group, "unsigned": a, "signed": b})

        pr = {k: v for k, v in (b.get("headers") or {}).items()
              if PRICE_HINT.search(k)}
        print("  %-24s %-6s -> %-6s  %s"
              % (host[:24], a.get("status") or a.get("error"),
                 b.get("status") or b.get("error"),
                 json.dumps(pr) if pr else ""))

    OUT.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    (OUT / ("tollbooth_" + stamp + ".json")).write_text(
        json.dumps({"collected_utc": stamp, "agent": args.agent,
                    "user_agent": session.headers["User-Agent"],
                    "rows": rows}, indent=2), encoding="utf-8")

    print()
    print("=" * 68)
    print("PRICE-BEARING HEADERS")
    print("=" * 68)
    found = Counter()
    prices = Counter()
    for r in rows:
        for arm in ("unsigned", "signed"):
            for k, v in (r[arm].get("headers") or {}).items():
                if PRICE_HINT.search(k):
                    found[k] += 1
                    prices[(k, v)] += 1
    if not found:
        print("  None. No header on any response names a price.")
        print()
        print("  That is itself reportable: the 402 is returned without a")
        print("  machine-readable price, so a crawler cannot discover the cost")
        print("  of the content it was refused. Confirm against the body text")
        print("  saved in the JSON before claiming it.")
    else:
        for k, n in found.most_common():
            print("  %-28s on %d responses" % (k, n))
        print()
        for (k, v), n in prices.most_common(30):
            print("  %-28s = %-28s x%d" % (k, str(v)[:28], n))

    print()
    print("=" * 68)
    print("DID THE SIGNATURE EFFECT REPRODUCE?")
    print("=" * 68)
    repro = sum(1 for r in rows if r["group"] == "signed_only"
                and r["signed"].get("status") == 402
                and r["unsigned"].get("status") != 402)
    still_both = sum(1 for r in rows if r["group"] == "both_arms"
                     and r["signed"].get("status") == 402
                     and r["unsigned"].get("status") == 402)
    print("  signed-only 402 reproduced : %d / %d" % (repro, len(SIGNED_ONLY)))
    print("  control origins still 402 both arms : %d / %d"
          % (still_both, len(BOTH_ARMS)))
    if repro == 0:
        print()
        print("  The effect did NOT reproduce. Either the configuration changed")
        print("  since 10 September, or it is conditional on something that")
        print("  differs between the runs. Report the non-replication; do not")
        print("  quietly keep the older number.")
    print()
    print("written: " + str(OUT) + "/tollbooth_" + stamp + ".json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
