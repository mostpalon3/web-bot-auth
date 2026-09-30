"""E7 - which header is the bot signal?

E1 showed that a validly signed request is blocked where the identical
unsigned one is served. E1b showed that Web Bot Auth header NAMES carrying
syntactically invalid values are blocked at the same rate, so the enforcement
path is not reading the cryptography. E4 showed no origin ever fetches the
key, so it could not read the cryptography even if it wanted to.

None of that says WHICH header triggers the decision. Web Bot Auth sends
three, and they carry very different information:

  Signature-Agent   a URL naming who you are          identity
  Signature-Input   which components are covered      metadata
  Signature         the Ed25519 bytes                 the proof

If `Signature-Agent` alone reproduces the full effect, the signal is a URL in
a header - the exact user-agent-string trust the protocol was designed to
replace, wearing a different name. If the effect needs `Signature`, something
is at least looking at the shape of a proof. Nobody has separated them.

  A  no protocol headers                    control
  B  Signature-Agent only
  C  Signature-Input only
  D  Signature + Signature-Input, no agent  a proof with no identity
  E  all three, valid                       full protocol, the E1 arm

Every arm uses only our own identity and our own key. No borrowed keyids, no
third-party agent URLs: arm E of the impersonation design is deliberately
absent because sending another operator's identity to a third party attributes
our traffic to them.

Run against origins that already demonstrably react to signing, so a null
would mean something.

    python decompose.py --contact you@example.org --info-url https://study/
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402

from wba.keys import SigningKey  # noqa: E402
from wba.signature import Request, SigParams, sign  # noqa: E402

OUT = Path("results/decompose")
CHALLENGE = ("just a moment", "checking your browser", "attention required",
             "cf_chl_opt", "verifying you are human")

ARMS = ["A none", "B agent only", "C input only", "D proof no agent",
        "E full valid"]


def build(arm, key, url, agent):
    hdr_agent = '"' + agent + '"'
    if arm == "A none":
        return {}
    if arm == "B agent only":
        return {"Signature-Agent": hdr_agent}
    full = sign(key, Request("GET", url, {"Signature-Agent": hdr_agent}),
                SigParams.fresh(key.thumbprint()))
    if arm == "C input only":
        return {"Signature-Input": full["Signature-Input"]}
    if arm == "D proof no agent":
        return {"Signature": full["Signature"],
                "Signature-Input": full["Signature-Input"]}
    h = dict(full)
    h["Signature-Agent"] = hdr_agent
    return h


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


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hosts", default="blockers.txt")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--contact", required=True)
    ap.add_argument("--info-url", required=True)
    ap.add_argument("--agent",
                    default="https://wba-probe.aniksaha4049.workers.dev")
    ap.add_argument("--delay", type=float, default=0.9)
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--seed", type=int, default=20260913)
    args = ap.parse_args()

    if "@" not in args.contact or not args.info_url.startswith("https://"):
        print("--contact must be monitored, --info-url an https page")
        return 1

    key = SigningKey.from_pem("keys/research.pem")
    hosts = [h.strip() for h in
             Path(args.hosts).read_text(encoding="utf-8").splitlines()
             if h.strip() and not h.startswith("#")]
    if args.limit:
        hosts = hosts[:args.limit]

    session = requests.Session()
    session.headers["User-Agent"] = (
        "wba-decompose/0.1 (+" + args.info_url + "; academic measurement; "
        "five requests per origin; contact: " + args.contact + ")")

    rng = random.Random(args.seed)
    print("origins: %d   arms: %d   requests: %d"
          % (len(hosts), len(ARMS), len(hosts) * len(ARMS)))
    print("agent  : " + args.agent)
    print("Ctrl+C within 10 seconds to abort.")
    time.sleep(10)

    rows = []
    counts = defaultdict(Counter)
    t0 = time.time()
    for i, host in enumerate(hosts, 1):
        url = "https://" + host + "/"
        order = ARMS[:]
        rng.shuffle(order)          # arm order randomised per origin
        rec = {"host": host}
        for arm in order:
            try:
                resp = session.get(url, headers=build(arm, key, url, args.agent),
                                   timeout=args.timeout, allow_redirects=True)
            except requests.RequestException:
                resp = None
            out = classify(resp)
            rec[arm] = out
            counts[arm][out] += 1
            time.sleep(args.delay)
        rows.append(rec)
        if i % 25 == 0 or i == len(hosts):
            print("  %4d/%d  %s" % (i, len(hosts),
                                    {a: counts[a]["blocked"] for a in ARMS}))

    OUT.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    (OUT / ("decompose_" + stamp + ".json")).write_text(
        json.dumps({"collected_utc": stamp, "agent": args.agent,
                    "user_agent": session.headers["User-Agent"],
                    "rows": rows}, indent=2), encoding="utf-8")

    # Only origins where every arm produced a real answer are comparable.
    clean = [r for r in rows if all(r.get(a) != "error" for a in ARMS)]
    print()
    print("=" * 68)
    print("BLOCK RATE BY ARM   (%d origins, all arms clean)" % len(clean))
    print("=" * 68)
    res = {}
    for a in ARMS:
        b = sum(1 for r in clean if r[a] == "blocked")
        res[a] = b
        print("  %-20s %4d / %d   %6.2f%%"
              % (a, b, len(clean), 100 * b / len(clean) if clean else 0))

    print()
    print("=" * 68)
    print("READING")
    print("=" * 68)
    if not clean:
        print("  no clean origins")
        return 0
    n = len(clean)
    a, b = res["A none"], res["B agent only"]
    d, e = res["D proof no agent"], res["E full valid"]
    if e and b >= 0.9 * e:
        print("  Signature-Agent ALONE reproduces %.0f%% of the full effect."
              % (100 * b / e))
        print("  The signal is a URL in a header. The cryptographic material")
        print("  is not what the decision turns on - which is the same trust")
        print("  model as a user-agent string, under a new name.")
    elif e and d >= 0.9 * e and b < 0.5 * e:
        print("  The proof headers carry the effect and the identity header")
        print("  does not. Something is reacting to the shape of a signature")
        print("  rather than to the declared identity.")
    else:
        print("  No single header reproduces the effect on its own; the")
        print("  combination matters. Report the table.")
    print()
    print("  baseline (arm A, no protocol headers): %.2f%%" % (100 * a / n))
    print("  every rate above is measured against that on the same origins.")
    print()
    print("written: " + str(OUT) + "/decompose_" + stamp + ".json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
