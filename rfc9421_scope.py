"""E10 - does the deny-list key on the header name, or on the tag?

Web Bot Auth is RFC 9421 plus two things: a `Signature-Agent` header, and a
`;tag="web-bot-auth"` parameter inside `Signature-Input`.

E7 and E9 both sent that tag without noticing. Our signer emits it by default
(`wba/signature.py`, `tag: Optional[str] = WEB_BOT_AUTH_TAG`), so E7's arm D -
described at the time as "a proof with no identity" - was not generic RFC 9421
at all. It carried an explicit Web Bot Auth marker in the signature
parameters. The same defect would have gone into the first version of this
script.

That leaves the important cell untested, and it decides how wide the finding
is:

  keyed on the tag     the deny-list targets Web Bot Auth specifically.
                       Other RFC 9421 users are unaffected.

  keyed on the name    the deny-list catches RFC 9421 itself, and every
                       non-bot use of HTTP Message Signatures - API
                       authentication, webhook verification, payment
                       callbacks, inter-service authorisation - is collateral.

  A  nothing                                          control
  B  Signature-Input WITH tag="web-bot-auth"          replicates E9, ~97%
  C  Signature-Input WITHOUT the tag                  generic RFC 9421
  D  Signature + Signature-Input (no tag) + digest    RFC 9421 as an API sends
                                                      it: body digest plus a
                                                      signature over it

No arm sends `Signature-Agent`. Arms C and D contain no Web Bot Auth marker of
any kind; they are indistinguishable from a signed API request.

    python rfc9421_scope.py --contact you@x.org --info-url https://study/
"""
from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
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

OUT = Path("results/rfc9421")
CHALLENGE = ("just a moment", "checking your browser", "attention required",
             "cf_chl_opt", "verifying you are human")

ARMS = ["A none", "B Input with tag", "C Input no tag", "D RFC9421 API shape"]


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


def build(arm, key, url):
    """Arms C and D carry NO Web Bot Auth marker: no Signature-Agent, and
    tag=None so the signature parameters do not name the protocol either."""
    if arm == "A none":
        return {}
    tagged = SigParams.fresh(key.thumbprint())
    untagged = dataclasses.replace(tagged, tag=None)
    req = Request("GET", url, {})
    if arm == "B Input with tag":
        h = sign(key, req, tagged)
        return {"Signature-Input": h["Signature-Input"]}
    h = sign(key, req, untagged)
    if arm == "C Input no tag":
        return {"Signature-Input": h["Signature-Input"]}
    digest = base64.b64encode(hashlib.sha256(b"").digest()).decode()
    return {"Signature": h["Signature"],
            "Signature-Input": h["Signature-Input"],
            "Content-Digest": "sha-256=:" + digest + ":"}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hosts", default="blockers.txt")
    ap.add_argument("--limit", type=int, default=150)
    ap.add_argument("--contact", required=True)
    ap.add_argument("--info-url", required=True)
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
        "wba-rfc9421-scope/0.1 (+" + args.info_url + "; academic measurement; "
        "four requests per origin; contact: " + args.contact + ")")

    rng = random.Random(args.seed)
    print("origins %d, arms %d, requests %d"
          % (len(hosts), len(ARMS), len(hosts) * len(ARMS)))
    print("No Signature-Agent is sent by any arm: this is base RFC 9421.")
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
                resp = session.get(url, headers=build(arm, key, url),
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
    (OUT / ("rfc9421_" + stamp + ".json")).write_text(
        json.dumps({"collected_utc": stamp, "rows": rows}, indent=2),
        encoding="utf-8")

    clean = [r for r in rows if all(r.get(a) != "error" for a in ARMS)]
    print()
    print("=" * 66)
    print("BLOCK RATE  (%d origins clean on all arms)" % len(clean))
    print("=" * 66)
    res = {}
    for a in ARMS:
        k = sum(1 for r in clean if r[a] == "blocked")
        res[a] = k
        print("  %-24s %4d / %d   %6.2f%%"
              % (a, k, len(clean), 100 * k / len(clean) if clean else 0))
    if not clean:
        return 0

    print()
    print("  paired")
    for x, y in (("A none", "B Input with tag"),
                 ("A none", "C Input no tag"),
                 ("A none", "D RFC9421 API shape"),
                 ("C Input no tag", "B Input with tag")):
        b, c, p = mcnemar(clean, x, y)
        print("    %-22s -> %-20s b=%-4d c=%-4d p=%.4g" % (x, y, b, c, p))

    n = len(clean)
    a_, b_, c_, d_ = (res[k] for k in ARMS)
    print()
    print("=" * 66)
    print("READING")
    print("=" * 66)
    if c_ > 0.5 * n:
        print("  KEYED ON THE HEADER NAME, NOT THE TAG.")
        print()
        print("  A signed request carrying no Web Bot Auth marker of any kind -")
        print("  no Signature-Agent, no tag - is blocked at %.2f%% against a"
              % (100 * c_ / n))
        print("  %.2f%% baseline. In the shape an API or webhook actually sends"
              % (100 * a_ / n))
        print("  it, with a Content-Digest: %.2f%%." % (100 * d_ / n))
        print()
        print("  The deny-list does not target Web Bot Auth. It catches RFC")
        print("  9421 itself. Every non-bot use of HTTP Message Signatures -")
        print("  API authentication, webhook verification, payment callbacks -")
        print("  is collateral at these origins.")
    elif b_ > 0.5 * n and c_ < 0.2 * n:
        print("  KEYED ON THE TAG.")
        print()
        print("  With tag=\"web-bot-auth\": %.2f%%. Without it: %.2f%%."
              % (100 * b_ / n, 100 * c_ / n))
        print("  The deny-list targets Web Bot Auth specifically, and other")
        print("  RFC 9421 users are unaffected. This NARROWS the finding, and")
        print("  it also means E7 and E9 measured the tag as much as the name -")
        print("  correct that reading rather than leaving it.")
    else:
        print("  Mixed: with tag %.2f%%, without %.2f%%, baseline %.2f%%."
              % (100 * b_ / n, 100 * c_ / n, 100 * a_ / n))
        print("  Report the table and do not force a single reading.")
    print()
    print("  NOTE: E7 arm D and all of E9 carried tag=\"web-bot-auth\" without")
    print("  it being noticed. Whatever this run shows, that is a correction")
    print("  those sections need.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
