"""E6 - probe the admitted population's directories directly.

Our census walks Tranco apexes and found 12 operators. Cloudflare's verified
bot directory lists 90 Web Bot Auth entries, most on service subdomains an
apex census can never reach. Those 90 URLs are published, so the population
the census cannot discover can still be measured - directly, one GET each.

This is the admitted population: operators already on the list that grants
access. Everything the paper says about conformance and declarations rests on
n=12 drawn from the *undiscovered* side. This gives up to n=90 from the
admitted side, and the two can be compared.

What is checked, and why each matters:

  media type      the specification defines one; our own GitHub Pages
                  deployment fails it, so it is a fair test of how easy it is
  purpose         registry draft field; 3 of 11 publish it in our census
  behavioural     rate-expectation, rate-control, rfc9309-compliance,
  declarations    expected-user-agent, targeted-content, trigger - the fields
                  that would justify admission. 0 of 11 in our census.
  key algorithm   the profile requires OKP/Ed25519
  nbf / exp       key validity windows; 2 of 11 use them, wildly differently
  key reuse       the draft forbids sharing a signing key across purposes, so
                  a thumbprint appearing at two operators is a finding

One request per URL, 1/s, contact in the User-Agent. ~90 requests.

    python admitted_probe.py --contact you@example.org --info-url https://s/
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402

from wba.keys import thumbprint_of_jwk  # noqa: E402

OUT = Path("results/admitted")
DIRECTORY = Path("data/cf_bot_directory.json")

DEFINED_TYPE = "application/http-message-signatures-directory+json"

# The registry draft's behavioural fields - the ones that would say what an
# operator intends to do with the access it has been granted.
BEHAVIOURAL = ("rate-expectation", "rate_expectation", "rate-control",
               "rate_control", "rfc9309-compliance", "rfc9309_compliance",
               "expected-user-agent", "expected_user_agent",
               "targeted-content", "targeted_content", "trigger")
DESCRIPTIVE = ("purpose", "signature_agent", "signature-agent", "contact",
               "operator", "client_id", "client_name", "client_uri")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--contact", required=True)
    ap.add_argument("--info-url", required=True)
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    if "@" not in args.contact or not args.info_url.startswith("https://"):
        print("--contact must be a monitored address, --info-url an https page")
        return 1
    if not DIRECTORY.exists():
        print("missing " + str(DIRECTORY))
        return 1

    entries = [e for e in json.load(DIRECTORY.open(encoding="utf-8"))
               if e.get("signatureAgentUrl")]
    # One probe per distinct URL; several Bedrock entries share a pattern but
    # not a host, and each is its own deployment.
    seen, targets = set(), []
    for e in entries:
        u = e["signatureAgentUrl"].strip()
        if u not in seen:
            seen.add(u)
            targets.append(e)
    if args.limit:
        targets = targets[:args.limit]

    session = requests.Session()
    session.headers["User-Agent"] = (
        "wba-admitted-probe/0.1 (+" + args.info_url + "; academic measurement "
        "of published key directories; one request per operator; contact: "
        + args.contact + ")")

    print("probing " + str(len(targets)) + " published signature agent URLs")
    print()

    rows = []
    for i, e in enumerate(targets, 1):
        url = e["signatureAgentUrl"].strip()
        rec = {"name": e.get("name"), "operator": e.get("operator"),
               "category": e.get("category"),
               "follows_robots_recorded": e.get("followsRobotsTxt"),
               "url": url, "host": (urlsplit(url).netloc or "").lower()}
        try:
            r = session.get(url, timeout=args.timeout)
            rec["status"] = r.status_code
            rec["content_type"] = r.headers.get("Content-Type", "")
            rec["conformant_media_type"] = DEFINED_TYPE in rec["content_type"]
            rec["bytes"] = len(r.content)
            try:
                j = r.json()
            except ValueError:
                j = None
                rec["error"] = "not_json"
            if isinstance(j, dict):
                keys = j.get("keys") or []
                rec["key_count"] = len(keys)
                rec["top_level"] = sorted(k for k in j if k != "keys")
                rec["descriptive"] = sorted(k for k in j if k in DESCRIPTIVE)
                rec["behavioural"] = sorted(k for k in j if k in BEHAVIOURAL)
                rec["purpose"] = j.get("purpose")
                rec["algs"] = sorted({
                    str(k.get("kty")) + "/" + str(k.get("crv")) for k in keys})
                rec["thumbprints"] = []
                for k in keys:
                    try:
                        rec["thumbprints"].append(thumbprint_of_jwk(k))
                    except Exception:
                        pass
                rec["has_exp"] = any("exp" in k for k in keys)
                rec["has_nbf"] = any("nbf" in k for k in keys)
        except requests.RequestException as ex:
            rec["error"] = type(ex).__name__
        rows.append(rec)
        flag = rec.get("error") or rec.get("status")
        print("  %3d/%d  %-40s %-6s keys=%-3s %s"
              % (i, len(targets), rec["host"][:40], flag,
                 rec.get("key_count", "-"),
                 ",".join(rec.get("behavioural") or []) or
                 (rec.get("purpose") or "")))
        time.sleep(args.delay)

    OUT.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    (OUT / ("admitted_" + stamp + ".json")).write_text(
        json.dumps({"collected_utc": stamp, "rows": rows}, indent=2),
        encoding="utf-8")

    live = [r for r in rows if r.get("key_count") is not None]
    print()
    print("=" * 70)
    print("THE ADMITTED POPULATION")
    print("=" * 70)
    print("  probed              : %d" % len(rows))
    print("  served a directory  : %d" % len(live))
    err = Counter(r.get("error") or ("http_" + str(r.get("status")))
                  for r in rows if r.get("key_count") is None)
    if err:
        print("  unreachable/invalid : %s" % dict(err))

    if not live:
        return 0

    print()
    print("  CONFORMANCE")
    ct = sum(1 for r in live if r.get("conformant_media_type"))
    print("    defined media type      %3d / %d  (%.1f%%)"
          % (ct, len(live), 100 * ct / len(live)))
    algs = Counter(a for r in live for a in (r.get("algs") or []))
    print("    key algorithms          %s" % dict(algs))
    print("    keys with exp           %3d / %d"
          % (sum(1 for r in live if r.get("has_exp")), len(live)))
    print("    keys with nbf           %3d / %d"
          % (sum(1 for r in live if r.get("has_nbf")), len(live)))

    print()
    print("  DECLARATIONS")
    beh = [r for r in live if r.get("behavioural")]
    print("    ANY behavioural field   %3d / %d" % (len(beh), len(live)))
    for r in beh:
        print("       %-34s %s" % (r["host"][:34], r["behavioural"]))
    pur = [r for r in live if r.get("purpose")]
    print("    purpose published       %3d / %d  (%.1f%%)"
          % (len(pur), len(live), 100 * len(pur) / len(live)))
    print("    purpose values          %s"
          % dict(Counter(str(r["purpose"])[:24] for r in pur)))
    other = Counter(k for r in live for k in (r.get("top_level") or []))
    print("    all top-level fields    %s" % dict(other))

    print()
    print("  KEY REUSE  (draft s5.6 forbids sharing a key across purposes)")
    owners = defaultdict(set)
    for r in live:
        for t in r.get("thumbprints") or []:
            owners[t].add(r["host"])
    shared = {t: h for t, h in owners.items() if len(h) > 1}
    print("    distinct keys           %d" % len(owners))
    print("    keys at >1 host         %d" % len(shared))
    for t, h in list(shared.items())[:15]:
        print("       %s  %s" % (t[:20], sorted(h)))

    print()
    print("  ROBOTS.TXT, as the directory records it, vs what they publish")
    rt = Counter(r.get("follows_robots_recorded") for r in live)
    print("    recorded true/false     %s" % dict(rt))
    both = [r for r in live
            if r.get("follows_robots_recorded") and r.get("behavioural")]
    print("    recorded true AND publishing a behavioural field: %d" % len(both))

    print()
    print("written: " + str(OUT) + "/admitted_" + stamp + ".json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
