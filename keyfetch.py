"""E4 - does any origin ever retrieve the key it would need to verify?

THE ARGUMENT
============
E1b found that origins block requests carrying Web Bot Auth header NAMES with
syntactically invalid contents at 93.6%, against 96.8% for a validly signed
request - statistically indistinguishable. The natural reading is that the
enforcement path never evaluates the cryptography. But that is an inference
from two rates, and a reviewer can propose alternatives: perhaps verification
runs and fails closed, perhaps it is cached, perhaps the invalid arm happens
to trip a different rule.

This experiment removes the inference. Verifying an RFC 9421 signature
requires the signer's public key. The only route to ours is the directory
named in the Signature-Agent header. We now serve that directory from an
origin we control and log every retrieval, with the requester's address, ASN
and User-Agent.

So we send one signed request to each origin that demonstrably reacts to
signing, and then read the log.

  at least one fetch  the origin obtained key material. Note who, and when
                      relative to the request. Verification was possible.

  zero fetches        no origin held the public key at any point. Verification
                      was not merely skipped, it was impossible. Whatever
                      admission is keyed on, it is not the signature. This is
                      a deductive result, not a statistical one.

WHY THE 298 BLOCKERS
====================
Targeting the origins that already changed behaviour when signed is the
strongest available test. A null across origins that ignore signatures
entirely would prove little; a null across the origins that provably notice
them is the whole claim.

Sends one request per origin, serially, at one per second. 298 requests.

    python keyfetch.py --agent https://wba-probe.example.workers.dev \\
        --contact you@example.org --info-url https://your.study/page
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402

from wba.keys import SigningKey  # noqa: E402
from wba.signature import Request, SigParams, sign  # noqa: E402

OUT = Path("results/keyfetch")
CHALLENGE = ("just a moment", "checking your browser", "attention required",
             "cf_chl_opt", "verifying you are human")


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


def signed_headers(key, url, agent_url):
    hdr = '"' + agent_url + '"'
    req = Request("GET", url, {"Signature-Agent": hdr})
    headers = sign(key, req, SigParams.fresh(key.thumbprint()))
    headers["Signature-Agent"] = hdr
    return headers


def read_hits(agent_url, token):
    """Read the Worker's fetch log. Absent a token we cannot, and say so."""
    if not token:
        return None, "no token supplied; read the log yourself or use wrangler tail"
    try:
        r = requests.get(agent_url.rstrip("/") + "/hits",
                         params={"token": token, "n": 1000}, timeout=25)
    except requests.RequestException as e:
        return None, "could not reach the log: " + str(e)
    if r.status_code == 401:
        return None, "token rejected by the Worker"
    try:
        return r.json(), None
    except ValueError:
        return None, "log endpoint did not return JSON (is the Worker deployed?)"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--agent", required=True,
                    help="the instrumented origin serving our directory")
    ap.add_argument("--hosts", default="blockers.txt")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--contact", required=True)
    ap.add_argument("--info-url", required=True)
    ap.add_argument("--token", default=None,
                    help="HITS_TOKEN, to read the fetch log afterwards")
    ap.add_argument("--settle", type=int, default=150,
                    help="seconds to wait after the last request before "
                         "reading the log; an asynchronous verifier may fetch "
                         "the key well after it answered")
    args = ap.parse_args()

    if "@" not in args.contact or not args.info_url.startswith("https://"):
        print("--contact must be a monitored address and --info-url an https page")
        return 1

    # The directory must be live and correct before we point thousands of
    # origins at it, or a null result is our own fault rather than a finding.
    key = SigningKey.from_pem("keys/research.pem")
    dir_url = args.agent.rstrip("/") + "/.well-known/http-message-signatures-directory"
    print("checking our own directory first")
    print("  " + dir_url)
    try:
        d = requests.get(dir_url, timeout=25)
        ct = d.headers.get("Content-Type", "")
        served = d.json()
    except Exception as e:
        print("  ABORT - directory is not readable: " + str(e))
        return 1
    from wba.keys import thumbprint_of_jwk
    kids = [thumbprint_of_jwk(k) for k in served.get("keys", [])]
    print("  media type : " + ct)
    print("  keyids     : " + str(kids))
    print("  our keyid  : " + key.thumbprint())
    if key.thumbprint() not in kids:
        print("  ABORT - the directory does not publish the key we sign with.")
        print("  A verifier fetching it would correctly reject us, and a null")
        print("  result would mean nothing.")
        return 1
    if "http-message-signatures-directory" not in ct:
        print("  WARNING - media type is not the one the specification defines.")
        print("  Proceeding, but note it: a strict verifier may refuse to parse.")

    # Our own address, so our preflight and any local checks can be excluded
    # from the log by something more reliable than the user-agent string.
    try:
        our_ip = requests.get("https://api64.ipify.org", timeout=20).text.strip()
    except requests.RequestException:
        our_ip = None
    print("  our address: " + str(our_ip))

    # Baseline the counter so we attribute only fetches caused by this run.
    before, err = read_hits(args.agent, args.token)
    if before:
        print("  fetches already logged: " + str(before.get("total_fetches")))
    elif err:
        print("  log not readable now (" + err + ")")

    hosts = [h.strip() for h in Path(args.hosts).read_text(encoding="utf-8").splitlines()
             if h.strip() and not h.startswith("#")]
    if args.limit:
        hosts = hosts[:args.limit]

    ua = ("wba-keyfetch/0.1 (+" + args.info_url + "; academic measurement; "
          "one request per origin; contact: " + args.contact + ")")
    session = requests.Session()
    session.headers["User-Agent"] = ua

    print()
    print("sending one signed request to each of " + str(len(hosts)) + " origins")
    print("Signature-Agent: " + args.agent)
    print("Ctrl+C within 10 seconds to abort.")
    time.sleep(10)

    rows, counts = [], Counter()
    t0 = time.time()
    for i, host in enumerate(hosts, 1):
        url = "https://" + host + "/"
        sent = time.time()
        try:
            resp = session.get(url, headers=signed_headers(key, url, args.agent),
                               timeout=args.timeout, allow_redirects=True)
        except requests.RequestException:
            resp = None
        out = classify(resp)
        counts[out] += 1
        rows.append({"host": host, "outcome": out,
                     "status": resp.status_code if resp is not None else None,
                     "sent_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(sent))})
        if i % 25 == 0 or i == len(hosts):
            print("  %4d/%d  %s" % (i, len(hosts), dict(counts)))
        time.sleep(args.delay)

    print()
    print("outcomes: " + str(dict(counts)))
    print("elapsed : %.1f min" % ((time.time() - t0) / 60))

    print()
    print("waiting " + str(args.settle) + "s for any asynchronous verifier")
    time.sleep(args.settle)

    after, err = read_hits(args.agent, args.token)
    OUT.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    payload = {"collected_utc": stamp, "agent": args.agent, "hosts": len(hosts),
               "user_agent": ua, "keyid": key.thumbprint(),
               "directory_media_type": ct,
               "outcomes": dict(counts), "rows": rows,
               "hits_before": before, "hits_after": after, "hits_error": err}
    (OUT / ("keyfetch_" + stamp + ".json")).write_text(
        json.dumps(payload, indent=2), encoding="utf-8")

    print()
    print("=" * 66)
    print("RESULT")
    print("=" * 66)
    if err or after is None:
        print("  Could not read the fetch log: " + str(err))
        print("  The requests were sent and are recorded. Read the log with")
        print("    curl \"" + args.agent.rstrip('/') + "/hits?token=...\"")
        print("  or `npx wrangler tail`, and rerun the reading by hand.")
    else:
        n0 = (before or {}).get("total_fetches", 0)
        n1 = after.get("total_fetches", 0)
        new = n1 - n0

        # The counter delta is not trustworthy on its own. KV list and get are
        # eventually consistent, and the read-modify-write on the counter is
        # racy under concurrency, so a delta can both over- and under-report.
        # The verdict therefore rests on the entries: any fetch that is not
        # ours, identified by user-agent and source address.
        entries = after.get("entries", [])
        mine_ua = ("wba-keyfetch", "wba-impersonation", "curl/", "python-requests")
        third = [e for e in entries
                 if not any(m in (e.get("ua") or "") for m in mine_ua)
                 and e.get("ip") != our_ip]
        print("  counter delta over the run        : " + str(new))
        print("  entries visible in the log        : " + str(len(entries)))
        print("  of those, not from this machine   : " + str(len(third)))
        if new > 0 and not third:
            print("  (the delta is accounted for by our own preflight fetches)")
        if not third:
            print()
            print("  ZERO. " + str(len(hosts)) + " origins received a validly signed")
            print("  request naming this directory. None retrieved the public key.")
            print()
            print("  No origin in the sample held the key material required to")
            print("  verify any signature we sent. Verification was impossible,")
            print("  not merely absent. The differential response measured in E1")
            print("  is therefore keyed on the presence of the headers, not on")
            print("  the cryptography they carry.")
            print()
            print("  Caveat to state in the paper: a verifier could have fetched")
            print("  the directory before this run and cached it. Our key was")
            print("  first published at this origin for this experiment, so a")
            print("  prior fetch would itself appear in the log; the counter was")
            print("  " + str(n0) + " before the run.")
        else:
            print()
            print("  Some origin DID retrieve the key. Who:")
            by_asn = Counter((e.get("as_org"), e.get("ua")) for e in third)
            for (org, u), c in by_asn.most_common(20):
                print("    %-28s x%-4d %s" % (str(org)[:28], c, str(u)[:60]))
            print()
            print("  Match fetch timestamps against the per-host send times in")
            print("  the saved JSON to attribute each fetch to a request.")
    print()
    print("written: " + str(OUT) + "/keyfetch_" + stamp + ".json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
