"""E8 - the matched pair from a second network.

Every measurement in this study leaves one residential IP in one country. The
matched-pair design holds the source address constant *within* each
comparison, which is what licenses the causal reading, but the absolute rates
belong to that vantage and a reviewer is right to press on it.

This runs the same A/B pair from Cloudflare's edge instead: different ASN,
different address, no shared history with the origins, and — since the laptop's
reputation demonstrably degraded during earlier collection — no accumulated
penalty either.

The private key never leaves this machine. Each request is signed here and only
the finished headers are posted to the Worker, which replays them. A leaked
Worker secret would expose a public key and nothing else.

  arm A   unsigned
  arm B   the same validly signed request the laptop would have sent

Batched at 25 hosts because free-tier Workers allow 50 subrequests per
invocation and each host costs two.

KNOWN CONFOUND. Traffic from Cloudflare's network to Cloudflare-fronted
origins may be routed or treated differently from traffic arriving over the
public internet. Two thirds of the sample is not Cloudflare-fronted, and the
comparison is reported split on that. A result that holds only on the
non-Cloudflare subset is still a second vantage; a result that holds on both
is stronger.

    python vantage_edge.py --limit 400 --contact you@x.org --info-url https://s/
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from math import comb
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402

from wba.keys import SigningKey  # noqa: E402
from wba.signature import Request, SigParams, sign  # noqa: E402

OUT = Path("results/vantage_edge")


def signed_headers(key, url, agent):
    hdr = '"' + agent + '"'
    h = sign(key, Request("GET", url, {"Signature-Agent": hdr}),
             SigParams.fresh(key.thumbprint()))
    h["Signature-Agent"] = hdr
    return h


def mcnemar(rows, pred_a, pred_b):
    b = sum(1 for r in rows if not pred_a(r) and pred_b(r))
    c = sum(1 for r in rows if pred_a(r) and not pred_b(r))
    n = b + c
    if not n:
        return b, c, 1.0
    k = min(b, c)
    return b, c, min(1.0, 2 * sum(comb(n, i) for i in range(k + 1)) / (2 ** n))


def load_laptop_cdn():
    """CDN attribution per host, taken from the laptop run.

    `cf-ray` cannot be used from inside Cloudflare's network: the edge adds it
    to responses it proxies on the Worker's behalf, so every origin looks
    Cloudflare-fronted. The first version of this script reported 28 of 28
    Cloudflare, which is how the defect surfaced. Attribution therefore comes
    from the laptop run, where the header means what it says.
    """
    import glob
    import os
    files = glob.glob("results/differential/e1_stream_*.jsonl")
    if not files:
        return {}
    path = max(files, key=os.path.getsize)
    cdn = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            label = "other"
            for o in (r.get("A") or []) + (r.get("B") or []):
                h = o.get("bot_headers") or {}
                srv = (h.get("server") or "").lower()
                if "cf-ray" in h or "cf-mitigated" in h or "cloudflare" in srv:
                    label = "Cloudflare"
                    break
                if srv == "qrator":
                    label = "Qrator"
                    break
                if "akamai" in srv or "akamai-grn" in h:
                    label = "Akamai"
                    break
            cdn[(r.get("host") or "").lower()] = label
    return cdn


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--worker",
                    default="https://wba-probe.aniksaha4049.workers.dev")
    ap.add_argument("--token-file", default="worker/.hits_token")
    ap.add_argument("--hosts", default="tranco.csv")
    ap.add_argument("--limit", type=int, default=400)
    ap.add_argument("--batch", type=int, default=25)
    ap.add_argument("--agent",
                    default="https://wba-probe.aniksaha4049.workers.dev")
    ap.add_argument("--contact", required=True)
    ap.add_argument("--info-url", required=True)
    ap.add_argument("--delay-ms", type=int, default=400)
    args = ap.parse_args()

    if "@" not in args.contact or not args.info_url.startswith("https://"):
        print("--contact must be monitored, --info-url an https page")
        return 1
    tok = Path(args.token_file)
    if not tok.exists():
        print("no token at " + str(tok))
        return 1
    token = tok.read_text(encoding="utf-8").strip()

    hosts = []
    with open(args.hosts, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.strip().split(",")
            h = (parts[1] if len(parts) >= 2 else parts[0]).strip().lower()
            if h:
                hosts.append(h)
            if len(hosts) >= args.limit:
                break

    key = SigningKey.from_pem("keys/research.pem")
    ua = ("wba-vantage/0.1 (+" + args.info_url + "; academic measurement from "
          "a second network vantage; two requests per origin; contact: "
          + args.contact + ")")

    print("origins : " + str(len(hosts)))
    print("worker  : " + args.worker)
    print("agent   : " + args.agent)
    print("The signing key stays on this machine; only finished headers are sent.")
    print("Ctrl+C within 10 seconds to abort.")
    time.sleep(10)

    session = requests.Session()
    rows, colos = [], Counter()
    for i in range(0, len(hosts), args.batch):
        chunk = hosts[i:i + args.batch]
        jobs = [{"host": h,
                 "signed": signed_headers(key, "https://" + h + "/", args.agent)}
                for h in chunk]
        try:
            r = session.post(args.worker + "/vantage",
                             params={"token": token},
                             json={"ua": ua, "jobs": jobs,
                                   "delay_ms": args.delay_ms},
                             timeout=120)
            if r.status_code != 200:
                print("  batch %d: HTTP %d %s"
                      % (i // args.batch, r.status_code, r.text[:120]))
                continue
            payload = r.json()
        except Exception as e:
            print("  batch %d failed: %s" % (i // args.batch, e))
            continue
        colos[payload.get("colo")] += 1
        rows.extend(payload.get("results", []))
        done = len(rows)
        blocked_b = sum(1 for x in rows if (x.get("B") or {}).get("outcome") == "blocked")
        print("  %4d/%d  signed-blocked so far: %d" % (done, len(hosts), blocked_b))

    OUT.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    (OUT / ("vantage_edge_" + stamp + ".json")).write_text(
        json.dumps({"collected_utc": stamp, "worker": args.worker,
                    "agent": args.agent, "user_agent": ua,
                    "colos": dict(colos), "rows": rows}, indent=2),
        encoding="utf-8")

    clean = [r for r in rows
             if (r.get("A") or {}).get("outcome") not in (None, "error")
             and (r.get("B") or {}).get("outcome") not in (None, "error")]
    print()
    print("=" * 68)
    print("SECOND VANTAGE  (Cloudflare edge, colo %s)" % dict(colos))
    print("=" * 68)
    print("  origins probed : %d" % len(rows))
    print("  clean pairs    : %d (%.1f%%)"
          % (len(clean), 100 * len(clean) / len(rows) if rows else 0))
    if not clean:
        return 0

    blk_a = lambda r: (r["A"] or {}).get("outcome") == "blocked"   # noqa: E731
    blk_b = lambda r: (r["B"] or {}).get("outcome") == "blocked"   # noqa: E731
    ra = sum(1 for r in clean if blk_a(r))
    rb = sum(1 for r in clean if blk_b(r))
    b, c, p = mcnemar(clean, blk_a, blk_b)
    n = len(clean)
    print("  arm A blocked  : %d (%.2f%%)" % (ra, 100 * ra / n))
    print("  arm B blocked  : %d (%.2f%%)" % (rb, 100 * rb / n))
    print("  paired diff    : %+.2f pp" % (100 * (rb - ra) / n))
    print("  McNemar        : b=%d c=%d p=%.4g" % (b, c, p))

    cdn = load_laptop_cdn()
    if not cdn:
        print("\n  (no laptop run found; CDN split unavailable)")
    subsets = (
        ("Cloudflare-fronted (per laptop run)",
         [r for r in clean if cdn.get(r["host"].lower()) == "Cloudflare"]),
        ("NOT Cloudflare (per laptop run)",
         [r for r in clean if cdn.get(r["host"].lower()) not in (None, "Cloudflare")]),
        ("unattributed",
         [r for r in clean if r["host"].lower() not in cdn]),
    )
    for label, subset in subsets:
        if not subset:
            continue
        m = len(subset)
        sa = sum(1 for r in subset if blk_a(r))
        sb = sum(1 for r in subset if blk_b(r))
        bb, cc, pp = mcnemar(subset, blk_a, blk_b)
        print()
        print("  %s: %d origins" % (label, m))
        print("    A %.2f%%   B %.2f%%   diff %+.2f pp   b=%d c=%d p=%.4g"
              % (100 * sa / m, 100 * sb / m, 100 * (sb - sa) / m, bb, cc, pp))

    print()
    print("=" * 68)
    print("READING")
    print("=" * 68)
    print("  Laptop baseline: arm A 12.55-15.91%, paired difference +3.7 to")
    print("  +4.0 pp, p < 10^-75 on 7,267 pairs.")
    print()
    discordant = b + c
    if discordant < 10:
        print("  UNDERPOWERED - only %d discordant pairs. McNemar uses nothing"
              % discordant)
        print("  else, so p=%.3g here carries no information about replication."
              % p)
        print("  Zero discordant pairs is an empty sample, not a null result.")
        print("  Raise --limit, or point --hosts at blockers.txt, where every")
        print("  origin is already known to block from the laptop and the test")
        print("  is therefore powered.")
    elif p < 0.01 and rb > ra:
        print("  The paired effect REPLICATES from a different network, with no")
        print("  shared address history with these origins. The single-vantage")
        print("  limitation is removed for the rate as well as the comparison.")
    elif rb <= ra or p >= 0.05:
        print("  The effect DOES NOT replicate from this vantage, on %d"
              % discordant)
        print("  discordant pairs. That is a substantive negative result:")
        print("  blocking would then depend on source reputation rather than on")
        print("  the signature, and the central claim needs restating. Report")
        print("  it, do not bury it.")
    else:
        print("  Direction consistent, underpowered. Report both and pool.")
    print()
    print("  Confound to state either way: this traffic originates inside")
    print("  Cloudflare's network. The non-Cloudflare split above is the")
    print("  cleaner of the two comparisons.")
    print()
    print("written: " + str(OUT) + "/vantage_edge_" + stamp + ".json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
