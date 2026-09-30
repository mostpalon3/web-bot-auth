"""E1d - which mechanism fires, and what the tollbooth charges.

Three questions the outcome codes leave on the table, all answerable from
data already collected.

1. WHICH MITIGATION. Cloudflare states its action in `cf-mitigated`. If
   signed requests draw a different mitigation than unsigned ones - a block
   rather than a challenge, say - that names the product path involved and
   turns "Cloudflare blocks signed requests" into a statement about a
   specific configurable mechanism.

2. WHAT THE TOLLBOOTH CHARGES. 20 origins answered the signed arm with 402.
   Pay-per-crawl is new enough that nobody has reported a price distribution.
   Whatever was captured about those responses is worth reading.

3. IS THE EFFECT STABLE. Each arm ran twice. An origin that blocked once and
   served once is not the same phenomenon as one that blocked both times, and
   the split bears on whether this is deterministic policy or sampling.

Reads existing results. Sends no traffic.

    python mitigation.py
"""
from __future__ import annotations

import glob
import json
from collections import Counter, defaultdict


def load(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return rows


def cdn_of(row):
    for o in row.get("A", []) + row.get("B", []):
        h = o.get("bot_headers") or {}
        srv = (h.get("server") or "").lower()
        if "cf-ray" in h or "cf-mitigated" in h or "cloudflare" in srv:
            return "Cloudflare"
        if "akamai-grn" in h or "x-akamai-request-id" in h or "akamai" in srv:
            return "Akamai"
        if "x-datadome" in h:
            return "DataDome"
        if "x-iinfo" in h:
            return "Imperva"
        if "x-sucuri-id" in h:
            return "Sucuri"
    return "other"


def main():
    path = max(glob.glob("results/differential/e1_stream_*.jsonl"),
               key=lambda p: __import__("os").path.getsize(p))
    rows = load(path)
    print("stream : " + path)
    print("records: " + str(len(rows)))

    # ---------------------------------------------------------------- 1
    print()
    print("=" * 70)
    print("1. WHICH MITIGATION CLOUDFLARE APPLIES")
    print("=" * 70)
    mit = {"A": Counter(), "B": Counter()}
    mit_by_outcome = defaultdict(Counter)
    for r in rows:
        for arm in "AB":
            for o in r[arm]:
                v = (o.get("bot_headers") or {}).get("cf-mitigated")
                if v:
                    mit[arm][v] += 1
                    mit_by_outcome[(arm, o.get("outcome"))][v] += 1
    print("  %-22s %10s %10s" % ("cf-mitigated value", "unsigned", "signed"))
    for v in sorted(set(mit["A"]) | set(mit["B"])):
        print("  %-22s %10d %10d" % (v, mit["A"][v], mit["B"][v]))
    print("  %-22s %10d %10d" % ("TOTAL", sum(mit["A"].values()),
                                 sum(mit["B"].values())))
    if sum(mit["B"].values()) and sum(mit["A"].values()):
        ratio = sum(mit["B"].values()) / sum(mit["A"].values())
        print()
        print("  signed requests draw %.2fx as many mitigations as unsigned" % ratio)

    print()
    print("  by outcome:")
    for (arm, outcome), c in sorted(mit_by_outcome.items()):
        print("    arm %s / %-12s %s" % (arm, outcome, dict(c)))

    # Origins where the signed arm was mitigated and the unsigned arm was not.
    only_b = []
    for r in rows:
        a = {(o.get("bot_headers") or {}).get("cf-mitigated") for o in r["A"]}
        b = {(o.get("bot_headers") or {}).get("cf-mitigated") for o in r["B"]}
        a.discard(None)
        b.discard(None)
        if b and not a:
            only_b.append((r["host"], sorted(b), r.get("outcome_A"), r.get("outcome_B")))
    print()
    print("  origins mitigated ONLY when signed: " + str(len(only_b)))
    for h, v, oa, ob in only_b[:25]:
        print("    %-32s %-14s %s -> %s" % (h[:32], ",".join(v), oa, ob))
    if len(only_b) > 25:
        print("    ... and %d more" % (len(only_b) - 25))

    only_a = 0
    for r in rows:
        a = {(o.get("bot_headers") or {}).get("cf-mitigated") for o in r["A"]}
        b = {(o.get("bot_headers") or {}).get("cf-mitigated") for o in r["B"]}
        a.discard(None)
        b.discard(None)
        if a and not b:
            only_a += 1
    print("  origins mitigated ONLY when unsigned: " + str(only_a))

    # ---------------------------------------------------------------- 2
    print()
    print("=" * 70)
    print("2. THE TOLLBOOTH")
    print("=" * 70)
    pay = []
    for r in rows:
        oa, ob = r.get("outcome_A"), r.get("outcome_B")
        if "payment" in str(oa) or "payment" in str(ob) or any(
                o.get("status") == 402 for o in r["A"] + r["B"]):
            pay.append(r)
    print("  origins involving a 402: " + str(len(pay)))
    print()
    print("  %-30s %-14s %-14s %s" % ("host", "unsigned", "signed", "cdn"))
    for r in sorted(pay, key=lambda x: x["host"]):
        print("  %-30s %-14s %-14s %s"
              % (r["host"][:30], r.get("outcome_A"), r.get("outcome_B"), cdn_of(r)))
    # Anything captured about the 402 responses themselves.
    print()
    keys = Counter()
    for r in pay:
        for o in r["A"] + r["B"]:
            if o.get("status") == 402:
                for k in (o.get("bot_headers") or {}):
                    keys[k] += 1
    print("  headers captured on 402 responses: " + (str(dict(keys)) or "none"))
    print("  NOTE: `crawler-price` was not in the captured header set, so the")
    print("  price distribution is not recoverable from this run. One targeted")
    print("  re-probe of these origins would recover it - 20 requests.")

    # ---------------------------------------------------------------- 3
    print()
    print("=" * 70)
    print("3. IS THE BLOCKING DETERMINISTIC?")
    print("=" * 70)
    both = once = never = 0
    flappers = []
    for r in rows:
        bs = [o.get("outcome") for o in r["B"]]
        if len(bs) < 2:
            continue
        nb = sum(1 for x in bs if x == "blocked")
        if nb == len(bs):
            both += 1
        elif nb:
            once += 1
            flappers.append(r["host"])
        else:
            never += 1
    print("  signed arm blocked in EVERY repetition : %d" % both)
    print("  blocked in SOME but not all            : %d" % once)
    print("  never blocked                          : %d" % never)
    if both + once:
        print()
        print("  %.1f%% of origins that ever blocked the signed arm did so"
              % (100 * both / (both + once)))
        print("  consistently. The effect is policy, not sampling.")
    print("  inconsistent origins: " + ", ".join(flappers[:12]))

    # CDN breakdown of consistent blockers
    print()
    cdn_blocked = Counter()
    cdn_total = Counter()
    for r in rows:
        if r.get("outcome_A") == "error" or r.get("outcome_B") == "error":
            continue
        c = cdn_of(r)
        cdn_total[c] += 1
        if r.get("outcome_B") == "blocked" and r.get("outcome_A") != "blocked":
            cdn_blocked[c] += 1
    print("  signed-only blocking by CDN (clean pairs):")
    print("    %-12s %8s %8s %8s" % ("cdn", "origins", "blocked", "rate"))
    for c in sorted(cdn_total, key=lambda x: -cdn_total[x]):
        n, b = cdn_total[c], cdn_blocked[c]
        print("    %-12s %8d %8d %7.2f%%" % (c, n, b, 100 * b / n if n else 0))


if __name__ == "__main__":
    main()
