"""E1 - does carrying a signature change how a site treats you?

Matched-pair experiment. The same request is sent to the same origin twice,
identical in every respect except that one carries a valid Web Bot Auth
signature and the other does not. Any difference in treatment is attributable
to the signature, because nothing else varies.

Two arms are available; the third is not, and that shapes the claim:

  A  unsigned
  B  validly signed with a key in NO CDN directory
  C  validly signed with a listed key    <- requires being admitted to a
                                            gatekeeper's allowlist, which is
                                            not obtainable for this study

That limitation is also the experiment's sharpest question. If B is treated no
better than A, then a valid signature buys nothing on its own and the signed
lane is an **allowlist**, not a cryptographic mechanism - the cryptography
authenticates, but admission is what grants access. If B is treated *worse*
than A, an unrecognised signature reads as a spoofing attempt, which is a
different and equally reportable finding.

Either way the answer is a result. Nothing here depends on a hoped-for
direction.

    python differential.py --hosts tranco.csv --limit 200 --contact ... --info-url ...
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import statistics
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import threading  # noqa: E402
from concurrent.futures import ThreadPoolExecutor, as_completed  # noqa: E402

import requests  # noqa: E402

from scan import (build_ua, check_attributable, load_blocklist,  # noqa: E402
                  preflight)
from wba.keys import SigningKey  # noqa: E402
from wba.signature import Request, SigParams, sign  # noqa: E402

OUT = Path("results/differential")

# Header evidence that a bot-management layer inspected the request. Presence
# is not proof of a decision, but a change in these across arms is.
BOT_HEADERS = ("cf-ray", "cf-mitigated", "cf-cache-status", "x-akamai-request-id",
               "akamai-grn", "x-iinfo", "x-cdn", "x-served-by", "server",
               "x-sucuri-id", "x-datadome", "x-kong-request-id")

CHALLENGE_MARKERS = (
    "just a moment", "checking your browser", "cf-browser-verification",
    "cf_chl_opt", "attention required", "enable javascript and cookies",
    "verifying you are human", "captcha", "px-captcha",
    "incapsula incident id", "akamai reference", "access denied",
)


def looks_challenged(resp) -> bool:
    if "html" not in resp.headers.get("Content-Type", "").lower():
        return False
    body = resp.text[:20000].lower()
    return any(m in body for m in CHALLENGE_MARKERS)


def classify(resp) -> str:
    if resp is None:
        return "error"
    if resp.status_code in (401, 403):
        return "blocked"
    if resp.status_code == 429:
        return "rate_limited"
    if 200 <= resp.status_code < 300:
        return "challenged" if looks_challenged(resp) else "served"
    if 300 <= resp.status_code < 400:
        return "redirect"
    return f"http_{resp.status_code}"


def observe(session, url: str, headers: dict, timeout: float) -> dict:
    started = time.monotonic()
    try:
        resp = session.get(url, headers=headers or {}, timeout=timeout,
                           allow_redirects=True)
    except requests.RequestException as exc:
        return {"outcome": "error", "status": None,
                "error": type(exc).__name__, "latency_ms": None,
                "bytes": None, "bot_headers": {}}
    outcome = classify(resp)
    rec = {
        "outcome": outcome,
        "status": resp.status_code,
        "error": "",
        "latency_ms": round((time.monotonic() - started) * 1000),
        "bytes": len(resp.content),
        "bot_headers": {h: resp.headers[h] for h in BOT_HEADERS
                        if h in resp.headers},
        "title": "",
        "body_sample": "",
    }
    # Retain evidence for any classification that rests on body inspection.
    # A `challenged` verdict comes from a hand-written marker list that has
    # never been checked against a real interstitial; without the text there is
    # no way to audit it afterwards, and an unauditable classification cannot
    # carry a claim.
    if outcome in ("challenged", "blocked") or resp.status_code == 200:
        text = resp.text[:4000]
        rec["body_sample"] = text[:1200]
        lo = text.lower()
        if "<title" in lo:
            start = lo.index("<title")
            end = lo.find("</title>", start)
            if end > start:
                rec["title"] = text[lo.index(">", start) + 1:end].strip()[:200]
        rec["matched_markers"] = [m for m in CHALLENGE_MARKERS if m in lo]
    return rec


def signed_headers(key: SigningKey, url: str, agent_url: str) -> dict:
    req = Request("GET", url, {"Signature-Agent": f'"{agent_url}"'})
    params = SigParams.fresh(key.thumbprint())
    headers = sign(key, req, params)
    headers["Signature-Agent"] = f'"{agent_url}"'
    return headers


class _Rate:
    """Global token bucket, shared across worker threads."""

    def __init__(self, per_second: float):
        self.interval = 1.0 / per_second if per_second > 0 else 0.0
        self._lock = threading.Lock()
        self._next = time.monotonic()

    def acquire(self) -> None:
        if not self.interval:
            return
        with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._next - now)
            self._next = max(now, self._next) + self.interval
        if wait:
            time.sleep(wait)


def _one_origin(host: str, key: SigningKey, ua: str, agent_url: str,
                washout: float, timeout: float, repeats: int,
                rate: "_Rate", seed: int) -> dict:
    """One origin's complete matched-pair trial.

    Parallelism is across origins only. Within an origin the arms stay
    sequential and separated by a washout, because that ordering *is* the
    experiment: interleaving them would let one arm's effect on the origin's
    rate limiter or bot score contaminate the other.
    """
    session = requests.Session()
    session.headers["User-Agent"] = ua
    rng = random.Random(seed)
    url = f"https://{host}/"
    trial = {"host": host, "A": [], "B": []}

    for _ in range(repeats):
        arms = ["A", "B"]
        rng.shuffle(arms)
        for arm in arms:
            rate.acquire()
            hdrs = {} if arm == "A" else signed_headers(key, url, agent_url)
            trial[arm].append(observe(session, url, hdrs, timeout))
            time.sleep(washout)

    a = Counter(o["outcome"] for o in trial["A"]).most_common(1)[0][0]
    b = Counter(o["outcome"] for o in trial["B"]).most_common(1)[0][0]
    trial["outcome_A"], trial["outcome_B"] = a, b
    trial["differs"] = a != b
    return trial


def run(hosts: list, key: SigningKey, ua: str, agent_url: str,
        delay: float, timeout: float, repeats: int,
        workers: int = 1, rate_per_s: float = 0.0,
        stream: "Path" = None, verbose: bool = False) -> list:
    rate = _Rate(rate_per_s)
    rows, done, differing = [], 0, 0
    lock = threading.Lock()
    fh = open(stream, "a", encoding="utf-8") if stream else None

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {
            pool.submit(_one_origin, h, key, ua, agent_url, delay, timeout,
                        repeats, rate, 20260910 + i): h
            for i, h in enumerate(hosts)
        }
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                trial = fut.result()
            except Exception as exc:
                trial = {"host": host, "A": [], "B": [], "outcome_A": "error",
                         "outcome_B": "error", "differs": False,
                         "harness_error": type(exc).__name__}
            with lock:
                rows.append(trial)
                done += 1
                if trial["differs"]:
                    differing += 1
                    print(f"\n  DIFFERS  {trial['host']:<32} "
                          f"A={trial['outcome_A']:<12} B={trial['outcome_B']}")
                if fh:
                    # Stream to disk: a run of thousands should survive a crash.
                    fh.write(json.dumps(trial, ensure_ascii=False) + "\n")
                    fh.flush()
                if not verbose and done % 25 == 0:
                    sys.stdout.write(f"\r  {done}/{len(hosts)}  "
                                     f"{differing} differing   ")
                    sys.stdout.flush()
    if fh:
        fh.close()
    print()
    return rows


def mcnemar(rows: list) -> dict:
    """Exact McNemar on the paired served/not-served outcome.

    The discordant pairs carry all the information: sites that behave the same
    under both arms tell you nothing about the signature's effect.
    """
    b = sum(1 for r in rows
            if r["outcome_A"] == "served" and r["outcome_B"] != "served")
    c = sum(1 for r in rows
            if r["outcome_A"] != "served" and r["outcome_B"] == "served")
    n = b + c
    if n == 0:
        return {"b": 0, "c": 0, "p": 1.0,
                "note": "no discordant pairs: the signature changed nothing anywhere"}

    from math import comb
    k = min(b, c)
    p = min(1.0, 2 * sum(comb(n, i) for i in range(k + 1)) / (2 ** n))
    return {"b": b, "c": c, "p": p,
            "note": f"{b} served unsigned but not signed; "
                    f"{c} served signed but not unsigned"}


def report(rows: list) -> None:
    print(f"\n{len(rows)} origins, two arms each")
    print("=" * 74)

    a_dist = Counter(r["outcome_A"] for r in rows)
    b_dist = Counter(r["outcome_B"] for r in rows)
    outcomes = sorted(set(a_dist) | set(b_dist))
    print(f"\n  {'outcome':<16} {'A unsigned':>12} {'B signed':>12}   delta")
    print("  " + "-" * 56)
    for o in outcomes:
        d = b_dist[o] - a_dist[o]
        print(f"  {o:<16} {a_dist[o]:>12} {b_dist[o]:>12}   {d:+d}")

    differing = [r for r in rows if r["differs"]]
    print(f"\n  origins treating the arms differently: {len(differing)}/{len(rows)}")
    for r in differing[:25]:
        print(f"    {r['host']:<34} A={r['outcome_A']:<12} B={r['outcome_B']}")

    stat = mcnemar(rows)
    print(f"\n  McNemar exact, served vs not-served")
    print(f"    discordant pairs: b={stat['b']}  c={stat['c']}   p={stat['p']:.4f}")
    print(f"    {stat['note']}")

    lat_a = [o["latency_ms"] for r in rows for o in r["A"] if o["latency_ms"]]
    lat_b = [o["latency_ms"] for r in rows for o in r["B"] if o["latency_ms"]]
    if lat_a and lat_b:
        print(f"\n  median latency   A {statistics.median(lat_a):.0f}ms   "
              f"B {statistics.median(lat_b):.0f}ms")

    print("\n  Interpretation, fixed before the run:")
    print("    B == A          a valid signature alone buys nothing; the signed")
    print("                    lane is an allowlist, and cryptography is not what")
    print("                    grants access")
    print("    B better than A signature presence alone is rewarded")
    print("    B worse than A  an unrecognised signature reads as spoofing")
    print("\n  Arm C - a key listed in a gatekeeper's directory - is not")
    print("  obtainable for this study. Any claim about listed keys would be")
    print("  extrapolation and is not made.")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--skip", type=int, default=0)
    ap.add_argument("--repeats", type=int, default=2)
    ap.add_argument("--delay", type=float, default=2.0)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--contact", default="")
    ap.add_argument("--info-url", default="")
    ap.add_argument("--i-have-signoff", action="store_true")
    ap.add_argument("--blocklist", default="blocklist.txt")
    ap.add_argument("--workers", type=int, default=1,
                    help="origins probed in parallel; arms within an origin "
                         "always stay sequential")
    ap.add_argument("--rate", type=float, default=0.0,
                    help="global requests/sec ceiling across all workers")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="print every origin as it completes, not only the "
                         "ones whose arms differ")
    args = ap.parse_args()

    ua = build_ua(args.contact or "you@example.org",
                  args.info_url or "https://example.org/research")
    problems = check_attributable(args.contact, args.info_url, args.limit)
    if not args.i_have_signoff:
        problems.append("--i-have-signoff not given")
    if not problems:
        print(f"preflight: {args.info_url}")
        issue = preflight(args.info_url, ua)
        if issue:
            problems.append(issue)
    if problems:
        print("Refusing to run against external hosts.\n")
        for p in problems:
            print(f"  - {p}")
        return

    hosts, seen = [], set()
    with open(args.hosts, encoding="utf-8", errors="ignore") as fh:
        for i, row in enumerate(csv.reader(fh)):
            if not row:
                continue
            h = (row[1] if len(row) > 1 else row[0]).strip().lower()
            if not h or h.startswith("#") or i < args.skip or h in seen:
                continue
            seen.add(h)
            hosts.append(h)
            if len(hosts) >= args.limit:
                break

    blocked = load_blocklist(args.blocklist)
    hosts = [h for h in hosts if h not in blocked]

    # The research key, whose public half is published at the study site so a
    # verifier that follows Signature-Agent can actually resolve it.
    keydir = Path("keys/research.pem")
    if not keydir.exists():
        print("keys/research.pem missing - the published directory would not "
              "match what we sign with. Refusing to send unverifiable signatures.")
        return
    key = SigningKey.from_pem(str(keydir))

    total = len(hosts) * args.repeats * 2
    eff = args.rate if args.rate else (args.workers / max(args.delay, 0.01))
    print(f"E1: {len(hosts)} origins x {args.repeats} repetitions x 2 arms "
          f"= {total} requests")
    print(f"  {args.workers} workers, "
          f"{'global cap ' + str(args.rate) + '/s' if args.rate else 'uncapped'}"
          f"  ~{total / max(eff, 0.01) / 60:.0f} min")
    print(f"  keyid {key.thumbprint()} (published at {args.info_url}, "
          f"listed in no CDN directory)")
    print(f"  estimated {total * args.delay / 60:.0f} min\n")

    OUT.mkdir(parents=True, exist_ok=True)
    stamp0 = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    stream = OUT / f"e1_stream_{stamp0}.jsonl"

    rows = run(hosts, key, ua, args.info_url, args.delay, args.timeout,
               args.repeats, args.workers, args.rate, stream, args.verbose)

    OUT.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = OUT / f"e1_{stamp}.json"
    path.write_text(json.dumps({
        "collected_utc": stamp, "user_agent": ua, "keyid": key.thumbprint(),
        "arms": {"A": "unsigned", "B": "signed, key not in any CDN directory"},
        "repeats": args.repeats, "rows": rows,
    }, indent=2), encoding="utf-8")

    report(rows)
    print(f"\nwritten: {path}")


if __name__ == "__main__":
    main()
