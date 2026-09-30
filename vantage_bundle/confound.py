"""E1b - is the blocking caused by Web Bot Auth, or by unfamiliar headers?

E1 compared an unsigned request against one carrying three extra headers:
Signature-Input, Signature and Signature-Agent. It attributed the resulting
blocking to the signature. That attribution has an obvious alternative
explanation which E1 cannot rule out:

    a bot-management edge may penalise ANY request carrying unfamiliar
    headers, regardless of what those headers mean.

If so, the headline finding is about header novelty, not about this protocol,
and the paper's central claim collapses. Four arms separate the explanations:

  A  unsigned                          control
  B  valid Web Bot Auth signature      the treatment E1 measured
  C  decoy headers, same shape and     tests "any unfamiliar header"
     size, unrelated names
  D  Web Bot Auth header NAMES with    tests "the header names alone",
     syntactically invalid values      independent of cryptographic validity

Readings, fixed before collection:

  C blocks like B   -> header novelty. The E1 finding is not about Web Bot Auth
                       and must be restated.
  C does not block,
  B does            -> the effect is specific to Web Bot Auth.
  D blocks like B   -> origins react to the header names, not to signature
                       validity: they are not verifying, only pattern-matching.
  D does not block,
  B does            -> origins are genuinely verifying and rejecting unlisted
                       keys.

Run against the origins E1 observed blocking, where the effect is concentrated
and power is highest.

    python confound.py --hosts blockers.txt --contact ... --info-url ...
"""
from __future__ import annotations

import argparse
import base64
import json
import random
import secrets
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from math import comb
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402

from differential import BOT_HEADERS, classify, signed_headers  # noqa: E402
from scan import build_ua, check_attributable, preflight  # noqa: E402
from wba.keys import SigningKey  # noqa: E402

OUT = Path("results/confound")


def decoy_headers(agent_url: str) -> dict:
    """Arm C: same shape, same rough size, unrelated names.

    Deliberately not signature-adjacent. If an edge penalises this as hard as
    a real signature, it is reacting to strangeness rather than to meaning.
    """
    blob = base64.b64encode(secrets.token_bytes(64)).decode()
    return {
        "X-Research-Token": f"tok1=:{blob}:",
        "X-Research-Input": ('tok1=("@authority" "@method" "@path");'
                             f'created={int(time.time())};alg="ed25519"'),
        "X-Research-Agent": f'"{agent_url}"',
    }


def malformed_headers(agent_url: str, key: SigningKey) -> dict:
    """Arm D: the real header names, syntactically invalid contents.

    Anything actually verifying will reject this at parse time, exactly as it
    would reject an unlisted key. Anything merely pattern-matching on header
    names cannot tell it apart from arm B.
    """
    blob = base64.b64encode(secrets.token_bytes(64)).decode()
    return {
        "Signature-Input": ('sig1=("@authority" "@method" "@path");'
                            f'created={int(time.time())};'
                            f'keyid="{key.thumbprint()}";alg="ed25519";'
                            'nonce="!!not-valid!!";tag="web-bot-auth"'),
        "Signature": f"sig1=:{blob}:",
        "Signature-Agent": f'"{agent_url}"',
    }


def observe(session, url, headers, timeout):
    started = time.monotonic()
    try:
        resp = session.get(url, headers=headers or {}, timeout=timeout,
                           allow_redirects=True)
    except requests.RequestException as exc:
        return {"outcome": "error", "status": None,
                "error": type(exc).__name__, "latency_ms": None}
    return {"outcome": classify(resp), "status": resp.status_code, "error": "",
            "latency_ms": round((time.monotonic() - started) * 1000),
            "bot_headers": {h: resp.headers[h] for h in BOT_HEADERS
                            if h in resp.headers}}


def one_origin(host, key, ua, agent_url, washout, timeout, repeats, seed):
    session = requests.Session()
    session.headers["User-Agent"] = ua
    rng = random.Random(seed)
    url = f"https://{host}/"
    trial = {"host": host, "A": [], "B": [], "C": [], "D": []}

    for _ in range(repeats):
        arms = ["A", "B", "C", "D"]
        rng.shuffle(arms)
        for arm in arms:
            if arm == "A":
                hdrs = {}
            elif arm == "B":
                hdrs = signed_headers(key, url, agent_url)
            elif arm == "C":
                hdrs = decoy_headers(agent_url)
            else:
                hdrs = malformed_headers(agent_url, key)
            trial[arm].append(observe(session, url, hdrs, timeout))
            time.sleep(washout)

    for arm in "ABCD":
        trial[f"outcome_{arm}"] = Counter(
            o["outcome"] for o in trial[arm]).most_common(1)[0][0]
    return trial


def mcnemar(rows, arm_x, arm_y, pred):
    b = sum(1 for r in rows if pred(r[f"outcome_{arm_x}"])
            and not pred(r[f"outcome_{arm_y}"]))
    c = sum(1 for r in rows if not pred(r[f"outcome_{arm_x}"])
            and pred(r[f"outcome_{arm_y}"]))
    n = b + c
    if not n:
        return b, c, 1.0
    k = min(b, c)
    return b, c, min(1.0, 2 * sum(comb(n, i) for i in range(k + 1)) / (2 ** n))


def report(rows):
    clean = [r for r in rows
             if all(r[f"outcome_{a}"] != "error" for a in "ABCD")]
    print(f"\n{len(rows)} origins | {len(clean)} with a definite outcome in all "
          f"four arms")
    if not clean:
        print("  nothing to analyse")
        return

    print(f"\n  {'arm':<38} {'blocked':>9} {'rate':>8}")
    print("  " + "-" * 58)
    labels = {"A": "A  unsigned (control)",
              "B": "B  valid Web Bot Auth signature",
              "C": "C  decoy headers, unrelated names",
              "D": "D  WBA header names, invalid values"}
    for a in "ABCD":
        n = sum(1 for r in clean if r[f"outcome_{a}"] == "blocked")
        print(f"  {labels[a]:<38} {n:>9} {100*n/len(clean):>7.1f}%")

    isb = lambda o: o == "blocked"  # noqa: E731
    print("\n  McNemar exact, blocked vs not-blocked:")
    for x, y, question in (
        ("A", "B", "does a real signature block more than nothing?"),
        ("A", "C", "do unfamiliar headers alone block?"),
        ("C", "B", "does a real signature block more than decoys?"),
        ("D", "B", "does validity matter, or only the header names?"),
    ):
        b, c, p = mcnemar(clean, x, y, isb)
        print(f"    {x} vs {y}   b={b:<4} c={c:<4} p={p:<10.3g}  {question}")

    print("\n  Reading:")
    cb = sum(1 for r in clean if r["outcome_C"] == "blocked")
    bb = sum(1 for r in clean if r["outcome_B"] == "blocked")
    db = sum(1 for r in clean if r["outcome_D"] == "blocked")
    if cb >= bb * 0.7:
        print("    C blocks about as much as B. The effect is header novelty,")
        print("    NOT Web Bot Auth. The E1 finding must be restated.")
    else:
        print("    C blocks far less than B. The effect is specific to Web Bot")
        print("    Auth rather than to unfamiliar headers in general.")
    if db >= bb * 0.7:
        print("    D blocks about as much as B. Origins react to the header")
        print("    NAMES; they are pattern-matching, not verifying.")
    else:
        print("    D blocks far less than B. Origins are parsing and evaluating")
        print("    the signature, not merely spotting the headers.")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--limit", type=int, default=300)
    ap.add_argument("--repeats", type=int, default=2)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--contact", default="")
    ap.add_argument("--info-url", default="")
    ap.add_argument("--i-have-signoff", action="store_true")
    args = ap.parse_args()

    ua = build_ua(args.contact or "you@example.org",
                  args.info_url or "https://example.org/research")
    problems = check_attributable(args.contact, args.info_url, args.limit)
    if not args.i_have_signoff:
        problems.append("--i-have-signoff not given")
    if not problems:
        issue = preflight(args.info_url, ua)
        if issue:
            problems.append(issue)
    if problems:
        print("Refusing to run against external hosts.\n")
        for p in problems:
            print(f"  - {p}")
        return

    hosts = [h.strip() for h in open(args.hosts, encoding="utf-8")
             if h.strip() and not h.startswith("#")][:args.limit]
    key = SigningKey.from_pem("keys/research.pem")

    total = len(hosts) * args.repeats * 4
    print(f"E1b: {len(hosts)} origins x {args.repeats} reps x 4 arms = "
          f"{total} requests\n")

    rows = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(one_origin, h, key, ua, args.info_url,
                               args.delay, args.timeout, args.repeats,
                               7000 + i): h for i, h in enumerate(hosts)}
        done = 0
        for fut in as_completed(futures):
            try:
                rows.append(fut.result())
            except Exception:
                pass
            done += 1
            if done % 20 == 0:
                sys.stdout.write(f"\r  {done}/{len(hosts)}   ")
                sys.stdout.flush()
    print()

    OUT.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    (OUT / f"confound_{stamp}.json").write_text(
        json.dumps({"collected_utc": stamp, "user_agent": ua,
                    "keyid": key.thumbprint(), "rows": rows}, indent=2),
        encoding="utf-8")
    report(rows)
    print(f"\nwritten: {OUT}/confound_{stamp}.json")


if __name__ == "__main__":
    main()
