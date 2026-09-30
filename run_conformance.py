"""E2 conformance runner.

Sends each case in the matrix to a target origin and records whether the
signature was accepted. Defaults to the local reference origin; pointing it
anywhere else is a deliberate act and rate limits apply.

    python -m testbed.origin --port 8422        # terminal 1
    python run_conformance.py                   # terminal 2
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wba.keys import SigningKey  # noqa: E402
from wba.mutations import CASES  # noqa: E402
from wba.signature import Request, SigParams  # noqa: E402

RESULTS = Path("results")


# Interstitials that carry HTTP 200 while granting nothing. Treating these as
# acceptances would systematically overstate how permissive origins are, which
# is the direction of error that would flatter our own hypothesis.
CHALLENGE_MARKERS = (
    "just a moment",
    "checking your browser",
    "cf-browser-verification",
    "cf_chl_opt",
    "attention required",
    "enable javascript and cookies",
    "verifying you are human",
    "ddos protection by",
    "captcha",
    "px-captcha",
    "incapsula incident id",
    "request unsuccessful. incapsula",
    "akamai reference",
)


def looks_like_challenge(response) -> bool:
    ctype = response.headers.get("Content-Type", "")
    if "html" not in ctype.lower():
        return False
    body = response.text[:20000].lower()
    return any(marker in body for marker in CHALLENGE_MARKERS)


def classify(response) -> str:
    """Reduce a response to accepted / rejected / challenged / inconclusive.

    The reference origin answers explicitly. Third-party origins do not, so we
    fall back to status class, and a 200 carrying a bot interstitial is scored
    as `challenged` rather than accepted. Anything ambiguous is reported as
    inconclusive and reviewed by hand; it is never guessed.
    """
    try:
        payload = response.json()
        if isinstance(payload, dict) and "verified" in payload:
            return "accepted" if payload["verified"] else "rejected"
    except ValueError:
        pass
    if response.status_code in (401, 403):
        return "rejected"
    if response.status_code == 429:
        return "rate_limited"
    if 200 <= response.status_code < 300:
        if looks_like_challenge(response):
            return "challenged"
        # A 200 from a third-party origin does NOT mean the signature was
        # accepted. It usually means the resource is public and was served
        # without the signature being consulted at all. Scoring that as
        # acceptance would manufacture conformance findings against origins
        # that never verified anything.
        #
        # Acceptance is only meaningful where signature validity is
        # load-bearing: an endpoint that refuses the control and serves a valid
        # signature. Establishing such an endpoint requires allowlist
        # admission, which an outside party cannot obtain.
        return "served_unconditionally"
    if 500 <= response.status_code < 600:
        return "inconclusive"
    return "inconclusive"


def reason(response) -> str:
    try:
        payload = response.json()
        if isinstance(payload, dict):
            return payload.get("reason", "")
    except ValueError:
        pass
    return ""


def run(target: str, path: str, delay: float, agent: str,
        origin_url: str = None, agent_url: str = None) -> list:
    primary = SigningKey.generate()
    alt = SigningKey.generate()

    keydir = Path("keys")
    # Against a real origin the signature must be resolvable: use the key whose
    # public half is published at the study site, not the local test key.
    if agent_url and (keydir / "research.pem").exists():
        primary = SigningKey.from_pem(str(keydir / "research.pem"))
    elif (keydir / "primary.pem").exists():
        primary = SigningKey.from_pem(str(keydir / "primary.pem"))

    url = target.rstrip("/") + path
    ctx: dict = {}
    if origin_url:
        # The authority the cross-origin cases mint their signatures for.
        ctx["origin_url"] = origin_url.rstrip("/") + path
    rows = []

    session = requests.Session()
    session.headers["User-Agent"] = agent

    ordered = [c for c in CASES if not c.stateful] + [c for c in CASES if c.stateful]

    for case in ordered:
        request = Request("GET", url, {})
        params = SigParams.fresh(primary.thumbprint())

        headers = case.build(primary, alt, request, params, ctx)
        if headers is not None and agent_url:
            headers.setdefault("Signature-Agent", f'"{agent_url}"')
        if headers is None:
            rows.append({
                "case": case.name, "requirement": case.requirement,
                "expectation": case.expectation, "outcome": "skipped",
                "status": "", "reason": "precondition unmet", "conforms": "",
            })
            continue

        try:
            resp = session.get(url, headers=headers, timeout=15)
        except requests.RequestException as exc:
            rows.append({
                "case": case.name, "requirement": case.requirement,
                "expectation": case.expectation, "outcome": "error",
                "status": "", "reason": str(exc)[:80], "conforms": "",
            })
            continue

        outcome = classify(resp)
        why = reason(resp)

        if (case.expectation == "policy"
                or outcome in ("inconclusive", "rate_limited",
                               "served_unconditionally")):
            conforms = ""
        elif case.expectation == "accept":
            conforms = "yes" if outcome == "accepted" else "no"
        else:
            conforms = "yes" if outcome == "rejected" else "NO"

        if case.name == "control_valid" and outcome == "accepted":
            try:
                ctx["last_accepted_nonce"] = resp.json().get("nonce")
            except ValueError:
                pass

        rows.append({
            "case": case.name, "requirement": case.requirement,
            "expectation": case.expectation, "outcome": outcome,
            "status": resp.status_code, "reason": why, "conforms": conforms,
        })
        time.sleep(delay)

    return rows


def report(rows: list, target: str) -> None:
    w = {"case": 26, "requirement": 17, "expectation": 12, "outcome": 12, "status": 7}
    print()
    print(f"target: {target}")
    print("-" * 92)
    header = "".join(k.ljust(w[k]) for k in w) + "conforms  reason"
    print(header)
    print("-" * 92)
    for r in rows:
        line = "".join(str(r[k]).ljust(w[k]) for k in w)
        flag = {"NO": "  <-- FINDING", "no": "  <-- harness or origin broken"}.get(
            r["conforms"], "")
        print(f"{line}{str(r['conforms']).ljust(10)}{r['reason'][:22]}{flag}")
    print("-" * 92)

    unconditional = [r for r in rows if r["outcome"] == "served_unconditionally"]
    if len(unconditional) >= len(rows) - 3:
        print("\n  INCONCLUSIVE. Every case was served regardless of what the")
        print("  signature contained, so this endpoint does not gate on signature")
        print("  validity and nothing about its verification behaviour follows.")
        print("  A conformance test needs an endpoint where a valid signature is")
        print("  required - which needs allowlist admission.")
    checked = [r for r in rows if r["conforms"] in ("yes", "no", "NO")]
    findings = [r for r in rows if r["conforms"] == "NO"]
    broken = [r for r in rows if r["conforms"] == "no"]
    print(f"{len(checked)} checkable cases | {len(findings)} accepted-when-must-reject "
          f"| {len(broken)} control failures")
    if broken:
        print("\nControl failed. Fix the harness before trusting any other row.")
    elif findings:
        print("\nFindings: " + ", ".join(f["case"] for f in findings))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", default="http://127.0.0.1:8422")
    ap.add_argument("--path", default="/robots.txt")
    ap.add_argument("--delay", type=float, default=1.0,
                    help="seconds between requests; raise it for anything remote")
    ap.add_argument("--agent", default=(
        "wba-conformance-research/0.1 "
        "(+https://example.org/research; academic measurement; contact: you@example.org)"))
    ap.add_argument("--origin-url", default=None,
                    help="second authority for the cross-origin replay cases; "
                         "signatures are minted for this host and presented to --target")
    ap.add_argument("--agent-url", default=None,
                    help="published directory for Signature-Agent; required "
                         "for any real target")
    ap.add_argument("--label", default="local")
    args = ap.parse_args()

    if not args.target.startswith("http://127.0.0.1") and args.delay < 2.0:
        print("Remote target: raising delay to 2.0s", file=sys.stderr)
        args.delay = 2.0

    rows = run(args.target, args.path, args.delay, args.agent,
               args.origin_url, args.agent_url)
    report(rows, args.target)

    RESULTS.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = RESULTS / f"e2_{args.label}_{stamp}"

    with open(f"{stem}.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    with open(f"{stem}.json", "w", encoding="utf-8") as fh:
        json.dump({
            "target": args.target, "path": args.path,
            "collected_utc": stamp, "user_agent": args.agent,
            "origin_url": args.origin_url,
            "delay_seconds": args.delay, "rows": rows,
        }, fh, indent=2)

    print(f"\nwritten: {stem}.csv / .json")


if __name__ == "__main__":
    main()
