"""A synthetic signed agent, for validating the honeypot before real traffic.

Drives the honeypot with a crawler whose compliance is set by the operator, so
the pipeline can be checked end to end: does a violation actually appear in the
logs, get attributed to a cryptographically verified identity, and surface in
the analysis?

Without this, the first real agent visit would be both the first data and the
first test of the code that records it - and there is no second chance at a
month of unattended collection.

    python -m testbed.origin --port 8422              # publishes the directory
    python -m honeypot.server --domain test.local --port 8080
    python -m honeypot.simulate --obedient
    python -m honeypot.simulate --violating
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests  # noqa: E402

from honeypot.allocate import MANIFESTS  # noqa: E402
from wba.keys import SigningKey  # noqa: E402
from wba.signature import Request, SigParams, sign  # noqa: E402


def parse_robots(text: str) -> tuple:
    disallowed, delay = [], None
    in_group = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "user-agent":
            in_group = value == "*"
        elif in_group and key == "disallow" and value:
            disallowed.append(value)
        elif in_group and key == "crawl-delay":
            try:
                delay = float(value)
            except ValueError:
                pass
    return disallowed, delay


def fetch(session, key, target, path, agent_url, ua):
    url = target.rstrip("/") + path
    req = Request("GET", url, {"Signature-Agent": f'"{agent_url}"'})
    params = SigParams.fresh(key.thumbprint(), components=["@authority", "@method", "@path"])
    headers = sign(key, req, params)
    headers["Signature-Agent"] = f'"{agent_url}"'
    headers["User-Agent"] = ua
    try:
        return session.get(url, headers=headers, timeout=10)
    except requests.RequestException:
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", default="http://127.0.0.1:8080")
    ap.add_argument("--agent-url", default="http://127.0.0.1:8422",
                    help="where this agent's key directory is published")
    ap.add_argument("--domain", default="test.local")
    ap.add_argument("--ua", default="SimulatedBot/1.0")
    ap.add_argument("--keyfile", default="keys/primary.pem",
                    help="a distinct key gives this agent a distinct identity")
    ap.add_argument("--pages", type=int, default=12)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--obedient", action="store_true",
                      help="read robots.txt, honour Disallow and Crawl-delay")
    mode.add_argument("--violating", action="store_true",
                      help="ignore robots.txt entirely")
    ap.add_argument("--ignore-delay", action="store_true",
                    help="obey Disallow but not Crawl-delay")
    args = ap.parse_args()

    keyfile = Path(args.keyfile)
    if not keyfile.exists():
        print(f"no key at {keyfile} - start testbed.origin once to generate it")
        return
    key = SigningKey.from_pem(str(keyfile))

    manifest_path = MANIFESTS / f"{args.domain}.json"
    if not manifest_path.exists():
        print(f"no manifest for {args.domain}")
        return
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    session = requests.Session()
    rng = random.Random(1234)

    disallowed, delay = [], None
    if args.obedient:
        resp = fetch(session, key, args.target, "/robots.txt", args.agent_url, args.ua)
        if resp is None:
            print("honeypot unreachable")
            return
        disallowed, delay = parse_robots(resp.text)
        print(f"read robots.txt: {len(disallowed)} Disallow, crawl-delay {delay}")
    else:
        print("ignoring robots.txt entirely")

    paths = [s["path"] for s in manifest["paths"]]
    rng.shuffle(paths)
    paths = paths[:args.pages]

    fetched = skipped = 0
    for path in paths:
        if args.obedient and any(path.startswith(d) for d in disallowed):
            skipped += 1
            continue
        resp = fetch(session, key, args.target, path, args.agent_url, args.ua)
        fetched += 1
        code = resp.status_code if resp is not None else "err"
        print(f"  GET {path:<40} {code}")
        if delay and args.obedient and not args.ignore_delay:
            time.sleep(delay)
        else:
            time.sleep(0.05)

    print(f"\nfetched {fetched}, skipped {skipped} on Disallow")


if __name__ == "__main__":
    main()
