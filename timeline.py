"""Adoption timeline, reconstructed from the Internet Archive.

A census is a snapshot: it says who publishes a directory today and nothing
about when they started. The Wayback Machine has been crawling well-known paths
for years, so the archive can answer a question the census cannot — **when did
each operator deploy?** — and turn a static count into an adoption curve.

The curve matters because Web Bot Auth is pre-standard. If deployment clusters
tightly after a particular CDN announcement, adoption is being driven by one
gatekeeper rather than by the specification, which is a different claim about
how this trust layer came to exist.

Uses the CDX API: public, no key, one query per host.

    python timeline.py --hosts chatgpt.com,meta.com
    python timeline.py --scan "results/scans/scan_*.jsonl"
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402

from wba.directory import WELL_KNOWN  # noqa: E402

CDX = "http://web.archive.org/cdx/search/cdx"
OUT = Path("results/timeline")
UA = ("wba-census/0.1 (+https://sumit-sagar.github.io/signed-lane/; academic "
      "measurement; opt out: sumit.sagar.ug23@nsut.ac.in)")


def history(host: str, timeout: float = 30.0) -> dict:
    """Archived snapshots of this host's directory path.

    `collapse=digest` folds consecutive identical captures, so the result is a
    list of *changes* rather than every crawl - which is what a deployment
    timeline needs.
    """
    url = f"{host}{WELL_KNOWN}"
    rec = {"host": host, "url": url, "snapshots": [], "error": ""}
    try:
        resp = requests.get(CDX, timeout=timeout, headers={"User-Agent": UA},
                            params={"url": url, "output": "json",
                                    "fl": "timestamp,statuscode,digest,length",
                                    "collapse": "digest", "limit": 500})
    except requests.RequestException as exc:
        rec["error"] = type(exc).__name__
        return rec

    if resp.status_code != 200:
        rec["error"] = f"cdx_http_{resp.status_code}"
        return rec
    try:
        rows = resp.json()
    except ValueError:
        rec["error"] = "cdx_not_json"
        return rec
    if not rows or len(rows) < 2:
        return rec  # no captures: the archive has never seen this path

    header, *data = rows
    for row in data:
        entry = dict(zip(header, row))
        rec["snapshots"].append({
            "timestamp": entry.get("timestamp"),
            "status": entry.get("statuscode"),
            "digest": entry.get("digest"),
            "length": entry.get("length"),
        })
    return rec


def first_success(rec: dict):
    """Earliest capture that actually served something.

    A 404 in the archive is evidence of *absence* at that date, which is as
    useful as a hit: it bounds when deployment happened from below.
    """
    ok = [s for s in rec["snapshots"] if s["status"] == "200"]
    if not ok:
        return None
    return min(s["timestamp"] for s in ok)


def last_absent(rec: dict, before: str):
    """Latest capture showing the path missing, before it first appeared."""
    misses = [s["timestamp"] for s in rec["snapshots"]
              if s["status"] in ("404", "403") and s["timestamp"] < before]
    return max(misses) if misses else None


def fmt(ts):
    if not ts:
        return "-"
    return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"


def report(records: list) -> None:
    print(f"\narchive timeline for {len(records)} host(s)")
    print("=" * 78)

    dated = []
    for rec in records:
        if rec["error"]:
            print(f"  {rec['host']:<24} archive error: {rec['error']}")
            continue
        if not rec["snapshots"]:
            print(f"  {rec['host']:<24} never captured by the archive")
            continue

        appeared = first_success(rec)
        absent = last_absent(rec, appeared) if appeared else None
        captures = len(rec["snapshots"])
        codes = Counter(s["status"] for s in rec["snapshots"])

        if appeared:
            dated.append((appeared, rec["host"], absent))
            window = f"absent {fmt(absent)} -> present {fmt(appeared)}" if absent \
                else f"first seen {fmt(appeared)}"
            print(f"  {rec['host']:<24} {window}   ({captures} distinct captures)")
        else:
            print(f"  {rec['host']:<24} captured {captures}x, never a 200 "
                  f"({dict(codes)})")

    if not dated:
        print("\n  No datable deployments. The archive crawls well-known paths")
        print("  sparsely, so absence here is weak evidence - report coverage,")
        print("  not conclusions.")
        return

    dated.sort()
    print("\nadoption order")
    print("-" * 78)
    for ts, host, absent in dated:
        bound = f"  (bounded: absent as late as {fmt(absent)})" if absent else \
                "  (no prior capture - true start may be earlier)"
        print(f"  {fmt(ts)}  {host}{bound}")

    span_lo, span_hi = fmt(dated[0][0]), fmt(dated[-1][0])
    print(f"\n  earliest observed deployment {span_lo}, latest {span_hi}")

    by_q = Counter(f"{t[:4]}-Q{(int(t[4:6]) - 1) // 3 + 1}" for t, _, _ in dated)
    print("\n  by quarter")
    for q, n in sorted(by_q.items()):
        print(f"    {q}  {'#' * n} {n}")

    print("\n  Archive coverage of well-known paths is sparse and uneven, so a")
    print("  first-seen date is an upper bound on deployment, not the date of it.")
    print("  Where a 404 precedes the first 200, the pair brackets the window and")
    print("  that bracket is the citable claim.")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hosts")
    ap.add_argument("--scan")
    ap.add_argument("--delay", type=float, default=2.0,
                    help="the archive is a shared public good; be gentle")
    args = ap.parse_args()

    hosts = []
    if args.hosts:
        hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    elif args.scan:
        for path in glob.glob(args.scan):
            for line in open(path, encoding="utf-8"):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("ok"):
                    hosts.append(rec["host"])
    hosts = sorted(set(hosts))
    if not hosts:
        print("no hosts given")
        return

    records = []
    for i, host in enumerate(hosts, 1):
        print(f"  [{i}/{len(hosts)}] querying archive for {host}")
        records.append(history(host))
        time.sleep(args.delay)

    OUT.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = OUT / f"timeline_{stamp}.json"
    path.write_text(json.dumps(records, indent=2), encoding="utf-8")
    report(records)
    print(f"\nwritten: {path}")


if __name__ == "__main__":
    main()
