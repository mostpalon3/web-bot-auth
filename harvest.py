"""T1 registry harvester.

Probes candidate Web Bot Auth key directories, snapshots what it finds, and
diffs snapshots over time.

The seed list is a hypothesis set, not a known population: which candidates
actually resolve is the first result, and unreachable seeds are recorded rather
than dropped. A harvester that silently discards its failures cannot tell you
how small the population is, which is the finding if the population is small.

    python harvest.py --seeds seeds.txt          # probe and snapshot
    python harvest.py --report                   # summarise the latest
    python harvest.py --diff                     # latest vs previous
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wba.directory import DECLARED_FIELDS, candidate_urls, fetch  # noqa: E402

SNAPSHOTS = Path("results/snapshots")
UA = ("wba-registry-harvest/0.1 "
      "(+https://example.org/research; academic measurement; contact: you@example.org)")


def read_seeds(path: Path) -> list:
    seeds = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            seeds.append(line)
    return seeds


def harvest(seeds: list, delay: float, user_agent: str) -> list:
    records = []
    for i, seed in enumerate(seeds, 1):
        for url in candidate_urls(seed):
            rec = fetch(url, source=seed, user_agent=user_agent)
            status = ("ok " + rec.shape) if rec.reachable else (rec.error or "failed")
            keys = f"{len(rec.keys)} key(s)" if rec.reachable else ""
            print(f"  [{i:>3}/{len(seeds)}] {seed:<44} {status:<34} {keys}")
            records.append(rec.to_row())
            time.sleep(delay)
    return records


def write_snapshot(records: list, seeds_path: str, user_agent: str) -> Path:
    SNAPSHOTS.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = SNAPSHOTS / f"registry_{stamp}.json"
    path.write_text(json.dumps({
        "collected_utc": stamp,
        "seeds_file": seeds_path,
        "user_agent": user_agent,
        "seed_count": len({r["source"] for r in records}),
        "records": records,
    }, indent=2), encoding="utf-8")

    csv_path = path.with_suffix(".csv")
    if records:
        cols = ["source", "url", "reachable", "status", "shape", "key_count",
                "kids", "redirected", "content_type", "error"]
        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(records)
    return path


def snapshots() -> list:
    return sorted(SNAPSHOTS.glob("registry_*.json"))


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def report(snap: dict) -> None:
    records = snap["records"]
    live = [r for r in records if r["reachable"]]
    print(f"\nsnapshot {snap['collected_utc']}  ({snap['seed_count']} seeds)")
    print("-" * 74)
    print(f"  probed          {len(records)}")
    print(f"  reachable       {len(live)}")
    print(f"  unreachable     {len(records) - len(live)}")

    if not live:
        print("\n  Nothing resolved. If the seed list is sound, that is the T1")
        print("  result: the published population is effectively empty, and the")
        print("  privileged lane is gated by CDN-internal lists rather than by")
        print("  anything an outside party can enumerate. Verify the seeds before")
        print("  reporting it as such.")
        return

    shapes = Counter(r["shape"] for r in live)
    print(f"  shapes          {dict(shapes)}")

    kids = {k for r in live for k in r["kids"].split(";") if k}
    print(f"  distinct keys   {len(kids)}")
    print(f"  operators       {len({r['source'] for r in live})}")

    errors = Counter(r["error"] for r in records if not r["reachable"] and r["error"])
    if errors:
        print("\n  failure modes")
        for err, n in errors.most_common(8):
            print(f"    {n:>4}  {err[:60]}")

    cards = [r for r in live if r["shape"] == "agent_card"]
    if cards:
        print(f"\n  agent cards     {len(cards)}")
        print("  declaration coverage (present / total cards)")
        for f in DECLARED_FIELDS:
            n = sum(1 for r in cards if r["declared"].get(f) is not None)
            bar = "#" * int(24 * n / len(cards))
            print(f"    {f:<24} {n:>3}/{len(cards)}  {bar}")
        print("\n  A declaration that is absent cannot be violated, and cannot be")
        print("  checked. Coverage bounds what E3 can measure.")


def diff(old: dict, new: dict) -> None:
    def index(snap):
        return {r["source"]: r for r in snap["records"] if r["reachable"]}

    a, b = index(old), index(new)
    print(f"\n{old['collected_utc']}  ->  {new['collected_utc']}")
    print("-" * 74)

    appeared = sorted(set(b) - set(a))
    vanished = sorted(set(a) - set(b))
    for s in appeared:
        print(f"  + appeared    {s}")
    for s in vanished:
        print(f"  - vanished    {s}   (was {a[s]['key_count']} key(s))")

    changes = 0
    for src in sorted(set(a) & set(b)):
        old_kids = set(k for k in a[src]["kids"].split(";") if k)
        new_kids = set(k for k in b[src]["kids"].split(";") if k)
        if old_kids != new_kids:
            added, dropped = new_kids - old_kids, old_kids - new_kids
            print(f"  ~ keys        {src}  +{len(added)} -{len(dropped)}")
            changes += 1

        for f in DECLARED_FIELDS:
            ov, nv = a[src]["declared"].get(f), b[src]["declared"].get(f)
            if ov != nv:
                print(f"  ! declaration {src}  {f}")
                print(f"                  was: {json.dumps(ov)[:64]}")
                print(f"                  now: {json.dumps(nv)[:64]}")
                changes += 1

    if not (appeared or vanished or changes):
        print("  no change")
    else:
        print(f"\n  {len(appeared)} appeared, {len(vanished)} vanished, {changes} altered")
        print("\n  A widened purpose or a raised rate expectation after listing is")
        print("  the kind of change only a time series catches. Keep every snapshot.")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seeds", default="seeds.txt")
    ap.add_argument("--delay", type=float, default=2.0)
    ap.add_argument("--agent", default=UA)
    ap.add_argument("--report", action="store_true", help="summarise latest snapshot")
    ap.add_argument("--diff", action="store_true", help="latest against previous")
    args = ap.parse_args()

    if args.report or args.diff:
        snaps = snapshots()
        if not snaps:
            print("no snapshots yet - run without --report first")
            return
        if args.diff:
            if len(snaps) < 2:
                print(f"only {len(snaps)} snapshot; need two to diff")
                return
            diff(load(snaps[-2]), load(snaps[-1]))
        else:
            report(load(snaps[-1]))
        return

    seeds_path = Path(args.seeds)
    if not seeds_path.exists():
        print(f"no seed file at {seeds_path}")
        return

    seeds = read_seeds(seeds_path)
    print(f"probing {len(seeds)} seed(s) from {seeds_path}\n")
    records = harvest(seeds, args.delay, args.agent)
    path = write_snapshot(records, str(seeds_path), args.agent)
    report(load(path))
    print(f"\nwritten: {path}")


if __name__ == "__main__":
    main()
