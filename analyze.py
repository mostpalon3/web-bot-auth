"""Aggregate E2 results across targets.

The paper's claim is per-requirement, not per-implementation: "N of M origins
accept signatures that RFC 9421 s3.2 requires them to reject." This produces
that table, plus a per-origin conformance profile and a clustering of origins
by which checks they skip.

    python analyze.py                       # everything in results/
    python analyze.py --glob "e2_prod_*"    # one measurement round
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

RESULTS = Path("results")


def load(pattern: str) -> list:
    runs = []
    for path in sorted(RESULTS.glob(f"{pattern}.json")):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["_file"] = path.name
        runs.append(data)
    return runs


def wilson(k: int, n: int, z: float = 1.96):
    """Wilson score interval. Correct at the small n and extreme proportions
    this study will actually produce, where the normal approximation is not."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def per_requirement(runs: list) -> list:
    """Acceptance rate per specification requirement, across targets."""
    tally = defaultdict(lambda: {"accepted": 0, "checked": 0, "cases": set()})
    for run in runs:
        for row in run["rows"]:
            if row["expectation"] != "reject":
                continue
            if row["conforms"] not in ("yes", "NO"):
                continue
            slot = tally[row["requirement"]]
            slot["checked"] += 1
            slot["cases"].add(row["case"])
            if row["conforms"] == "NO":
                slot["accepted"] += 1

    out = []
    for req, slot in sorted(tally.items(), key=lambda kv: -kv[1]["accepted"]):
        lo, hi = wilson(slot["accepted"], slot["checked"])
        out.append({
            "requirement": req,
            "accepted": slot["accepted"],
            "checked": slot["checked"],
            "rate": slot["accepted"] / slot["checked"] if slot["checked"] else 0.0,
            "ci_low": lo,
            "ci_high": hi,
            "cases": ", ".join(sorted(slot["cases"])),
        })
    return out


def per_origin(runs: list) -> list:
    out = []
    for run in runs:
        rows = run["rows"]
        checked = [r for r in rows if r["conforms"] in ("yes", "NO")]
        failed = [r["case"] for r in rows if r["conforms"] == "NO"]
        out.append({
            "target": run["target"],
            "collected": run.get("collected_utc", ""),
            "checked": len(checked),
            "findings": len(failed),
            "control": "ok" if not any(r["conforms"] == "no" for r in rows) else "FAILED",
            "skipped": sum(1 for r in rows if r["outcome"] in ("skipped", "error")),
            "accepts": ", ".join(sorted(failed)) or "-",
        })
    return out


def profiles(runs: list) -> list:
    """Group origins by the exact set of checks they skip.

    Identical profiles across independent operators usually mean a shared
    implementation, which is the more interesting claim: the failure is in a
    library, not in a deployment.
    """
    groups = Counter()
    for run in runs:
        sig = frozenset(r["case"] for r in run["rows"] if r["conforms"] == "NO")
        groups[sig] += 1
    return [
        {"profile": ", ".join(sorted(sig)) or "fully conforming", "origins": n}
        for sig, n in groups.most_common()
    ]


def table(rows: list, cols: list, title: str) -> str:
    if not rows:
        return f"\n{title}\n  (no data)\n"
    widths = {c: max(len(c), max(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    widths = {c: min(w, 46) for c, w in widths.items()}
    line = "  ".join(c.ljust(widths[c]) for c in cols)
    out = [f"\n{title}", "-" * len(line), line, "-" * len(line)]
    for r in rows:
        out.append("  ".join(str(r.get(c, ""))[:widths[c]].ljust(widths[c]) for c in cols))
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--glob", default="e2_*")
    ap.add_argument("--csv", default=None, help="write the per-requirement table here")
    args = ap.parse_args()

    runs = load(args.glob)
    if not runs:
        print(f"no runs matching results/{args.glob}.json")
        return

    excluded = [r for r in runs
                if any(row["conforms"] == "no" for row in r["rows"])]
    usable = [r for r in runs if r not in excluded]

    print(f"loaded {len(runs)} run(s); {len(usable)} usable, "
          f"{len(excluded)} excluded for control failure")

    req = per_requirement(usable)
    for r in req:
        r["rate"] = f"{r['rate']:.3f}"
        r["ci"] = f"[{r.pop('ci_low'):.3f}, {r.pop('ci_high'):.3f}]"

    print(table(req, ["requirement", "accepted", "checked", "rate", "ci", "cases"],
                "Acceptance of signatures the specification requires be rejected"))
    print(table(per_origin(usable),
                ["target", "checked", "findings", "control", "skipped", "accepts"],
                "Per-origin conformance"))
    print(table(profiles(usable), ["profile", "origins"],
                "Failure-mode profiles (shared profiles suggest a shared library)"))
    print()

    if args.csv and req:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(req[0].keys()))
            w.writeheader()
            w.writerows(req)
        print(f"written: {args.csv}")


if __name__ == "__main__":
    main()
