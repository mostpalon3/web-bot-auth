"""Compare this vantage's results against the laptop baseline.

The laptop measurement was taken from one residential IP whose reputation
demonstrably degraded during collection (unsigned baseline rose 13.2% -> 19.2%).
A second vantage answers the question that drift raised: is the paired effect a
property of the signature, or of that particular address?

Prints the comparison and states what it licenses. Run after go.sh.

    python3 compare.py
"""
from __future__ import annotations

import glob
import json
import sys
from collections import Counter
from math import comb
from pathlib import Path


def mcnemar(clean, pred):
    b = sum(1 for r in clean if not pred(r["outcome_A"]) and pred(r["outcome_B"]))
    c = sum(1 for r in clean if pred(r["outcome_A"]) and not pred(r["outcome_B"]))
    n = b + c
    if not n:
        return b, c, 1.0
    k = min(b, c)
    return b, c, min(1.0, 2 * sum(comb(n, i) for i in range(k + 1)) / (2 ** n))


def cdn_of(r):
    for o in r.get("A", []) + r.get("B", []):
        h = o.get("bot_headers") or {}
        if "cf-ray" in h or "cf-mitigated" in h:
            return "Cloudflare"
        if (h.get("server") or "").lower().find("cloudflare") >= 0:
            return "Cloudflare"
    return "other"


def load_e1():
    files = sorted(glob.glob("results/differential/e1_stream_*.jsonl"))
    if not files:
        return []
    rows = []
    for line in open(files[-1], encoding="utf-8"):
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


def load_confound():
    files = sorted(glob.glob("results/confound/confound_*.json"))
    if not files:
        return []
    return json.load(open(files[-1], encoding="utf-8"))["rows"]


def load_census():
    files = sorted(glob.glob("results/scans/scan_*.jsonl"))
    if not files:
        return []
    rows = []
    for line in open(files[-1], encoding="utf-8"):
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


def main():
    base = json.load(open("baseline.json", encoding="utf-8"))
    ip = Path("vantage_ip.txt").read_text().strip() if Path("vantage_ip.txt").exists() else "?"

    print("=" * 68)
    print("VANTAGE COMPARISON")
    print("=" * 68)
    print(f"  baseline : {base['vantage']}  ({base['collected']})")
    print(f"  this run : {ip}")
    same = ip == "202.59.209.34"
    print(f"  {'SAME network - this varies the TLS stack only' if same else 'DIFFERENT network - genuine second vantage'}")

    rows = load_e1()
    if not rows:
        print("\nNo E1 results found. Did go.sh complete?")
        return
    clean = [r for r in rows
             if r.get("outcome_A") != "error" and r.get("outcome_B") != "error"]
    if not clean:
        print("\nNo clean pairs.")
        return

    ba = sum(1 for r in clean if r["outcome_A"] == "blocked") / len(clean) * 100
    bb = sum(1 for r in clean if r["outcome_B"] == "blocked") / len(clean) * 100
    b, c, p = mcnemar(clean, lambda o: o == "blocked")

    print("\n--- E1 differential ---")
    print(f"  {'':<26} {'baseline':>12} {'this run':>12}")
    print(f"  {'origins':<26} {base['origins']:>12} {len(rows):>12}")
    print(f"  {'clean pairs':<26} {base['clean']:>12} {len(clean):>12}")
    print(f"  {'clean %':<26} {base['clean_pct']:>11.1f}% {100*len(clean)/len(rows):>11.1f}%")
    print(f"  {'arm A blocked %':<26} {base['block_rate_A_pct']:>11.2f}% {ba:>11.2f}%")
    print(f"  {'arm B blocked %':<26} {base['block_rate_B_pct']:>11.2f}% {bb:>11.2f}%")
    print(f"  {'paired difference (pp)':<26} "
          f"{base['block_rate_B_pct']-base['block_rate_A_pct']:>+11.2f}  {bb-ba:>+11.2f}")
    print(f"  {'McNemar b / c':<26} "
          f"{str(base['mcnemar_b'])+' / '+str(base['mcnemar_c']):>12} "
          f"{str(b)+' / '+str(c):>12}")
    print(f"  {'p':<26} {'4.7e-76':>12} {p:>12.3g}")

    cf = [r for r in clean if cdn_of(r) == "Cloudflare"]
    cfb = [r for r in cf if r["outcome_B"] == "blocked"]
    if cf:
        print(f"\n  Cloudflare origins        {len(cf)}, blocked {len(cfb)} "
              f"({100*len(cfb)/len(cf):.1f}%)  [baseline {base['cloudflare_block_rate_pct']}%]")

    conf = load_confound()
    if conf:
        cc = [r for r in conf
              if all(r.get(f"outcome_{a}") != "error" for a in "ABCD")]
        if cc:
            print("\n--- E1b confound ---")
            print(f"  {'arm':<40} {'baseline':>10} {'this run':>10}")
            for a, label, key in (
                ("A", "A  unsigned", "confound_arm_A_blocked_pct"),
                ("B", "B  valid signature", "confound_arm_B_blocked_pct"),
                ("C", "C  decoy headers", "confound_arm_C_blocked_pct"),
                ("D", "D  WBA names, invalid values", "confound_arm_D_blocked_pct"),
            ):
                n = sum(1 for r in cc if r[f"outcome_{a}"] == "blocked")
                print(f"  {label:<40} {base[key]:>9.1f}% {100*n/len(cc):>9.1f}%")

    cen = load_census()
    if cen:
        ok = [r for r in cen if r.get("ok")]
        res = [r for r in cen if r.get("error") != "dns"]
        print("\n--- census slice ---")
        print(f"  {len(cen)} hosts, {len(res)} resolvable, {len(ok)} directories")
        for r in ok:
            print(f"    {r['host']}  {r.get('key_count', 0)} key(s)")

    print("\n" + "=" * 68)
    print("WHAT THIS LICENSES")
    print("=" * 68)
    base_diff = base["block_rate_B_pct"] - base["block_rate_A_pct"]
    this_diff = bb - ba
    if p < 0.01 and this_diff > 0:
        print("  The paired effect REPLICATES. Signing is associated with blocking")
        print(f"  here too ({this_diff:+.2f}pp, p={p:.3g}), independently of the")
        print("  laptop's IP reputation.")
        if not same:
            print("  From a different network, this removes the single-vantage")
            print("  limitation: the effect is not a property of one address.")
        else:
            print("  Same network, different TLS stack: this rules out client")
            print("  fingerprint as the cause, but not network reputation.")
    elif this_diff <= 0 or p >= 0.05:
        print("  The paired effect DOES NOT replicate here.")
        print("  If this is a different network, blocking may be reputation-")
        print("  dependent rather than signature-dependent, and the central")
        print("  claim needs restating. That is an important negative result -")
        print("  report it, do not bury it.")
    else:
        print("  Direction consistent but underpowered. Report both runs and the")
        print("  pooled estimate; do not lean on this one alone.")

    if abs(ba - base["block_rate_A_pct"]) > 5:
        print()
        print(f"  NOTE: the unsigned baseline differs markedly ({base['block_rate_A_pct']:.1f}%")
        print(f"  vs {ba:.1f}%). Absolute rates are vantage-specific; the paired")
        print("  difference is the comparable quantity. Say so in the methods.")

    out = {"vantage_ip": ip, "same_network": same,
           "e1": {"origins": len(rows), "clean": len(clean),
                  "block_A_pct": round(ba, 2), "block_B_pct": round(bb, 2),
                  "mcnemar_b": b, "mcnemar_c": c, "p": p},
           "baseline": base}
    Path("results").mkdir(exist_ok=True)
    Path("results/vantage_comparison.json").write_text(
        json.dumps(out, indent=2), encoding="utf-8")
    print("\nwritten: results/vantage_comparison.json")


if __name__ == "__main__":
    main()
