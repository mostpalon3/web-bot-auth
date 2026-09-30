"""Recompute every headline figure in the paper from the committed result files.

`verify_e1.py` checks the single principal result. This checks all of them, so a
drift in any committed file is a failure rather than a quietly different number.

Nothing here touches the network. Every figure below is derived from a file in
results/, and the expected values are pinned so that a mismatch is loud.

    python reproduce.py
"""
from __future__ import annotations

import glob
import json
import math
import sys
from pathlib import Path

RESULTS = Path("results")
ERR = "error"


def pick(pattern: str):
    hits = sorted(glob.glob(str(RESULTS / pattern)))
    if not hits:
        raise SystemExit(f"missing: results/{pattern}")
    return json.loads(Path(hits[-1]).read_text(encoding="utf-8"))


def mcnemar(b: int, c: int) -> float:
    """Two-sided exact test on the discordant pairs."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n))


def rate(k: int, n: int) -> str:
    return f"{100 * k / n:.2f}%" if n else "n/a"


CHECKS: list[tuple[str, str, object, object]] = []


def check(label: str, got, want, note: str = "") -> None:
    CHECKS.append((label, note, got, want))


# ── Census ────────────────────────────────────────────────────────────────
d = json.loads((RESULTS / "census_consolidated.json").read_text(encoding="utf-8"))
hosts, resolvable, found = d["distinct_hosts"], d["resolvable"], d["found"]
check("census: distinct hosts", hosts, 34900)
check("census: resolvable", resolvable, 24069)
check("census: operators found", found, 12)
check("census: density", f"{100 * found / resolvable:.4f}%", "0.0499%")
check("census: operators listed", len(d["operators"]), 12)

# ── E1 — matched pair ─────────────────────────────────────────────────────
rows = json.loads((RESULTS / "differential" / "e1_summary.json")
                  .read_text(encoding="utf-8"))["rows"]
clean = [r for r in rows if r["outcome_A"] != ERR and r["outcome_B"] != ERR]
a_blocked = sum(1 for r in clean if r["outcome_A"] == "blocked")
b_blocked = sum(1 for r in clean if r["outcome_B"] == "blocked")
b = sum(1 for r in clean if r["outcome_A"] != "blocked" and r["outcome_B"] == "blocked")
c = sum(1 for r in clean if r["outcome_A"] == "blocked" and r["outcome_B"] != "blocked")
check("E1: origins probed", len(rows), 10000)
check("E1: clean pairs", len(clean), 7267)
check("E1: arm A blocked", a_blocked, 1156)
check("E1: arm B blocked", b_blocked, 1445)
check("E1: discordant b : c", f"{b} : {c}", "298 : 9")
check("E1: exact p", f"{mcnemar(b, c):.2e}", "4.69e-76")

# ── E1b — is the cryptography checked ─────────────────────────────────────
rows = pick("confound/confound_*.json")["rows"]
arms = ["A", "B", "C", "D"]
cl = [r for r in rows if all(r[f"outcome_{a}"] != ERR for a in arms)]
blk = {a: sum(1 for r in cl if r[f"outcome_{a}"] == "blocked") for a in arms}
check("E1b: clean origins", len(cl), 94)
check("E1b: valid signature", rate(blk["B"], len(cl)), "96.81%")
check("E1b: garbage values", rate(blk["D"], len(cl)), "93.62%")
check("E1b: decoy headers", rate(blk["C"], len(cl)), "5.32%")
check("E1b: no signature", rate(blk["A"], len(cl)), "0.00%")

# ── E4 — was the key ever fetched ─────────────────────────────────────────
d = pick("keyfetch/keyfetch_*.json")
blocked = sum(1 for r in d["rows"] if r["outcome"] == "blocked")
before = d["hits_before"]["total_fetches"]
after = d["hits_after"]["total_fetches"]
check("E4: origins probed", d["hosts"], 298)
check("E4: blocked again", f"{blocked}/{d['hosts']}", "293/298")
check("E4: key fetches before", before, 4)
check("E4: key fetches after", after, 4)
check("E4: counter delta", after - before, 0, "<- the deductive claim")

# ── E6 — admitted population ──────────────────────────────────────────────
rows = pick("admitted/admitted_*.json")["rows"]
reach = [r for r in rows if r.get("status") == 200]
media = sum(1 for r in reach if r.get("conformant_media_type"))
ed = sum(1 for r in reach if "OKP/Ed25519" in (r.get("algs") or []))
behav = sum(1 for r in reach if r.get("behavioural"))
purpose = sum(1 for r in reach if r.get("purpose"))
check("E6: directory entries", len(rows), 90)
check("E6: reachable", len(reach), 83)
check("E6: conformant media type", f"{media}/{len(reach)}", "78/83")
check("E6: Ed25519", f"{ed}/{len(reach)}", "82/83")
check("E6: publishes a purpose", f"{purpose}/{len(reach)}", "10/83")
check("E6: behavioural declarations", f"{behav}/{len(reach)}", "0/83", "<- the accountability gap")

# ── E7 — which header carries the effect ──────────────────────────────────
rows = pick("decompose/decompose_*.json")["rows"]
keys = [k for k in rows[0] if k != "host"]
cl = [r for r in rows if all(r[k] != ERR for k in keys)]
blk = {k: sum(1 for r in cl if r[k] == "blocked") for k in keys}
check("E7: clean origins", len(cl), 296)
check("E7: nothing sent", rate(blk["A none"], len(cl)), "2.70%")
check("E7: Signature-Input alone", rate(blk["C input only"], len(cl)), "96.96%")
check("E7: full valid signature", rate(blk["E full valid"], len(cl)), "97.30%")
bb = sum(1 for r in cl if r["C input only"] != "blocked" and r["E full valid"] == "blocked")
cc = sum(1 for r in cl if r["C input only"] == "blocked" and r["E full valid"] != "blocked")
check("E7: C vs E exact p", f"{mcnemar(bb, cc):.3g}", "1")

# ── E9 — does the exact name matter ───────────────────────────────────────
rows = pick("nearmiss/nearmiss_*.json")["rows"]
keys = [k for k in rows[0] if k != "host"]
cl = [r for r in rows if all(r[k] != ERR for k in keys)]
blk = {k: sum(1 for r in cl if r[k] == "blocked") for k in keys}
check("E9: clean origins", len(cl), 148)
check("E9: exact name", rate(blk["B Signature-Input"], len(cl)), "96.62%")
check("E9: X-Signature-Input", rate(blk["C X-Signature-Input"], len(cl)), "10.14%")
check("E9: Signature-Inputs", rate(blk["D Signature-Inputs"], len(cl)), "10.81%")

# ── E10 — is it Web Bot Auth specific ─────────────────────────────────────
rows = pick("rfc9421/rfc9421_*.json")["rows"]
keys = [k for k in rows[0] if k != "host"]
cl = [r for r in rows if all(r[k] != ERR for k in keys)]
blk = {k: sum(1 for r in cl if r[k] == "blocked") for k in keys}
check("E10: clean origins", len(cl), 150)
check("E10: bare RFC 9421", rate(blk["C Input no tag"], len(cl)), "94.67%")
check("E10: webhook shape", rate(blk["D RFC9421 API shape"], len(cl)), "96.00%")

# ── E8 — second network vantage ───────────────────────────────────────────
rows = pick("vantage_edge/vantage_edge_*.json")["rows"]
cl = [r for r in rows if r["A"].get("outcome") != ERR and r["B"].get("outcome") != ERR]
a_b = sum(1 for r in cl if r["A"].get("outcome") == "blocked")
b_b = sum(1 for r in cl if r["B"].get("outcome") == "blocked")
bb = sum(1 for r in cl if r["A"].get("outcome") != "blocked" and r["B"].get("outcome") == "blocked")
cc = sum(1 for r in cl if r["A"].get("outcome") == "blocked" and r["B"].get("outcome") != "blocked")
check("E8: clean pairs", len(cl), 198)
check("E8: unsigned blocked", rate(a_b, len(cl)), "20.71%")
check("E8: signed blocked", rate(b_b, len(cl)), "94.44%")
check("E8: paired difference", f"+{100 * (b_b - a_b) / len(cl):.2f} pp", "+73.74 pp")
check("E8: reversals (c)", cc, 0)

# ── E5 — the tollbooth ────────────────────────────────────────────────────
rows = pick("tollbooth/tollbooth_*.json")["rows"]
signed_only = sum(1 for r in rows if r["group"] == "signed_only")
check("E5: origins returning 402", len(rows), 23)
check("E5: signed-arm only", signed_only, 20)

# ── report ────────────────────────────────────────────────────────────────
width = max(len(l) for l, _, _, _ in CHECKS)
failed = 0
print(f"\n{'check':<{width}}  {'computed':>14}  {'expected':>14}")
print("-" * (width + 34))
for label, note, got, want in CHECKS:
    ok = str(got) == str(want)
    failed += not ok
    flag = "" if ok else "   <-- MISMATCH"
    print(f"{label:<{width}}  {str(got):>14}  {str(want):>14}{flag or ('   ' + note if note else '')}")

print("-" * (width + 34))
if failed:
    print(f"\n{failed} of {len(CHECKS)} checks do NOT match the published figures.\n")
    sys.exit(1)
print(f"\nAll {len(CHECKS)} figures reproduce from the committed result files.\n")
