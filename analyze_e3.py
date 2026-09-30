"""E3 analysis: declared behaviour against observed behaviour.

Joins honeypot logs to the declarations harvested in T1 and asks, per agent,
whether the claims that earned it a place in the signed lane hold in its
traffic.

Agent identity is taken from a *verified* signature where one exists. Where it
does not, the agent is identified by its Signature-Agent or User-Agent and
reported in a separate stratum, clearly labelled, because an unverified
identity is a claim rather than a fact - which is the premise of the study.

    python analyze_e3.py --domain example.org
"""
from __future__ import annotations

import argparse
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

LOGS = Path("honeypot/logs")
MANIFESTS = Path("honeypot/manifests")
SNAPSHOTS = Path("results/snapshots")


def wilson(k: int, n: int, z: float = 1.96):
    if n == 0:
        return (0.0, 0.0)
    p, d = k / n, 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def two_proportion(k1, n1, k2, n2):
    """Pooled z-test. Returns (difference, z). Reported alongside the interval,
    never on its own."""
    if not n1 or not n2:
        return (0.0, 0.0)
    p1, p2 = k1 / n1, k2 / n2
    pooled = (k1 + k2) / (n1 + n2)
    se = math.sqrt(pooled * (1 - pooled) * (1 / n1 + 1 / n2))
    return (p1 - p2, (p1 - p2) / se if se else 0.0)


def load_logs(domain: str) -> list:
    path = LOGS / f"{domain}.jsonl"
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # a torn final line from an unclean shutdown
    return out


def load_declarations() -> dict:
    """keyid -> declared fields, from the most recent T1 snapshot."""
    snaps = sorted(SNAPSHOTS.glob("registry_*.json"))
    if not snaps:
        return {}
    snap = json.loads(snaps[-1].read_text(encoding="utf-8"))
    out = {}
    for rec in snap["records"]:
        if not rec.get("reachable"):
            continue
        for kid in (rec.get("kids") or "").split(";"):
            if kid:
                out[kid] = {"source": rec["source"], **(rec.get("declared") or {})}
    return out


def identify(entry: dict) -> tuple:
    """Return (identity, basis). Basis is reported; it is not decoration."""
    sig = entry.get("signature") or {}
    if sig.get("verified") and sig.get("keyid"):
        return sig["keyid"], "verified_signature"
    if sig.get("signed") and sig.get("keyid"):
        return sig["keyid"], "unverified_signature"
    if sig.get("signature_agent"):
        return sig["signature_agent"], "signature_agent_header"
    ua = (entry.get("user_agent") or "").strip()
    return (ua or "<no user-agent>"), "user_agent_only"


def analyse(entries: list, manifest: dict, declarations: dict) -> list:
    agents = defaultdict(lambda: {
        "basis": set(), "requests": 0, "disallowed": 0, "allowed": 0,
        "canary": 0, "timestamps": [], "user_agents": set(),
        "content_types": set(), "paths": set(),
    })

    for e in entries:
        if e["path"] in ("/robots.txt", "/sitemap.xml", "/about", "/"):
            robots_seen = e["path"] == "/robots.txt"
        else:
            robots_seen = False
        ident, basis = identify(e)
        a = agents[ident]
        a["basis"].add(basis)
        a["requests"] += 1
        a["timestamps"].append(e["ts"])
        if e.get("user_agent"):
            a["user_agents"].add(e["user_agent"])
        a["paths"].add(e["path"])
        if robots_seen:
            a["fetched_robots"] = True
        if e.get("arm") == "disallow":
            a["disallowed"] += 1
            if e["path"] == "/private/deep-canary":
                a["canary"] += 1
        elif e.get("arm"):
            a["allowed"] += 1
        if e.get("content_type"):
            a["content_types"].add(e["content_type"])

    rows = []
    for ident, a in agents.items():
        ts = sorted(a["timestamps"])
        gaps = [b - x for x, b in zip(ts, ts[1:])] if len(ts) > 1 else []
        scored = a["disallowed"] + a["allowed"]
        lo, hi = wilson(a["disallowed"], scored)
        decl = declarations.get(ident, {})

        declared_ua = decl.get("expected-user-agent")
        ua_match = None
        if declared_ua and a["user_agents"]:
            ua_match = any(declared_ua.split("/")[0] in u for u in a["user_agents"])

        rows.append({
            "agent": ident[:44],
            "basis": "+".join(sorted(a["basis"])),
            "requests": a["requests"],
            "on_arms": scored,
            "disallowed_fetches": a["disallowed"],
            "violation_rate": round(a["disallowed"] / scored, 4) if scored else 0.0,
            "ci": f"[{lo:.3f}, {hi:.3f}]",
            "deep_canary": a["canary"],
            "fetched_robots": bool(a.get("fetched_robots")),
            "median_gap_s": round(statistics.median(gaps), 2) if gaps else None,
            "min_gap_s": round(min(gaps), 2) if gaps else None,
            "declared_compliance": decl.get("rfc9309-compliance"),
            "declared_rate": decl.get("rate-expectation"),
            "declared_purpose": decl.get("purpose"),
            "declared_ua": declared_ua,
            "ua_matches_declaration": ua_match,
            "crawl_delay_honoured": (
                None if not gaps or not manifest.get("crawl_delay_seconds")
                else min(gaps) >= manifest["crawl_delay_seconds"]),
        })

    rows.sort(key=lambda r: (-r["disallowed_fetches"], -r["requests"]))
    return rows


def table(rows: list, cols: list, title: str) -> str:
    if not rows:
        return f"\n{title}\n  (no data)\n"
    w = {c: min(46, max(len(c), max(len(str(r.get(c, ""))) for r in rows))) for c in cols}
    head = "  ".join(c.ljust(w[c]) for c in cols)
    out = [f"\n{title}", "-" * len(head), head, "-" * len(head)]
    for r in rows:
        out.append("  ".join(str(r.get(c, ""))[:w[c]].ljust(w[c]) for c in cols))
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--domain", required=True)
    args = ap.parse_args()

    manifest_path = MANIFESTS / f"{args.domain}.json"
    if not manifest_path.exists():
        print(f"no manifest for {args.domain}")
        return
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    entries = load_logs(args.domain)
    if not entries:
        print(f"no requests logged for {args.domain} yet.")
        print("\nThis is the expected state for a newly registered domain. E3 is")
        print("gated on agents finding the site, which needs domain age and")
        print("inbound links. Nothing else in the study is blocked by it.")
        return

    declarations = load_declarations()
    rows = analyse(entries, manifest, declarations)

    verified = [r for r in rows if "verified_signature" in r["basis"]]
    unverified = [r for r in rows if "verified_signature" not in r["basis"]]

    print(f"\n{args.domain}: {len(entries)} requests, {len(rows)} distinct agents")
    print(f"  crawl-delay declared to crawlers: {manifest['crawl_delay_seconds']}s")
    print(f"  agents with a verified signature: {len(verified)}")
    print(f"  identified by header or UA only:  {len(unverified)}")

    cols = ["agent", "requests", "on_arms", "disallowed_fetches", "violation_rate",
            "ci", "deep_canary", "fetched_robots", "min_gap_s",
            "declared_compliance", "ua_matches_declaration"]
    print(table(verified, cols, "Verified agents - declared against observed"))
    print(table(unverified, cols,
                "Unverified (identity is claimed, not established)"))

    kv = sum(r["disallowed_fetches"] for r in verified)
    nv = sum(r["on_arms"] for r in verified)
    ku = sum(r["disallowed_fetches"] for r in unverified)
    nu = sum(r["on_arms"] for r in unverified)

    if nv and nu:
        diff, z = two_proportion(kv, nv, ku, nu)
        lo_v, hi_v = wilson(kv, nv)
        lo_u, hi_u = wilson(ku, nu)
        print("\nDisallowed-path fetch rate")
        print("-" * 62)
        print(f"  verified    {kv}/{nv} = {kv/nv:.3f}  [{lo_v:.3f}, {hi_v:.3f}]")
        print(f"  unverified  {ku}/{nu} = {ku/nu:.3f}  [{lo_u:.3f}, {hi_u:.3f}]")
        print(f"  difference  {diff:+.3f}   z = {z:.2f}")
        print("\n  If verified agents comply no better than unverified ones, then")
        print("  verification selects for paperwork rather than behaviour. That")
        print("  is the paper's headline either way it falls.")
    else:
        print("\nNot enough traffic in both strata to compare rates yet.")


if __name__ == "__main__":
    main()
