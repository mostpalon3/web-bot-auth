"""Randomised allocation of paths to robots.txt treatments.

This is the experimental core of E3. A honeypot that simply logs what arrives
is an observational study; randomly assigning paths to allow and disallow arms
makes it an experiment, because a crawler cannot have any prior reason to treat
one arm differently from the other except by reading robots.txt.

The allocation is seeded and written to a manifest **before any traffic
arrives**, and must not change afterwards. A robots.txt that shifts under a
crawler mid-visit destroys the attribution: you could no longer say whether a
fetch of a disallowed path was a violation or a stale read.

    python -m honeypot.allocate --domain example.org --seed 20260910 --paths 60
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import time
from dataclasses import dataclass, asdict
from pathlib import Path

MANIFESTS = Path("honeypot/manifests")

# Path-level arms. Assignment is random, so any difference in fetch rate
# between ALLOW and DISALLOW is attributable to robots.txt and nothing else.
ARMS = ("allow_implicit", "allow_explicit", "disallow")

# Section headings, used only to make the pages look like an ordinary small
# site. Content is inert: no forms, no scripts, no outbound links beyond the
# site itself.
TOPICS = [
    "notes", "archive", "reference", "changelog", "glossary", "index",
    "summary", "tables", "figures", "appendix", "errata", "sources",
]


@dataclass
class PathSpec:
    path: str
    arm: str
    linked_from: str          # "root" | "disallowed_page" | "sitemap_only" | "orphan"
    content_type: str

    def disallowed(self) -> bool:
        return self.arm == "disallow"


def allocate(domain: str, seed: int, n_paths: int, crawl_delay: int) -> dict:
    rng = random.Random(f"{domain}:{seed}")
    specs = []

    for i in range(n_paths):
        topic = rng.choice(TOPICS)
        slug = hashlib.sha256(f"{domain}:{seed}:{i}".encode()).hexdigest()[:10]
        arm = rng.choice(ARMS)

        # Reachability is crossed with the arm so that the two questions -
        # "did it obey robots.txt" and "how did it find the page" - can be
        # separated in analysis.
        if arm == "disallow":
            linked = rng.choice(["root", "sitemap_only", "disallowed_page", "orphan"])
        else:
            linked = rng.choice(["root", "sitemap_only"])

        content_type = rng.choice(["text/html", "text/html", "text/html",
                                   "text/plain", "application/json"])
        specs.append(PathSpec(f"/{topic}/{slug}", arm, linked, content_type))

    # A disallowed page reachable only from another disallowed page. Fetching
    # it means robots.txt was not consulted before following links, which is a
    # stronger violation than fetching a disallowed page linked from the root.
    specs.append(PathSpec("/private/deep-canary", "disallow", "disallowed_page",
                          "text/html"))

    return {
        "domain": domain,
        "seed": seed,
        "allocated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "crawl_delay_seconds": crawl_delay,
        "arms": list(ARMS),
        "paths": [asdict(s) for s in specs],
        "counts": {arm: sum(1 for s in specs if s.arm == arm) for arm in ARMS},
    }


def robots_txt(manifest: dict) -> str:
    """One group, applying to every agent.

    Per-agent groups would let a crawler match a narrower group and ignore the
    wildcard, which would confound the arms. A single wildcard group keeps the
    treatment identical for everyone.
    """
    lines = [
        "# Research measurement site. Contact: you@example.org",
        "# See /about for what is collected and why.",
        "",
        "User-agent: *",
    ]
    for spec in manifest["paths"]:
        if spec["arm"] == "disallow":
            lines.append(f"Disallow: {spec['path']}")
    for spec in manifest["paths"]:
        if spec["arm"] == "allow_explicit":
            lines.append(f"Allow: {spec['path']}")
    if manifest["crawl_delay_seconds"]:
        lines.append(f"Crawl-delay: {manifest['crawl_delay_seconds']}")
    lines += ["", f"Sitemap: https://{manifest['domain']}/sitemap.xml", ""]
    return "\n".join(lines)


def sitemap_xml(manifest: dict) -> str:
    """Includes disallowed paths deliberately.

    A sitemap listing a disallowed URL is a real and common misconfiguration,
    and the precedence question - which directive wins - is worth measuring
    rather than avoiding.
    """
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for spec in manifest["paths"]:
        if spec["linked_from"] in ("root", "sitemap_only"):
            out.append(f"  <url><loc>https://{manifest['domain']}{spec['path']}</loc></url>")
    out.append("</urlset>")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--domain", required=True)
    ap.add_argument("--seed", type=int, required=True,
                    help="record this in the pre-registration")
    ap.add_argument("--paths", type=int, default=60)
    ap.add_argument("--crawl-delay", type=int, default=10,
                    help="vary across domains to test rate adherence")
    ap.add_argument("--force", action="store_true",
                    help="overwrite an existing manifest (destroys attribution)")
    args = ap.parse_args()

    MANIFESTS.mkdir(parents=True, exist_ok=True)
    path = MANIFESTS / f"{args.domain}.json"

    if path.exists() and not args.force:
        print(f"manifest already exists: {path}")
        print("Refusing to reallocate. Once traffic has arrived, changing the")
        print("allocation makes every observation uninterpretable. Use --force")
        print("only before the site has been published.")
        return

    manifest = allocate(args.domain, args.seed, args.paths, args.crawl_delay)
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"allocated {len(manifest['paths'])} paths for {args.domain}")
    print(f"  seed            {args.seed}")
    print(f"  crawl-delay     {args.crawl_delay}s")
    for arm, n in manifest["counts"].items():
        print(f"  {arm:<16} {n}")
    print(f"\nmanifest: {path}")
    print("Record the seed in PREREGISTRATION.md before publishing the site.")


if __name__ == "__main__":
    main()
