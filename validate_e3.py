"""End-to-end validation of the E3 pipeline.

Unattended collection has no second chance: if the honeypot mislabels an arm,
fails to verify a signature, or drops a request, the loss is only discovered
after the months of traffic it was supposed to capture. This drives the whole
chain - allocate, serve, sign, log, join to declarations, analyse - with two
synthetic agents whose behaviour is known in advance, and asserts that the
analysis recovers it.

Two agents, distinct keys, distinct directories:

  obedient   reads robots.txt, honours Disallow  -> violation rate must be 0
  violating  ignores robots.txt entirely         -> violation rate must be > 0

If the analysis cannot tell those two apart, it cannot tell a compliant agent
from a non-compliant one, and no amount of real traffic would fix that.

    python validate_e3.py
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from analyze_e3 import analyse, load_declarations, load_logs  # noqa: E402
from honeypot.allocate import MANIFESTS  # noqa: E402

DOMAIN = "validate.local"
HONEYPOT_PORT = 18080
DIR_A_PORT = 18422
DIR_B_PORT = 18426
LOG = Path("honeypot/logs") / f"{DOMAIN}.jsonl"


def run(*args, **kw):
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, **kw)


def spawn(*args):
    return subprocess.Popen([sys.executable, *args],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def check(label: str, ok: bool, detail: str = "") -> bool:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if detail and not ok:
        print(f"         {detail}")
    return ok


def main() -> int:
    ok = True
    procs = []

    # Fresh state: a stale manifest or log would silently invalidate the run.
    for path in (MANIFESTS / f"{DOMAIN}.json", LOG):
        path.unlink(missing_ok=True)
    shutil.rmtree("keys_vb", ignore_errors=True)

    print("\nallocation")
    rc = run("-m", "honeypot.allocate", "--domain", DOMAIN,
             "--seed", "424242", "--paths", "40", "--crawl-delay", "2")
    ok &= check("manifest allocated", rc.returncode == 0, rc.stdout + rc.stderr)

    manifest = json.loads((MANIFESTS / f"{DOMAIN}.json").read_text(encoding="utf-8"))
    counts = manifest["counts"]
    ok &= check("all three arms populated",
                all(counts.get(a, 0) > 0 for a in manifest["arms"]), str(counts))
    ok &= check("deep canary allocated",
                any(s["path"] == "/private/deep-canary" for s in manifest["paths"]))

    try:
        procs.append(spawn("-m", "testbed.origin", "--port", str(DIR_A_PORT),
                           "--keydir", "keys"))
        procs.append(spawn("-m", "testbed.origin", "--port", str(DIR_B_PORT),
                           "--keydir", "keys_vb", "--card",
                           "--purpose", "ai-training", "--rate", "600"))
        procs.append(spawn("-m", "honeypot.server", "--domain", DOMAIN,
                           "--port", str(HONEYPOT_PORT), "--bind", "127.0.0.1"))
        time.sleep(4)

        print("\ntraffic")
        target = f"http://127.0.0.1:{HONEYPOT_PORT}"
        rc_good = run("-m", "honeypot.simulate", "--obedient", "--domain", DOMAIN,
                      "--target", target, "--ua", "GoodBot/1.0",
                      "--keyfile", "keys/primary.pem",
                      "--agent-url", f"http://127.0.0.1:{DIR_A_PORT}", "--pages", "18")
        ok &= check("obedient agent ran", rc_good.returncode == 0,
                    (rc_good.stdout + rc_good.stderr)[-300:])
        ok &= check("obedient agent skipped disallowed paths",
                    "skipped 0 on Disallow" not in rc_good.stdout,
                    "it skipped nothing, so the arms may not be reaching robots.txt")

        rc_bad = run("-m", "honeypot.simulate", "--violating", "--domain", DOMAIN,
                     "--target", target, "--ua", "ReferenceBot/1.0",
                     "--keyfile", "keys_vb/primary.pem",
                     "--agent-url", f"http://127.0.0.1:{DIR_B_PORT}", "--pages", "24")
        ok &= check("violating agent ran", rc_bad.returncode == 0,
                    (rc_bad.stdout + rc_bad.stderr)[-300:])

        print("\nharvest and analysis")
        Path("seeds_validate.txt").write_text(
            f"http://127.0.0.1:{DIR_A_PORT}\nhttp://127.0.0.1:{DIR_B_PORT}\n",
            encoding="utf-8")
        rc = run("harvest.py", "--seeds", "seeds_validate.txt", "--delay", "0.05")
        ok &= check("directories harvested", rc.returncode == 0, rc.stdout[-300:])

        entries = load_logs(DOMAIN)
        ok &= check("requests were logged", len(entries) > 20, f"{len(entries)} entries")

        rows = analyse(entries, manifest, load_declarations())
        verified = [r for r in rows if "verified_signature" in r["basis"]]
        ok &= check("two distinct verified identities", len(verified) == 2,
                    f"got {len(verified)}: {[r['agent'][:12] for r in verified]}")

        if len(verified) == 2:
            worst = max(verified, key=lambda r: r["violation_rate"])
            best = min(verified, key=lambda r: r["violation_rate"])
            ok &= check("violating agent shows violations",
                        worst["violation_rate"] > 0,
                        f"rate {worst['violation_rate']}")
            ok &= check("obedient agent shows none",
                        best["violation_rate"] == 0,
                        f"rate {best['violation_rate']}")
            ok &= check("the two are separated by the analysis",
                        worst["violation_rate"] > best["violation_rate"])
            ok &= check("robots.txt fetch recorded for the obedient agent",
                        best["fetched_robots"] is True)
            ok &= check("declaration joined from the harvested card",
                        worst["declared_compliance"] is not None,
                        "the T1 join failed, so declared-vs-observed is unavailable")
    finally:
        for p in procs:
            p.terminate()
        time.sleep(0.5)
        Path("seeds_validate.txt").unlink(missing_ok=True)
        shutil.rmtree("keys_vb", ignore_errors=True)

    print()
    print("=" * 62)
    print("E3 PIPELINE VALIDATED" if ok else "VALIDATION FAILED - do not deploy")
    print("=" * 62)
    if ok:
        print("\nThe chain records what it is supposed to record. What it cannot")
        print("tell you is whether real agents will ever arrive; that is a matter")
        print("of domain age and inbound links, not of code.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
