"""End-to-end validation of the E2 harness.

Two controls, both required:

  positive - against a strictly conforming origin, every must-reject case is
             rejected and the control is accepted. Catches a harness that
             produces malformed requests and mistakes the resulting rejections
             for findings.

  negative - against an origin with four documented weaknesses, the suite
             reports findings at exactly those weaknesses and nowhere else.
             Catches a harness whose cases have no discriminating power - one
             that would report a clean bill of health for any target.

A suite that passes only the positive control demonstrates nothing. Run this
before every measurement round; a green run is what licenses belief in a red
row against any other target.

    python validate.py
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from run_conformance import run  # noqa: E402

STRICT_PORT = 18422
LAX_PORT = 18424
PEER_PORT = 18426

# The lax origin trusts X-Forwarded-Host, skips nonce tracking, ignores expires
# and drops the tag requirement. Only three of those are scored as findings;
# the tag cases are recorded as policy, not judged.
EXPECTED_LAX_FINDINGS = {"expired", "nonce_replayed", "forwarded_host_confusion"}


def spawn(port: int, lax: bool = False) -> subprocess.Popen:
    cmd = [sys.executable, "-m", "testbed.origin", "--port", str(port)]
    if lax:
        cmd.append("--lax")
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def findings(rows) -> set:
    return {r["case"] for r in rows if r["conforms"] == "NO"}


def control_failures(rows) -> set:
    return {r["case"] for r in rows if r["conforms"] == "no"}


def check(label: str, ok: bool, detail: str = "") -> bool:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if detail and not ok:
        print(f"         {detail}")
    return ok


def main() -> int:
    procs = [spawn(STRICT_PORT), spawn(LAX_PORT, lax=True), spawn(PEER_PORT)]
    time.sleep(3)
    ok = True
    peer = f"http://127.0.0.1:{PEER_PORT}"

    try:
        print("\npositive control - strictly conforming origin")
        rows = run(f"http://127.0.0.1:{STRICT_PORT}", "/robots.txt", 0.01,
                   "wba-validate/0.1", peer)
        f, cf = findings(rows), control_failures(rows)
        executed = [r for r in rows if r["outcome"] not in ("skipped", "error")]
        ok &= check("control_valid accepted", not cf, f"control failures: {cf}")
        ok &= check("no spurious findings", not f, f"unexpected findings: {sorted(f)}")
        ok &= check(f"all {len(executed)} cases executed",
                    len(executed) == len(rows),
                    f"{len(rows) - len(executed)} skipped or errored")

        print("\nnegative control - origin with four injected weaknesses")
        rows = run(f"http://127.0.0.1:{LAX_PORT}", "/robots.txt", 0.01,
                   "wba-validate/0.1", peer)
        f, cf = findings(rows), control_failures(rows)
        ok &= check("control_valid still accepted", not cf, f"control failures: {cf}")
        ok &= check("findings match injected weaknesses exactly",
                    f == EXPECTED_LAX_FINDINGS,
                    f"expected {sorted(EXPECTED_LAX_FINDINGS)}, got {sorted(f)}")
        ok &= check("cross_origin_replay still rejected without the forwarded header",
                    "cross_origin_replay" not in f,
                    "the two cross-origin cases should differ in discriminating power")

        print("\nunit tests")
        for script, label in (
            ("tests/test_rfc9421_vectors.py",
             "signature base reproduces RFC 9421 B.2.6"),
            ("tests/test_directory.py",
             "directory and agent-card parsing"),
        ):
            rc = subprocess.run([sys.executable, script],
                                capture_output=True, text=True)
            ok &= check(label, rc.returncode == 0, rc.stdout.strip()[-400:])
    finally:
        for p in procs:
            p.terminate()

    print()
    print("=" * 62)
    print("HARNESS VALIDATED" if ok else "VALIDATION FAILED - do not collect data")
    print("=" * 62)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
