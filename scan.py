"""Internet-scale census of Web Bot Auth key directories.

The well-known path is a fixed URL on every host, so the population is not a
seed list to be guessed at - it is a census to be taken. This scans a large
host list (Tranco, Majestic, a zone file) for
`/.well-known/http-message-signatures-directory` and records what it finds.

Precedent for the scale and method: the ECH deployment studies scanned 7.5M
domains from multiple vantage points; internet-wide TLS and DNS measurement is
routine at IMC and USENIX Security. This is one HTTPS GET per host.

Designed for runs measured in days:

  concurrent      threads, because the work is entirely IO-bound
  rate-limited    a global token bucket, not just a per-thread sleep
  resumable       checkpointed, so a crash costs minutes rather than the run
  streaming       results append to JSONL; a 1M-host run never sits in memory
  fail-soft       DNS, TLS and timeout failures are recorded, never dropped

    python scan.py --hosts tranco.csv --limit 100000 --rate 40 --workers 64
    python scan.py --hosts tranco.csv --resume
    python scan.py --summarise results/scans/scan_<stamp>.jsonl
"""
from __future__ import annotations

import argparse
import csv
import json
import queue
import signal
import sys
import threading
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402
from requests.adapters import HTTPAdapter  # noqa: E402
from urllib3.util.retry import Retry  # noqa: E402

from wba.directory import WELL_KNOWN, parse  # noqa: E402

SCANS = Path("results/scans")
PLACEHOLDERS = ("example.org", "example.com", "you@", "your@", "TODO", "changeme")


def build_ua(contact_email: str, info_url: str) -> str:
    return (f"wba-census/0.1 (+{info_url}; academic measurement of Web Bot Auth "
            f"deployment; opt out: {contact_email})")


def check_attributable(contact_email: str, info_url: str, hosts: int) -> list:
    """Refuse an external census that cannot be attributed or opted out of.

    A million requests land in a million logs. If the contact address in the
    User-Agent does not resolve to a person who answers, the traffic is
    unattributable scanning rather than measurement, and no amount of good
    intent recorded elsewhere changes how it looks from the receiving end.
    """
    problems = []
    if not contact_email or "@" not in contact_email:
        problems.append("--contact must be a real address that is monitored")
    if not info_url.startswith("https://"):
        problems.append("--info-url must be an https page describing the study")
    for field, value in (("--contact", contact_email), ("--info-url", info_url)):
        if any(p.lower() in (value or "").lower() for p in PLACEHOLDERS):
            problems.append(f"{field} still contains a placeholder: {value}")
    if hosts > 10_000:
        prereg = Path("PREREGISTRATION.md")
        if prereg.exists() and "not yet timestamped" in prereg.read_text(
                encoding="utf-8", errors="ignore"):
            problems.append(
                "PREREGISTRATION.md is still marked 'not yet timestamped'. "
                "Register before collecting, or the analysis plan is unfalsifiable.")
    return problems

_stop = threading.Event()


class Backoff:
    """A shared pause, tripped when any host asks us to slow down.

    Per-worker backoff is useless here: each host is visited once, so the
    worker that was rebuffed never returns to that host. The signal is only
    meaningful if it slows the whole scan.
    """

    def __init__(self, base: float = 15.0, cap: float = 300.0,
                 window: float = 60.0, threshold: int = 3):
        self.base, self.cap = base, cap
        self.window, self.threshold = window, threshold
        self._until = 0.0
        self._events = []
        self._count = 0
        self._lock = threading.Lock()

    def trip(self, retry_after=None) -> None:
        """Pause only when rate limits cluster in time.

        A single 429 from one host is a statement about that host, not about
        our aggregate rate. In a scan of thousands, isolated 429s and 503s are
        ordinary noise from sites that reject any unfamiliar client.

        An earlier version escalated on a counter that never reset, so 105
        one-off responses from 105 unrelated hosts ratcheted the pause to 240s
        and stalled the run. Events now age out of a rolling window, and only a
        genuine cluster - several limits inside a minute, which is what being
        too fast actually looks like - slows everything down.

        An explicit Retry-After is always honoured: that is an instruction,
        not an inference.
        """
        now = time.monotonic()
        with self._lock:
            self._events = [t for t in self._events if now - t < self.window]
            self._events.append(now)
            recent = len(self._events)
            self._count += 1
            wait = 0.0
            if retry_after:
                try:
                    wait = min(self.cap, float(retry_after))
                except (TypeError, ValueError):
                    wait = 0.0
            if recent >= self.threshold:
                wait = max(wait, self.base * min(6, recent - self.threshold + 1))
            if wait <= 0:
                return
            self._until = max(self._until, now + min(wait, self.cap))
            total = self._count
        print("  backing off {:.0f}s ({} limits in {:.0f}s, {} total)".format(
            min(wait, self.cap), recent, self.window, total))

    def wait(self) -> None:
        while True:
            with self._lock:
                remaining = self._until - time.monotonic()
            if remaining <= 0 or _stop.is_set():
                return
            time.sleep(min(remaining, 2.0))

    @property
    def count(self) -> int:
        return self._count


_backoff = Backoff()


class RateLimiter:
    """Global token bucket.

    Per-thread sleeps do not bound aggregate rate: 64 workers each pausing one
    second still emit 64 requests per second. The limit has to be shared.
    """

    def __init__(self, per_second: float):
        self.interval = 1.0 / per_second if per_second > 0 else 0.0
        self._lock = threading.Lock()
        self._next = time.monotonic()

    def acquire(self) -> None:
        if not self.interval:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._next - now
            if wait < 0:
                self._next = now + self.interval
                wait = 0.0
            else:
                self._next += self.interval
        if wait > 0:
            time.sleep(wait)


def make_session(ua: str) -> requests.Session:
    s = requests.Session()
    # One attempt per host. Retrying a census multiplies load on the hosts
    # least able to answer, and a timeout is itself a result worth recording.
    adapter = HTTPAdapter(max_retries=Retry(total=0), pool_maxsize=4)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers.update({"User-Agent": ua, "Accept": "application/json"})
    return s


def probe(session: requests.Session, host: str, timeout: float) -> dict:
    # A bare host is probed over HTTPS: draft s5.1 makes a directory served over
    # plaintext a finding rather than a fallback. An explicit scheme is honoured
    # so the scanner can be exercised against a local origin.
    if host.startswith(("http://", "https://")):
        url = host.rstrip("/") + WELL_KNOWN
    else:
        url = f"https://{host}{WELL_KNOWN}"
    rec = {"host": host, "url": url, "ts": round(time.time(), 3),
           "ok": False, "status": None, "shape": None,
           "key_count": 0, "kids": "", "declared": None, "error": ""}
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
    except requests.exceptions.SSLError:
        rec["error"] = "tls"
        return rec
    except requests.exceptions.ConnectTimeout:
        rec["error"] = "connect_timeout"
        return rec
    except requests.exceptions.ReadTimeout:
        rec["error"] = "read_timeout"
        return rec
    except requests.exceptions.ConnectionError as exc:
        rec["error"] = "dns" if "NameResolution" in str(exc) else "connect"
        return rec
    except Exception as exc:
        rec["error"] = type(exc).__name__.lower()
        return rec

    rec["status"] = resp.status_code
    retry_after = resp.headers.get("Retry-After")
    if resp.status_code == 429 or (resp.status_code == 503 and retry_after):
        # 429 means precisely "too many requests" - the clearest signal a scan
        # can receive, so it pauses every worker rather than just this one.
        #
        # A bare 503 does NOT. Large sites routinely return 503 as a generic
        # block for unfamiliar clients, with no rate-limit meaning at all. An
        # earlier version treated the two alike; a single 503 from one large
        # host stalled the whole scan for thirty seconds, and at scale that
        # compounds into days. A 503 counts only when it carries Retry-After,
        # which makes it an explicit instruction rather than a guess.
        rec["error"] = f"http_{resp.status_code}"
        _backoff.trip(retry_after)
        return rec
    if resp.status_code != 200:
        rec["error"] = f"http_{resp.status_code}"
        return rec
    if len(resp.content) > 2_000_000:
        rec["error"] = "oversized"
        return rec
    try:
        payload = resp.json()
    except ValueError:
        rec["error"] = "not_json"
        return rec
    if not isinstance(payload, dict):
        rec["error"] = "not_object"
        return rec

    shape, keys, declared, _card = parse(payload)
    if shape == "unknown":
        rec["error"] = "no_keys_or_card"
        return rec

    rec.update({"ok": True, "shape": shape, "key_count": len(keys),
                "kids": ";".join(k["kid"] for k in keys),
                "declared": {k: v for k, v in declared.items() if v is not None}})
    return rec


def load_blocklist(path: str) -> set:
    """Hosts that have asked not to be scanned.

    Removal requests are honoured permanently and without argument. Keep this
    file in version control: it is the evidence that opt-outs were respected,
    and a reviewer is entitled to ask.
    """
    if not path:
        return set()
    p = Path(path)
    if not p.exists():
        return set()
    out = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line:
            out.add(line)
    return out


def preflight(info_url: str, ua: str) -> str:
    """Confirm the study page is actually live before any scanning starts.

    A User-Agent pointing at a 404 is worse than no URL at all: an
    administrator who follows it concludes the traffic is disguised.
    """
    try:
        resp = requests.get(info_url, timeout=10, headers={"User-Agent": ua})
    except requests.RequestException as exc:
        return f"info URL is not reachable ({type(exc).__name__})"
    if resp.status_code != 200:
        return f"info URL returned HTTP {resp.status_code}"
    if len(resp.text.strip()) < 200:
        return "info URL is reachable but nearly empty; it must explain the study"
    return ""


def load_hosts(path: Path, limit: int, skip: int) -> list:
    """Accepts a bare list or a ranked CSV such as Tranco (rank,domain)."""
    hosts, seen = [], set()
    with open(path, encoding="utf-8", errors="ignore") as fh:
        sample = fh.read(4096)
        fh.seek(0)
        reader = csv.reader(fh) if "," in sample else ((line.strip(),) for line in fh)
        for i, row in enumerate(reader):
            if not row:
                continue
            host = (row[1] if len(row) > 1 else row[0]).strip().lower()
            if not host or host.startswith("#"):
                continue
            if i < skip or host in seen:
                continue
            seen.add(host)
            hosts.append(host)
            if limit and len(hosts) >= limit:
                break
    return hosts


def worker(jobs: queue.Queue, out: queue.Queue, limiter: RateLimiter,
           timeout: float, ua: str):
    session = make_session(ua)
    while not _stop.is_set():
        try:
            host = jobs.get_nowait()
        except queue.Empty:
            return
        _backoff.wait()
        limiter.acquire()
        if _stop.is_set():
            return
        try:
            out.put(probe(session, host, timeout))
        finally:
            jobs.task_done()


def writer(out: queue.Queue, path: Path, total: int, checkpoint: Path,
           base_skip: int = 0):
    done = hits = 0
    started = time.time()
    with open(path, "a", encoding="utf-8") as fh:
        while True:
            rec = out.get()
            if rec is None:
                break
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            done += 1
            if rec["ok"]:
                hits += 1
                fh.flush()
                print(f"\n  FOUND  {rec['host']}  {rec['shape']}  "
                      f"{rec['key_count']} key(s)")
            if done % 200 == 0:
                fh.flush()
                # Absolute row in the host list, not records-this-run. A run
                # started with --skip must resume where it stopped in the file,
                # not at the count of what it processed.
                checkpoint.write_text(str(base_skip + done), encoding="utf-8")
                rate = done / max(1e-6, time.time() - started)
                eta = (total - done) / rate if rate else 0
                sys.stdout.write(
                    f"\r  {done}/{total}  {hits} found  "
                    f"{rate:.1f}/s  eta {eta/3600:.1f}h   ")
                sys.stdout.flush()
    print(f"\n\nscanned {done}, found {hits}")


def summarise(path: Path) -> None:
    total = Counter()
    shapes = Counter()
    declared = Counter()
    found = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            total["scanned"] += 1
            if rec["ok"]:
                total["found"] += 1
                shapes[rec["shape"]] += 1
                found.append(rec)
                for k in (rec.get("declared") or {}):
                    declared[k] += 1
            else:
                total[rec["error"] or "error"] += 1

    n = total["scanned"]
    resolvable = n - total.get("dns", 0)
    print(f"\n{path.name}")
    print("-" * 70)
    print(f"  scanned            {n}")
    print(f"  resolvable         {resolvable}"
          f"   ({total.get('dns', 0)} without an A record at the apex)")
    print(f"  directories found  {total['found']}"
          f"  ({100 * total['found'] / n:.4f}%)" if n else "")
    print(f"  shapes             {dict(shapes)}")

    print("\n  non-responses")
    for reason, c in total.most_common():
        if reason in ("scanned", "found"):
            continue
        print(f"    {reason:<22} {c:>8}  ({100 * c / n:.2f}%)")

    if found:
        kids = {k for r in found for k in r["kids"].split(";") if k}
        print(f"\n  distinct keys      {len(kids)}")
        print(f"  hosts per key      {len(found) / max(1, len(kids)):.2f}")
        if declared:
            print("\n  declared fields across agent cards")
            for f, c in declared.most_common():
                print(f"    {f:<26} {c}")
        print("\n  hosts")
        for r in sorted(found, key=lambda r: r["host"])[:40]:
            print(f"    {r['host']:<44} {r['shape']:<12} {r['key_count']} key(s)")
        if len(found) > 40:
            print(f"    ... and {len(found) - 40} more")

    if total.get("dns"):
        print("\n  Tranco ranks by DNS query volume, so CDN and DNS infrastructure")
        print("  domains rank highly while serving nothing at the apex. They cannot")
        print("  host a directory; report rates over the resolvable denominator.")
    print("\n  Non-responses are data. A census that reports only its hits")
    print("  cannot tell you how rare the thing is, which is the finding when")
    print("  the population turns out to be small.")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hosts", help="host list or ranked CSV (e.g. Tranco)")
    ap.add_argument("--limit", type=int, default=0, help="0 scans the whole file")
    ap.add_argument("--skip", type=int, default=0)
    ap.add_argument("--workers", type=int, default=32)
    ap.add_argument("--rate", type=float, default=25.0,
                    help="global requests per second, shared across workers")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--resume", action="store_true",
                    help="continue the most recent scan from its checkpoint")
    ap.add_argument("--summarise", help="summarise an existing scan file")
    ap.add_argument("--contact", default="",
                    help="a monitored address, carried in the User-Agent")
    ap.add_argument("--info-url", default="",
                    help="https page describing the study and how to opt out")
    ap.add_argument("--i-have-signoff", action="store_true",
                    help="assert institutional approval is in hand")
    ap.add_argument("--blocklist", default="blocklist.txt",
                    help="hosts that have opted out; always skipped")
    args = ap.parse_args()

    if args.summarise:
        summarise(Path(args.summarise))
        return

    if not args.hosts:
        ap.error("--hosts is required unless --summarise is given")

    SCANS.mkdir(parents=True, exist_ok=True)
    if args.resume:
        existing = sorted(SCANS.glob("scan_*.jsonl"))
        if not existing:
            print("nothing to resume")
            return
        outfile = existing[-1]
        checkpoint = outfile.with_suffix(".checkpoint")
        args.skip = int(checkpoint.read_text()) if checkpoint.exists() else 0
        print(f"resuming {outfile.name} from {args.skip}")
    else:
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        outfile = SCANS / f"scan_{stamp}.jsonl"
        checkpoint = outfile.with_suffix(".checkpoint")

    hosts = load_hosts(Path(args.hosts), args.limit, args.skip)
    if not hosts:
        print("no hosts loaded")
        return

    blocked = load_blocklist(args.blocklist)
    if blocked:
        before = len(hosts)
        hosts = [h for h in hosts if h.lower() not in blocked]
        print(f"blocklist: {before - len(hosts)} host(s) skipped by request")

    local_only = all(h.startswith("http://127.0.0.1") or
                     h.startswith("http://localhost") for h in hosts)
    ua = build_ua(args.contact or "you@example.org",
                  args.info_url or "https://example.org/research")

    if not local_only:
        problems = check_attributable(args.contact, args.info_url, len(hosts))
        if not args.i_have_signoff:
            problems.append("--i-have-signoff not given; confirm approval is in hand")
        if not problems:
            # The details look plausible. Now confirm they are real: a
            # User-Agent pointing at a dead URL is worse than none at all,
            # because an administrator who follows it concludes the traffic
            # was disguised rather than declared.
            print(f"preflight: fetching {args.info_url} ...")
            issue = preflight(args.info_url, ua)
            if issue:
                problems.append(issue)
            else:
                print("  study page is live\n")
        if problems:
            print("Refusing to scan external hosts.\n")
            for prob in problems:
                print(f"  - {prob}")
            print("\nA local run needs none of this:")
            print("  python scan.py --hosts hosts_local.txt   (127.0.0.1 targets only)")
            return

    print(f"census of {len(hosts)} hosts")
    print(f"  ua        {ua}")
    print(f"  path      {WELL_KNOWN}")
    print(f"  workers   {args.workers}   global rate {args.rate}/s")
    print(f"  output    {outfile}")
    print(f"  estimated {len(hosts) / args.rate / 3600:.1f}h\n")

    jobs: queue.Queue = queue.Queue()
    for h in hosts:
        jobs.put(h)
    out: queue.Queue = queue.Queue(maxsize=4096)
    limiter = RateLimiter(args.rate)

    def handle_sigint(_sig, _frm):
        print("\n\ninterrupted; finishing in-flight requests")
        _stop.set()
    signal.signal(signal.SIGINT, handle_sigint)

    scribe = threading.Thread(target=writer,
                              args=(out, outfile, len(hosts), checkpoint,
                                    args.skip))
    scribe.start()
    pool = [threading.Thread(target=worker,
                             args=(jobs, out, limiter, args.timeout, ua),
                             daemon=True) for _ in range(args.workers)]
    for t in pool:
        t.start()
    for t in pool:
        t.join()
    out.put(None)
    scribe.join()

    summarise(outfile)


if __name__ == "__main__":
    main()
