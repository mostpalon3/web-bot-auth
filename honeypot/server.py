"""E3 honeypot.

Serves a small, inert site whose robots.txt was randomly allocated in advance,
and records every request in full fidelity.

Two rules govern the design:

  Never block. A disallowed path must still be served, or a violation of
  robots.txt is unobservable - refusing the request would measure our own
  enforcement instead of the crawler's compliance.

  Establish identity cryptographically. Agent attribution comes from a verified
  Web Bot Auth signature, not from a User-Agent string, because a User-Agent is
  exactly what the signed lane exists to stop trusting. Requests that carry no
  valid signature are logged and analysed separately.

Runs unattended for months, so it fails soft everywhere: a request that cannot
be verified, parsed or resolved is still served and still logged.

    python -m honeypot.allocate --domain example.org --seed 20260910
    python -m honeypot.server --domain example.org --port 8080
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests  # noqa: E402

from honeypot.allocate import MANIFESTS, robots_txt, sitemap_xml  # noqa: E402
from wba.keys import jwk_to_public, thumbprint_of_jwk, verify  # noqa: E402
from wba.signature import Request, SigParams, signature_base  # noqa: E402

LOGS = Path("honeypot/logs")
DIRECTORY_TTL = 3600

_INNER = re.compile(r"^\s*([A-Za-z0-9_-]+)\s*=\s*\((.*?)\)(.*)$", re.S)
_PARAM = re.compile(r';\s*([A-Za-z0-9_-]+)\s*=\s*("?)([^";]*)\2')
_SIG = re.compile(r":([A-Za-z0-9+/=]+):")

ABOUT = """<!doctype html>
<title>About this site</title>
<h1>About this site</h1>
<p>This host is part of an academic measurement study of automated web
traffic. It serves ordinary, inert pages and records the requests it receives:
timestamp, path, headers, and whether the request carried a valid HTTP Message
Signature.</p>
<p>Nothing here is a trap, a paywall, or a challenge. Every page is served to
every requester, including pages excluded by robots.txt, because the study
measures whether crawlers honour those directives rather than enforcing them.</p>
<p>No personal data is sought or retained beyond what an ordinary web server
log contains. To have your agent excluded from the dataset, write to
you@example.org and it will be removed without argument.</p>
"""


class DirectoryCache:
    """Resolves keyids by fetching the directory a request points at.

    Doubles as passive discovery: every Signature-Agent seen here is a real,
    observed operator, which is a far better source of T1 seeds than guessing
    at well-known paths.
    """

    def __init__(self):
        self._keys: dict = {}
        self._fetched: dict = {}
        self._lock = threading.Lock()
        self.seen_agents: dict = {}

    def note_agent(self, url: str) -> None:
        with self._lock:
            entry = self.seen_agents.setdefault(url, {"first": time.time(), "count": 0})
            entry["count"] += 1
            entry["last"] = time.time()

    def resolve(self, keyid: str, agent_url: str):
        if not agent_url:
            return None
        with self._lock:
            cached = self._keys.get(keyid)
            fresh = time.time() - self._fetched.get(agent_url, 0) < DIRECTORY_TTL
        if cached and fresh:
            return cached
        try:
            base = agent_url.rstrip("/")
            if not base.endswith("http-message-signatures-directory"):
                base += "/.well-known/http-message-signatures-directory"
            resp = requests.get(base, timeout=8, headers={
                "User-Agent": "wba-honeypot-key-resolution/0.1"})
            payload = resp.json()
        except Exception:
            with self._lock:
                self._fetched[agent_url] = time.time()
            return None

        keys = payload.get("keys")
        if keys is None:
            keys = payload.get("jwks", {}).get("keys", [])
        with self._lock:
            for jwk in keys or []:
                try:
                    self._keys[thumbprint_of_jwk(jwk)] = jwk_to_public(jwk)
                except Exception:
                    continue
            self._fetched[agent_url] = time.time()
            return self._keys.get(keyid)


def parse_signature_input(value: str):
    m = _INNER.match(value)
    if not m:
        return None, [], {}
    components = re.findall(r'"([^"]+)"', m.group(2))
    params = {}
    for name, _q, raw in _PARAM.findall(m.group(3)):
        params[name] = int(raw) if raw.isdigit() else raw
    return m.group(1), components, params


def inspect_signature(method: str, url: str, headers: dict, cache: DirectoryCache) -> dict:
    """Never raises. Returns what could be established about the signature."""
    out = {"signed": False, "verified": False, "keyid": None,
           "signature_agent": None, "tag": None, "created": None,
           "expires": None, "nonce": None, "covered": [], "note": ""}

    sig_input, sig = headers.get("signature-input"), headers.get("signature")
    agent = (headers.get("signature-agent") or "").strip().strip('"')
    if agent:
        out["signature_agent"] = agent
        cache.note_agent(agent)
    if not sig_input or not sig:
        return out

    out["signed"] = True
    _label, components, params = parse_signature_input(sig_input)
    out.update({
        "keyid": params.get("keyid"), "tag": params.get("tag"),
        "created": params.get("created"), "expires": params.get("expires"),
        "nonce": params.get("nonce"), "covered": components,
    })

    if not out["keyid"]:
        out["note"] = "no keyid"
        return out

    pub = cache.resolve(out["keyid"], agent)
    if pub is None:
        out["note"] = "key not resolvable"
        return out

    try:
        rebuilt = SigParams(
            keyid=out["keyid"], components=components,
            created=params.get("created"), expires=params.get("expires"),
            nonce=params.get("nonce"), alg=params.get("alg"), tag=params.get("tag"))
        base = signature_base(Request(method, url, headers), rebuilt)
        m = _SIG.search(sig)
        if not m:
            out["note"] = "malformed signature value"
            return out
        out["verified"] = verify(pub, base64.b64decode(m.group(1)), base)
        if not out["verified"]:
            out["note"] = "signature did not verify"
    except Exception as exc:
        out["note"] = f"verification error: {type(exc).__name__}"
    return out


class Handler(BaseHTTPRequestHandler):
    manifest: dict = None
    index: dict = None
    cache: DirectoryCache = None
    logfile = None
    loglock = threading.Lock()
    server_version = "wba-honeypot/0.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # the structured log is the record; stderr noise is not

    def _send(self, code: int, body: bytes, content_type: str):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Research-Contact", "you@example.org")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _record(self, path: str, status: int, sig: dict, spec: dict) -> None:
        entry = {
            "ts": round(time.time(), 6),
            "method": self.command,
            "path": path,
            "status": status,
            "remote": self.client_address[0],
            "http_version": self.request_version,
            "user_agent": self.headers.get("User-Agent", ""),
            "arm": spec.get("arm") if spec else None,
            "linked_from": spec.get("linked_from") if spec else None,
            "content_type": spec.get("content_type") if spec else None,
            "signature": sig,
            "headers": {k.lower(): v for k, v in self.headers.items()},
        }
        line = json.dumps(entry, ensure_ascii=False)
        with self.loglock:
            self.logfile.write(line + "\n")
            self.logfile.flush()

    def do_GET(self):
        self._handle()

    def do_HEAD(self):
        self._handle(head=True)

    def _handle(self, head: bool = False):
        parts = urlsplit(self.path)
        path = parts.path
        host = self.headers.get("Host", self.manifest["domain"])
        url = f"https://{host}{self.path}"

        headers = {k.lower(): v for k, v in self.headers.items()}
        sig = inspect_signature(self.command, url, headers, self.cache)
        spec = self.index.get(path)

        if path == "/robots.txt":
            body, ctype, status = robots_txt(self.manifest).encode(), "text/plain", 200
        elif path == "/sitemap.xml":
            body, ctype, status = sitemap_xml(self.manifest).encode(), "application/xml", 200
        elif path == "/about":
            body, ctype, status = ABOUT.encode(), "text/html", 200
        elif path == "/":
            body, ctype, status = self._root().encode(), "text/html", 200
        elif spec:
            # Served regardless of arm. Blocking here would measure our own
            # enforcement rather than the crawler's compliance.
            body, ctype, status = self._page(path, spec), spec["content_type"], 200
        else:
            body, ctype, status = b"not found\n", "text/plain", 404

        self._record(path, status, sig, spec)
        self._send(status, b"" if head else body, ctype)

    def _root(self) -> str:
        links = [f'<li><a href="{s["path"]}">{s["path"]}</a></li>'
                 for s in self.manifest["paths"] if s["linked_from"] == "root"]
        return ("<!doctype html><title>Index</title><h1>Index</h1>"
                f'<p><a href="/about">About this site</a></p><ul>{"".join(links)}</ul>')

    def _page(self, path: str, spec: dict) -> bytes:
        if spec["content_type"] == "application/json":
            return json.dumps({"path": path, "note": "research measurement page"},
                              indent=2).encode()
        if spec["content_type"] == "text/plain":
            return f"{path}\n\nResearch measurement page. See /about\n".encode()

        # A disallowed page is the only place a deep canary is linked from, so
        # fetching the canary proves robots.txt was not consulted before
        # following links.
        extra = ""
        if spec["arm"] == "disallow":
            deep = [s["path"] for s in self.manifest["paths"]
                    if s["linked_from"] == "disallowed_page"]
            extra = "".join(f'<li><a href="{d}">{d}</a></li>' for d in deep)
            extra = f"<ul>{extra}</ul>" if extra else ""
        return (f"<!doctype html><title>{path}</title><h1>{path}</h1>"
                f'<p>Research measurement page. <a href="/about">About</a></p>'
                f"{extra}").encode()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--domain", required=True)
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--bind", default="0.0.0.0")
    args = ap.parse_args()

    manifest_path = MANIFESTS / f"{args.domain}.json"
    if not manifest_path.exists():
        print(f"no manifest for {args.domain}. Run honeypot.allocate first.")
        return
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    LOGS.mkdir(parents=True, exist_ok=True)
    logpath = LOGS / f"{args.domain}.jsonl"

    Handler.manifest = manifest
    Handler.index = {s["path"]: s for s in manifest["paths"]}
    Handler.cache = DirectoryCache()
    Handler.logfile = open(logpath, "a", encoding="utf-8")

    counts = manifest["counts"]
    print(f"honeypot for {args.domain} on {args.bind}:{args.port}")
    print(f"  seed          {manifest['seed']}")
    print(f"  crawl-delay   {manifest['crawl_delay_seconds']}s")
    print(f"  paths         {len(manifest['paths'])}  {counts}")
    print(f"  log           {logpath}")
    print("\nServing every path, including disallowed ones. That is deliberate.")
    try:
        ThreadingHTTPServer((args.bind, args.port), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        Handler.logfile.close()


if __name__ == "__main__":
    main()
