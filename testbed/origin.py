"""A strictly conforming Web Bot Auth origin, used as ground truth.

The harness is only trustworthy if a correct verifier accepts the control and
rejects every case the specification says it must. This origin is that
reference: it enforces the requirements literally, reports which check failed,
and is the target the harness is validated against before it is ever pointed
at anything else.

    python -m testbed.origin --port 8422
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wba.keys import SigningKey, jwk_to_public, thumbprint_of_jwk, verify  # noqa: E402
from wba.signature import Request, SigParams, signature_base  # noqa: E402

DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
MAX_SKEW = 60          # seconds a created timestamp may lead the clock
MAX_LIFETIME = 3600    # seconds a signature may remain valid

_INNER = re.compile(r"^\s*([A-Za-z0-9_-]+)\s*=\s*\((.*?)\)(.*)$", re.S)
_PARAM = re.compile(r';\s*([A-Za-z0-9_-]+)\s*=\s*("?)([^";]*)\2')


class Rejected(Exception):
    """Carries the identifier of the check that failed."""


def parse_signature_input(value: str):
    m = _INNER.match(value)
    if not m:
        raise Rejected("malformed_signature_input")
    label, inner, tail = m.group(1), m.group(2), m.group(3)
    components = re.findall(r'"([^"]+)"', inner)
    params = {}
    for name, _q, raw in _PARAM.findall(tail):
        params[name] = int(raw) if raw.isdigit() else raw
    return label, components, params


class Verifier:
    """Strict by default.

    `lax` injects four specific, documented weaknesses. It exists as a negative
    control: a conformance suite that only ever agrees with a correct verifier
    demonstrates nothing about its power to detect an incorrect one. Running
    the matrix against lax mode must produce findings at exactly the injected
    weaknesses and nowhere else.
    """

    LAX_WEAKNESSES = (
        "trusts X-Forwarded-Host when reconstructing @authority",
        "does not track nonces, so replays succeed",
        "ignores the expires parameter",
        "does not require the web-bot-auth tag",
    )

    def __init__(self, document: dict, lax: bool = False):
        # A directory is either a plain JWKS or a Signature Agent Card with the
        # key set nested under "jwks". Both are in circulation.
        keys = document.get("keys")
        if keys is None:
            keys = document.get("jwks", {}).get("keys", [])
        self.keys = {thumbprint_of_jwk(k): jwk_to_public(k) for k in keys}
        self.seen_nonces: set = set()
        self.lax = lax

    def check(self, method: str, url: str, headers: dict) -> str:
        sig_input = headers.get("signature-input")
        sig = headers.get("signature")
        if not sig_input or not sig:
            raise Rejected("no_signature")

        label, components, params = parse_signature_input(sig_input)

        # -- profile scoping
        if not self.lax and params.get("tag") != "web-bot-auth":
            raise Rejected("tag_not_web_bot_auth")

        # -- algorithm: this profile is Ed25519 only
        if params.get("alg") not in (None, "ed25519"):
            raise Rejected("algorithm_not_permitted")

        # -- freshness
        now = int(time.time())
        created, expires = params.get("created"), params.get("expires")
        if created is None:
            raise Rejected("created_absent")
        if created > now + MAX_SKEW:
            raise Rejected("created_in_future")
        if not self.lax:
            if expires is None:
                raise Rejected("expires_absent")
            if expires <= now:
                raise Rejected("expired")
            if expires - created > MAX_LIFETIME:
                raise Rejected("lifetime_too_long")

        # -- nonce uniqueness: draft s5.3 makes this the origin's job
        nonce = params.get("nonce")
        if not nonce:
            raise Rejected("nonce_absent")
        if not self.lax and nonce in self.seen_nonces:
            raise Rejected("nonce_replayed")

        # -- coverage: an uncovered authority is portable between origins
        if "@authority" not in components:
            raise Rejected("authority_uncovered")

        # -- key resolution
        keyid = params.get("keyid")
        pub = self.keys.get(keyid)
        if pub is None:
            raise Rejected("keyid_unknown")

        # -- cryptographic verification over the reconstructed base
        rebuilt = SigParams(
            keyid=keyid,
            components=components,
            created=created,
            expires=expires,
            nonce=nonce,
            alg=params.get("alg"),
            tag=params.get("tag"),
        )
        if self.lax and headers.get("x-forwarded-host"):
            # The weakness: rebuild the authority from an attacker-supplied
            # header instead of the connection this request actually arrived on.
            from urllib.parse import urlsplit
            p = urlsplit(url)
            url = f"{p.scheme}://{headers['x-forwarded-host']}{p.path}"
        request = Request(method, url, headers)
        try:
            base = signature_base(request, rebuilt)
        except KeyError:
            raise Rejected("covered_component_missing")

        m = re.search(r":([A-Za-z0-9+/=]+):", sig)
        if not m:
            raise Rejected("malformed_signature")
        try:
            raw = base64.b64decode(m.group(1))
        except Exception:
            raise Rejected("malformed_signature")

        if not verify(pub, raw, base):
            raise Rejected("bad_signature")

        self.seen_nonces.add(nonce)
        return nonce


class Handler(BaseHTTPRequestHandler):
    verifier: Verifier = None
    jwks: dict = None
    server_version = "wba-reference-origin/0.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("  origin: " + fmt % args + "\n")

    def _json(self, code: int, payload: dict):
        body = json.dumps(payload, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == DIRECTORY_PATH:
            self._json(200, self.jwks)
            return

        headers = {k.lower(): v for k, v in self.headers.items()}
        url = f"http://{self.headers.get('Host', 'localhost')}{self.path}"
        try:
            nonce = self.verifier.check("GET", url, headers)
        except Rejected as exc:
            self._json(401, {"verified": False, "reason": str(exc)})
            return
        self._json(200, {"verified": True, "nonce": nonce})


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8422)
    ap.add_argument("--keydir", default="keys")
    ap.add_argument("--lax", action="store_true",
                    help="negative control: inject known weaknesses")
    ap.add_argument("--card", action="store_true",
                    help="serve a Signature Agent Card rather than a plain JWKS")
    ap.add_argument("--purpose", default="search-index",
                    help="declared purpose, for exercising the harvester diff")
    ap.add_argument("--rate", type=int, default=60,
                    help="declared rate-expectation, requests per minute")
    args = ap.parse_args()

    keydir = Path(args.keydir)
    keydir.mkdir(exist_ok=True)
    primary_pem = keydir / "primary.pem"
    if primary_pem.exists():
        primary = SigningKey.from_pem(str(primary_pem))
    else:
        primary = SigningKey.generate()
        primary.save_pem(str(primary_pem))

    jwks = {"keys": [primary.jwk()]}
    if args.card:
        # draft-meunier-webbotauth-registry: OAuth client metadata plus the
        # web_bot_auth object carrying the declarations that earn listing.
        jwks = {
            "client_id": "https://reference.example/agent",
            "client_name": "Reference Agent",
            "client_uri": "https://reference.example",
            "contacts": ["ops@reference.example"],
            "jwks": {"keys": [primary.jwk()]},
            "web_bot_auth": {
                "purpose": args.purpose,
                "trigger": "crawler",
                "rate-expectation": {"requests-per-minute": args.rate},
                "rfc9309-compliance": True,
                "rfc9309-product-token": "ReferenceBot",
                "expected-user-agent": "ReferenceBot/1.0",
                "targeted-content": ["text/html"],
            },
        }
    (keydir / "directory.json").write_text(json.dumps(jwks, indent=2))

    Handler.verifier = Verifier(jwks, lax=args.lax)
    Handler.jwks = jwks

    mode = "LAX (negative control)" if args.lax else "strict"
    print(f"reference origin on http://127.0.0.1:{args.port}  [{mode}]")
    if args.lax:
        for w in Verifier.LAX_WEAKNESSES:
            print(f"    weakness: {w}")
    print(f"  directory  {DIRECTORY_PATH}")
    print(f"  keyid      {primary.thumbprint()}")
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
