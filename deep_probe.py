"""Deep characterisation of every directory the census finds.

The census answers one binary question per host, so most of its answers are
"no". That is not a thin result, it is a thin *question*. This asks many
questions of the small population the census identifies, each independently
answerable, several of which map onto explicit requirements in the drafts.

Dimensions, and what each can find:

  serving hygiene   Content-Type, caching, CORS, compression. The draft defines
                    a media type; serving JSON as text/html is a conformance
                    miss that nobody has counted.

  transport         TLS version, HTTP version, HSTS. Draft s5.1 requires a
                    secure channel, so the directory's own transport security
                    is in scope.

  key material      algorithm and curve per key. The profile is Ed25519; any
                    other algorithm present is an interoperability finding.

  key reuse         draft s5.6: "Implementations MUST NOT reuse a signing key
                    for different purposes." A keyid appearing at two operators
                    is a direct, citable violation - and it is invisible to any
                    study that looks at one host at a time.

  operator posture  does the publisher also document its crawler in the
                    conventional places? Publishing keys while documenting
                    nothing is a different posture from doing both.

    python deep_probe.py --scan results/scans/scan_*.jsonl
    python deep_probe.py --hosts chatgpt.com,meta.com
"""
from __future__ import annotations

import argparse
import glob
import json
import socket
import ssl
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402

from wba.directory import WELL_KNOWN  # noqa: E402
from wba.keys import thumbprint_of_jwk  # noqa: E402

OUT = Path("results/deep")
UA = ("wba-census/0.1 (+https://sumit-sagar.github.io/signed-lane/; academic "
      "measurement of Web Bot Auth deployment; opt out: sumit.sagar.ug23@nsut.ac.in)")

# draft-meunier-web-bot-auth-architecture defines a media type for the
# directory. Serving it as something else still works but is a conformance miss.
EXPECTED_TYPES = ("application/http-message-signatures-directory",
                  "application/json")

# Places an operator conventionally documents automated traffic. Absence is not
# misconduct - it is a posture, and worth counting.
DOC_PATHS = ("/robots.txt", "/.well-known/security.txt", "/bot", "/bots",
             "/crawler", "/about/crawler")


def tls_profile(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    """TLS version and certificate basics, from a bare handshake."""
    out = {"tls_version": None, "cipher": None, "cert_issuer": None,
           "cert_days_remaining": None, "error": ""}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                out["tls_version"] = tls.version()
                cipher = tls.cipher()
                out["cipher"] = cipher[0] if cipher else None
                cert = tls.getpeercert()
                if cert:
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    out["cert_issuer"] = issuer.get("organizationName")
                    not_after = cert.get("notAfter")
                    if not_after:
                        exp = ssl.cert_time_to_seconds(not_after)
                        out["cert_days_remaining"] = int((exp - time.time()) / 86400)
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}"
    return out


def probe_directory(host: str, timeout: float = 12.0) -> dict:
    url = f"https://{host}{WELL_KNOWN}"
    rec = {"host": host, "url": url,
           "probed_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    session = requests.Session()
    session.headers.update({"User-Agent": UA})

    try:
        resp = session.get(url, timeout=timeout)
    except requests.RequestException as exc:
        rec["error"] = type(exc).__name__
        return rec

    h = {k.lower(): v for k, v in resp.headers.items()}
    ctype = h.get("content-type", "")
    rec["serving"] = {
        "status": resp.status_code,
        "content_type": ctype,
        "content_type_conformant": any(t in ctype.lower() for t in EXPECTED_TYPES),
        "uses_defined_media_type": EXPECTED_TYPES[0] in ctype.lower(),
        "bytes": len(resp.content),
        "cache_control": h.get("cache-control"),
        "etag": bool(h.get("etag")),
        "last_modified": bool(h.get("last-modified")),
        "cors": h.get("access-control-allow-origin"),
        "content_encoding": h.get("content-encoding"),
        "server": h.get("server"),
        "hsts": bool(h.get("strict-transport-security")),
        "http_version": f"HTTP/{resp.raw.version / 10:.1f}"
        if getattr(resp.raw, "version", None) else None,
    }
    rec["tls"] = tls_profile(host)

    try:
        payload = resp.json()
    except ValueError:
        rec["error"] = "not_json"
        return rec

    keys = payload.get("keys")
    if keys is None:
        keys = payload.get("jwks", {}).get("keys", [])
    parsed = []
    for jwk in keys or []:
        entry = {"kty": jwk.get("kty"), "crv": jwk.get("crv"),
                 "alg": jwk.get("alg"), "use": jwk.get("use"),
                 "kid_declared": jwk.get("kid"), "kid_thumbprint": None,
                 "profile_conformant": jwk.get("kty") == "OKP"
                 and jwk.get("crv") == "Ed25519"}
        try:
            entry["kid_thumbprint"] = thumbprint_of_jwk(jwk)
        except Exception:
            pass
        parsed.append(entry)
    rec["keys"] = parsed
    rec["key_count"] = len(parsed)
    rec["declared"] = payload.get("web_bot_auth") or {}
    rec["card_fields"] = [k for k in ("client_id", "client_name", "client_uri",
                                      "contacts", "jwks_uri", "logo_uri")
                          if k in payload]

    # Operator posture: does whoever publishes keys also document the bot?
    docs = {}
    for path in DOC_PATHS:
        try:
            r = session.get(f"https://{host}{path}", timeout=6,
                            allow_redirects=True)
            docs[path] = r.status_code if r.status_code != 200 else (
                200 if len(r.content) > 20 else "empty")
        except requests.RequestException:
            docs[path] = None
        time.sleep(0.4)
    rec["documentation"] = docs
    return rec


def key_reuse(records: list) -> dict:
    """Keys appearing under more than one operator.

    Draft s5.6 forbids reusing a signing key across purposes. A shared keyid is
    either that violation or shared infrastructure between operators; both are
    worth reporting, and neither is visible one host at a time.
    """
    by_key = defaultdict(set)
    for rec in records:
        for k in rec.get("keys", []):
            if k.get("kid_thumbprint"):
                by_key[k["kid_thumbprint"]].add(rec["host"])
    return {kid: sorted(hosts) for kid, hosts in by_key.items() if len(hosts) > 1}


def report(records: list) -> None:
    live = [r for r in records if "error" not in r]
    print(f"\ndeep probe: {len(records)} hosts, {len(live)} directories readable")
    if not live:
        return

    print("\nserving conformance")
    print("-" * 78)
    for r in live:
        s = r["serving"]
        media = "defined type" if s["uses_defined_media_type"] else (
            "application/json" if s["content_type_conformant"] else
            f"NON-CONFORMANT: {s['content_type'][:34]}")
        print(f"  {r['host']:<24} {media}")
    n_defined = sum(1 for r in live if r["serving"]["uses_defined_media_type"])
    print(f"\n  {n_defined}/{len(live)} use the media type the draft defines")

    print("\ncaching and transport")
    print("-" * 78)
    hdr = f"  {'host':<24} {'cache-control':<26} {'etag':<6} {'tls':<9} cert days"
    print(hdr)
    for r in live:
        s, t = r["serving"], r["tls"]
        print(f"  {r['host']:<24} {str(s['cache_control'])[:26]:<26} "
              f"{str(s['etag']):<6} {str(t['tls_version']):<9} "
              f"{t['cert_days_remaining']}")
    n_cache = sum(1 for r in live if r["serving"]["cache_control"])
    print(f"\n  {n_cache}/{len(live)} send Cache-Control. A directory fetched on "
          f"every\n  verification with no caching guidance is an availability "
          f"question:\n  the key endpoint becomes a dependency of every signed "
          f"request.")

    print("\nkey material")
    print("-" * 78)
    total = conformant = 0
    for r in live:
        for k in r["keys"]:
            total += 1
            conformant += bool(k["profile_conformant"])
        algs = ", ".join(f"{k['kty']}/{k['crv']}" for k in r["keys"]) or "none"
        print(f"  {r['host']:<24} {r['key_count']} key(s)  {algs}")
    print(f"\n  {conformant}/{total} keys are OKP/Ed25519, the profile's algorithm")

    print("\ndeclarations")
    print("-" * 78)
    with_card = [r for r in live if r["declared"] or r["card_fields"]]
    for r in live:
        fields = list(r["declared"]) or r["card_fields"] or []
        print(f"  {r['host']:<24} {', '.join(fields) if fields else 'bare JWKS'}")
    print(f"\n  {len(with_card)}/{len(live)} publish any Signature Agent Card field")

    print("\noperator posture: is the bot documented anywhere conventional?")
    print("-" * 78)
    for r in live:
        found = [p for p, code in r["documentation"].items() if code == 200]
        print(f"  {r['host']:<24} {', '.join(found) if found else 'nothing found'}")

    reuse = key_reuse(live)
    print("\nkey reuse across operators (draft s5.6: MUST NOT)")
    print("-" * 78)
    if reuse:
        for kid, hosts in reuse.items():
            print(f"  FINDING  {kid[:22]}...  shared by {', '.join(hosts)}")
    else:
        print("  none observed - every key is unique to one operator")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scan", help="glob of census JSONL to take hosts from")
    ap.add_argument("--hosts", help="comma-separated hosts instead")
    ap.add_argument("--delay", type=float, default=2.0)
    args = ap.parse_args()

    hosts = []
    if args.hosts:
        hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    elif args.scan:
        for path in glob.glob(args.scan):
            for line in open(path, encoding="utf-8"):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("ok"):
                    hosts.append(rec["host"])
    hosts = sorted(set(hosts))
    if not hosts:
        print("no hosts. Pass --hosts or --scan pointing at census output.")
        return

    print(f"deep-probing {len(hosts)} director{'y' if len(hosts) == 1 else 'ies'}")
    records = []
    for i, host in enumerate(hosts, 1):
        print(f"  [{i}/{len(hosts)}] {host}")
        records.append(probe_directory(host))
        time.sleep(args.delay)

    OUT.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = OUT / f"deep_{stamp}.json"
    path.write_text(json.dumps(records, indent=2), encoding="utf-8")
    report(records)
    print(f"\nwritten: {path}")


if __name__ == "__main__":
    main()
