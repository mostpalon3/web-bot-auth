"""Fetching and parsing Web Bot Auth key directories and Signature Agent Cards.

Two document shapes are in circulation and a harvester has to handle both:

  plain JWKS          {"keys": [...]}                      RFC 7517
  Signature Agent Card OAuth client metadata + a web_bot_auth object,
                       carrying the declarations that earn an agent its place
                       in the signed lane (draft-meunier-webbotauth-registry)

The declared fields are the point. They are self-asserted claims about purpose,
rate and robots compliance, and the study exists to compare them against
observed behaviour, so they are parsed and retained verbatim rather than
normalised.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

import requests

from .keys import thumbprint_of_jwk

WELL_KNOWN = "/.well-known/http-message-signatures-directory"

# draft-meunier-webbotauth-registry: the web_bot_auth object. Retained verbatim;
# absence is itself data, so missing fields are recorded as null, not dropped.
DECLARED_FIELDS = [
    "purpose",
    "trigger",
    "rate-expectation",
    "rate-control",
    "rfc9309-compliance",
    "rfc9309-product-token",
    "expected-user-agent",
    "targeted-content",
    "known-urls",
    "ips_uri",
]

CARD_FIELDS = [
    "client_id", "client_name", "client_uri", "logo_uri", "contacts", "jwks_uri",
]


@dataclass
class Directory:
    """One fetched directory, reachable or not. Failures are records too."""

    source: str
    url: str
    fetched_utc: str
    reachable: bool = False
    status: Optional[int] = None
    content_type: str = ""
    final_url: str = ""
    redirected: bool = False
    scheme: str = ""
    error: str = ""
    shape: str = ""              # jwks | agent_card | unknown
    keys: list = field(default_factory=list)      # [{kid, kty, crv}]
    declared: dict = field(default_factory=dict)  # web_bot_auth object
    card: dict = field(default_factory=dict)      # OAuth client metadata
    raw_bytes: int = 0

    def to_row(self) -> dict:
        d = asdict(self)
        d["key_count"] = len(self.keys)
        d["kids"] = ";".join(k["kid"] for k in self.keys)
        return d


def _parse_keys(payload: dict) -> list:
    jwks = payload.get("keys")
    if jwks is None and isinstance(payload.get("jwks"), dict):
        jwks = payload["jwks"].get("keys")
    if not isinstance(jwks, list):
        return []
    out = []
    for jwk in jwks:
        if not isinstance(jwk, dict):
            continue
        entry = {"kty": jwk.get("kty", ""), "crv": jwk.get("crv", ""), "kid": ""}
        try:
            entry["kid"] = thumbprint_of_jwk(jwk)
        except (KeyError, TypeError, ValueError):
            # A key we cannot thumbprint is still a key. Record it and say why.
            entry["kid"] = f"<unthumbprintable:{jwk.get('kty', '?')}>"
        out.append(entry)
    return out


def parse(payload: dict) -> tuple:
    """Return (shape, keys, declared, card)."""
    declared = payload.get("web_bot_auth")
    declared = declared if isinstance(declared, dict) else {}
    card = {k: payload[k] for k in CARD_FIELDS if k in payload}
    keys = _parse_keys(payload)

    if declared or card:
        shape = "agent_card"
    elif keys:
        shape = "jwks"
    else:
        shape = "unknown"

    normalised = {f: declared.get(f) for f in DECLARED_FIELDS}
    extra = {k: v for k, v in declared.items() if k not in DECLARED_FIELDS}
    if extra:
        normalised["_undocumented_fields"] = extra

    return shape, keys, normalised, card


def fetch(url: str, source: str, timeout: float = 15.0,
          user_agent: str = "wba-registry-harvest/0.1") -> Directory:
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    rec = Directory(source=source, url=url, fetched_utc=stamp,
                    scheme=url.split(":", 1)[0])
    try:
        resp = requests.get(url, timeout=timeout, headers={
            "User-Agent": user_agent,
            "Accept": "application/json, application/http-message-signatures-directory",
        })
    except requests.RequestException as exc:
        rec.error = type(exc).__name__ + ": " + str(exc)[:160]
        return rec

    rec.status = resp.status_code
    rec.content_type = resp.headers.get("Content-Type", "")
    rec.final_url = resp.url
    rec.redirected = resp.url.rstrip("/") != url.rstrip("/")
    rec.raw_bytes = len(resp.content)

    if resp.status_code != 200:
        rec.error = f"http {resp.status_code}"
        return rec

    try:
        payload = resp.json()
    except ValueError:
        rec.error = "response is not JSON"
        return rec

    if not isinstance(payload, dict):
        rec.error = "top-level JSON is not an object"
        return rec

    rec.reachable = True
    rec.shape, rec.keys, rec.declared, rec.card = parse(payload)
    return rec


def candidate_urls(host: str) -> list:
    """Directory URLs to try for a bare host.

    HTTPS only. Draft section 5.1 says an origin SHOULD refuse signatures over an
    unsecured channel, so a directory served over plaintext is a finding rather
    than a fallback - it is probed explicitly by the audit, never used silently.
    """
    host = host.strip().rstrip("/")
    if host.startswith("http://") or host.startswith("https://"):
        base = host
    else:
        base = f"https://{host}"
    if base.endswith(WELL_KNOWN):
        return [base]
    return [base + WELL_KNOWN]
