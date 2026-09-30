"""The E2 conformance matrix.

Each case isolates exactly one deviation from the specification, so that an
origin's response attributes to that deviation and nothing else. Cases carry
the requirement they violate; the paper's claim is per-requirement rather than
per-implementation, so the citation is part of the data.

expectation:
  reject  - the specification requires rejection; acceptance is a finding
  accept  - control; rejection means the harness or the origin is broken
  policy  - the specification leaves this open; we record what deployments do
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, replace
from typing import Callable

from .keys import b64u
from .signature import sign, signature_base

SIGNED_AGENT = '"https://signed.example"'
SENT_AGENT = '"https://transmitted.example"'


@dataclass
class Case:
    name: str
    requirement: str
    expectation: str
    rationale: str
    build: Callable
    stateful: bool = False


# --- control ---------------------------------------------------------------

def c_valid(key, alt, request, params, ctx):
    return sign(key, request, params)


# --- freshness -------------------------------------------------------------

def c_expired(key, alt, request, params, ctx):
    now = int(time.time())
    return sign(key, request, replace(params, created=now - 7200, expires=now - 3600))


def c_created_future(key, alt, request, params, ctx):
    now = int(time.time())
    return sign(key, request, replace(params, created=now + 86400, expires=now + 90000))


def c_expires_absent(key, alt, request, params, ctx):
    return sign(key, request, replace(params, expires=None))


def c_created_absent(key, alt, request, params, ctx):
    return sign(key, request, replace(params, created=None))


# --- nonce -----------------------------------------------------------------

def c_nonce_absent(key, alt, request, params, ctx):
    return sign(key, request, replace(params, nonce=None))


def c_nonce_replayed(key, alt, request, params, ctx):
    """Reuse a nonce the origin has already accepted.

    Stateful: the runner sends the control first and passes its nonce through
    ctx, so this signature is valid in every respect except uniqueness.
    """
    prior = ctx.get("last_accepted_nonce")
    if prior is None:
        return None
    return sign(key, request, replace(params, nonce=prior))


# --- signature integrity ---------------------------------------------------

def c_signature_tampered(key, alt, request, params, ctx):
    raw = bytearray(key.sign(signature_base(request, params)))
    raw[-1] ^= 0x01
    return sign(key, request, params, signature_override=bytes(raw))


def c_component_tampered(key, alt, request, params, ctx):
    """Sign over one Signature-Agent value, transmit a different one."""
    signed_over = replace(request, headers=dict(request.headers))
    signed_over.headers["Signature-Agent"] = SIGNED_AGENT
    p = replace(params, components=params.components + ["signature-agent"])
    headers = sign(key, signed_over, p)
    headers["Signature-Agent"] = SENT_AGENT
    return headers


def c_wrong_key(key, alt, request, params, ctx):
    """Signature from a second key, advertising the first key's identifier."""
    return sign(alt, request, params)


def c_keyid_unknown(key, alt, request, params, ctx):
    bogus = b64u(hashlib.sha256(secrets.token_bytes(32)).digest())
    return sign(key, request, replace(params, keyid=bogus))


# --- algorithm -------------------------------------------------------------

def c_alg_confusion(key, alt, request, params, ctx):
    """Ed25519 signature bytes presented under an RSA algorithm label."""
    return sign(key, request, params, emit_params=replace(params, alg="rsa-v1_5-sha256"))


def c_shared_hmac(key, alt, request, params, ctx):
    """Symmetric MAC. Draft section 5.5 says implementations MUST NOT."""
    p = replace(params, alg="hmac-sha256")
    mac = hmac.new(b"web-bot-auth-shared-secret", signature_base(request, p),
                   hashlib.sha256).digest()
    return sign(key, request, p, signature_override=mac)


# --- coverage --------------------------------------------------------------

def c_authority_uncovered(key, alt, request, params, ctx):
    """Drop @authority so the signature no longer binds to a host, making it
    portable across origins by a reverse proxy (draft section 5.7)."""
    comps = [c for c in params.components if c != "@authority"]
    if comps == params.components:
        return None
    return sign(key, request, replace(params, components=comps))


def c_tag_absent(key, alt, request, params, ctx):
    return sign(key, request, replace(params, tag=None))


def c_tag_wrong(key, alt, request, params, ctx):
    return sign(key, request, replace(params, tag="not-web-bot-auth"))



# --- cross-origin portability (draft s5.7) ---------------------------------

def c_cross_origin_replay(key, alt, request, params, ctx):
    """Sign for one authority, present the signature at another.

    Draft section 5.7 warns that a reverse proxy sees the signature before the
    origin and may replay it elsewhere. A verifier that reconstructs
    @authority from the request it actually received will reject this; one
    that does not bind to the host will not.
    """
    origin_url = ctx.get("origin_url")
    if not origin_url:
        return None
    signed_for = replace(request, url=origin_url)
    return sign(key, signed_for, params)


def c_forwarded_host_confusion(key, alt, request, params, ctx):
    """Cross-origin replay, plus an X-Forwarded-Host naming the original.

    Sharper than the plain replay: it separates verifiers that bind to the
    connection's own authority from verifiers that trust a forwarded header
    when reconstructing it. The latter accept signatures minted for a
    different origin.
    """
    origin_url = ctx.get("origin_url")
    if not origin_url:
        return None
    from urllib.parse import urlsplit
    signed_for = replace(request, url=origin_url)
    headers = sign(key, signed_for, params)
    headers["X-Forwarded-Host"] = urlsplit(origin_url).netloc
    return headers

CASES = [
    Case("control_valid", "-", "accept",
         "Well-formed signature. Establishes that the origin verifies at all.",
         c_valid),

    Case("expired", "RFC 9421 s3.2", "reject",
         "expires precedes now, so the signature is outside its validity window.",
         c_expired),
    Case("created_future", "RFC 9421 s3.2", "reject",
         "created is a day ahead; accepting it defeats any replay window.",
         c_created_future),
    Case("expires_absent", "draft s4.2", "policy",
         "No expiry, so validity is unbounded unless the origin imposes one.",
         c_expires_absent),
    Case("created_absent", "draft s4.2", "policy",
         "No creation time, so the origin cannot bound freshness.",
         c_created_absent),

    Case("nonce_absent", "draft s4.2.2", "reject",
         "Clients MUST provide a globally unique nonce.",
         c_nonce_absent),
    Case("nonce_replayed", "draft s5.3", "reject",
         "Nonce reuse. The draft assigns enforcement to the origin, so this "
         "measures whether origins actually enforce it.",
         c_nonce_replayed, stateful=True),

    Case("signature_tampered", "RFC 9421 s3.2", "reject",
         "One flipped byte. Cryptographic verification must fail.",
         c_signature_tampered),
    Case("component_tampered", "RFC 9421 s2.5", "reject",
         "A covered header differs between signing and transmission.",
         c_component_tampered),
    Case("wrong_key", "RFC 9421 s3.2", "reject",
         "Signature by a key other than the advertised keyid.",
         c_wrong_key),
    Case("keyid_unknown", "draft s4.2", "reject",
         "keyid resolves to no key in any published directory.",
         c_keyid_unknown),

    Case("alg_confusion", "RFC 9421 s3.3", "reject",
         "Ed25519 bytes labelled as RSA. Tests algorithm agility handling.",
         c_alg_confusion),
    Case("shared_hmac", "draft s5.5", "reject",
         "Symmetric MAC, explicitly MUST NOT. Breaks non-repudiation.",
         c_shared_hmac),

    Case("authority_uncovered", "draft s5.7", "reject",
         "@authority uncovered, so the signature is portable across origins.",
         c_authority_uncovered),
    Case("tag_absent", "draft s4.2", "policy",
         "No tag, so the signature is not scoped to the web-bot-auth profile.",
         c_tag_absent),
    Case("tag_wrong", "draft s4.2", "policy",
         "A tag belonging to a different signature profile.",
         c_tag_wrong),

    Case("cross_origin_replay", "draft s5.7", "reject",
         "A signature minted for a different authority, presented here.",
         c_cross_origin_replay, stateful=True),
    Case("forwarded_host_confusion", "draft s5.7", "reject",
         "Cross-origin replay with X-Forwarded-Host naming the original "
         "authority. Tests whether the verifier trusts a forwarded header.",
         c_forwarded_host_confusion, stateful=True),
]

BY_NAME = {c.name: c for c in CASES}


def summary() -> str:
    rows = ["{:24} {:18} {:8} {}".format("case", "requirement", "expect", "rationale")]
    rows.append("-" * 104)
    for c in CASES:
        rows.append("{:24} {:18} {:8} {}".format(
            c.name, c.requirement, c.expectation, c.rationale[:52]))
    return "\n".join(rows)
