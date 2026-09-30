"""Validate the signature base against RFC 9421's published test vectors.

A conformance harness that is itself non-conformant produces findings that are
its own bugs. These tests pin the implementation to the RFC's worked examples:
if the signature base is assembled correctly, the RFC's published signature
verifies against the RFC's published key. If it is assembled incorrectly, it
does not. There is no way to fake a pass.

    python -m pytest tests/ -v      (or: python tests/test_rfc9421_vectors.py)
"""
from __future__ import annotations

import base64
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wba.keys import verify  # noqa: E402
from wba.signature import Request, SigParams, signature_base  # noqa: E402

# RFC 9421 Appendix B.1.4 - the test key for Ed25519.
#
# Only the PUBLIC half is kept here. The RFC also publishes the matching
# private key, but nothing in this suite needs it: the load-bearing test
# verifies the RFC's own published signature against our assembled base, which
# requires the public key alone. The round-trip test below generates a fresh
# ephemeral key instead, so this repository contains no private key material
# of any kind.
ED25519_PUBLIC = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----
"""

# RFC 9421 Appendix B.2.6 - "Signing a Request using ed25519"
B26_SIGNATURE = (
    "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw=="
)

B26_EXPECTED_BASE = (
    '"date": Tue, 20 Apr 2021 02:07:55 GMT\n'
    '"@method": POST\n'
    '"@path": /foo\n'
    '"@authority": example.com\n'
    '"content-type": application/json\n'
    '"content-length": 18\n'
    '"@signature-params": ("date" "@method" "@path" "@authority" '
    '"content-type" "content-length");created=1618884473;keyid="test-key-ed25519"'
)


def _b26_request() -> Request:
    return Request(
        method="POST",
        url="https://example.com/foo?param=Value&Pet=dog",
        headers={
            "Date": "Tue, 20 Apr 2021 02:07:55 GMT",
            "Content-Type": "application/json",
            "Content-Length": "18",
        },
    )


def _b26_params() -> SigParams:
    return SigParams(
        keyid="test-key-ed25519",
        components=["date", "@method", "@path", "@authority",
                    "content-type", "content-length"],
        created=1618884473,
        expires=None,
        nonce=None,
        alg=None,
        tag=None,
    )


def test_signature_base_matches_rfc_text():
    """Our assembled base is byte-identical to the RFC's printed example."""
    produced = signature_base(_b26_request(), _b26_params()).decode()
    assert produced == B26_EXPECTED_BASE, (
        "signature base diverges from RFC 9421 B.2.6\n"
        f"--- produced ---\n{produced}\n--- expected ---\n{B26_EXPECTED_BASE}"
    )


def test_rfc_signature_verifies_over_our_base():
    """The RFC's published signature verifies against our base and its key.

    This is the load-bearing test. Ed25519 verification only succeeds over the
    exact bytes that were signed, so a pass proves the base is correct.
    """
    public = serialization.load_pem_public_key(ED25519_PUBLIC.encode())
    base = signature_base(_b26_request(), _b26_params())
    assert verify(public, base64.b64decode(B26_SIGNATURE), base)


def test_our_signature_verifies_over_our_base():
    """Round trip over the same base, with an ephemeral key.

    This checks that our sign and verify paths agree with each other. It
    deliberately does NOT use the RFC's private key: signing and verifying
    with the same key proves nothing about RFC conformance, which is what
    test_rfc_signature_verifies_over_our_base establishes.
    """
    private = ed25519.Ed25519PrivateKey.generate()
    base = signature_base(_b26_request(), _b26_params())
    assert verify(private.public_key(), private.sign(base), base)


def test_derived_components():
    r = Request("get", "https://Example.COM:8443/a/b?x=1&y=2", {})
    assert r.derived("@method") == "GET"
    assert r.derived("@authority") == "example.com:8443"
    assert r.derived("@path") == "/a/b"
    assert r.derived("@scheme") == "https"
    assert r.derived("@query") == "?x=1&y=2"


def test_header_values_are_trimmed():
    r = Request("GET", "https://example.com/", {"X-Thing": "  spaced  "})
    assert r.component_value("x-thing") == "spaced"
    assert r.component_value("X-THING") == "spaced"


def test_missing_covered_component_raises():
    r = Request("GET", "https://example.com/", {})
    try:
        r.component_value("signature-agent")
    except KeyError:
        return
    raise AssertionError("expected KeyError for an absent covered component")


def test_param_order_is_stable():
    """Base and header must serialise parameters identically, or verification
    fails for reasons unrelated to the case under test."""
    p = SigParams(keyid="k", created=1, expires=2, nonce="n", alg="ed25519",
                  tag="web-bot-auth")
    s = p.serialize()
    assert s.index("created") < s.index("expires") < s.index("keyid")
    assert s.index("keyid") < s.index("alg") < s.index("nonce") < s.index("tag")


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failures += 1
            print(f"  FAIL  {name}\n        {exc}")
    print()
    print("RFC 9421 conformance:", "OK" if failures == 0 else f"{failures} FAILURES")
    sys.exit(1 if failures else 0)
