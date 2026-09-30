"""Unit tests for directory parsing.

Network-free. These pin the parsing decisions that the T1 population figures
depend on, particularly the ones where a silent failure would understate the
population or lose a declaration.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wba.directory import DECLARED_FIELDS, candidate_urls, parse  # noqa: E402
from wba.keys import SigningKey  # noqa: E402

KEY = SigningKey.generate()


def test_plain_jwks():
    shape, keys, declared, card = parse({"keys": [KEY.jwk()]})
    assert shape == "jwks"
    assert len(keys) == 1
    assert keys[0]["kid"] == KEY.thumbprint()
    assert card == {}


def test_agent_card_with_nested_jwks():
    doc = {
        "client_id": "https://a.example/agent",
        "client_name": "A",
        "jwks": {"keys": [KEY.jwk()]},
        "web_bot_auth": {"purpose": "search-index", "rfc9309-compliance": True},
    }
    shape, keys, declared, card = parse(doc)
    assert shape == "agent_card"
    assert keys[0]["kid"] == KEY.thumbprint()
    assert card["client_id"] == "https://a.example/agent"
    assert declared["purpose"] == "search-index"
    assert declared["rfc9309-compliance"] is True


def test_absent_declarations_are_recorded_as_null_not_dropped():
    """Absence is data: a field that is not declared cannot be violated, and
    the coverage figure depends on distinguishing absent from false."""
    _, _, declared, _ = parse({"jwks": {"keys": []}, "web_bot_auth": {"purpose": "x"}})
    for f in DECLARED_FIELDS:
        assert f in declared
    assert declared["rate-expectation"] is None


def test_undocumented_fields_are_retained():
    """Vendor extensions are evidence of divergence from the draft."""
    _, _, declared, _ = parse({
        "web_bot_auth": {"purpose": "x", "x-vendor-quirk": 1}})
    assert declared["_undocumented_fields"] == {"x-vendor-quirk": 1}


def test_card_with_no_keys_still_parses_as_card():
    """A card advertising jwks_uri rather than inline keys is still a card and
    must count toward the population."""
    shape, keys, _, card = parse({
        "client_id": "https://b.example", "jwks_uri": "https://b.example/jwks"})
    assert shape == "agent_card"
    assert keys == []
    assert card["jwks_uri"] == "https://b.example/jwks"


def test_unthumbprintable_key_is_kept_with_a_reason():
    """Dropping a malformed key would understate the population silently."""
    _, keys, _, _ = parse({"keys": [{"kty": "RSA", "n": "...", "e": "AQAB"}]})
    assert len(keys) == 1
    assert keys[0]["kid"].startswith("<unthumbprintable:")


def test_empty_document():
    shape, keys, declared, card = parse({})
    assert shape == "unknown"
    assert keys == [] and card == {}


def test_candidate_urls_default_to_https():
    """Draft s5.1: a directory over plaintext is a finding, not a fallback."""
    assert candidate_urls("example.com") == [
        "https://example.com/.well-known/http-message-signatures-directory"]


def test_candidate_urls_preserve_explicit_scheme_and_path():
    assert candidate_urls("http://127.0.0.1:8422")[0].startswith("http://127.0.0.1:8422")
    full = "https://x.example/.well-known/http-message-signatures-directory"
    assert candidate_urls(full) == [full]


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
            print(f"  FAIL  {name}: {exc}")
    print()
    print("directory parsing:", "OK" if failures == 0 else f"{failures} FAILURES")
    sys.exit(1 if failures else 0)
