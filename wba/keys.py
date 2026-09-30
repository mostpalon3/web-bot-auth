"""Ed25519 key handling and RFC 7638 JWK thumbprints for Web Bot Auth."""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def b64u(data: bytes) -> str:
    """base64url without padding, per RFC 7515 §2."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


@dataclass
class SigningKey:
    """An Ed25519 keypair with its Web Bot Auth key identifier."""

    private: Ed25519PrivateKey
    label: str = "primary"

    @classmethod
    def generate(cls, label: str = "primary") -> "SigningKey":
        return cls(Ed25519PrivateKey.generate(), label)

    @classmethod
    def from_pem(cls, path: str, label: str = "primary") -> "SigningKey":
        with open(path, "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError(f"{path} is not an Ed25519 private key")
        return cls(key, label)

    def save_pem(self, path: str) -> None:
        pem = self.private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(path, "wb") as fh:
            fh.write(pem)

    @property
    def public(self) -> Ed25519PublicKey:
        return self.private.public_key()

    @property
    def raw_public(self) -> bytes:
        return self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def jwk(self) -> dict:
        """Public JWK. Members required by RFC 8037 for OKP/Ed25519."""
        return {"kty": "OKP", "crv": "Ed25519", "x": b64u(self.raw_public)}

    def thumbprint(self) -> str:
        """RFC 7638 JWK thumbprint - the keyid Web Bot Auth signatures carry.

        The thumbprint is computed over the required members only, serialised
        with lexicographic key order and no whitespace.
        """
        canonical = json.dumps(
            self.jwk(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return b64u(hashlib.sha256(canonical).digest())

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data)


def verify(public: Ed25519PublicKey, signature: bytes, data: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature

    try:
        public.verify(signature, data)
        return True
    except InvalidSignature:
        return False


def jwk_to_public(jwk: dict) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError(f"unsupported key type: {jwk.get('kty')}/{jwk.get('crv')}")
    return Ed25519PublicKey.from_public_bytes(b64u_decode(jwk["x"]))


def thumbprint_of_jwk(jwk: dict) -> str:
    required = {"kty": jwk["kty"], "crv": jwk["crv"], "x": jwk["x"]}
    canonical = json.dumps(required, sort_keys=True, separators=(",", ":")).encode()
    return b64u(hashlib.sha256(canonical).digest())
