"""RFC 9421 HTTP Message Signatures, scoped to the Web Bot Auth profile.

Signing and header emission are deliberately separable: a conformance probe
needs to sign over one set of parameters and transmit another, which a
correctness-focused library would refuse to do.
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field, replace
from typing import Optional
from urllib.parse import urlsplit

from .keys import SigningKey, b64u

DEFAULT_COMPONENTS = ["@authority", "@method", "@path"]
WEB_BOT_AUTH_TAG = "web-bot-auth"


@dataclass
class Request:
    """The request a signature is computed over."""

    method: str
    url: str
    headers: dict = field(default_factory=dict)

    @property
    def parts(self):
        return urlsplit(self.url)

    def derived(self, name: str) -> str:
        p = self.parts
        if name == "@method":
            return self.method.upper()
        if name == "@authority":
            return p.netloc.lower()
        if name == "@path":
            return p.path or "/"
        if name == "@scheme":
            return p.scheme.lower()
        if name == "@target-uri":
            return self.url
        if name == "@query":
            return f"?{p.query}" if p.query else "?"
        raise ValueError(f"unsupported derived component: {name}")

    def component_value(self, name: str) -> str:
        if name.startswith("@"):
            return self.derived(name)
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return str(v).strip()
        raise KeyError(f"covered component not present in request: {name}")


@dataclass
class SigParams:
    """The contents of @signature-params."""

    keyid: str
    components: list = field(default_factory=lambda: list(DEFAULT_COMPONENTS))
    created: Optional[int] = None
    expires: Optional[int] = None
    nonce: Optional[str] = None
    alg: Optional[str] = "ed25519"
    tag: Optional[str] = WEB_BOT_AUTH_TAG

    @classmethod
    def fresh(cls, keyid: str, lifetime: int = 300, **kw) -> "SigParams":
        now = int(time.time())
        return cls(
            keyid=keyid,
            created=now,
            expires=now + lifetime,
            nonce=b64u(secrets.token_bytes(16)),
            **kw,
        )

    def serialize(self) -> str:
        """Structured-field inner list with parameters, RFC 8941 §3.1.1.

        Parameter order is significant: it must be byte-identical between the
        signature base and the Signature-Input header, or verification fails.
        """
        inner = " ".join(f'"{c}"' for c in self.components)
        out = f"({inner})"
        if self.created is not None:
            out += f";created={self.created}"
        if self.expires is not None:
            out += f";expires={self.expires}"
        if self.keyid is not None:
            out += f';keyid="{self.keyid}"'
        if self.alg is not None:
            out += f';alg="{self.alg}"'
        if self.nonce is not None:
            out += f';nonce="{self.nonce}"'
        if self.tag is not None:
            out += f';tag="{self.tag}"'
        return out


def signature_base(request: Request, params: SigParams) -> bytes:
    """Assemble the signature base, RFC 9421 §2.5.

    Every covered component contributes one LF-terminated line; the final
    @signature-params line carries no trailing LF.
    """
    lines = [
        f'"{name}": {request.component_value(name)}' for name in params.components
    ]
    lines.append(f'"@signature-params": {params.serialize()}')
    return "\n".join(lines).encode("utf-8")


def sign(
    key: SigningKey,
    request: Request,
    params: SigParams,
    *,
    label: str = "sig1",
    emit_params: Optional[SigParams] = None,
    signature_override: Optional[bytes] = None,
) -> dict:
    """Return the Signature-Input and Signature headers.

    emit_params lets a probe transmit parameters that differ from those the
    signature actually covers - the mechanism behind most conformance cases.
    signature_override substitutes raw signature bytes wholesale.
    """
    base = signature_base(request, params)
    raw = signature_override if signature_override is not None else key.sign(base)
    shown = emit_params or params
    import base64 as _b64

    return {
        "Signature-Input": f"{label}={shown.serialize()}",
        "Signature": f"{label}=:{_b64.b64encode(raw).decode('ascii')}:",
    }


def with_component(params: SigParams, name: str) -> SigParams:
    if name in params.components:
        return params
    return replace(params, components=params.components + [name])
