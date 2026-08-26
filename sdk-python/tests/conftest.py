"""Shared fixtures for the ztxbas SDK tests."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


@dataclass
class FakeSigner:
    """Tiny in-test ES256 signer that mirrors the server's signing scheme."""

    kid: str = "test-kid"
    _priv: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )

    def sign(self, claims: Dict[str, Any]) -> str:
        header = {"alg": "ES256", "typ": "JWT", "kid": self.kid}
        signing_input = f"{b64u(json.dumps(header).encode())}.{b64u(json.dumps(claims).encode())}"
        der = self._priv.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return f"{signing_input}.{b64u(raw)}"

    def jwks(self) -> bytes:
        pub_nums = self._priv.public_key().public_numbers()
        x = pub_nums.x.to_bytes(32, "big")
        y = pub_nums.y.to_bytes(32, "big")
        return json.dumps({
            "keys": [{
                "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig",
                "kid": self.kid, "x": b64u(x), "y": b64u(y),
            }],
        }).encode()


@dataclass
class RecordedCall:
    """One call captured by :class:`FakeHTTP`."""

    method: str
    url: str
    headers: Dict[str, str]
    body: bytes


@dataclass
class FakeHTTP:
    """Injectable HTTP double for Client tests.

    Populate ``responder`` with a callable that inspects the recorded
    call and returns ``(status, body_bytes)``. Every call is stored in
    ``calls`` for later inspection.
    """

    responder: Callable[[RecordedCall], Tuple[int, bytes]]
    calls: List[RecordedCall] = field(default_factory=list)

    def __call__(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: bytes,
        timeout: float,
    ) -> Tuple[int, bytes]:
        # Normalise header casing for tests — case-insensitive lookups
        # would be more work than they're worth given the fixed set of
        # headers the SDK sends.
        call = RecordedCall(method=method, url=url, headers=dict(headers), body=body)
        self.calls.append(call)
        return self.responder(call)


@pytest.fixture
def signer() -> FakeSigner:
    return FakeSigner()


@pytest.fixture
def jwks_fetcher(signer: FakeSigner) -> Callable[[str], bytes]:
    """Standalone JWKS fetcher for Verifier tests. Records hits."""

    def _fetch(url: str) -> bytes:
        _fetch.hits += 1  # type: ignore[attr-defined]
        return signer.jwks()

    _fetch.hits = 0  # type: ignore[attr-defined]
    return _fetch


@pytest.fixture
def fake_http() -> Callable[[Callable[[RecordedCall], Tuple[int, bytes]]], FakeHTTP]:
    """Factory: pass a responder callable, get a FakeHTTP back."""

    def _make(responder: Callable[[RecordedCall], Tuple[int, bytes]]) -> FakeHTTP:
        return FakeHTTP(responder=responder)

    return _make
