"""Tests for the JWT verifier — signature, alg, claims, JWKS caching."""

from __future__ import annotations

import base64
import json
import time
from typing import Callable

import pytest

from ztxbas import JwtVerifyError, Verifier

from .conftest import FakeSigner, b64u


def test_valid_jwt_returns_claims(
    signer: FakeSigner, jwks_fetcher: Callable[[str], bytes]
) -> None:
    v = Verifier(
        "https://x/.well-known/jwks.json",
        expected_issuer="https://ztxbas.example.com",
        http_get=jwks_fetcher,
    )
    now = int(time.time())
    tok = signer.sign({
        "iss": "https://ztxbas.example.com",
        "sub": "alice@example.com",
        "aud": "https://app.example.com",
        "email": "alice@example.com",
        "origin": "https://app.example.com",
        "challenge_id": "c_1",
        "iat": now,
        "exp": now + 300,
    })
    claims = v.verify(tok)
    assert claims.email == "alice@example.com"
    assert claims.origin == "https://app.example.com"


def test_alg_none_rejected(
    signer: FakeSigner, jwks_fetcher: Callable[[str], bytes]
) -> None:
    v = Verifier("https://x", http_get=jwks_fetcher)
    header = {"alg": "none", "typ": "JWT", "kid": signer.kid}
    payload = {"email": "attacker@example.com", "exp": int(time.time()) + 3600}
    tok = f"{b64u(json.dumps(header).encode())}.{b64u(json.dumps(payload).encode())}."
    with pytest.raises(JwtVerifyError, match=r"alg"):
        v.verify(tok)


def test_expired_token_rejected(
    signer: FakeSigner, jwks_fetcher: Callable[[str], bytes]
) -> None:
    v = Verifier("https://x", http_get=jwks_fetcher)
    tok = signer.sign({"exp": int(time.time()) - 3600})
    with pytest.raises(JwtVerifyError, match=r"expired"):
        v.verify(tok)


def test_wrong_issuer_rejected(
    signer: FakeSigner, jwks_fetcher: Callable[[str], bytes]
) -> None:
    v = Verifier(
        "https://x",
        expected_issuer="https://legit.example.com",
        http_get=jwks_fetcher,
    )
    tok = signer.sign({
        "iss": "https://evil.example.com",
        "exp": int(time.time()) + 3600,
    })
    with pytest.raises(JwtVerifyError, match=r"iss"):
        v.verify(tok)


def test_tampered_payload_rejected(
    signer: FakeSigner, jwks_fetcher: Callable[[str], bytes]
) -> None:
    v = Verifier("https://x", http_get=jwks_fetcher)
    tok = signer.sign({"email": "alice@example.com", "exp": int(time.time()) + 3600})
    h, _, s = tok.split(".")
    forged = b64u(json.dumps({
        "email": "attacker@example.com",
        "exp": int(time.time()) + 3600,
    }).encode())
    with pytest.raises(JwtVerifyError, match=r"signature invalid"):
        v.verify(f"{h}.{forged}.{s}")


def test_unknown_kid_rejected(jwks_fetcher: Callable[[str], bytes]) -> None:
    known = FakeSigner(kid="known-kid")
    rogue = FakeSigner(kid="unknown-kid")

    def fetch(_: str) -> bytes:
        return known.jwks()

    v = Verifier("https://x", http_get=fetch)
    tok = rogue.sign({"exp": int(time.time()) + 3600})
    with pytest.raises(JwtVerifyError, match=r"kid"):
        v.verify(tok)


def test_jwks_cache_reused_within_ttl(
    signer: FakeSigner, jwks_fetcher: Callable[[str], bytes]
) -> None:
    v = Verifier("https://x", http_get=jwks_fetcher)
    tok = signer.sign({"exp": int(time.time()) + 3600})
    for _ in range(3):
        v.verify(tok)
    # Only the first verify should have gone to the network.
    assert jwks_fetcher.hits == 1  # type: ignore[attr-defined]


def test_off_curve_public_key_rejected() -> None:
    """Serve a JWKS whose (x, y) is not on P-256 — invalid-curve defence."""
    bad = {
        "keys": [{
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "bad",
            "x": b64u((1).to_bytes(1, "big")),
            "y": b64u((1).to_bytes(1, "big")),
        }]
    }
    v = Verifier("https://x", http_get=lambda _: json.dumps(bad).encode())
    sig = FakeSigner()  # any valid ES256 token; we should never get to verify
    tok = sig.sign({"exp": int(time.time()) + 3600})
    with pytest.raises(JwtVerifyError):
        v.verify(tok)


@pytest.mark.parametrize("bad", ["", "a.b", "a.b.c.d", "not-base64.also.bad"])
def test_malformed_tokens_rejected(
    signer: FakeSigner, jwks_fetcher: Callable[[str], bytes], bad: str
) -> None:
    v = Verifier("https://x", http_get=jwks_fetcher)
    with pytest.raises(JwtVerifyError):
        v.verify(bad)


def test_missing_kid_rejected(
    signer: FakeSigner, jwks_fetcher: Callable[[str], bytes]
) -> None:
    v = Verifier("https://x", http_get=jwks_fetcher)
    header = {"alg": "ES256", "typ": "JWT"}  # no kid
    payload = {"exp": int(time.time()) + 3600}
    tok = (
        b64u(json.dumps(header).encode()) + "."
        + b64u(json.dumps(payload).encode()) + "."
        + b64u(b"\x00" * 64)
    )
    with pytest.raises(JwtVerifyError, match=r"kid"):
        v.verify(tok)


# sanity: silence unused import
_ = base64
