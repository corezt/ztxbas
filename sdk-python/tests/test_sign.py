"""Tests for the HMAC canonical form.

The known-vector hex must match sdk-go/sign_test.go and sdk-node's
sign.test.ts — if any of the three drifts, RPs on that stack will start
seeing INVALID_SIGNATURE from the server.
"""

from __future__ import annotations

import hashlib
import hmac
import re

import pytest

from ztxbas import (
    HDR_APPLICATION_ID,
    HDR_NONCE,
    HDR_SIGNATURE,
    HDR_TIMESTAMP,
    new_nonce,
    sign_request,
)


def test_known_vector_matches_pinned_hex() -> None:
    method = "POST"
    path = "/v1/users"
    body = b'{"email":"alice@example.com"}'
    app_id = "app_test"
    secret = "topsecret"
    nonce = "abc123"
    ts = 1704067200

    headers = sign_request(method, path, body, app_id, secret, now=ts, nonce=nonce)

    assert headers[HDR_APPLICATION_ID] == app_id
    assert headers[HDR_TIMESTAMP] == str(ts)
    assert headers[HDR_NONCE] == nonce
    assert (
        headers[HDR_SIGNATURE]
        == "92c2aca00ba47b4377aebf3e3af134aff93cf7ad959d05e31a0f0618df9f7d9a"
    )

    canonical = f"{method}|{path}|{ts}|{nonce}|".encode() + body
    want = hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()
    assert headers[HDR_SIGNATURE] == want


def test_empty_body_still_produces_valid_signature() -> None:
    h = sign_request("GET", "/v1/users", b"", "a", "s", now=1000, nonce="n1")
    assert len(h[HDR_SIGNATURE]) == 64
    assert re.fullmatch(r"[0-9a-f]{64}", h[HDR_SIGNATURE])


def test_new_nonce_hex_and_unique() -> None:
    seen: set[str] = set()
    for _ in range(100):
        n = new_nonce()
        assert len(n) == 32
        assert re.fullmatch(r"[0-9a-f]{32}", n)
        assert n not in seen
        seen.add(n)


@pytest.mark.parametrize("bad_secret", ["", "\x00"])
def test_signature_deterministic_for_same_inputs(bad_secret: str) -> None:
    kwargs = dict(method="POST", path="/x", body=b"{}", app_id="a", now=1, nonce="n")
    a = sign_request(secret="s", **kwargs)  # type: ignore[arg-type]
    b = sign_request(secret="s", **kwargs)  # type: ignore[arg-type]
    assert a[HDR_SIGNATURE] == b[HDR_SIGNATURE]
    # Sanity: even a pathological secret produces distinct sigs vs "s".
    c = sign_request(secret=bad_secret, **kwargs)  # type: ignore[arg-type]
    assert c[HDR_SIGNATURE] != a[HDR_SIGNATURE]
