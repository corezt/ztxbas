"""Tests for the Client's HTTP surface, error mapping, and polling."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from typing import Callable, Tuple

import pytest

from ztxbas import (
    ApiError,
    ChallengeDeniedError,
    ChallengeExpiredError,
    ChallengeTimeoutError,
    Client,
    ConflictError,
    NotFoundError,
    UnauthorizedError,
    UnregisteredOriginError,
)

from .conftest import FakeHTTP, RecordedCall, FakeSigner


def _assert_sig_valid(call: RecordedCall, secret: str) -> None:
    """Re-run the server's HMAC check on the recorded call."""
    app_id = call.headers.get("X-Application-ID")
    ts = call.headers.get("X-Timestamp")
    nonce = call.headers.get("X-Nonce")
    sig = call.headers.get("X-Signature")
    assert app_id and ts and nonce and sig
    assert len(sig) == 64

    # Reconstruct path from URL (headers were signed over path only).
    from urllib.parse import urlsplit
    path = urlsplit(call.url).path
    canonical = f"{call.method}|{path}|{ts}|{nonce}|".encode() + call.body
    want = hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()
    assert sig == want, "signature mismatch"


def test_register_user_signs_and_parses(
    fake_http: Callable[..., FakeHTTP],
) -> None:
    def responder(call: RecordedCall) -> Tuple[int, bytes]:
        assert call.method == "POST"
        assert call.url.endswith("/v1/users")
        _assert_sig_valid(call, "secret_test")
        return 201, b'{"id":"u_1","email":"alice@example.com","enrolled":false}'

    http = fake_http(responder)
    c = Client("https://ztxbas.example.com", "app_test", "secret_test", http_do=http)
    out = c.register_user("alice@example.com")
    assert out["id"] == "u_1"
    assert out["email"] == "alice@example.com"
    assert out["enrolled"] is False


def test_list_users_unwraps_envelope(
    fake_http: Callable[..., FakeHTTP],
) -> None:
    def responder(_: RecordedCall) -> Tuple[int, bytes]:
        return 200, b'{"users":[{"id":"u_1","email":"a@x","enrolled":true}]}'

    http = fake_http(responder)
    c = Client("https://x", "a", "s", http_do=http)
    users = c.list_users()
    assert len(users) == 1
    assert users[0]["email"] == "a@x"


def test_deregister_user_204(fake_http: Callable[..., FakeHTTP]) -> None:
    def responder(call: RecordedCall) -> Tuple[int, bytes]:
        _assert_sig_valid(call, "s")
        assert call.method == "DELETE"
        return 204, b""

    http = fake_http(responder)
    c = Client("https://x", "a", "s", http_do=http)
    c.deregister_user("alice@example.com")


def test_register_origin_round_trip(fake_http: Callable[..., FakeHTTP]) -> None:
    def responder(call: RecordedCall) -> Tuple[int, bytes]:
        _assert_sig_valid(call, "s")
        parsed = json.loads(call.body)
        assert parsed["origin"] == "https://app.example.com"
        assert parsed["display_name"] == "App"
        return 201, (
            b'{"id":"o_1","origin":"https://app.example.com",'
            b'"origin_hash":"abc","display_name":"App"}'
        )

    http = fake_http(responder)
    c = Client("https://x", "a", "s", http_do=http)
    o = c.register_origin("https://app.example.com", "App")
    assert o["id"] == "o_1"


def test_delete_origin_quotes_id(fake_http: Callable[..., FakeHTTP]) -> None:
    def responder(call: RecordedCall) -> Tuple[int, bytes]:
        assert call.url.endswith("/v1/origins/o_1")
        return 204, b""

    http = fake_http(responder)
    c = Client("https://x", "a", "s", http_do=http)
    c.delete_origin("o_1")


def test_create_challenge(fake_http: Callable[..., FakeHTTP]) -> None:
    def responder(_: RecordedCall) -> Tuple[int, bytes]:
        return 201, (
            b'{"challenge_id":"c_1","expires_in":300,'
            b'"origin_display":"App","origin_url":"https://app.example.com"}'
        )

    http = fake_http(responder)
    c = Client("https://x", "a", "s", http_do=http)
    ch = c.create_challenge("a@x", "https://app.example.com")
    assert ch["challenge_id"] == "c_1"
    assert ch["expires_in"] == 300


@pytest.mark.parametrize(
    "status,code,cls",
    [
        (401, "INVALID_SIGNATURE", UnauthorizedError),
        (404, "USER_NOT_FOUND", NotFoundError),
        (409, "DUPLICATE_EMAIL", ConflictError),
        (403, "UNREGISTERED_ORIGIN", UnregisteredOriginError),
        (500, "INTERNAL", ApiError),
    ],
)
def test_error_mapping(
    fake_http: Callable[..., FakeHTTP],
    status: int,
    code: str,
    cls: type,
) -> None:
    def responder(_: RecordedCall) -> Tuple[int, bytes]:
        return status, json.dumps({"error": code, "message": "boom"}).encode()

    http = fake_http(responder)
    c = Client("https://x", "a", "s", http_do=http)
    with pytest.raises(cls) as ei:
        c.list_users()
    assert ei.value.status_code == status  # type: ignore[attr-defined]
    assert ei.value.code == code  # type: ignore[attr-defined]


def test_constructor_validation() -> None:
    with pytest.raises(ValueError):
        Client("", "a", "s")
    with pytest.raises(ValueError):
        Client("https://x", "", "s")
    with pytest.raises(ValueError):
        Client("https://x", "a", "")
    with pytest.raises(ValueError):
        Client("no-scheme", "a", "s")


def test_constructor_strips_trailing_slash(
    fake_http: Callable[..., FakeHTTP],
) -> None:
    seen: dict = {}

    def responder(call: RecordedCall) -> Tuple[int, bytes]:
        seen["url"] = call.url
        return 204, b""

    http = fake_http(responder)
    c = Client("https://x/", "a", "s", http_do=http)
    c.deregister_user("x@y")
    # Should be exactly one leading slash, not two.
    assert seen["url"] == "https://x/v1/users"


def test_poll_challenge_denied(fake_http: Callable[..., FakeHTTP]) -> None:
    def responder(_: RecordedCall) -> Tuple[int, bytes]:
        return 200, b'{"status":"denied"}'

    c = Client("https://x", "a", "s", http_do=fake_http(responder))
    with pytest.raises(ChallengeDeniedError):
        c.poll_challenge("c_1")


def test_poll_challenge_expired(fake_http: Callable[..., FakeHTTP]) -> None:
    def responder(_: RecordedCall) -> Tuple[int, bytes]:
        return 200, b'{"status":"expired"}'

    c = Client("https://x", "a", "s", http_do=fake_http(responder))
    with pytest.raises(ChallengeExpiredError):
        c.poll_challenge("c_1")


def test_poll_challenge_timeout(fake_http: Callable[..., FakeHTTP]) -> None:
    def responder(_: RecordedCall) -> Tuple[int, bytes]:
        return 200, b'{"status":"pending"}'

    c = Client("https://x", "a", "s", http_do=fake_http(responder))
    # Short interval + very short timeout ⇒ ChallengeTimeoutError.
    with pytest.raises(ChallengeTimeoutError):
        c.poll_challenge("c_1", interval=0.01, timeout=0.05)


def test_poll_challenge_approved_verifies_jwt(
    fake_http: Callable[..., FakeHTTP],
    signer: FakeSigner,
) -> None:
    """End-to-end: pending, pending, approved with a signed JWT.

    Also exercises the lazy Verifier wiring by pointing the Client at a
    fake HTTP that serves both the challenge status and JWKS.
    """
    call_count = {"n": 0}

    def responder(call: RecordedCall) -> Tuple[int, bytes]:
        if call.url.endswith("/.well-known/jwks.json"):
            return 200, signer.jwks()
        call_count["n"] += 1
        if call_count["n"] < 3:
            return 200, b'{"status":"pending"}'
        now = int(time.time())
        tok = signer.sign({
            "email": "alice@example.com",
            "origin": "https://app.example.com",
            "iat": now,
            "exp": now + 300,
        })
        return 200, json.dumps({
            "status": "approved",
            "user_email": "alice@example.com",
            "jwt": tok,
        }).encode()

    http = fake_http(responder)
    c = Client("https://ztxbas.example.com", "app_test", "sec", http_do=http)
    # Override the Verifier's HTTP fetcher too, so the JWKS goes through
    # the same fake. We reach into the client for this — no public
    # setter, but it's fine for the test to swap out the default.
    from ztxbas.verify import Verifier
    c._verifier = Verifier(  # type: ignore[attr-defined]
        f"{c._base_url}/.well-known/jwks.json",  # type: ignore[attr-defined]
        http_get=lambda url: http("GET", url, {}, b"", 10)[1],
    )
    claims = c.poll_challenge("c_1", interval=0.01, timeout=1.0)
    assert claims.email == "alice@example.com"
    assert claims.origin == "https://app.example.com"


def test_headers_are_signed_over_correct_path(
    fake_http: Callable[..., FakeHTTP],
) -> None:
    """Regression: DELETE /v1/origins/{id} must sign the encoded path."""
    def responder(call: RecordedCall) -> Tuple[int, bytes]:
        _assert_sig_valid(call, "s")
        assert call.url.endswith("/v1/origins/abc%20def"), call.url
        return 204, b""

    http = fake_http(responder)
    c = Client("https://x", "a", "s", http_do=http)
    c.delete_origin("abc def")


# sanity: silence unused-import warning in editors
_ = re
