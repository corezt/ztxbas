"""HMAC request signing — the RP side of the ztxbas HMAC scheme.

Kept in one place so callers cannot accidentally use different
serializations for signing and sending. Any drift here surfaces as
INVALID_SIGNATURE on the server side.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Dict, Optional

#: HTTP header names — must match the server's middleware constants.
HDR_APPLICATION_ID = "X-Application-ID"
HDR_TIMESTAMP = "X-Timestamp"
HDR_NONCE = "X-Nonce"
HDR_SIGNATURE = "X-Signature"

#: Number of random bytes in a nonce → 32 hex chars.
_NONCE_BYTES = 16


def new_nonce() -> str:
    """Generate a fresh hex-encoded nonce."""
    return secrets.token_hex(_NONCE_BYTES)


def sign_request(
    method: str,
    path: str,
    body: bytes,
    app_id: str,
    secret: str,
    now: Optional[float] = None,
    nonce: Optional[str] = None,
) -> Dict[str, str]:
    """Compute the four HMAC headers for a request.

    Canonical form (single line, no trailing newline)::

        METHOD "|" PATH "|" TIMESTAMP "|" NONCE "|" BODY

    ``body`` is the exact bytes that will be sent as the HTTP body — the
    empty bytes when there is no body. The client MUST send those same
    bytes; any re-serialisation between signing and sending will break
    the signature.

    Args:
        method: HTTP method, uppercase (e.g. ``"POST"``).
        path: URL path exactly as it will appear in the request line,
            starting with ``"/"``.
        body: Raw request body bytes (empty for GET/DELETE with no body).
        app_id: Application id issued by ``ztxbas app create``.
        secret: HMAC secret for the application, hex-encoded.
        now: Unix seconds; ``None`` uses ``time.time()``. Passed in so
            tests can pin it.
        nonce: Hex-encoded nonce; ``None`` generates a fresh one.

    Returns:
        Dict of header name → value.
    """
    ts = str(int(now if now is not None else time.time()))
    nonce_val = nonce if nonce is not None else new_nonce()
    canonical = f"{method}|{path}|{ts}|{nonce_val}|".encode("utf-8") + body
    sig = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    return {
        HDR_APPLICATION_ID: app_id,
        HDR_TIMESTAMP: ts,
        HDR_NONCE: nonce_val,
        HDR_SIGNATURE: sig,
    }
