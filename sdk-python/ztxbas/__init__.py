"""Official Python SDK for ZTXBAS.

Handles HMAC-SHA256 request signing, JWT verification against the
server's JWKS, and JWKS caching.

Typical usage::

    from ztxbas import Client, ChallengeDeniedError

    c = Client(
        "https://ztxbas.example.com",
        "app_YOUR_APPLICATION_ID",
        "YOUR_HMAC_SECRET_HEX",
    )

    c.register_user("alice@example.com")
    c.register_origin("https://app.example.com", "Example App")

    ch = c.create_challenge("alice@example.com", "https://app.example.com")
    try:
        claims = c.poll_challenge(ch["challenge_id"])
        print(f"authenticated: {claims.email} @ {claims.origin}")
    except ChallengeDeniedError:
        ...
"""

from .client import (
    Client,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_POLL_TIMEOUT,
    DEFAULT_TIMEOUT,
)
from .errors import (
    ApiError,
    ChallengeDeniedError,
    ChallengeExpiredError,
    ChallengeTimeoutError,
    ConflictError,
    JwtVerifyError,
    NotFoundError,
    UnauthorizedError,
    UnregisteredOriginError,
    ZtxbasError,
)
from .sign import (
    HDR_APPLICATION_ID,
    HDR_NONCE,
    HDR_SIGNATURE,
    HDR_TIMESTAMP,
    new_nonce,
    sign_request,
)
from .verify import Claims, Verifier

__version__ = "1.0.0"

__all__ = [
    "Client",
    "Verifier",
    "Claims",
    "sign_request",
    "new_nonce",
    "HDR_APPLICATION_ID",
    "HDR_TIMESTAMP",
    "HDR_NONCE",
    "HDR_SIGNATURE",
    "ZtxbasError",
    "ApiError",
    "UnauthorizedError",
    "NotFoundError",
    "ConflictError",
    "UnregisteredOriginError",
    "ChallengeDeniedError",
    "ChallengeExpiredError",
    "ChallengeTimeoutError",
    "JwtVerifyError",
    "DEFAULT_TIMEOUT",
    "DEFAULT_POLL_INTERVAL",
    "DEFAULT_POLL_TIMEOUT",
]
