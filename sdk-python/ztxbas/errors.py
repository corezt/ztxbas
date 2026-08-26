"""Error hierarchy for the ZTXBAS SDK.

Every operation that touches the network can raise ZtxbasError or one of
its subclasses. Application code that only cares about "did it work"
can catch ZtxbasError; code that wants to distinguish user-denied from
expired-challenge can catch the narrower subclasses.
"""

from __future__ import annotations


class ZtxbasError(Exception):
    """Base for every SDK-raised exception."""


class ApiError(ZtxbasError):
    """Server returned a non-2xx response.

    Attributes:
        status_code: HTTP status.
        code: machine-readable error code from the server envelope
            (e.g. ``UNREGISTERED_ORIGIN``); may be empty if the server
            returned a non-JSON body.
        message: human-readable message.
    """

    def __init__(self, status_code: int, code: str, message: str) -> None:
        self.status_code = status_code
        self.code = code
        self.message = message
        prefix = code if code else f"HTTP_{status_code}"
        super().__init__(f"ztxbas: {prefix}: {message}")


class UnauthorizedError(ApiError):
    """HTTP 401 — HMAC signature rejected. Usually clock skew or bad secret."""


class NotFoundError(ApiError):
    """HTTP 404 — resource does not exist."""


class ConflictError(ApiError):
    """HTTP 409 — a resource with the same identifier already exists."""


class UnregisteredOriginError(ApiError):
    """403 UNREGISTERED_ORIGIN — origin binding check failed."""


class ChallengeDeniedError(ZtxbasError):
    """The user tapped Deny on their phone."""

    def __init__(self) -> None:
        super().__init__("ztxbas: challenge denied by user")


class ChallengeExpiredError(ZtxbasError):
    """The challenge TTL elapsed before approval."""

    def __init__(self) -> None:
        super().__init__("ztxbas: challenge expired")


class ChallengeTimeoutError(ZtxbasError):
    """Polling stopped because the caller's timeout elapsed."""

    def __init__(self) -> None:
        super().__init__(
            "ztxbas: polling timed out before challenge reached a terminal state"
        )


class JwtVerifyError(ZtxbasError):
    """JWT verification failed (bad signature, wrong alg, expired, etc.)."""

    def __init__(self, message: str) -> None:
        super().__init__(f"ztxbas: {message}")


def api_error_from_response(status: int, code: str, message: str) -> ApiError:
    """Build the right subclass for an API error response.

    Kept in one place so status→class mapping does not drift across
    call sites.
    """
    if code == "UNREGISTERED_ORIGIN":
        return UnregisteredOriginError(status, code, message)
    if status == 401:
        return UnauthorizedError(status, code, message)
    if status == 404:
        return NotFoundError(status, code, message)
    if status == 409:
        return ConflictError(status, code, message)
    return ApiError(status, code, message)
