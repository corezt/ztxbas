"""Python client for the ZTXBAS public API."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

from .errors import (
    ChallengeDeniedError,
    ChallengeExpiredError,
    ChallengeTimeoutError,
    ZtxbasError,
    api_error_from_response,
)
from .sign import sign_request
from .verify import Claims, Verifier

#: Default per-request HTTP timeout in seconds.
DEFAULT_TIMEOUT = 10.0

#: Default gap between challenge status polls in seconds.
DEFAULT_POLL_INTERVAL = 1.0

#: Default upper bound on challenge polling. Mirrors server-side TTL.
DEFAULT_POLL_TIMEOUT = 4 * 60 + 30


# Callable signature the client uses to reach the server. Injected in
# tests. Returns (status, body_bytes).
HttpDo = Callable[[str, str, Dict[str, str], bytes, float], Tuple[int, bytes]]


def _urllib_do(
    method: str, url: str, headers: Dict[str, str], body: bytes, timeout: float
) -> Tuple[int, bytes]:
    """Default HTTP fetcher — uses urllib.request from the stdlib."""
    req = urllib.request.Request(url, method=method, data=body if body else None)
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(1 << 20)  # cap 1 MiB
    except urllib.error.HTTPError as e:
        # Non-2xx also comes back through here — read the body so the
        # caller can decode the error envelope.
        return e.code, e.read(65536)
    except urllib.error.URLError as e:
        raise ZtxbasError(f"http: {e}") from e


class Client:
    """ZTXBAS API client.

    Handles HMAC-SHA256 request signing, JSON marshaling, JWT
    verification, and JWKS caching. Instance methods are thread-safe.
    """

    def __init__(
        self,
        base_url: str,
        app_id: str,
        secret: str,
        timeout: float = DEFAULT_TIMEOUT,
        user_agent: str = "ztxbas-python/1.0",
        expected_issuer: Optional[str] = None,
        http_do: Optional[HttpDo] = None,
    ) -> None:
        """Build a client.

        Args:
            base_url: ztxbas server root, e.g. ``https://ztxbas.example.com``.
            app_id: Application id issued by ``ztxbas app create``.
            secret: HMAC secret (hex) for the application.
            timeout: Per-request HTTP timeout in seconds.
            user_agent: Sent on every request; surfaces in ztxbas access logs.
            expected_issuer: Advisory. If set, the built-in verifier
                requires ``iss`` to equal this value on every JWT.
            http_do: Custom HTTP fetcher — mainly for testing.
        """
        if not base_url:
            raise ValueError("ztxbas: base_url required")
        if not app_id or not secret:
            raise ValueError("ztxbas: app_id and secret required")
        parsed = urllib.parse.urlsplit(base_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("ztxbas: base_url must include scheme and host")
        # Strip trailing slash so path composition is unambiguous.
        self._base_url = base_url.rstrip("/")
        self._app_id = app_id
        self._secret = secret
        self._timeout = timeout
        self._user_agent = user_agent
        self._expected_issuer = expected_issuer
        self._http_do: HttpDo = http_do or _urllib_do
        self._verifier: Optional[Verifier] = None

    # ---- users ----------------------------------------------------------

    def register_user(
        self, email: str, external_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Register (enroll) a user. Triggers the biometric-setup email."""
        body: Dict[str, Any] = {"email": email}
        if external_id:
            body["external_id"] = external_id
        return self._do("POST", "/v1/users", body)  # type: ignore[return-value]

    def list_users(self) -> List[Dict[str, Any]]:
        """List every user in the tenant."""
        out = self._do("GET", "/v1/users", None)
        return out.get("users", []) if isinstance(out, dict) else []

    def deregister_user(self, email: str) -> None:
        """Deregister a user by email."""
        self._do("DELETE", "/v1/users", {"email": email})

    # ---- origins --------------------------------------------------------

    def register_origin(self, origin: str, display_name: str) -> Dict[str, Any]:
        """Register (or update) an origin the application authenticates for."""
        return self._do(  # type: ignore[return-value]
            "POST", "/v1/origins", {"origin": origin, "display_name": display_name}
        )

    def list_origins(self) -> List[Dict[str, Any]]:
        """List every origin registered for this application."""
        out = self._do("GET", "/v1/origins", None)
        return out.get("origins", []) if isinstance(out, dict) else []

    def delete_origin(self, origin_id: str) -> None:
        """Delete an origin by id."""
        self._do("DELETE", f"/v1/origins/{urllib.parse.quote(origin_id, safe='')}", None)

    # ---- auth -----------------------------------------------------------

    def create_challenge(self, user_email: str, origin: str) -> Dict[str, Any]:
        """Create a challenge and trigger the mobile biometric push."""
        return self._do(  # type: ignore[return-value]
            "POST",
            "/v1/auth/challenge",
            {"user_email": user_email, "origin": origin},
        )

    def get_challenge_status(self, challenge_id: str) -> Dict[str, Any]:
        """One-shot status fetch."""
        if not challenge_id:
            raise ValueError("ztxbas: challenge_id required")
        return self._do(  # type: ignore[return-value]
            "GET",
            f"/v1/auth/status/{urllib.parse.quote(challenge_id, safe='')}",
            None,
        )

    def poll_challenge(
        self,
        challenge_id: str,
        interval: float = DEFAULT_POLL_INTERVAL,
        timeout: float = DEFAULT_POLL_TIMEOUT,
    ) -> Claims:
        """Poll until the challenge reaches a terminal state.

        On approval, verifies the JWT and returns its claims.

        Raises:
            ChallengeDeniedError: user tapped Deny on their phone.
            ChallengeExpiredError: challenge TTL elapsed.
            ChallengeTimeoutError: caller-supplied timeout elapsed.
        """
        deadline = time.monotonic() + timeout
        while True:
            st = self.get_challenge_status(challenge_id)
            status = st.get("status")
            if status == "approved":
                jwt = st.get("jwt")
                if not jwt:
                    raise ZtxbasError("approved status missing jwt")
                return self.verify_jwt(jwt)
            if status == "denied":
                raise ChallengeDeniedError()
            if status == "expired":
                raise ChallengeExpiredError()
            if time.monotonic() + interval >= deadline:
                raise ChallengeTimeoutError()
            time.sleep(interval)

    # ---- verify ---------------------------------------------------------

    def verify_jwt(self, token: str) -> Claims:
        """Verify a JWT using the server's JWKS.

        The Verifier is built lazily on first use, so integrations that
        only call CRUD methods pay nothing extra.
        """
        if self._verifier is None:
            self._verifier = Verifier(
                f"{self._base_url}/.well-known/jwks.json",
                expected_issuer=self._expected_issuer,
                timeout=self._timeout,
            )
        return self._verifier.verify(token)

    # ---- internal -------------------------------------------------------

    def _do(
        self, method: str, path: str, body: Optional[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        body_bytes = json.dumps(body).encode("utf-8") if body is not None else b""
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": self._user_agent,
            **sign_request(method, path, body_bytes, self._app_id, self._secret),
        }
        if body is not None:
            headers["Content-Type"] = "application/json"

        status, raw = self._http_do(
            method, self._base_url + path, headers, body_bytes, self._timeout
        )

        if status == 204:
            return None
        if status >= 400:
            code = ""
            message = ""
            try:
                env = json.loads(raw)
                code = str(env.get("error", "") or "")
                message = str(env.get("message", "") or "")
            except (ValueError, json.JSONDecodeError):
                message = raw.decode("utf-8", errors="replace")
            raise api_error_from_response(status, code, message or f"HTTP {status}")

        try:
            return json.loads(raw) if raw else None
        except (ValueError, json.JSONDecodeError) as e:
            raise ZtxbasError(f"decode response: {e}") from e
