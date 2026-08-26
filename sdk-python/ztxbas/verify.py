"""JWT verification against the ztxbas JWKS.

Uses ``cryptography`` for ES256 primitives. Kept dependency-light: no
PyJWT, no third-party JWKS lib.
"""

from __future__ import annotations

import base64
import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .errors import JwtVerifyError

#: How long a cached JWKS document is trusted before re-fetching.
_JWKS_CACHE_TTL = 5 * 60  # seconds

#: Leeway on ``iat``/``exp`` — matches server-side HMAC timestamp skew.
_CLOCK_SKEW = 30  # seconds


@dataclass
class Claims:
    """Fields ztxbas includes in every issued JWT.

    All fields are optional at the type level because JWTs from other
    issuers, or malformed ones, might omit them. In practice a
    successful ``verify()`` call always populates ``iss``, ``sub``,
    ``exp``, ``email``, ``origin``, and ``challenge_id``.
    """

    iss: Optional[str] = None
    sub: Optional[str] = None
    aud: Optional[str] = None
    iat: Optional[int] = None
    exp: Optional[int] = None
    email: Optional[str] = None
    origin: Optional[str] = None
    challenge_id: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "Claims":
        return cls(
            iss=d.get("iss"),  # type: ignore[arg-type]
            sub=d.get("sub"),  # type: ignore[arg-type]
            aud=d.get("aud"),  # type: ignore[arg-type]
            iat=d.get("iat"),  # type: ignore[arg-type]
            exp=d.get("exp"),  # type: ignore[arg-type]
            email=d.get("email"),  # type: ignore[arg-type]
            origin=d.get("origin"),  # type: ignore[arg-type]
            challenge_id=d.get("challenge_id"),  # type: ignore[arg-type]
        )


def _b64url_decode(s: str) -> bytes:
    """Decode base64url, tolerating missing padding (per RFC 7515)."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


class Verifier:
    """Verifies ztxbas-issued JWTs against a cached JWKS.

    Thread-safe. JWKS fetches are coalesced under a lock so a burst of
    verifies against a cold cache produces at most one HTTP call.
    """

    def __init__(
        self,
        jwks_url: str,
        expected_issuer: Optional[str] = None,
        http_get: Optional[Callable[[str], bytes]] = None,
        timeout: float = 10.0,
    ) -> None:
        """Build a verifier.

        Args:
            jwks_url: Fully-qualified URL, typically
                ``https://<host>/.well-known/jwks.json``.
            expected_issuer: If set, verified JWTs must carry ``iss``
                equal to this value. Recommended for RPs talking to a
                single ztxbas deployment.
            http_get: Callable ``(url) -> bytes`` used to fetch the
                JWKS. Defaults to ``urllib.request``; tests can inject
                a fake.
            timeout: Timeout for the default HTTP fetcher, in seconds.
        """
        if not jwks_url:
            raise ValueError("ztxbas: jwks_url required")
        self._jwks_url = jwks_url
        self._expected_issuer = expected_issuer
        self._timeout = timeout
        self._http_get = http_get or self._default_get
        self._lock = threading.Lock()
        self._keys: Dict[str, ec.EllipticCurvePublicKey] = {}
        self._fetched_at: float = 0.0

    # ---- HTTP -----------------------------------------------------------

    def _default_get(self, url: str) -> bytes:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                if resp.status != 200:
                    raise JwtVerifyError(f"JWKS fetch returned {resp.status}")
                # Cap the read — legitimate JWKS docs are ~1 KiB.
                return resp.read(65536)
        except urllib.error.URLError as e:
            raise JwtVerifyError(f"fetch JWKS: {e}") from e

    # ---- public API -----------------------------------------------------

    def verify(self, token: str) -> Claims:
        """Verify ``token``. Return the claims on success, raise on failure."""
        parts = token.split(".")
        if len(parts) != 3:
            raise JwtVerifyError(
                f"malformed JWT: expected 3 parts, got {len(parts)}"
            )
        enc_header, enc_payload, enc_sig = parts
        try:
            header = json.loads(_b64url_decode(enc_header))
        except (ValueError, json.JSONDecodeError) as e:
            raise JwtVerifyError(f"decode JWT header: {e}") from e

        # Reject anything other than ES256 up front — the classic
        # alg=none / algorithm-substitution defence.
        if header.get("alg") != "ES256":
            raise JwtVerifyError(
                f"unsupported JWT alg {header.get('alg')!r} (want ES256)"
            )
        kid = header.get("kid")
        if not kid:
            raise JwtVerifyError("JWT header missing kid")

        key = self._key_for_kid(kid)

        try:
            raw_sig = _b64url_decode(enc_sig)
        except (ValueError, TypeError) as e:
            raise JwtVerifyError(f"decode JWT signature: {e}") from e
        if len(raw_sig) != 64:
            raise JwtVerifyError(
                f"ES256 signature must be 64 bytes, got {len(raw_sig)}"
            )
        # cryptography expects a DER-encoded (r, s) pair; convert from
        # the raw r||s that JWS puts on the wire (RFC 7515 §3.4).
        r = int.from_bytes(raw_sig[:32], "big")
        s = int.from_bytes(raw_sig[32:], "big")
        der_sig = encode_dss_signature(r, s)

        signing_input = f"{enc_header}.{enc_payload}".encode("ascii")
        try:
            key.verify(der_sig, signing_input, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as e:
            raise JwtVerifyError("JWT signature invalid") from e

        try:
            payload = json.loads(_b64url_decode(enc_payload))
        except (ValueError, json.JSONDecodeError) as e:
            raise JwtVerifyError(f"decode JWT payload: {e}") from e

        now = int(time.time())
        exp = payload.get("exp")
        if exp is not None and now > exp + _CLOCK_SKEW:
            raise JwtVerifyError(f"JWT expired at {exp} (now {now})")
        iat = payload.get("iat")
        if iat is not None and iat > now + _CLOCK_SKEW:
            raise JwtVerifyError(f"JWT iat in the future ({iat}, now {now})")
        if self._expected_issuer and payload.get("iss") != self._expected_issuer:
            raise JwtVerifyError(
                f"JWT iss {payload.get('iss')!r} does not match "
                f"expected {self._expected_issuer!r}"
            )
        return Claims.from_dict(payload)

    # ---- internal -------------------------------------------------------

    def _key_for_kid(self, kid: str) -> ec.EllipticCurvePublicKey:
        with self._lock:
            key = self._keys.get(kid)
            if key is not None and time.time() - self._fetched_at < _JWKS_CACHE_TTL:
                return key
            self._refresh_locked()
            key = self._keys.get(kid)
            if key is None:
                raise JwtVerifyError(f"JWT kid {kid!r} not present in JWKS")
            return key

    def _refresh_locked(self) -> None:
        raw = self._http_get(self._jwks_url)
        try:
            doc = json.loads(raw)
        except (ValueError, json.JSONDecodeError) as e:
            raise JwtVerifyError(f"parse JWKS: {e}") from e
        keys = doc.get("keys")
        if not isinstance(keys, list):
            raise JwtVerifyError("JWKS missing keys array")
        out: Dict[str, ec.EllipticCurvePublicKey] = {}
        for k in keys:
            if k.get("kty") != "EC" or k.get("crv") != "P-256":
                continue
            try:
                x = int.from_bytes(_b64url_decode(k["x"]), "big")
                y = int.from_bytes(_b64url_decode(k["y"]), "big")
                # from_encoded_point raises for off-curve points, which
                # is exactly the invalid-curve defence we want.
                pub_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
                out[k["kid"]] = pub_numbers.public_key()
            except (KeyError, ValueError) as e:
                raise JwtVerifyError(
                    f"decode key {k.get('kid')!r}: {e}"
                ) from e
        if not out:
            raise JwtVerifyError("JWKS has no usable P-256 keys")
        self._keys = out
        self._fetched_at = time.time()
