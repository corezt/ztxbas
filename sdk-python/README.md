# ztxbas — Python SDK

Official Python client for [ZTXBAS](https://corezt.com/docs/ztxbas) —
the Zero-Trust Biometric Authentication Server.

Handles HMAC-SHA256 request signing, JWT verification against the
server's JWKS, and JWKS caching. Uses `cryptography` for ES256; no
other runtime deps.

## Install

```bash
pip install ztxbas
```

Requires Python 3.9 or newer.

## Quick start

```python
from ztxbas import Client, ChallengeDeniedError, ChallengeExpiredError

c = Client(
    "https://ztxbas.example.com",
    "app_YOUR_APPLICATION_ID",
    "YOUR_HMAC_SECRET_HEX",
)

# 1. One-time: enroll the user (triggers biometric-setup email).
c.register_user("alice@example.com")

# 2. One-time: register the origin your app authenticates for.
c.register_origin("https://app.example.com", "Example App")

# 3. Every login: create a challenge, poll for approval.
ch = c.create_challenge("alice@example.com", "https://app.example.com")

try:
    claims = c.poll_challenge(ch["challenge_id"])
    print(f"authenticated: {claims.email} @ {claims.origin}")
except ChallengeDeniedError:
    ...  # user tapped Deny
except ChallengeExpiredError:
    ...  # approval didn't happen in time
```

## Error handling

Every SDK-raised exception inherits from `ZtxbasError`. Common failures
are typed subclasses you can catch by name:

| Exception                    | Meaning                                        |
| ---------------------------- | ---------------------------------------------- |
| `UnauthorizedError`          | 401 (usually clock skew or wrong secret)       |
| `NotFoundError`              | 404 (user or origin doesn't exist)             |
| `ConflictError`              | 409 (duplicate registration)                   |
| `UnregisteredOriginError`    | 403 UNREGISTERED_ORIGIN                        |
| `ChallengeDeniedError`       | user tapped Deny                               |
| `ChallengeExpiredError`      | challenge TTL elapsed                          |
| `ChallengeTimeoutError`      | client-side poll timeout elapsed               |
| `JwtVerifyError`             | signature / claims failed verification         |
| `ApiError`                   | any other non-2xx (has `status_code`, `code`)  |

## Verify-only mode

If your architecture receives JWTs elsewhere and only needs to verify:

```python
from ztxbas import Verifier

v = Verifier(
    "https://ztxbas.example.com/.well-known/jwks.json",
    expected_issuer="https://ztxbas.example.com",
)
claims = v.verify(jwt_from_mobile)
```

`Verifier` is thread-safe; multiple threads can share one instance.

## API surface

| Method                                                  | Endpoint                                  |
| ------------------------------------------------------- | ----------------------------------------- |
| `register_user(email, external_id=None)`                | `POST /v1/users`                          |
| `list_users()`                                          | `GET /v1/users`                           |
| `deregister_user(email)`                                | `DELETE /v1/users`                        |
| `register_origin(origin, display_name)`                 | `POST /v1/origins`                        |
| `list_origins()`                                        | `GET /v1/origins`                         |
| `delete_origin(id)`                                     | `DELETE /v1/origins/{id}`                 |
| `create_challenge(user_email, origin)`                  | `POST /v1/auth/challenge`                 |
| `get_challenge_status(id)`                              | `GET /v1/auth/status/{id}`                |
| `poll_challenge(id, interval=1.0, timeout=270)`         | poll + `verify_jwt`                       |
| `verify_jwt(token)`                                     | verify against `/.well-known/jwks.json`   |

## Development

```bash
pip install -e '.[dev]'
pytest tests/
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
