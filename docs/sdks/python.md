---
sidebar_position: 3
title: Python SDK
---

# Python SDK

Thin, dependency-light Python client. Uses `cryptography` for ES256;
no other runtime deps.

## Install

```bash
pip install ztxbas
```

Requires Python 3.9 or newer.

## Import

```python
from ztxbas import Client, ChallengeDeniedError, ChallengeExpiredError
```

## Minimal end-to-end

```python
c = Client(
    "https://ztxbas.example.com",
    "app_YOUR_APPLICATION_ID",
    "YOUR_HMAC_SECRET_HEX",
)

c.register_user("alice@example.com")
c.register_origin("https://app.example.com", "Example App")

ch = c.create_challenge("alice@example.com", "https://app.example.com")
claims = c.poll_challenge(ch["challenge_id"])
print(claims.email, claims.origin)
```

## Errors as exceptions

```python
from ztxbas import (
    ChallengeDeniedError,
    ChallengeExpiredError,
    UnregisteredOriginError,
)

try:
    claims = c.poll_challenge(ch["challenge_id"])
except ChallengeDeniedError:
    ...  # user tapped Deny
except ChallengeExpiredError:
    ...  # approval too slow
except UnregisteredOriginError:
    ...  # programmer error
```

For the raw envelope, catch `ApiError` and inspect `status_code`,
`code`, and `message`.

## Verify-only mode

```python
from ztxbas import Verifier

v = Verifier(
    "https://ztxbas.example.com/.well-known/jwks.json",
    expected_issuer="https://ztxbas.example.com",
)
claims = v.verify(jwt_from_mobile)
```

`Verifier` is thread-safe — a single instance can back many worker
threads or async tasks.

## Repo and reference

- Source: [`sdk-python/`](https://github.com/corezt/ztxbas/tree/main/sdk-python)
- Package: [`ztxbas`](https://pypi.org/project/ztxbas/)
- Quickstart: [`quickstarts/python/`](https://github.com/corezt/ztxbas/tree/main/quickstarts/python)
