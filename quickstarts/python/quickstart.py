"""ZTXBAS Python quickstart.

Runs the full enroll → challenge → JWT verify flow against a live
ztxbas server. Requires an application id + HMAC secret from
``ztxbas app create`` on the server.

Usage::

    export ZTXBAS_URL=https://ztxbas.example.com
    export ZTXBAS_APP_ID=app_xxx
    export ZTXBAS_SECRET=hex...
    export ZTXBAS_USER_EMAIL=alice@example.com
    export ZTXBAS_ORIGIN=https://app.example.com

    python quickstart.py
"""

from __future__ import annotations

import datetime as dt
import os
import sys

from ztxbas import (
    ChallengeDeniedError,
    ChallengeExpiredError,
    Client,
    ConflictError,
)


def env(key: str) -> str:
    val = os.environ.get(key)
    if not val:
        print(f"required env var {key} is unset", file=sys.stderr)
        sys.exit(1)
    return val


def main() -> None:
    base_url = env("ZTXBAS_URL")
    app_id = env("ZTXBAS_APP_ID")
    secret = env("ZTXBAS_SECRET")
    user_email = env("ZTXBAS_USER_EMAIL")
    origin = env("ZTXBAS_ORIGIN")

    c = Client(base_url, app_id, secret)

    # 1. Register the origin (idempotent).
    c.register_origin(origin, "Quickstart")
    print(f"[1/4] origin registered: {origin}")

    # 2. Register the user (idempotent from our POV).
    try:
        c.register_user(user_email)
        print(f"[2/4] user enrolled: {user_email} (check email to complete device setup)")
    except ConflictError:
        print(f"[2/4] user already enrolled: {user_email}")

    # 3. Create a challenge — this triggers the mobile push.
    ch = c.create_challenge(user_email, origin)
    print(
        f"[3/4] challenge {ch['challenge_id']} created "
        f"(approve on your phone within {ch['expires_in']}s)"
    )

    # 4. Poll for approval and verify the JWT.
    try:
        claims = c.poll_challenge(ch["challenge_id"])
    except ChallengeDeniedError:
        print("[4/4] user denied the request", file=sys.stderr)
        sys.exit(2)
    except ChallengeExpiredError:
        print("[4/4] challenge expired", file=sys.stderr)
        sys.exit(2)

    exp = dt.datetime.fromtimestamp(claims.exp or 0, tz=dt.timezone.utc)
    print("[4/4] ✅ authenticated")
    print(
        f"      email={claims.email} origin={claims.origin} "
        f"challenge_id={claims.challenge_id} exp={exp.isoformat()}"
    )


if __name__ == "__main__":
    main()
