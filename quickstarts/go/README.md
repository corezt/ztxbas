# ZTXBAS Go quickstart

End-to-end demo: enroll → challenge → JWT verify, using the Go SDK.

## Prereqs

- A running ZTXBAS server (see [deploy/README.md](../../deploy/README.md)).
- An application id + HMAC secret. Create one from the admin console
  (**Applications → New application**) or via CLI:
  `docker exec <container> ztxbas app create <name>`.
- A phone with the CoreZT authenticator installed and ready to enroll.

## Run

```bash
export ZTXBAS_URL=https://ztxbas.example.com
export ZTXBAS_APP_ID=app_xxx
export ZTXBAS_SECRET=hex...
export ZTXBAS_USER_EMAIL=alice@example.com
export ZTXBAS_ORIGIN=https://app.example.com

go run .
```

If this is the user's first login you'll receive an enrollment email —
complete the mobile enrollment before the challenge times out. On
subsequent runs the challenge push fires immediately.

## What it does

1. Registers the origin (`https://app.example.com`) so ztxbas will
   accept challenges for it.
2. Registers the user (idempotent — skipped with a note if they exist).
3. Creates a challenge; the mobile app pushes a biometric prompt.
4. Polls status until the user approves, then verifies the returned
   JWT against the server's JWKS.

Read the code in `main.go` for the annotated version.
