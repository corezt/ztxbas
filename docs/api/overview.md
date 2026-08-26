---
sidebar_position: 1
title: API overview
---

# API overview

The ZTXBAS public API is small on purpose. Ten endpoints across four
resources, all under `/v1/*`, plus two unauthenticated endpoints for
health and key discovery.

## Machine-readable spec

The authoritative specification is
[`openapi.yaml`](https://github.com/corezt/ztxbas/blob/main/api/openapi.yaml)
in the repo. It's OpenAPI 3.1 and validates in
[Swagger Editor](https://editor.swagger.io/), Stoplight, and every
codegen tool worth using.

## Endpoints at a glance

| Verb   | Path                                 | Purpose                                  |
| ------ | ------------------------------------ | ---------------------------------------- |
| POST   | `/v1/users`                          | Enroll a user; sends the setup email.    |
| GET    | `/v1/users`                          | List users in the tenant.                |
| DELETE | `/v1/users`                          | Deregister a user (email in body).       |
| POST   | `/v1/origins`                        | Register an origin.                      |
| GET    | `/v1/origins`                        | List registered origins.                 |
| DELETE | `/v1/origins/{id}`                   | Delete an origin.                        |
| POST   | `/v1/auth/challenge`                 | Create a challenge, push to phone.       |
| GET    | `/v1/auth/status/{challenge_id}`     | Poll for the challenge outcome.          |
| GET    | `/.well-known/jwks.json`             | Public keys for JWT verification.        |
| GET    | `/health`                            | Liveness probe. No auth.                 |

Everything under `/v1/*` requires HMAC-SHA256 signing — see
[HMAC signing](../concepts/hmac-signing) for the canonical form. The
SDKs handle it for you.

## Authentication

Four headers on every `/v1/*` request:

```
X-Application-ID: app_...
X-Timestamp: 1704067200
X-Nonce: 32-hex-chars
X-Signature: hex(HMAC-SHA256(secret, canonical))
```

Missing or invalid → `401 UNAUTHORIZED` with a specific `error` code
telling you which check failed.

## Error envelope

All 4xx/5xx responses share the same JSON shape:

```json
{ "error": "UNREGISTERED_ORIGIN", "message": "origin not registered for this application" }
```

- `error` is machine-readable and stable — code your retry / branching against it.
- `message` is human-readable and may change; don't parse it.

Common codes:

| Code                    | Where it comes from                                     |
| ----------------------- | ------------------------------------------------------- |
| `MISSING_AUTH`          | One of the four HMAC headers absent.                    |
| `INVALID_SIGNATURE`     | HMAC didn't verify.                                     |
| `INVALID_TIMESTAMP`     | Timestamp negative or non-integer.                      |
| `TIMESTAMP_EXPIRED`     | Timestamp outside ±300 s of server clock.               |
| `INVALID_APPLICATION`   | `X-Application-ID` unknown.                             |
| `BODY_TOO_LARGE`        | Request body over 8 KiB.                                |
| `DUPLICATE_EMAIL`       | Registering a user that already exists.                 |
| `UNREGISTERED_ORIGIN`   | Challenge origin wasn't `POST`ed to `/v1/origins` first.|
| `USER_NOT_FOUND`        | Challenge/deregister for an unknown user.               |
| `ENROLLMENT_FAILED`     | Server couldn't dispatch the enrollment email.          |

## Rate limits

None currently enforced by ZTXBAS itself. Run behind a reverse proxy
(nginx, Caddy, Cloudflare) if you need per-tenant limits — the
[hardening guide](../guides/hardening) covers a recommended baseline.

