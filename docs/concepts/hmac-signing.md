# HMAC request signing

Every request to `/v1/*` is signed with HMAC-SHA256 using the
application's secret. The SDKs handle this for you; this page is here
for anyone who needs to sign requests by hand (curl, another language,
debugging).

## The four headers

Every signed request carries:

| Header             | Value                                              |
| ------------------ | -------------------------------------------------- |
| `X-Application-ID` | Application id from `ztxbas app create`.           |
| `X-Timestamp`      | Unix seconds. Must be within ±300s of server clock.|
| `X-Nonce`          | Random string, unique per request. 32 hex is fine. |
| `X-Signature`      | `hex(HMAC-SHA256(secret, canonical))`.             |

## The canonical form

Single line, no trailing newline:

```
METHOD "|" PATH "|" TIMESTAMP "|" NONCE "|" BODY
```

- `METHOD` — uppercase (`GET`, `POST`, `DELETE`).
- `PATH` — URL path exactly as it will appear in the request line,
  starting with `/`. No query string (the API doesn't use one).
- `TIMESTAMP` — same value you put in `X-Timestamp`.
- `NONCE` — same value you put in `X-Nonce`.
- `BODY` — raw request bytes, or the empty string for GET/DELETE with
  no body. Whatever you put on the wire must match what you signed —
  don't reformat JSON between signing and sending.

## Example

Signing a `POST /v1/users` with body `{"email":"alice@example.com"}`:

```
canonical = 'POST|/v1/users|1704067200|abc123|{"email":"alice@example.com"}'
signature = hex(HMAC-SHA256("topsecret", canonical))
          = 92c2aca00ba47b4377aebf3e3af134aff93cf7ad959d05e31a0f0618df9f7d9a
```

Sent as:

```
POST /v1/users HTTP/1.1
Host: ztxbas.example.com
X-Application-ID: app_test
X-Timestamp: 1704067200
X-Nonce: abc123
X-Signature: 92c2aca00ba47b4377aebf3e3af134aff93cf7ad959d05e31a0f0618df9f7d9a
Content-Type: application/json

{"email":"alice@example.com"}
```

Every SDK ships with a unit test pinning this exact vector; if you're
implementing a signer in a new language, use the same inputs to
validate your work.

## Security notes

- **Store the secret at 0600.** Same as any private key.
- **Use `constant-time` comparison on the server side.** The server
  already does this (`crypto/subtle.ConstantTimeCompare` in Go). If
  you write your own signer/verifier stack, do the same.
- **Body size is capped at 8 KiB.** Anything larger returns 413
  `BODY_TOO_LARGE`. All v1 endpoints have small payloads.
- **Clock skew is bounded at 300 seconds.** If you see intermittent
  `TIMESTAMP_EXPIRED` errors, check that your host runs NTP.
- **Nonces are single-use in spirit but not enforced by ztxbas v1** —
  the timestamp window is the replay bound. Use a fresh random nonce
  every request anyway; it costs nothing and future-proofs against a
  strict-nonce mode.

## Related

- [Server hardening guide](../guides/hardening) — production-grade infra.
