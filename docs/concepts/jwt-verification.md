# JWT verification

After a user approves a challenge, ZTXBAS mints a short-lived ES256
JWT and returns it in the `status` response. This page covers what's
in it, how to verify it, and what to check beyond signature validity.

## What the JWT looks like

Header:

```json
{ "alg": "ES256", "typ": "JWT", "kid": "abc123..." }
```

Payload (claims):

```json
{
  "iss": "https://ztxbas.example.com",
  "sub": "alice@example.com",
  "aud": "https://app.example.com",
  "iat": 1704067200,
  "exp": 1704067500,
  "email": "alice@example.com",
  "origin": "https://app.example.com",
  "challenge_id": "c_abc123"
}
```

- `sub`, `email` — the authenticated user.
- `aud`, `origin` — the origin the challenge was bound to.
- `challenge_id` — one-shot correlation id, useful for logs.
- `iat`, `exp` — issued-at and expiry (5 minutes apart).
- `iss` — the ZTXBAS server that minted the token.

## How the SDKs verify it

Every SDK ships a verifier that does the following in order:

1. Parse the three base64url-encoded parts.
2. Confirm `alg == ES256`. Anything else (including `none`) is a hard
   reject — this is the classic algorithm-substitution defence.
3. Look up `kid` in the JWKS cache; refresh from
   `/.well-known/jwks.json` if unknown or stale (5-minute TTL).
4. Verify the ES256 signature over `header + "." + payload`.
5. Verify `exp` is in the future (with ±30 s clock skew).
6. Verify `iat` is not too far in the future (same skew).
7. If `expected_issuer` was configured, verify `iss` matches.

If any step fails, `verify` raises/returns an error and the token is
rejected.

## What to check beyond that

Signature + expiry + issuer verification proves the token is a real,
current assertion from your ZTXBAS server. Your backend should also
verify:

**The `origin` matches what you expected.** A user might have
legitimately approved a login on another site under your control; you
don't want that JWT to be usable elsewhere.

```go
if claims.Origin != expectedOrigin {
    return errors.New("token issued for a different origin")
}
```

**The `challenge_id` hasn't been used.** JWTs are stateless; if your
threat model includes stolen JWTs, keep a small LRU cache of recent
challenge ids and reject repeats. In most integrations this isn't
necessary because you're minting a real session cookie right after
verification and discarding the JWT — but note that the 5-minute
lifetime gives an attacker a small window.

## Doing verification without the SDK

If you're on a stack we don't ship an SDK for, use any conformant JWT
library that supports ES256 and JWKS. The server's JWKS is served at
`/.well-known/jwks.json` and looks like:

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "alg": "ES256",
      "use": "sig",
      "kid": "abc123...",
      "x": "base64url...",
      "y": "base64url..."
    }
  ]
}
```

The `kid` is stable across restarts — it's the first 16 chars of the
base64url SHA-256 of the DER-encoded public key. Two servers that
share the same signing key produce the same `kid`.

## Rotation

The JWKS may return more than one key when the operator rotates the
signing key. New tokens are signed with the newest key; old tokens
remain verifiable until their `exp` — usually within 5 minutes.
Consumers do nothing special: as long as they honour `kid` and refetch
the JWKS on unknown kids, rotation is transparent.

## Related

- [Origin binding](./origin-binding) — why the `origin` claim exists.
- [Challenge lifecycle](./challenge-lifecycle) — when you get a JWT and when you don't.
