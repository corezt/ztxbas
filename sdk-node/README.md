# @corezt/ztxbas

Official Node/TypeScript SDK for [ZTXBAS](https://corezt.com/docs/ztxbas)
— the Zero-Trust Biometric Authentication Server.

Handles HMAC-SHA256 request signing, JWT verification against the
server's JWKS, and JWKS caching. Zero external runtime dependencies —
uses Node's built-in `fetch` and `node:crypto`.

## Install

```bash
npm install @corezt/ztxbas
```

Requires Node 18 or newer.

## Quick start

```ts
import { Client, ChallengeDeniedError, ChallengeExpiredError } from '@corezt/ztxbas';

const client = new Client(
  'https://ztxbas.example.com',
  'app_YOUR_APPLICATION_ID',
  'YOUR_HMAC_SECRET_HEX',
);

// 1. One-time: enroll the user (triggers biometric-setup email).
await client.registerUser({ email: 'alice@example.com' });

// 2. One-time: register the origin your app authenticates for.
await client.registerOrigin({
  origin: 'https://app.example.com',
  display_name: 'Example App',
});

// 3. Every login: create a challenge, poll for approval.
const ch = await client.createChallenge({
  user_email: 'alice@example.com',
  origin: 'https://app.example.com',
});

try {
  const claims = await client.pollChallenge(ch.challenge_id);
  console.log(`authenticated: ${claims.email} @ ${claims.origin}`);
} catch (err) {
  if (err instanceof ChallengeDeniedError) {
    // User tapped Deny on their phone.
  } else if (err instanceof ChallengeExpiredError) {
    // Approval didn't happen in time.
  } else {
    throw err;
  }
}
```

## Error handling

Every SDK-thrown error inherits from `ZtxbasError`. Common failures are
typed subclasses you can `instanceof`-match:

- `UnauthorizedError` — 401 from the server (usually clock skew or wrong secret)
- `NotFoundError` — 404 (user or origin doesn't exist)
- `ConflictError` — 409 (duplicate registration)
- `UnregisteredOriginError` — 403 UNREGISTERED_ORIGIN
- `ChallengeDeniedError` — user tapped Deny
- `ChallengeExpiredError` — challenge TTL elapsed
- `ChallengeTimeoutError` — client-side poll timeout elapsed
- `JwtVerifyError` — signature / claims failed verification
- `ApiError` — any other non-2xx (carries `.statusCode`, `.code`, `.message`)

## Verify-only mode

If your architecture receives JWTs elsewhere and only needs to verify
them, skip the `Client`:

```ts
import { Verifier } from '@corezt/ztxbas';

const verifier = new Verifier(
  'https://ztxbas.example.com/.well-known/jwks.json',
  { expectedIssuer: 'https://ztxbas.example.com' },
);

const claims = await verifier.verify(jwtFromMobile);
```

## API surface

| Method                              | Endpoint                                  |
| ----------------------------------- | ----------------------------------------- |
| `registerUser(req)`                 | `POST /v1/users`                          |
| `listUsers()`                       | `GET /v1/users`                           |
| `deregisterUser(email)`             | `DELETE /v1/users`                        |
| `registerOrigin(req)`               | `POST /v1/origins`                        |
| `listOrigins()`                     | `GET /v1/origins`                         |
| `deleteOrigin(id)`                  | `DELETE /v1/origins/{id}`                 |
| `createChallenge(req)`              | `POST /v1/auth/challenge`                 |
| `getChallengeStatus(id)`            | `GET /v1/auth/status/{id}`                |
| `pollChallenge(id, [interval, timeout])` | `getChallengeStatus` in a loop + `verifyJwt` |
| `verifyJwt(token)`                  | verify against `/.well-known/jwks.json`   |

## Development

```bash
npm install
npm run build     # compile TS → dist/
npm test          # compile tests, run node:test
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
