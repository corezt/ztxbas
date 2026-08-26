---
sidebar_position: 2
title: Node / TypeScript SDK
---

# Node / TypeScript SDK

Idiomatic TypeScript client. Zero external runtime dependencies — uses
Node's built-in `fetch` and `node:crypto`.

## Install

```bash
npm install @corezt/ztxbas
```

Requires Node 18 or newer.

## Import

```ts
import { Client, ChallengeDeniedError } from '@corezt/ztxbas';
```

## Minimal end-to-end

```ts
const c = new Client(
  'https://ztxbas.example.com',
  'app_YOUR_APPLICATION_ID',
  'YOUR_HMAC_SECRET_HEX',
);

await c.registerUser({ email: 'alice@example.com' });
await c.registerOrigin({
  origin: 'https://app.example.com',
  display_name: 'Example App',
});

const ch = await c.createChallenge({
  user_email: 'alice@example.com',
  origin: 'https://app.example.com',
});

const claims = await c.pollChallenge(ch.challenge_id);
console.log(claims.email, claims.origin);
```

## Errors as typed subclasses

Every SDK-thrown error inherits from `ZtxbasError`. Match with
`instanceof`:

```ts
import {
  ChallengeDeniedError,
  ChallengeExpiredError,
  UnregisteredOriginError,
} from '@corezt/ztxbas';

try {
  await c.pollChallenge(ch.challenge_id);
} catch (e) {
  if (e instanceof ChallengeDeniedError) { /* user Denied */ }
  else if (e instanceof ChallengeExpiredError) { /* TTL elapsed */ }
  else if (e instanceof UnregisteredOriginError) { /* programmer error */ }
  else throw e;
}
```

## Verify-only mode

```ts
import { Verifier } from '@corezt/ztxbas';

const v = new Verifier(
  'https://ztxbas.example.com/.well-known/jwks.json',
  { expectedIssuer: 'https://ztxbas.example.com' },
);
const claims = await v.verify(jwtFromMobile);
```

## Repo and reference

- Source: [`sdk-node/`](https://github.com/corezt/ztxbas/tree/main/sdk-node)
- Package: [`@corezt/ztxbas`](https://www.npmjs.com/package/@corezt/ztxbas)
- Quickstart: [`quickstarts/node/`](https://github.com/corezt/ztxbas/tree/main/quickstarts/node)
