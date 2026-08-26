/**
 * ZTXBAS Node/TypeScript quickstart.
 *
 * Runs the full enroll → challenge → JWT verify flow against a live
 * ztxbas server. Requires an application id + HMAC secret from
 * `ztxbas app create` on the server.
 *
 * Usage:
 *   export ZTXBAS_URL=https://ztxbas.example.com
 *   export ZTXBAS_APP_ID=app_xxx
 *   export ZTXBAS_SECRET=hex...
 *   export ZTXBAS_USER_EMAIL=alice@example.com
 *   export ZTXBAS_ORIGIN=https://app.example.com
 *   npm start
 */

import {
  Client,
  ChallengeDeniedError,
  ChallengeExpiredError,
  ConflictError,
} from '@corezt/ztxbas';

function env(k: string): string {
  const v = process.env[k];
  if (!v) {
    console.error(`required env var ${k} is unset`);
    process.exit(1);
  }
  return v;
}

async function main(): Promise<void> {
  const baseUrl = env('ZTXBAS_URL');
  const appId = env('ZTXBAS_APP_ID');
  const secret = env('ZTXBAS_SECRET');
  const userEmail = env('ZTXBAS_USER_EMAIL');
  const origin = env('ZTXBAS_ORIGIN');

  const c = new Client(baseUrl, appId, secret);

  // 1. Register the origin (idempotent).
  await c.registerOrigin({ origin, display_name: 'Quickstart' });
  console.log(`[1/4] origin registered: ${origin}`);

  // 2. Register the user. If they exist, that's fine — we just want
  //    the user row to be present so challenges succeed.
  try {
    await c.registerUser({ email: userEmail });
    console.log(`[2/4] user enrolled: ${userEmail} (check email to complete device setup)`);
  } catch (e) {
    if (e instanceof ConflictError) {
      console.log(`[2/4] user already enrolled: ${userEmail}`);
    } else {
      throw e;
    }
  }

  // 3. Create a challenge — this triggers the mobile push.
  const ch = await c.createChallenge({ user_email: userEmail, origin });
  console.log(`[3/4] challenge ${ch.challenge_id} created (approve on your phone within ${ch.expires_in}s)`);

  // 4. Poll for approval and verify the JWT.
  try {
    const claims = await c.pollChallenge(ch.challenge_id);
    console.log('[4/4] ✅ authenticated');
    console.log(`      email=${claims.email} origin=${claims.origin} challenge_id=${claims.challenge_id}`);
    console.log(`      exp=${new Date((claims.exp ?? 0) * 1000).toISOString()}`);
  } catch (e) {
    if (e instanceof ChallengeDeniedError) {
      console.error('[4/4] user denied the request');
      process.exit(2);
    }
    if (e instanceof ChallengeExpiredError) {
      console.error('[4/4] challenge expired');
      process.exit(2);
    }
    throw e;
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
