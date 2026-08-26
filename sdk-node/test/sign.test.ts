import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { signRequest, newNonce, HDR_APPLICATION_ID, HDR_TIMESTAMP, HDR_NONCE, HDR_SIGNATURE } from '../src/sign.js';

// Pinned known vector — must match sdk-go/sign_test.go's TestSignRequest_KnownVector.
// If this hex drifts, an SDK is producing a canonical form the server
// won't accept.
test('signRequest produces the known-vector hex', () => {
  const method = 'POST';
  const path = '/v1/users';
  const body = '{"email":"alice@example.com"}';
  const appId = 'app_test';
  const secret = 'topsecret';
  const nonce = 'abc123';
  const ts = 1704067200;

  const headers = signRequest(method, path, body, appId, secret, ts * 1000, nonce);

  assert.equal(headers[HDR_APPLICATION_ID], appId);
  assert.equal(headers[HDR_TIMESTAMP], String(ts));
  assert.equal(headers[HDR_NONCE], nonce);
  assert.equal(
    headers[HDR_SIGNATURE],
    '92c2aca00ba47b4377aebf3e3af134aff93cf7ad959d05e31a0f0618df9f7d9a',
  );

  // Belt and braces: recompute the way the server would.
  const canonical = `${method}|${path}|${ts}|${nonce}|${body}`;
  const want = createHmac('sha256', secret).update(canonical).digest('hex');
  assert.equal(headers[HDR_SIGNATURE], want);
});

test('signRequest handles empty body', () => {
  const h = signRequest('GET', '/v1/users', '', 'a', 's', 1000_000, 'n1');
  assert.equal(h[HDR_SIGNATURE].length, 64);
});

test('newNonce returns unique 32-char hex strings', () => {
  const seen = new Set<string>();
  for (let i = 0; i < 100; i++) {
    const n = newNonce();
    assert.equal(n.length, 32);
    assert.match(n, /^[0-9a-f]{32}$/);
    assert.equal(seen.has(n), false);
    seen.add(n);
  }
});
