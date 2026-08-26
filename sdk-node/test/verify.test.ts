import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createHash,
  createPrivateKey,
  createSign,
  generateKeyPairSync,
  KeyObject,
} from 'node:crypto';
import { createServer, Server } from 'node:http';
import { Verifier, JwtVerifyError, Client } from '../src/index.js';

/**
 * Tiny in-test ES256 signer that mirrors the server's signing scheme.
 * Lives in the test file (not the SDK) so the SDK itself has no
 * signing surface — RPs only ever verify.
 */
class TestSigner {
  readonly kid: string;
  readonly privateKey: KeyObject;
  readonly publicKeyJwk: { kty: string; crv: string; x: string; y: string };

  constructor(kid = 'test-kid') {
    this.kid = kid;
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.privateKey = privateKey;
    const jwk = publicKey.export({ format: 'jwk' }) as { kty: string; crv: string; x: string; y: string };
    this.publicKeyJwk = jwk;
  }

  sign(claims: Record<string, unknown>): string {
    const header = { alg: 'ES256', typ: 'JWT', kid: this.kid };
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const signingInput = `${enc(header)}.${enc(claims)}`;
    // Node's createSign returns DER; convert to raw r||s (JWS-compact form).
    const der = createSign('SHA256').update(signingInput).sign({
      key: this.privateKey,
      dsaEncoding: 'ieee-p1363', // raw r||s
    });
    return `${signingInput}.${Buffer.from(der).toString('base64url')}`;
  }

  jwksBody(): string {
    return JSON.stringify({
      keys: [{
        kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig', kid: this.kid,
        x: this.publicKeyJwk.x, y: this.publicKeyJwk.y,
      }],
    });
  }
}

async function serveJwks(signer: TestSigner, onHit?: () => void): Promise<{ url: string; server: Server }> {
  const server = createServer((_, res) => {
    onHit?.();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(signer.jwksBody());
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  return { url: `http://127.0.0.1:${port}/`, server };
}

test('verifier accepts a valid ES256 JWT and returns claims', async () => {
  const sig = new TestSigner();
  const { url, server } = await serveJwks(sig);
  try {
    const v = new Verifier(url, { expectedIssuer: 'https://ztxbas.example.com' });
    const now = Math.floor(Date.now() / 1000);
    const tok = sig.sign({
      iss: 'https://ztxbas.example.com',
      sub: 'alice@example.com',
      aud: 'https://app.example.com',
      email: 'alice@example.com',
      origin: 'https://app.example.com',
      challenge_id: 'c_1',
      iat: now,
      exp: now + 300,
    });
    const claims = await v.verify(tok);
    assert.equal(claims.email, 'alice@example.com');
    assert.equal(claims.origin, 'https://app.example.com');
  } finally {
    server.close();
  }
});

test('verifier rejects alg=none', async () => {
  const sig = new TestSigner();
  const { url, server } = await serveJwks(sig);
  try {
    const v = new Verifier(url);
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const header = { alg: 'none', typ: 'JWT', kid: sig.kid };
    const payload = { email: 'attacker@example.com', exp: Math.floor(Date.now() / 1000) + 3600 };
    const tok = `${enc(header)}.${enc(payload)}.`;
    await assert.rejects(v.verify(tok), (e: Error) => e instanceof JwtVerifyError && /alg/i.test(e.message));
  } finally {
    server.close();
  }
});

test('verifier rejects expired token', async () => {
  const sig = new TestSigner();
  const { url, server } = await serveJwks(sig);
  try {
    const v = new Verifier(url);
    const tok = sig.sign({ exp: Math.floor(Date.now() / 1000) - 3600 });
    await assert.rejects(v.verify(tok), (e: Error) => /expired/i.test(e.message));
  } finally {
    server.close();
  }
});

test('verifier rejects wrong issuer', async () => {
  const sig = new TestSigner();
  const { url, server } = await serveJwks(sig);
  try {
    const v = new Verifier(url, { expectedIssuer: 'https://legit.example.com' });
    const tok = sig.sign({
      iss: 'https://evil.example.com',
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    await assert.rejects(v.verify(tok), (e: Error) => /iss/.test(e.message));
  } finally {
    server.close();
  }
});

test('verifier rejects tampered payload (signature invalid)', async () => {
  const sig = new TestSigner();
  const { url, server } = await serveJwks(sig);
  try {
    const v = new Verifier(url);
    const tok = sig.sign({ email: 'alice@example.com', exp: Math.floor(Date.now() / 1000) + 3600 });
    const [h, , s] = tok.split('.');
    const forged = Buffer.from(JSON.stringify({
      email: 'attacker@example.com', exp: Math.floor(Date.now() / 1000) + 3600,
    })).toString('base64url');
    await assert.rejects(v.verify(`${h}.${forged}.${s}`), (e: Error) => /signature invalid/i.test(e.message));
  } finally {
    server.close();
  }
});

test('verifier rejects unknown kid', async () => {
  const sig = new TestSigner('known-kid');
  const { url, server } = await serveJwks(sig);
  try {
    const v = new Verifier(url);
    const rogue = new TestSigner('unknown-kid');
    const tok = rogue.sign({ exp: Math.floor(Date.now() / 1000) + 3600 });
    await assert.rejects(v.verify(tok), (e: Error) => /kid/.test(e.message));
  } finally {
    server.close();
  }
});

test('verifier caches JWKS within TTL', async () => {
  let hits = 0;
  const sig = new TestSigner();
  const { url, server } = await serveJwks(sig, () => { hits += 1; });
  try {
    const v = new Verifier(url);
    const tok = sig.sign({ exp: Math.floor(Date.now() / 1000) + 3600 });
    for (let i = 0; i < 3; i++) {
      await v.verify(tok);
    }
    assert.equal(hits, 1, `expected 1 JWKS fetch, saw ${hits}`);
  } finally {
    server.close();
  }
});

test('verifier rejects malformed tokens', async () => {
  const sig = new TestSigner();
  const { url, server } = await serveJwks(sig);
  try {
    const v = new Verifier(url);
    for (const bad of ['', 'a.b', 'a.b.c.d', 'not-base64.also.bad']) {
      await assert.rejects(v.verify(bad));
    }
  } finally {
    server.close();
  }
});

test('Client.verifyJwt builds a Verifier at baseUrl/.well-known/jwks.json', async () => {
  const sig = new TestSigner();
  const server = createServer((req, res) => {
    if (req.url === '/.well-known/jwks.json') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(sig.jwksBody());
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  try {
    const c = new Client(`http://127.0.0.1:${port}`, 'app_test', 'sec');
    const tok = sig.sign({ email: 'alice@example.com', exp: Math.floor(Date.now() / 1000) + 3600 });
    const claims = await c.verifyJwt(tok);
    assert.equal(claims.email, 'alice@example.com');
  } finally {
    server.close();
  }
});

// Suppress unused-import warning for createHash (kept available for future
// tests that want to compute their own JWKS document).
void createHash;
void createPrivateKey;
