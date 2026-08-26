import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, Server, IncomingMessage, ServerResponse } from 'node:http';
import { createHmac } from 'node:crypto';
import {
  Client,
  ConflictError,
  NotFoundError,
  UnauthorizedError,
  UnregisteredOriginError,
  ApiError,
} from '../src/index.js';

/**
 * Spin up a real HTTP server on an ephemeral port, hand its base URL to a
 * Client, and return both. The handler receives the request plus its
 * fully-read body; test bodies can inspect and reply however they like.
 */
async function withServer(
  handler: (req: IncomingMessage, res: ServerResponse, body: string) => void,
): Promise<{ client: Client; server: Server; url: string }> {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => handler(req, res, Buffer.concat(chunks).toString('utf8')));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  if (typeof addr === 'string' || !addr) throw new Error('unexpected address');
  const url = `http://127.0.0.1:${addr.port}`;
  const client = new Client(url, 'app_test', 'secret_test');
  return { client, server, url };
}

/**
 * Re-run the server's HMAC check on an inbound request. If this fails,
 * the SDK produced headers the real server would reject — the whole
 * point of pinning tests here rather than only in a unit test.
 */
function assertSigValid(req: IncomingMessage, body: string, secret: string) {
  const appId = req.headers['x-application-id'] as string;
  const ts = req.headers['x-timestamp'] as string;
  const nonce = req.headers['x-nonce'] as string;
  const sig = req.headers['x-signature'] as string;
  assert.ok(appId && ts && nonce && sig, 'missing HMAC headers');
  assert.equal(sig.length, 64);
  const canonical = `${req.method}|${req.url}|${ts}|${nonce}|${body}`;
  const want = createHmac('sha256', secret).update(canonical).digest('hex');
  assert.equal(sig, want, 'signature mismatch');
}

test('registerUser sends signed POST and parses response', async () => {
  const { client, server } = await withServer((req, res, body) => {
    assert.equal(req.method, 'POST');
    assert.equal(req.url, '/v1/users');
    assertSigValid(req, body, 'secret_test');
    res.writeHead(201, { 'Content-Type': 'application/json' });
    res.end('{"id":"u_1","email":"alice@example.com","enrolled":false}');
  });
  try {
    const u = await client.registerUser({ email: 'alice@example.com' });
    assert.equal(u.id, 'u_1');
    assert.equal(u.email, 'alice@example.com');
    assert.equal(u.enrolled, false);
  } finally {
    server.close();
  }
});

test('listUsers unwraps the {users:[…]} envelope', async () => {
  const { client, server } = await withServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"users":[{"id":"u_1","email":"a@x","enrolled":true}]}');
  });
  try {
    const list = await client.listUsers();
    assert.equal(list.length, 1);
    assert.equal(list[0].email, 'a@x');
  } finally {
    server.close();
  }
});

test('deregisterUser handles 204', async () => {
  const { client, server } = await withServer((req, res, body) => {
    assertSigValid(req, body, 'secret_test');
    assert.equal(req.method, 'DELETE');
    res.writeHead(204);
    res.end();
  });
  try {
    await client.deregisterUser('alice@example.com');
  } finally {
    server.close();
  }
});

test('registerOrigin round trips', async () => {
  const { client, server } = await withServer((req, res, body) => {
    assertSigValid(req, body, 'secret_test');
    const parsed = JSON.parse(body);
    assert.equal(parsed.origin, 'https://app.example.com');
    assert.equal(parsed.display_name, 'App');
    res.writeHead(201, { 'Content-Type': 'application/json' });
    res.end('{"id":"o_1","origin":"https://app.example.com","origin_hash":"abc","display_name":"App"}');
  });
  try {
    const o = await client.registerOrigin({
      origin: 'https://app.example.com',
      display_name: 'App',
    });
    assert.equal(o.id, 'o_1');
  } finally {
    server.close();
  }
});

test('deleteOrigin uses percent-encoded path segment', async () => {
  let seenPath = '';
  const { client, server } = await withServer((req, res) => {
    seenPath = req.url ?? '';
    res.writeHead(204);
    res.end();
  });
  try {
    await client.deleteOrigin('o_1');
    assert.equal(seenPath, '/v1/origins/o_1');
  } finally {
    server.close();
  }
});

test('createChallenge parses full response', async () => {
  const { client, server } = await withServer((req, res, body) => {
    assertSigValid(req, body, 'secret_test');
    res.writeHead(201, { 'Content-Type': 'application/json' });
    res.end(
      '{"challenge_id":"c_1","expires_in":300,"origin_display":"App","origin_url":"https://app.example.com"}',
    );
  });
  try {
    const ch = await client.createChallenge({
      user_email: 'a@x',
      origin: 'https://app.example.com',
    });
    assert.equal(ch.challenge_id, 'c_1');
    assert.equal(ch.expires_in, 300);
  } finally {
    server.close();
  }
});

test('error responses map to typed subclasses', async () => {
  const cases: Array<{ status: number; code: string; ctor: unknown }> = [
    { status: 401, code: 'INVALID_SIGNATURE', ctor: UnauthorizedError },
    { status: 404, code: 'USER_NOT_FOUND', ctor: NotFoundError },
    { status: 409, code: 'DUPLICATE_EMAIL', ctor: ConflictError },
    { status: 403, code: 'UNREGISTERED_ORIGIN', ctor: UnregisteredOriginError },
    { status: 500, code: 'INTERNAL', ctor: ApiError },
  ];
  for (const c of cases) {
    const { client, server } = await withServer((req, res) => {
      res.writeHead(c.status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: c.code, message: 'boom' }));
    });
    try {
      let caught: unknown;
      try {
        await client.listUsers();
      } catch (e) {
        caught = e;
      }
      assert.ok(caught instanceof (c.ctor as { new (...args: never[]): Error }), `expected ${(c.ctor as { name: string }).name} for ${c.code}, got ${caught}`);
      const apiErr = caught as ApiError;
      assert.equal(apiErr.code, c.code);
      assert.equal(apiErr.statusCode, c.status);
    } finally {
      server.close();
    }
  }
});

test('constructor rejects missing arguments', () => {
  assert.throws(() => new Client('', 'a', 's'));
  assert.throws(() => new Client('https://x', '', 's'));
  assert.throws(() => new Client('https://x', 'a', ''));
  assert.throws(() => new Client('not-a-url', 'a', 's'));
});

test('constructor strips trailing slash from baseUrl', async () => {
  let seenPath = '';
  const server = createServer((req, res) => {
    seenPath = req.url ?? '';
    res.writeHead(204);
    res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  try {
    const c = new Client(`http://127.0.0.1:${port}/`, 'a', 's');
    await c.deregisterUser('x@y');
    // Should be exactly one leading slash, not two.
    assert.equal(seenPath, '/v1/users');
  } finally {
    server.close();
  }
});
