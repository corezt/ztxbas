import { createVerify, createPublicKey, KeyObject } from 'node:crypto';
import { JwtVerifyError } from './errors.js';
import type { Claims } from './types.js';

interface Jwk {
  kty: string;
  crv: string;
  alg?: string;
  use?: string;
  kid: string;
  x: string;
  y: string;
}

interface JwkSet {
  keys: Jwk[];
}

/** How long a cached JWKS document is trusted before re-fetching. */
const JWKS_CACHE_TTL_MS = 5 * 60 * 1000;

/** Leeway on iat/exp comparisons — matches server-side HMAC skew. */
const CLOCK_SKEW_S = 30;

export interface VerifierOptions {
  /** If set, verified JWTs must carry `iss` equal to this value. */
  expectedIssuer?: string;
  /** Override fetch — mainly for testing. */
  fetch?: typeof fetch;
}

/**
 * Verifies ztxbas-issued JWTs against a cached JWKS.
 *
 * Constructed automatically by {@link Client.verifyJwt}, or standalone
 * for RPs that only receive JWTs and never call other endpoints.
 */
export class Verifier {
  private cache: Map<string, KeyObject> = new Map();
  private fetchedAt = 0;
  private inflight: Promise<void> | null = null;

  constructor(
    private readonly jwksUrl: string,
    private readonly opts: VerifierOptions = {},
  ) {
    if (!jwksUrl) throw new Error('ztxbas: jwksUrl required');
  }

  /**
   * Verify the given compact JWT. On success returns the parsed claims;
   * on any failure throws a {@link JwtVerifyError}.
   */
  async verify(token: string): Promise<Claims> {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new JwtVerifyError(`malformed JWT: expected 3 parts, got ${parts.length}`);
    }
    const [encHeader, encPayload, encSig] = parts;

    let header: { alg?: string; kid?: string; typ?: string };
    try {
      header = JSON.parse(b64uToBuf(encHeader).toString('utf8'));
    } catch (e) {
      throw new JwtVerifyError(`decode JWT header: ${(e as Error).message}`);
    }

    // Reject anything other than ES256 up front — this is the
    // canonical alg=none / algorithm-substitution defence.
    if (header.alg !== 'ES256') {
      throw new JwtVerifyError(`unsupported JWT alg ${JSON.stringify(header.alg)} (want ES256)`);
    }
    if (!header.kid) {
      throw new JwtVerifyError('JWT header missing kid');
    }

    const key = await this.keyForKid(header.kid);
    const signingInput = `${encHeader}.${encPayload}`;
    const rawSig = b64uToBuf(encSig);
    if (rawSig.length !== 64) {
      throw new JwtVerifyError(`ES256 signature must be 64 bytes, got ${rawSig.length}`);
    }
    // Node's crypto.createVerify expects an ASN.1/DER-encoded ECDSA
    // signature, but JWS uses the raw r||s concatenation (RFC 7515).
    // Convert before handing it off.
    const derSig = rawSigToDer(rawSig);

    const ok = createVerify('SHA256')
      .update(signingInput)
      .verify(key, derSig);
    if (!ok) throw new JwtVerifyError('JWT signature invalid');

    let claims: Claims;
    try {
      claims = JSON.parse(b64uToBuf(encPayload).toString('utf8'));
    } catch (e) {
      throw new JwtVerifyError(`decode JWT payload: ${(e as Error).message}`);
    }

    const now = Math.floor(Date.now() / 1000);
    if (claims.exp && now > claims.exp + CLOCK_SKEW_S) {
      throw new JwtVerifyError(`JWT expired at ${claims.exp} (now ${now})`);
    }
    if (claims.iat && claims.iat > now + CLOCK_SKEW_S) {
      throw new JwtVerifyError(`JWT iat in the future (${claims.iat}, now ${now})`);
    }
    if (this.opts.expectedIssuer && claims.iss !== this.opts.expectedIssuer) {
      throw new JwtVerifyError(
        `JWT iss ${JSON.stringify(claims.iss)} does not match expected ${JSON.stringify(this.opts.expectedIssuer)}`,
      );
    }
    return claims;
  }

  private async keyForKid(kid: string): Promise<KeyObject> {
    const fresh = this.cache.get(kid);
    if (fresh && Date.now() - this.fetchedAt < JWKS_CACHE_TTL_MS) {
      return fresh;
    }
    // Coalesce concurrent misses onto a single fetch.
    if (!this.inflight) {
      this.inflight = this.refresh().finally(() => {
        this.inflight = null;
      });
    }
    await this.inflight;
    const key = this.cache.get(kid);
    if (!key) throw new JwtVerifyError(`JWT kid ${JSON.stringify(kid)} not present in JWKS`);
    return key;
  }

  private async refresh(): Promise<void> {
    const doFetch = this.opts.fetch ?? fetch;
    let resp: Response;
    try {
      resp = await doFetch(this.jwksUrl, { headers: { Accept: 'application/json' } });
    } catch (e) {
      throw new JwtVerifyError(`fetch JWKS: ${(e as Error).message}`);
    }
    if (!resp.ok) {
      throw new JwtVerifyError(`JWKS fetch returned ${resp.status}`);
    }
    let doc: JwkSet;
    try {
      doc = (await resp.json()) as JwkSet;
    } catch (e) {
      throw new JwtVerifyError(`parse JWKS: ${(e as Error).message}`);
    }
    if (!doc.keys || !Array.isArray(doc.keys)) {
      throw new JwtVerifyError('JWKS missing keys array');
    }
    const next = new Map<string, KeyObject>();
    for (const k of doc.keys) {
      if (k.kty !== 'EC' || k.crv !== 'P-256') continue;
      try {
        // Node's createPublicKey accepts JWKs natively and rejects
        // off-curve points internally — no separate curve check needed.
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const ko = createPublicKey({ key: k as unknown as any, format: 'jwk' });
        next.set(k.kid, ko);
      } catch (e) {
        throw new JwtVerifyError(`decode key ${JSON.stringify(k.kid)}: ${(e as Error).message}`);
      }
    }
    if (next.size === 0) throw new JwtVerifyError('JWKS has no usable P-256 keys');
    this.cache = next;
    this.fetchedAt = Date.now();
  }
}

/** Base64url → Buffer. Accepts unpadded input (per RFC 7515). */
function b64uToBuf(s: string): Buffer {
  // Buffer.from with 'base64url' handles unpadded input in Node 16+.
  return Buffer.from(s, 'base64url');
}

/**
 * Convert a raw JWS ECDSA signature (r||s, each 32 bytes) into the
 * ASN.1/DER structure Node's crypto.verify expects:
 *   SEQUENCE { INTEGER r, INTEGER s }
 *
 * The two components need a leading 0x00 byte whenever their MSB is set
 * (DER INTEGER is signed). Leading zero bytes on the raw component are
 * stripped so the DER form is minimal, which is what verifiers demand.
 */
function rawSigToDer(raw: Buffer): Buffer {
  const r = trimAndPad(raw.subarray(0, 32));
  const s = trimAndPad(raw.subarray(32, 64));
  const body = Buffer.concat([
    Buffer.from([0x02, r.length]), r,
    Buffer.from([0x02, s.length]), s,
  ]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

function trimAndPad(b: Buffer): Buffer {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  const trimmed = b.subarray(i);
  // If MSB is set, prepend 0x00 to keep DER INTEGER unambiguously positive.
  if (trimmed[0] & 0x80) {
    return Buffer.concat([Buffer.from([0x00]), trimmed]);
  }
  return trimmed;
}
