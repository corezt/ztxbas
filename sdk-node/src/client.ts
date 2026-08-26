import { signRequest } from './sign.js';
import {
  ChallengeDeniedError,
  ChallengeExpiredError,
  ChallengeTimeoutError,
  ZtxbasError,
  apiErrorFromResponse,
} from './errors.js';
import { Verifier } from './verify.js';
import type {
  Claims,
  CreateChallengeRequest,
  CreateChallengeResponse,
  Origin,
  RegisterOriginRequest,
  RegisterUserRequest,
  StatusResponse,
  User,
} from './types.js';

/** Default per-request HTTP timeout in ms. */
export const DEFAULT_TIMEOUT_MS = 10_000;

/** Default gap between challenge status polls. */
export const DEFAULT_POLL_INTERVAL_MS = 1_000;

/** Default upper bound on challenge polling (mirrors server-side TTL). */
export const DEFAULT_POLL_TIMEOUT_MS = 4 * 60_000 + 30_000;

export interface ClientOptions {
  /** Custom User-Agent — surfaces in ztxbas access logs. */
  userAgent?: string;
  /** Per-request timeout in ms. Default 10s. */
  timeoutMs?: number;
  /** Override fetch — mainly for testing. */
  fetch?: typeof fetch;
  /**
   * Advisory: expected JWT issuer. If set, the built-in verifier will
   * require `iss` on every incoming JWT to equal this value.
   */
  expectedIssuer?: string;
}

/**
 * ZTXBAS API client.
 *
 * Handles HMAC-SHA256 request signing, JSON marshaling, JWT verification,
 * and JWKS caching. All methods return Promises; construction is
 * synchronous and cheap.
 */
export class Client {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private verifier: Verifier | null = null;

  constructor(
    baseUrl: string,
    private readonly appId: string,
    private readonly secret: string,
    private readonly opts: ClientOptions = {},
  ) {
    if (!baseUrl) throw new Error('ztxbas: baseUrl required');
    if (!appId || !secret) throw new Error('ztxbas: appId and secret required');
    let parsed: URL;
    try {
      parsed = new URL(baseUrl);
    } catch (e) {
      throw new Error(`ztxbas: parse baseUrl: ${(e as Error).message}`);
    }
    if (!parsed.protocol || !parsed.host) {
      throw new Error('ztxbas: baseUrl must include scheme and host');
    }
    // Strip trailing slash so path composition is unambiguous.
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.fetchImpl = opts.fetch ?? fetch;
  }

  /** Register (enroll) a user. Triggers the biometric-setup email. */
  registerUser(req: RegisterUserRequest): Promise<User> {
    return this.do<User>('POST', '/v1/users', req);
  }

  /** List every user in the tenant. */
  async listUsers(): Promise<User[]> {
    const out = await this.do<{ users: User[] }>('GET', '/v1/users', null);
    return out.users;
  }

  /**
   * Deregister a user. Idempotent from the caller's perspective — a
   * repeated call for the same email throws NotFoundError.
   */
  deregisterUser(email: string): Promise<void> {
    return this.do<void>('DELETE', '/v1/users', { email });
  }

  /** Register (or update) an origin the application authenticates for. */
  registerOrigin(req: RegisterOriginRequest): Promise<Origin> {
    return this.do<Origin>('POST', '/v1/origins', req);
  }

  /** List every origin registered for this application. */
  async listOrigins(): Promise<Origin[]> {
    const out = await this.do<{ origins: Origin[] }>('GET', '/v1/origins', null);
    return out.origins;
  }

  /** Delete an origin by id. */
  deleteOrigin(id: string): Promise<void> {
    return this.do<void>('DELETE', `/v1/origins/${encodeURIComponent(id)}`, null);
  }

  /** Create a challenge and trigger the mobile biometric push. */
  createChallenge(req: CreateChallengeRequest): Promise<CreateChallengeResponse> {
    return this.do<CreateChallengeResponse>('POST', '/v1/auth/challenge', req);
  }

  /** One-shot status fetch. */
  getChallengeStatus(id: string): Promise<StatusResponse> {
    if (!id) throw new Error('ztxbas: challenge id required');
    return this.do<StatusResponse>('GET', `/v1/auth/status/${encodeURIComponent(id)}`, null);
  }

  /**
   * Poll status until the challenge reaches a terminal state, then
   * verify the JWT and return its claims.
   *
   * Terminal denial and expiry surface as ChallengeDeniedError and
   * ChallengeExpiredError; polling past `pollTimeoutMs` surfaces as
   * ChallengeTimeoutError.
   */
  async pollChallenge(
    id: string,
    pollIntervalMs: number = DEFAULT_POLL_INTERVAL_MS,
    pollTimeoutMs: number = DEFAULT_POLL_TIMEOUT_MS,
  ): Promise<Claims> {
    const deadline = Date.now() + pollTimeoutMs;
    for (;;) {
      const st = await this.getChallengeStatus(id);
      if (st.status === 'approved') {
        if (!st.jwt) throw new ZtxbasError('approved status missing jwt');
        return this.verifyJwt(st.jwt);
      }
      if (st.status === 'denied') throw new ChallengeDeniedError();
      if (st.status === 'expired') throw new ChallengeExpiredError();

      if (Date.now() + pollIntervalMs >= deadline) {
        throw new ChallengeTimeoutError();
      }
      await sleep(pollIntervalMs);
    }
  }

  /** Verify a JWT using the server's JWKS (built lazily on first use). */
  verifyJwt(token: string): Promise<Claims> {
    if (!this.verifier) {
      this.verifier = new Verifier(`${this.baseUrl}/.well-known/jwks.json`, {
        expectedIssuer: this.opts.expectedIssuer,
        fetch: this.fetchImpl,
      });
    }
    return this.verifier.verify(token);
  }

  /**
   * Core request pipeline. Marshals body, signs, sends with an
   * AbortController-driven timeout, and maps errors to typed subclasses.
   */
  private async do<T>(method: string, path: string, body: unknown): Promise<T> {
    const bodyStr = body != null ? JSON.stringify(body) : '';
    const headers: Record<string, string> = {
      Accept: 'application/json',
      ...signRequest(method, path, bodyStr, this.appId, this.secret),
    };
    if (body != null) headers['Content-Type'] = 'application/json';
    if (this.opts.userAgent) headers['User-Agent'] = this.opts.userAgent;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);

    let resp: Response;
    try {
      resp = await this.fetchImpl(this.baseUrl + path, {
        method,
        headers,
        body: body != null ? bodyStr : undefined,
        signal: controller.signal,
      });
    } catch (e) {
      throw new ZtxbasError(`http: ${(e as Error).message}`);
    } finally {
      clearTimeout(timer);
    }

    if (resp.status === 204) return undefined as T;
    if (resp.status >= 400) {
      let code = '';
      let message = '';
      try {
        const err = (await resp.json()) as { error?: string; message?: string };
        code = err.error ?? '';
        message = err.message ?? '';
      } catch {
        message = await resp.text();
      }
      throw apiErrorFromResponse(resp.status, code, message || resp.statusText);
    }
    // 200/201 with JSON body.
    return (await resp.json()) as T;
  }
}

/** Promise-friendly sleep. */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
