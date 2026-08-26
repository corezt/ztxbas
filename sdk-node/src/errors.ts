/**
 * Error hierarchy for the ZTXBAS SDK.
 *
 * Every operation that touches the network can throw ZtxbasError or one
 * of its subclasses. Application code that only cares about "did it
 * work" can `instanceof ZtxbasError`; code that wants to distinguish
 * user-denied from expired-challenge can use the narrower subclasses.
 */

/** Base class for every SDK-thrown error. */
export class ZtxbasError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ZtxbasError';
  }
}

/**
 * Server returned a non-2xx response. Carries the parsed `error` /
 * `message` envelope so callers can react programmatically.
 */
export class ApiError extends ZtxbasError {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
  ) {
    super(`ztxbas: ${code || 'HTTP_' + statusCode}: ${message}`);
    this.name = 'ApiError';
  }
}

/** HTTP 401 — HMAC signature rejected. Usually a clock skew or bad secret. */
export class UnauthorizedError extends ApiError {
  constructor(code: string, message: string) {
    super(401, code, message);
    this.name = 'UnauthorizedError';
  }
}

/** HTTP 404 — resource does not exist. */
export class NotFoundError extends ApiError {
  constructor(code: string, message: string) {
    super(404, code, message);
    this.name = 'NotFoundError';
  }
}

/** HTTP 409 — a resource with the same identifier already exists. */
export class ConflictError extends ApiError {
  constructor(code: string, message: string) {
    super(409, code, message);
    this.name = 'ConflictError';
  }
}

/** 403 UNREGISTERED_ORIGIN — origin binding check failed. */
export class UnregisteredOriginError extends ApiError {
  constructor(message: string) {
    super(403, 'UNREGISTERED_ORIGIN', message);
    this.name = 'UnregisteredOriginError';
  }
}

/** The user tapped Deny on their phone. */
export class ChallengeDeniedError extends ZtxbasError {
  constructor() {
    super('ztxbas: challenge denied by user');
    this.name = 'ChallengeDeniedError';
  }
}

/** The challenge TTL elapsed before approval. */
export class ChallengeExpiredError extends ZtxbasError {
  constructor() {
    super('ztxbas: challenge expired');
    this.name = 'ChallengeExpiredError';
  }
}

/** Polling stopped because the caller's timeout elapsed. */
export class ChallengeTimeoutError extends ZtxbasError {
  constructor() {
    super('ztxbas: polling timed out before challenge reached a terminal state');
    this.name = 'ChallengeTimeoutError';
  }
}

/** JWT verification failed (bad signature, wrong alg, expired, etc.). */
export class JwtVerifyError extends ZtxbasError {
  constructor(message: string) {
    super(`ztxbas: ${message}`);
    this.name = 'JwtVerifyError';
  }
}

/**
 * Build the right subclass for an API error response. Kept in one place
 * so status→class mapping doesn't drift across call sites.
 */
export function apiErrorFromResponse(
  status: number,
  code: string,
  message: string,
): ApiError {
  if (code === 'UNREGISTERED_ORIGIN') return new UnregisteredOriginError(message);
  if (status === 401) return new UnauthorizedError(code, message);
  if (status === 404) return new NotFoundError(code, message);
  if (status === 409) return new ConflictError(code, message);
  return new ApiError(status, code, message);
}
