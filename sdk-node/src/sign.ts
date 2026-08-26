import { createHmac, randomBytes } from 'node:crypto';

/**
 * HMAC header names — must match the server's middleware constants.
 * Any drift here shows up as INVALID_SIGNATURE on the RP side.
 */
export const HDR_APPLICATION_ID = 'X-Application-ID';
export const HDR_TIMESTAMP = 'X-Timestamp';
export const HDR_NONCE = 'X-Nonce';
export const HDR_SIGNATURE = 'X-Signature';

/** Number of random bytes in a nonce → 32 hex chars. */
const NONCE_BYTES = 16;

/**
 * Compute the four HMAC headers for a request.
 *
 * Canonical form (single line, no trailing newline):
 *
 *     METHOD "|" PATH "|" TIMESTAMP "|" NONCE "|" BODY
 *
 * `body` is the exact string that will be sent as the HTTP body — the
 * empty string when there is no body. The client MUST use this same
 * string on the wire; any re-serialisation between signing and sending
 * will break the signature.
 *
 * @param nowMs — milliseconds since epoch; passed in so tests can pin it.
 * @param nonce — hex-encoded random nonce; leave undefined to generate.
 */
export function signRequest(
  method: string,
  path: string,
  body: string,
  appId: string,
  secret: string,
  nowMs: number = Date.now(),
  nonce: string = newNonce(),
): Record<string, string> {
  const ts = Math.floor(nowMs / 1000).toString();
  const canonical = `${method}|${path}|${ts}|${nonce}|${body}`;
  const sig = createHmac('sha256', secret).update(canonical).digest('hex');
  return {
    [HDR_APPLICATION_ID]: appId,
    [HDR_TIMESTAMP]: ts,
    [HDR_NONCE]: nonce,
    [HDR_SIGNATURE]: sig,
  };
}

/** Generate a fresh hex-encoded nonce. */
export function newNonce(): string {
  return randomBytes(NONCE_BYTES).toString('hex');
}
