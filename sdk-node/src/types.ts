/**
 * Shared request/response types for the ZTXBAS API. Kept in one file so
 * consumers can `import type { User } from '@corezt/ztxbas'` without
 * pulling any runtime code.
 */

export type ChallengeStatus = 'pending' | 'approved' | 'denied' | 'expired';

export interface RegisterUserRequest {
  email: string;
  external_id?: string;
}

export interface User {
  id: string;
  email: string;
  external_id?: string;
  enrolled: boolean;
}

export interface RegisterOriginRequest {
  origin: string;
  display_name: string;
}

export interface Origin {
  id: string;
  origin: string;
  origin_hash: string;
  display_name: string;
}

export interface CreateChallengeRequest {
  user_email: string;
  origin: string;
}

export interface CreateChallengeResponse {
  challenge_id: string;
  expires_in: number;
  origin_display: string;
  origin_url: string;
}

export interface StatusResponse {
  status: ChallengeStatus;
  user_email?: string;
  /** Populated when status === 'approved'. Verify against JWKS. */
  jwt?: string;
}

/** Claims embedded in every ztxbas-issued JWT. */
export interface Claims {
  iss?: string;
  sub?: string;
  aud?: string;
  iat?: number;
  exp?: number;
  email?: string;
  origin?: string;
  challenge_id?: string;
}
