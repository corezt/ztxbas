package ztxbas

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

// ChallengeStatus enumerates the four states a challenge can be in.
type ChallengeStatus string

const (
	StatusPending  ChallengeStatus = "pending"
	StatusApproved ChallengeStatus = "approved"
	StatusDenied   ChallengeStatus = "denied"
	StatusExpired  ChallengeStatus = "expired"
)

// IsTerminal reports whether the status will no longer change. The
// server treats approved/denied/expired as sticky.
func (s ChallengeStatus) IsTerminal() bool {
	return s == StatusApproved || s == StatusDenied || s == StatusExpired
}

// CreateChallengeRequest is the payload for POST /v1/auth/challenge.
type CreateChallengeRequest struct {
	UserEmail string `json:"user_email"`
	Origin    string `json:"origin"`
}

// CreateChallengeResponse is the response from POST /v1/auth/challenge.
type CreateChallengeResponse struct {
	ChallengeID   string `json:"challenge_id"`
	ExpiresIn     int    `json:"expires_in"`
	OriginDisplay string `json:"origin_display"`
	OriginURL     string `json:"origin_url"`
}

// StatusResponse is the response from GET /v1/auth/status/{id}.
type StatusResponse struct {
	Status    ChallengeStatus `json:"status"`
	UserEmail string          `json:"user_email,omitempty"`
	// JWT is populated when Status == StatusApproved.
	JWT string `json:"jwt,omitempty"`
}

// CreateChallenge starts a challenge and triggers the mobile push.
func (c *Client) CreateChallenge(ctx context.Context, req CreateChallengeRequest) (*CreateChallengeResponse, error) {
	var out CreateChallengeResponse
	if err := c.do(ctx, "POST", "/v1/auth/challenge", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetChallengeStatus fetches the current state of a challenge exactly once.
func (c *Client) GetChallengeStatus(ctx context.Context, id string) (*StatusResponse, error) {
	if id == "" {
		return nil, fmt.Errorf("ztxbas: challenge id required")
	}
	var out StatusResponse
	if err := c.do(ctx, "GET", "/v1/auth/status/"+url.PathEscape(id), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PollInterval is the default gap between status polls in PollChallenge.
// Balanced for reasonable UX (approvals surface within a second) against
// server load.
const PollInterval = 1 * time.Second

// pollTestInterval is the actual interval used by PollChallenge. Kept as
// a package variable so tests can override without touching production
// callers.
var pollTestInterval = PollInterval

// PollTimeout is the default upper bound on PollChallenge. Matches the
// server-side challenge TTL (5 minutes) with a small buffer trimmed off
// so the caller doesn't race the sweeper.
const PollTimeout = 4*time.Minute + 30*time.Second

// PollChallenge polls GetChallengeStatus until the challenge reaches a
// terminal state, then verifies the JWT and returns its claims. Honours
// ctx cancellation.
//
// Errors map cleanly:
//   - StatusDenied  → ErrChallengeDenied
//   - StatusExpired → ErrChallengeExpired
//   - ctx deadline before terminal state → ErrChallengeTimeout
//
// Use ctx WithTimeout to bound polling; the built-in PollTimeout kicks
// in only if the caller passed context.Background or similar.
func (c *Client) PollChallenge(ctx context.Context, id string) (*Claims, error) {
	deadlineCtx, cancel := context.WithTimeout(ctx, PollTimeout)
	defer cancel()

	ticker := time.NewTicker(pollTestInterval)
	defer ticker.Stop()

	for {
		st, err := c.GetChallengeStatus(ctx, id)
		if err != nil {
			return nil, err
		}
		switch st.Status {
		case StatusApproved:
			// VerifyJWT builds the verifier lazily and caches the JWKS
			// so repeated approvals in the same process don't refetch.
			return c.VerifyJWT(ctx, st.JWT)
		case StatusDenied:
			return nil, ErrChallengeDenied
		case StatusExpired:
			return nil, ErrChallengeExpired
		}
		// Still pending — wait, respecting whichever ctx fires first.
		select {
		case <-deadlineCtx.Done():
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, ErrChallengeTimeout
		case <-ticker.C:
		}
	}
}
