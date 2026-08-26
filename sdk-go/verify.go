package ztxbas

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Claims are the fields ztxbas includes in every issued JWT.
type Claims struct {
	Issuer      string `json:"iss,omitempty"`
	Subject     string `json:"sub,omitempty"`
	Audience    string `json:"aud,omitempty"`
	IssuedAt    int64  `json:"iat,omitempty"`
	ExpiresAt   int64  `json:"exp,omitempty"`
	Email       string `json:"email,omitempty"`
	Origin      string `json:"origin,omitempty"`
	ChallengeID string `json:"challenge_id,omitempty"`
}

// jwkSet is the minimal JWKS shape we consume. Extra fields are ignored.
type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// jwksCacheTTL is how long a fetched JWKS is trusted before a fresh
// fetch. Short enough to propagate a rotation in a few minutes without
// operator intervention, long enough that spike traffic doesn't hammer
// the JWKS endpoint.
const jwksCacheTTL = 5 * time.Minute

// clockSkew is the leeway allowed on exp/iat/nbf when verifying tokens.
// Same value the server uses for HMAC timestamps, kept in sync so a JWT
// minted at t=now is not rejected by a caller whose clock is a few
// seconds behind.
const clockSkew = 30 * time.Second

// Verifier verifies ztxbas-issued JWTs against a cached JWKS.
//
// Constructed automatically by Client.VerifyJWT on first use, or
// explicitly via NewVerifier for callers who only want the verify side
// of the SDK (e.g. an RP backend that receives JWTs from a mobile
// frontend and doesn't itself call the ztxbas API).
type Verifier struct {
	jwksURL string
	hc      *http.Client

	mu          sync.Mutex
	keys        map[string]*ecdsa.PublicKey // kid → key
	fetchedAt   time.Time
	expectedIss string // optional; if set, JWTs must carry iss==this
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithExpectedIssuer requires that verified JWTs carry the given `iss`.
// Recommended for RPs that talk to a single ztxbas deployment.
func WithExpectedIssuer(iss string) VerifierOption {
	return func(v *Verifier) { v.expectedIss = iss }
}

// WithVerifierHTTPClient overrides the HTTP client used for JWKS fetches.
func WithVerifierHTTPClient(hc *http.Client) VerifierOption {
	return func(v *Verifier) { v.hc = hc }
}

// NewVerifier builds a standalone Verifier from a JWKS URL.
// The typical URL is `<baseURL>/.well-known/jwks.json`.
func NewVerifier(jwksURL string, opts ...VerifierOption) (*Verifier, error) {
	if jwksURL == "" {
		return nil, fmt.Errorf("ztxbas: jwksURL required")
	}
	v := &Verifier{
		jwksURL: jwksURL,
		hc:      &http.Client{Timeout: DefaultTimeout},
	}
	for _, o := range opts {
		o(v)
	}
	return v, nil
}

// VerifyJWT parses and verifies token, returning the claims on success.
// Verification includes signature (ES256/P-256), exp, iat, and — if a
// Verifier was configured with WithExpectedIssuer — iss.
//
// The convenience method on Client lazily builds a Verifier pointing at
// the same base URL, so a call to Client.VerifyJWT is enough for most
// integrations.
func (c *Client) VerifyJWT(ctx context.Context, token string) (*Claims, error) {
	if c.verifier == nil {
		// Race is benign — two goroutines both making a verifier just
		// duplicate the initial JWKS fetch; caching is per-instance so
		// the second will discard its work on next Verify.
		v, err := NewVerifier(c.baseURL.String()+"/.well-known/jwks.json",
			WithVerifierHTTPClient(c.hc))
		if err != nil {
			return nil, err
		}
		c.verifier = v
	}
	return c.verifier.Verify(ctx, token)
}

// Verify parses and verifies token, refreshing the JWKS if needed.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("ztxbas: malformed JWT: want 3 parts, got %d", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("ztxbas: decode JWT header: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return nil, fmt.Errorf("ztxbas: parse JWT header: %w", err)
	}
	// Reject anything other than the algorithm we know. This is the
	// classic "alg=none" / algorithm-substitution defence.
	if hdr.Alg != "ES256" {
		return nil, fmt.Errorf("ztxbas: unsupported JWT alg %q (want ES256)", hdr.Alg)
	}
	if hdr.Kid == "" {
		return nil, errors.New("ztxbas: JWT header missing kid")
	}

	key, err := v.keyForKID(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("ztxbas: decode JWT signature: %w", err)
	}
	// ES256 signature is r||s, each 32 bytes big-endian.
	if len(sigBytes) != 64 {
		return nil, fmt.Errorf("ztxbas: ES256 signature must be 64 bytes, got %d", len(sigBytes))
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))
	if !ecdsa.Verify(key, digest[:], r, s) {
		return nil, errors.New("ztxbas: JWT signature invalid")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("ztxbas: decode JWT payload: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("ztxbas: parse JWT payload: %w", err)
	}

	now := time.Now().Unix()
	if claims.ExpiresAt != 0 && now > claims.ExpiresAt+int64(clockSkew.Seconds()) {
		return nil, fmt.Errorf("ztxbas: JWT expired at %d (now %d)", claims.ExpiresAt, now)
	}
	if claims.IssuedAt != 0 && claims.IssuedAt > now+int64(clockSkew.Seconds()) {
		return nil, fmt.Errorf("ztxbas: JWT iat in the future (%d, now %d)", claims.IssuedAt, now)
	}
	if v.expectedIss != "" && claims.Issuer != v.expectedIss {
		return nil, fmt.Errorf("ztxbas: JWT iss %q does not match expected %q", claims.Issuer, v.expectedIss)
	}
	return &claims, nil
}

// keyForKID returns the cached key for kid, refreshing the JWKS if the
// cache is stale or the kid is unknown.
func (v *Verifier) keyForKID(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	v.mu.Lock()
	if key, ok := v.keys[kid]; ok && time.Since(v.fetchedAt) < jwksCacheTTL {
		v.mu.Unlock()
		return key, nil
	}
	v.mu.Unlock()

	// Fetch outside the lock so a slow JWKS endpoint doesn't stall
	// concurrent verifies waiting on the cache.
	fresh, err := v.fetchJWKS(ctx)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	v.keys = fresh
	v.fetchedAt = time.Now()
	key, ok := v.keys[kid]
	v.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("ztxbas: JWT kid %q not present in JWKS", kid)
	}
	return key, nil
}

// fetchJWKS pulls the JWKS document and decodes it into a kid→key map.
// Bounded by a 64 KiB read cap — legitimate JWKS docs are ≤1 KiB.
func (v *Verifier) fetchJWKS(ctx context.Context) (map[string]*ecdsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("ztxbas: build JWKS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ztxbas: fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ztxbas: JWKS fetch returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("ztxbas: read JWKS: %w", err)
	}
	var set jwkSet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("ztxbas: parse JWKS: %w", err)
	}
	out := make(map[string]*ecdsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" {
			continue // skip anything we can't verify
		}
		pk, err := jwkToECDSA(k)
		if err != nil {
			return nil, fmt.Errorf("ztxbas: decode key %q: %w", k.Kid, err)
		}
		out[k.Kid] = pk
	}
	if len(out) == 0 {
		return nil, errors.New("ztxbas: JWKS has no usable P-256 keys")
	}
	return out, nil
}

// jwkToECDSA rebuilds an ecdsa.PublicKey from a JWK's x/y coordinates.
// Validates that the point is on the P-256 curve — an off-curve key
// would let an attacker forge signatures via invalid-curve attacks.
func jwkToECDSA(k jwk) (*ecdsa.PublicKey, error) {
	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("x: %w", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("y: %w", err)
	}
	curve := elliptic.P256()
	pk := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	if !curve.IsOnCurve(pk.X, pk.Y) {
		return nil, errors.New("public key not on P-256 curve")
	}
	return pk, nil
}
