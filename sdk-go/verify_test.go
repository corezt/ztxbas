package ztxbas

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testSigner is a tiny in-test ES256 signer that mirrors the server's
// signing scheme. Kept here (not in the SDK) so the SDK itself has no
// signing surface — RPs only ever verify.
type testSigner struct {
	priv *ecdsa.PrivateKey
	kid  string
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &testSigner{priv: priv, kid: "test-kid"}
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (s *testSigner) sign(claims Claims) string {
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": s.kid})
	pl, _ := json.Marshal(claims)
	input := b64u(hdr) + "." + b64u(pl)
	sum := sha256.Sum256([]byte(input))
	r, ss, _ := ecdsa.Sign(rand.Reader, s.priv, sum[:])
	sig := make([]byte, 64)
	rb, sb := r.Bytes(), ss.Bytes()
	copy(sig[32-len(rb):32], rb)
	copy(sig[64-len(sb):64], sb)
	return input + "." + b64u(sig)
}

func (s *testSigner) jwks() []byte {
	pub := s.priv.PublicKey
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	x, y := make([]byte, byteLen), make([]byte, byteLen)
	xb, yb := pub.X.Bytes(), pub.Y.Bytes()
	copy(x[byteLen-len(xb):], xb)
	copy(y[byteLen-len(yb):], yb)
	doc, _ := json.Marshal(map[string]any{
		"keys": []map[string]string{
			{"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": s.kid, "x": b64u(x), "y": b64u(y)},
		},
	})
	return doc
}

func jwksHandler(s *testSigner, hits *int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt64(hits, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(s.jwks())
	})
}

func TestVerifier_Happy(t *testing.T) {
	sig := newTestSigner(t)
	ts := httptest.NewServer(jwksHandler(sig, nil))
	defer ts.Close()

	v, err := NewVerifier(ts.URL, WithExpectedIssuer("https://ztxbas.example.com"))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	token := sig.sign(Claims{
		Issuer: "https://ztxbas.example.com", Subject: "alice@example.com",
		Audience: "https://app.example.com", Email: "alice@example.com",
		Origin: "https://app.example.com", ChallengeID: "c_1",
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	})
	claims, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Email != "alice@example.com" || claims.Origin != "https://app.example.com" {
		t.Errorf("claims: %+v", claims)
	}
}

func TestVerifier_RejectsAlgNone(t *testing.T) {
	sig := newTestSigner(t)
	ts := httptest.NewServer(jwksHandler(sig, nil))
	defer ts.Close()
	v, _ := NewVerifier(ts.URL)

	// Handcraft an `alg: none` token with the same payload — the
	// classic algorithm-substitution attack. Must be rejected.
	hdr, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT", "kid": sig.kid})
	pl, _ := json.Marshal(Claims{Email: "attacker@example.com", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	token := b64u(hdr) + "." + b64u(pl) + "."
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Fatal("expected error on alg=none token")
	} else if !strings.Contains(err.Error(), "alg") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifier_RejectsExpired(t *testing.T) {
	sig := newTestSigner(t)
	ts := httptest.NewServer(jwksHandler(sig, nil))
	defer ts.Close()
	v, _ := NewVerifier(ts.URL)

	token := sig.sign(Claims{
		ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
	})
	_, err := v.Verify(context.Background(), token)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("want expiry error, got %v", err)
	}
}

func TestVerifier_RejectsWrongIssuer(t *testing.T) {
	sig := newTestSigner(t)
	ts := httptest.NewServer(jwksHandler(sig, nil))
	defer ts.Close()
	v, _ := NewVerifier(ts.URL, WithExpectedIssuer("https://legit.example.com"))

	token := sig.sign(Claims{
		Issuer: "https://evil.example.com", ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	_, err := v.Verify(context.Background(), token)
	if err == nil || !strings.Contains(err.Error(), "iss") {
		t.Errorf("want iss mismatch error, got %v", err)
	}
}

func TestVerifier_RejectsTamperedPayload(t *testing.T) {
	sig := newTestSigner(t)
	ts := httptest.NewServer(jwksHandler(sig, nil))
	defer ts.Close()
	v, _ := NewVerifier(ts.URL)

	orig := sig.sign(Claims{
		Email: "alice@example.com", ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	parts := strings.Split(orig, ".")
	// Swap payload for a claim declaring a different email; signature
	// no longer verifies over the new signing input.
	forged, _ := json.Marshal(Claims{
		Email: "attacker@example.com", ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	tampered := parts[0] + "." + b64u(forged) + "." + parts[2]
	if _, err := v.Verify(context.Background(), tampered); err == nil {
		t.Fatal("expected signature error on tampered payload")
	}
}

func TestVerifier_RejectsUnknownKID(t *testing.T) {
	sig := newTestSigner(t)
	sig.kid = "known-kid"
	ts := httptest.NewServer(jwksHandler(sig, nil))
	defer ts.Close()
	v, _ := NewVerifier(ts.URL)

	// Sign with an entirely different key but advertise our known kid?
	// Simpler: sign with a rogue signer that declares a kid the JWKS
	// doesn't publish. Verifier should refuse.
	rogue := newTestSigner(t)
	rogue.kid = "unknown-kid"
	tok := rogue.sign(Claims{ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected error on unknown kid")
	}
}

func TestVerifier_RejectsOffCurvePublicKey(t *testing.T) {
	// Serve a JWKS whose (x, y) is not on P-256 — this catches an
	// invalid-curve attack where the verifier is tricked into doing
	// scalar math on a weak curve.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bad, _ := json.Marshal(map[string]any{
			"keys": []map[string]string{{
				"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "bad",
				"x": b64u(big.NewInt(1).Bytes()), "y": b64u(big.NewInt(1).Bytes()),
			}},
		})
		_, _ = w.Write(bad)
	}))
	defer ts.Close()

	v, _ := NewVerifier(ts.URL)
	// Any well-formed ES256 token will do — verify should fail during
	// JWKS decode, not signature check.
	sig := newTestSigner(t)
	tok := sig.sign(Claims{ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected JWKS decode error for off-curve key")
	}
}

func TestVerifier_JWKSCacheReusesWithinTTL(t *testing.T) {
	sig := newTestSigner(t)
	var hits int64
	ts := httptest.NewServer(jwksHandler(sig, &hits))
	defer ts.Close()

	v, _ := NewVerifier(ts.URL)
	tok := sig.sign(Claims{ExpiresAt: time.Now().Add(time.Hour).Unix()})
	for i := 0; i < 3; i++ {
		if _, err := v.Verify(context.Background(), tok); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
	}
	// First Verify fills the cache; subsequent ones must not refetch.
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Errorf("JWKS fetched %d times, want 1", got)
	}
}

func TestVerifier_MalformedToken(t *testing.T) {
	sig := newTestSigner(t)
	ts := httptest.NewServer(jwksHandler(sig, nil))
	defer ts.Close()
	v, _ := NewVerifier(ts.URL)

	cases := []string{"", "a.b", "a.b.c.d", "not-base64-!!!.also.bad"}
	for _, c := range cases {
		if _, err := v.Verify(context.Background(), c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

// TestVerifier_ClientLazyBuild covers Client.VerifyJWT wiring — it
// should build a Verifier on first use pointing at the client's
// baseURL + /.well-known/jwks.json.
func TestVerifier_ClientLazyBuild(t *testing.T) {
	sig := newTestSigner(t)
	mux := http.NewServeMux()
	mux.Handle("/.well-known/jwks.json", jwksHandler(sig, nil))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	c, err := New(ts.URL, "app_test", "sec")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tok := sig.sign(Claims{Email: "alice@example.com", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	claims, err := c.VerifyJWT(context.Background(), tok)
	if err != nil {
		t.Fatalf("VerifyJWT: %v", err)
	}
	if claims.Email != "alice@example.com" {
		t.Errorf("claims: %+v", claims)
	}
}

// sanity: keep an import used only inside test bodies compiling.
var _ = fmt.Sprintf
