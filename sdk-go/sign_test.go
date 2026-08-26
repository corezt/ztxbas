package ztxbas

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestSignRequest_KnownVector verifies that the SDK produces the exact
// canonical form and hex digest the server's HMAC middleware expects.
// If this test ever drifts, RPs will start seeing INVALID_SIGNATURE —
// so pinning it here catches accidental changes early.
func TestSignRequest_KnownVector(t *testing.T) {
	const (
		appID  = "app_test"
		secret = "topsecret"
		nonce  = "abc123"
		body   = `{"email":"alice@example.com"}`
		method = "POST"
		path   = "/v1/users"
	)
	// Pinned timestamp: 2024-01-01T00:00:00Z = 1704067200
	now := time.Unix(1704067200, 0)
	ts := "1704067200"

	req, err := http.NewRequest(method, "https://example.com"+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	signRequest(req, []byte(body), appID, secret, now, nonce)

	// Recompute the expected signature the same way the server does.
	canonical := fmt.Sprintf("%s|%s|%s|%s|%s", method, path, ts, nonce, body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	want := hex.EncodeToString(mac.Sum(nil))

	if got := req.Header.Get(hdrSignature); got != want {
		t.Errorf("signature mismatch:\n got  %s\n want %s", got, want)
	}
	if got := req.Header.Get(hdrApplicationID); got != appID {
		t.Errorf("app id header: got %q want %q", got, appID)
	}
	if got := req.Header.Get(hdrTimestamp); got != ts {
		t.Errorf("timestamp header: got %q want %q", got, ts)
	}
	if got := req.Header.Get(hdrNonce); got != nonce {
		t.Errorf("nonce header: got %q want %q", got, nonce)
	}
	// Signature is deterministic HMAC — pin the hex so a canonical
	// form change fails loudly here rather than silently at runtime.
	const wantHex = "92c2aca00ba47b4377aebf3e3af134aff93cf7ad959d05e31a0f0618df9f7d9a"
	if want != wantHex {
		t.Errorf("expected known-vector hex mismatch\n got  %s\n want %s", want, wantHex)
	}
}

func TestSignRequest_EmptyBody(t *testing.T) {
	req, err := http.NewRequest("GET", "https://example.com/v1/users", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	signRequest(req, nil, "app_x", "sec", time.Unix(1000, 0), "n1")
	sig := req.Header.Get(hdrSignature)
	if len(sig) != 64 {
		t.Errorf("signature length = %d, want 64", len(sig))
	}
}

func TestNewNonce_UniqueAndHex(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		n, err := newNonce()
		if err != nil {
			t.Fatalf("newNonce: %v", err)
		}
		if len(n) != nonceBytes*2 {
			t.Fatalf("nonce length = %d, want %d", len(n), nonceBytes*2)
		}
		if _, err := hex.DecodeString(n); err != nil {
			t.Errorf("nonce not hex: %v", err)
		}
		if seen[n] {
			t.Errorf("duplicate nonce %q", n)
		}
		seen[n] = true
	}
}
