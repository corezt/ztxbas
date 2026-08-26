package ztxbas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestPollChallenge_PollsUntilApproved runs a small state machine on the
// test server: first N calls return pending, the last returns approved
// with a valid JWT. Verifies the poll loop, JWT verification, and
// happy-path claims propagation.
func TestPollChallenge_PollsUntilApproved(t *testing.T) {
	sig := newTestSigner(t)
	var polls int64

	mux := http.NewServeMux()
	mux.Handle("/.well-known/jwks.json", jwksHandler(sig, nil))
	mux.HandleFunc("/v1/auth/status/", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&polls, 1)
		if n < 3 {
			_, _ = w.Write([]byte(`{"status":"pending"}`))
			return
		}
		tok := sig.sign(Claims{
			Email: "alice@example.com", Origin: "https://app.example.com",
			ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		})
		payload, _ := json.Marshal(map[string]any{
			"status": "approved", "user_email": "alice@example.com", "jwt": tok,
		})
		_, _ = w.Write(payload)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Override poll interval to keep the test snappy.
	origInterval := pollTestInterval
	pollTestInterval = 10 * time.Millisecond
	defer func() { pollTestInterval = origInterval }()

	c, err := New(ts.URL, "app_test", "sec")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	claims, err := c.PollChallenge(ctx, "c_1")
	if err != nil {
		t.Fatalf("PollChallenge: %v", err)
	}
	if claims.Email != "alice@example.com" {
		t.Errorf("claims: %+v", claims)
	}
	if polls < 3 {
		t.Errorf("polls=%d, want at least 3", polls)
	}
}

func TestPollChallenge_Denied(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/status/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"denied","user_email":"alice@example.com"}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	c, _ := New(ts.URL, "app_test", "sec")
	_, err := c.PollChallenge(context.Background(), "c_1")
	if !errors.Is(err, ErrChallengeDenied) {
		t.Errorf("want ErrChallengeDenied, got %v", err)
	}
}

func TestPollChallenge_Expired(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/status/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"expired"}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	c, _ := New(ts.URL, "app_test", "sec")
	_, err := c.PollChallenge(context.Background(), "c_1")
	if !errors.Is(err, ErrChallengeExpired) {
		t.Errorf("want ErrChallengeExpired, got %v", err)
	}
}

func TestGetChallengeStatus_EmptyID(t *testing.T) {
	c, _ := New("https://x", "a", "s")
	_, err := c.GetChallengeStatus(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "challenge id") {
		t.Errorf("want id-required error, got %v", err)
	}
}

func TestChallengeStatus_IsTerminal(t *testing.T) {
	tests := map[ChallengeStatus]bool{
		StatusPending: false, StatusApproved: true,
		StatusDenied: true, StatusExpired: true,
	}
	for s, want := range tests {
		if got := s.IsTerminal(); got != want {
			t.Errorf("%s.IsTerminal() = %v, want %v", s, got, want)
		}
	}
}

// sanity: keep fmt import used only in optional debug output.
var _ = fmt.Sprintf
