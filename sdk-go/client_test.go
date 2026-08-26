package ztxbas

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// verifySig re-runs the server's HMAC check inside the test server so we
// can be certain the SDK is producing headers the real server would
// accept. Any deviation shows up here.
func verifySig(t *testing.T, r *http.Request, secret string) {
	t.Helper()
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytesReader(body))

	ts := r.Header.Get(hdrTimestamp)
	nonce := r.Header.Get(hdrNonce)
	sig := r.Header.Get(hdrSignature)
	appID := r.Header.Get(hdrApplicationID)
	if appID == "" || ts == "" || nonce == "" || sig == "" {
		t.Fatalf("missing HMAC headers: app=%q ts=%q nonce=%q sig=%q", appID, ts, nonce, sig)
	}
	if len(sig) != 64 {
		t.Fatalf("signature length %d, want 64", len(sig))
	}
	if _, err := strconv.ParseInt(ts, 10, 64); err != nil {
		t.Fatalf("timestamp not integer: %v", err)
	}
	canonical := fmt.Sprintf("%s|%s|%s|%s|%s", r.Method, r.URL.Path, ts, nonce, body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	want := hex.EncodeToString(mac.Sum(nil))
	if want != sig {
		t.Fatalf("signature mismatch\n canonical: %s\n want: %s\n got:  %s", canonical, want, sig)
	}
}

// bytesReader avoids pulling bytes into imports; tests are cleaner with
// this helper than an extra import block per file.
func bytesReader(b []byte) io.Reader {
	return &readerFromBytes{b: b}
}

type readerFromBytes struct {
	b []byte
	i int
}

func (r *readerFromBytes) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

func newTestClient(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	c, err := New(ts.URL, "app_test", "secret_test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, ts
}

func TestClient_RegisterUser(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/users" || r.Method != "POST" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		verifySig(t, r, "secret_test")
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("missing Content-Type")
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"u_1","email":"alice@example.com","enrolled":false}`))
	}))

	u, err := c.RegisterUser(context.Background(), RegisterUserRequest{Email: "alice@example.com"})
	if err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}
	if u.ID != "u_1" || u.Email != "alice@example.com" || u.Enrolled {
		t.Errorf("unexpected user %+v", u)
	}
}

func TestClient_ListUsers(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/users" || r.Method != "GET" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		verifySig(t, r, "secret_test")
		_, _ = w.Write([]byte(`{"users":[{"id":"u_1","email":"a@x","enrolled":true}]}`))
	}))
	list, err := c.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(list) != 1 || list[0].Email != "a@x" {
		t.Errorf("unexpected list: %+v", list)
	}
}

func TestClient_DeregisterUser_NoContent(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verifySig(t, r, "secret_test")
		w.WriteHeader(http.StatusNoContent)
	}))
	if err := c.DeregisterUser(context.Background(), "alice@example.com"); err != nil {
		t.Errorf("DeregisterUser: %v", err)
	}
}

func TestClient_RegisterOrigin(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verifySig(t, r, "secret_test")
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["origin"] != "https://app.example.com" {
			t.Errorf("body: %v", body)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"o_1","origin":"https://app.example.com","origin_hash":"abc","display_name":"App"}`))
	}))
	o, err := c.RegisterOrigin(context.Background(), RegisterOriginRequest{
		Origin: "https://app.example.com", DisplayName: "App",
	})
	if err != nil {
		t.Fatalf("RegisterOrigin: %v", err)
	}
	if o.ID != "o_1" {
		t.Errorf("id: %+v", o)
	}
}

func TestClient_DeleteOrigin_PathEscape(t *testing.T) {
	var seenPath string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verifySig(t, r, "secret_test")
		seenPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	if err := c.DeleteOrigin(context.Background(), "o_1"); err != nil {
		t.Fatalf("DeleteOrigin: %v", err)
	}
	if seenPath != "/v1/origins/o_1" {
		t.Errorf("path: %q", seenPath)
	}
}

func TestClient_CreateChallenge(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verifySig(t, r, "secret_test")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"challenge_id":"c_1","expires_in":300,"origin_display":"App","origin_url":"https://app.example.com"}`))
	}))
	ch, err := c.CreateChallenge(context.Background(), CreateChallengeRequest{
		UserEmail: "a@x", Origin: "https://app.example.com",
	})
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	if ch.ChallengeID != "c_1" || ch.ExpiresIn != 300 {
		t.Errorf("resp: %+v", ch)
	}
}

func TestClient_ErrorMapping(t *testing.T) {
	tests := []struct {
		status  int
		code    string
		wantErr error
	}{
		{http.StatusUnauthorized, "INVALID_SIGNATURE", ErrUnauthorized},
		{http.StatusNotFound, "USER_NOT_FOUND", ErrNotFound},
		{http.StatusConflict, "DUPLICATE_EMAIL", ErrConflict},
		{http.StatusForbidden, "UNREGISTERED_ORIGIN", ErrUnregisteredOrigin},
	}
	for _, tc := range tests {
		t.Run(tc.code, func(t *testing.T) {
			c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprintf(w, `{"error":%q,"message":"boom"}`, tc.code)
			}))
			_, err := c.ListUsers(context.Background())
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("errors.Is(_, %v) = false; got %v", tc.wantErr, err)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Errorf("errors.As APIError = false; got %v", err)
			} else if apiErr.Code != tc.code {
				t.Errorf("code %q, want %q", apiErr.Code, tc.code)
			}
		})
	}
}

func TestClient_TimestampWithinSkew(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts, _ := strconv.ParseInt(r.Header.Get(hdrTimestamp), 10, 64)
		if diff := time.Since(time.Unix(ts, 0)); diff < 0 || diff > 5*time.Second {
			t.Errorf("timestamp drift %v", diff)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	_ = c.DeregisterUser(context.Background(), "a@x")
}

func TestNew_Validation(t *testing.T) {
	if _, err := New("", "a", "s"); err == nil {
		t.Error("empty baseURL should error")
	}
	if _, err := New("https://x", "", "s"); err == nil {
		t.Error("empty appID should error")
	}
	if _, err := New("https://x", "a", ""); err == nil {
		t.Error("empty secret should error")
	}
	if _, err := New("not-a-url", "a", "s"); err == nil {
		t.Error("bare host without scheme should error")
	}
}
