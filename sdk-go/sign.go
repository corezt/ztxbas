package ztxbas

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// HMAC header names — must match the server's middleware constants.
const (
	hdrApplicationID = "X-Application-ID"
	hdrTimestamp     = "X-Timestamp"
	hdrNonce         = "X-Nonce"
	hdrSignature     = "X-Signature"
)

// nonceBytes is the size of the random nonce, in bytes. 16 bytes → 32 hex
// chars — plenty of entropy without bloating headers.
const nonceBytes = 16

// signRequest computes and attaches the four HMAC headers to req. body is
// the exact byte slice that will be sent (empty for GET/DELETE with no
// body). now is passed in so tests can pin time; production callers pass
// time.Now().
//
// Canonical form (single line, no trailing newline):
//
//	METHOD "|" PATH "|" TIMESTAMP "|" NONCE "|" BODY
//
// Kept in one place so callers cannot accidentally use different
// serializations for signing and sending.
func signRequest(req *http.Request, body []byte, appID, secret string, now time.Time, nonce string) {
	ts := strconv.FormatInt(now.Unix(), 10)
	canonical := fmt.Sprintf("%s|%s|%s|%s|%s", req.Method, req.URL.Path, ts, nonce, body)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	sig := hex.EncodeToString(mac.Sum(nil))

	req.Header.Set(hdrApplicationID, appID)
	req.Header.Set(hdrTimestamp, ts)
	req.Header.Set(hdrNonce, nonce)
	req.Header.Set(hdrSignature, sig)
}

// newNonce returns a random hex-encoded nonce. Failure to read from the
// system RNG is fatal for signing, so we return the error unchanged for
// the caller to surface.
func newNonce() (string, error) {
	b := make([]byte, nonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("ztxbas: read random nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}
