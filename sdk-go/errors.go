package ztxbas

import (
	"errors"
	"fmt"
	"net/http"
)

// Sentinel errors callers can match with errors.Is. Anything not covered
// here surfaces as an *APIError with the server's `error` / `message`
// fields preserved.
var (
	ErrUnauthorized       = errors.New("ztxbas: unauthorized (HMAC signature rejected)")
	ErrNotFound           = errors.New("ztxbas: resource not found")
	ErrConflict           = errors.New("ztxbas: resource already exists")
	ErrUnregisteredOrigin = errors.New("ztxbas: origin not registered for this application")
	ErrChallengeDenied    = errors.New("ztxbas: challenge denied by user")
	ErrChallengeExpired   = errors.New("ztxbas: challenge expired")
	ErrChallengeTimeout   = errors.New("ztxbas: polling timed out before challenge reached a terminal state")
)

// APIError is the structured error the server returns for any 4xx/5xx.
// It always wraps a sentinel error where a well-known code exists, so
// callers can errors.Is against ErrNotFound et al. without loss of detail.
type APIError struct {
	StatusCode int    // HTTP status
	Code       string // machine-readable code from server (e.g. UNREGISTERED_ORIGIN)
	Message    string // human-readable message

	inner error
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("ztxbas: %s [%d %s]: %s", e.Code, e.StatusCode, http.StatusText(e.StatusCode), e.Message)
	}
	return fmt.Sprintf("ztxbas: HTTP %d %s: %s", e.StatusCode, http.StatusText(e.StatusCode), e.Message)
}

func (e *APIError) Unwrap() error { return e.inner }

// newAPIError builds an APIError and links a sentinel where applicable
// so errors.Is works as expected.
func newAPIError(status int, code, msg string) *APIError {
	e := &APIError{StatusCode: status, Code: code, Message: msg}
	switch {
	case status == http.StatusUnauthorized:
		e.inner = ErrUnauthorized
	case status == http.StatusNotFound:
		e.inner = ErrNotFound
	case status == http.StatusConflict:
		e.inner = ErrConflict
	case code == "UNREGISTERED_ORIGIN":
		e.inner = ErrUnregisteredOrigin
	}
	return e
}
