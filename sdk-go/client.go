package ztxbas

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultTimeout is the per-request HTTP timeout used when the caller does
// not supply their own http.Client. Deliberately conservative — challenge
// creation triggers a mobile push and should complete in a couple of
// hundred ms end-to-end.
const DefaultTimeout = 10 * time.Second

// Option configures the client.
type Option func(*Client)

// WithHTTPClient overrides the default *http.Client. Supply your own if
// you need custom transport (proxies, mTLS, tracing) or a longer timeout.
// The passed client MUST have a non-zero Timeout — leaving it at zero
// invites goroutine leaks on network partitions.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.hc = hc }
}

// WithUserAgent sets the User-Agent header sent on every request. Handy
// for identifying your integration in ztxbas access logs.
func WithUserAgent(ua string) Option {
	return func(c *Client) { c.userAgent = ua }
}

// Client is a ztxbas API client. All methods are safe for concurrent use
// once the client is constructed.
type Client struct {
	baseURL   *url.URL
	appID     string
	secret    string
	hc        *http.Client
	userAgent string

	// verifier lazily built on first VerifyJWT / PollChallenge call.
	verifier *Verifier
}

// New builds a client. baseURL is the ztxbas server root (e.g.
// "https://ztxbas.example.com"). appID and secret are the credentials
// issued by `ztxbas app create` on the server.
func New(baseURL, appID, secret string, opts ...Option) (*Client, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("ztxbas: baseURL required")
	}
	if appID == "" || secret == "" {
		return nil, fmt.Errorf("ztxbas: appID and secret required")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("ztxbas: parse baseURL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("ztxbas: baseURL must include scheme and host")
	}
	// Strip trailing slash so path joins are unambiguous.
	u.Path = strings.TrimRight(u.Path, "/")

	c := &Client{
		baseURL:   u,
		appID:     appID,
		secret:    secret,
		userAgent: "ztxbas-go/1.0",
		hc:        &http.Client{Timeout: DefaultTimeout},
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// AppID returns the configured application id. Useful for logging.
func (c *Client) AppID() string { return c.appID }

// BaseURL returns the server root as a copy. Modifying the returned URL
// does not affect the client.
func (c *Client) BaseURL() *url.URL {
	u := *c.baseURL
	return &u
}

// do performs an authenticated request. path must start with "/".
// If reqBody is non-nil it is marshaled as JSON; the raw bytes are used
// both as the request body and as the fifth field of the HMAC canonical
// form, guaranteeing they cannot drift.
//
// respBody, when non-nil, is populated from a successful JSON response
// body. A 204 with respBody != nil is treated as success and respBody
// is left untouched.
func (c *Client) do(ctx context.Context, method, path string, reqBody, respBody any) error {
	var (
		bodyBytes []byte
		err       error
	)
	if reqBody != nil {
		bodyBytes, err = json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("ztxbas: marshal request: %w", err)
		}
	}

	target := *c.baseURL
	target.Path = c.baseURL.Path + path
	// Reject caller-supplied query strings — the HMAC canonical form
	// signs only the path, so any query would be tamper-visible to a
	// MITM without invalidating the signature. All v1 endpoints take
	// their inputs in body or path segment.
	target.RawQuery = ""

	req, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("ztxbas: build request: %w", err)
	}
	if bodyBytes != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}

	nonce, err := newNonce()
	if err != nil {
		return err
	}
	signRequest(req, bodyBytes, c.appID, c.secret, time.Now(), nonce)

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("ztxbas: http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode >= 400 {
		return decodeErr(resp)
	}
	if respBody == nil {
		return nil
	}
	// Bound the response body — protects against a compromised or
	// misbehaving server flooding us. 1 MiB is generous for anything
	// the v1 API returns.
	lr := io.LimitReader(resp.Body, 1<<20)
	if err := json.NewDecoder(lr).Decode(respBody); err != nil {
		return fmt.Errorf("ztxbas: decode response: %w", err)
	}
	return nil
}

// decodeErr reads and classifies a >=400 response. Keeps a short bound on
// the error body so a broken upstream cannot OOM us.
func decodeErr(resp *http.Response) error {
	var env struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	// Best-effort decode — if the body is not JSON we still return a
	// meaningful error with the status code.
	_ = json.Unmarshal(body, &env)
	msg := env.Message
	if msg == "" {
		msg = strings.TrimSpace(string(body))
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
	}
	return newAPIError(resp.StatusCode, env.Error, msg)
}
