package ztxbas

import (
	"context"
	"net/url"
)

// RegisterOriginRequest is the payload for POST /v1/origins.
type RegisterOriginRequest struct {
	// Origin is a scheme://host[:port] URL. Server-side it is normalized
	// (lowercased host, default ports stripped) before hashing.
	Origin string `json:"origin"`
	// DisplayName is what the user sees on the mobile approval prompt.
	DisplayName string `json:"display_name"`
}

// Origin is the shape returned by origin endpoints.
type Origin struct {
	ID          string `json:"id"`
	Origin      string `json:"origin"`
	OriginHash  string `json:"origin_hash"`
	DisplayName string `json:"display_name"`
}

// RegisterOrigin registers (or updates) an origin for the application.
// The call is idempotent — re-registering the same origin updates its
// display_name without creating a duplicate.
func (c *Client) RegisterOrigin(ctx context.Context, req RegisterOriginRequest) (*Origin, error) {
	var out Origin
	if err := c.do(ctx, "POST", "/v1/origins", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListOrigins returns every origin registered for this application.
func (c *Client) ListOrigins(ctx context.Context) ([]Origin, error) {
	var out struct {
		Origins []Origin `json:"origins"`
	}
	if err := c.do(ctx, "GET", "/v1/origins", nil, &out); err != nil {
		return nil, err
	}
	return out.Origins, nil
}

// DeleteOrigin removes an origin by id.
func (c *Client) DeleteOrigin(ctx context.Context, id string) error {
	// PathEscape guards against a caller passing an id that contains
	// slashes or reserved chars. Server-side ids are opaque, but a
	// defensive escape keeps the HMAC canonical path predictable.
	return c.do(ctx, "DELETE", "/v1/origins/"+url.PathEscape(id), nil, nil)
}
