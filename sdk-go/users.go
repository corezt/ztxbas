package ztxbas

import "context"

// RegisterUserRequest is the payload for POST /v1/users.
type RegisterUserRequest struct {
	Email      string `json:"email"`
	ExternalID string `json:"external_id,omitempty"`
}

// User is the shape returned by user endpoints.
type User struct {
	ID         string `json:"id"`
	Email      string `json:"email"`
	ExternalID string `json:"external_id,omitempty"`
	Enrolled   bool   `json:"enrolled"`
}

// RegisterUser creates a user and triggers the enrollment email/QR.
// The returned User has Enrolled=false until the mobile app completes
// device enrollment.
func (c *Client) RegisterUser(ctx context.Context, req RegisterUserRequest) (*User, error) {
	var out User
	if err := c.do(ctx, "POST", "/v1/users", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListUsers returns every user for the caller's tenant.
func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	var out struct {
		Users []User `json:"users"`
	}
	if err := c.do(ctx, "GET", "/v1/users", nil, &out); err != nil {
		return nil, err
	}
	return out.Users, nil
}

// DeregisterUser deletes a user by email. Idempotent: a subsequent call
// for the same email returns ErrNotFound.
func (c *Client) DeregisterUser(ctx context.Context, email string) error {
	body := struct {
		Email string `json:"email"`
	}{Email: email}
	return c.do(ctx, "DELETE", "/v1/users", body, nil)
}
