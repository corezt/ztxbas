// Package ztxbas is the official Go client for ZTXBAS — the Zero-Trust
// Biometric Authentication Server.
//
// Typical usage:
//
//	c, err := ztxbas.New("https://ztxbas.example.com", "app_123", "hexsecret")
//	if err != nil { return err }
//
//	// One-time enrollment.
//	if _, err := c.RegisterUser(ctx, ztxbas.RegisterUserRequest{Email: "alice@example.com"}); err != nil {
//	    return err
//	}
//
//	// Every login.
//	ch, err := c.CreateChallenge(ctx, ztxbas.CreateChallengeRequest{
//	    UserEmail: "alice@example.com",
//	    Origin:    "https://app.example.com",
//	})
//	if err != nil { return err }
//
//	claims, err := c.PollChallenge(ctx, ch.ChallengeID)
//	if err != nil { return err }
//	// claims.Email is now a trusted, origin-bound identity.
//
// The client handles HMAC-SHA256 request signing, JWT verification
// against the server's JWKS, and JWKS caching. It has no dependencies
// outside the Go standard library.
package ztxbas
