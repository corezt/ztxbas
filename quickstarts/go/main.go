// Command quickstart is the ZTXBAS Go SDK quickstart.
//
// Runs the full enroll → challenge → JWT verify flow against a live
// ztxbas server. Requires an application id + HMAC secret from
// `ztxbas app create` on the server.
//
// Usage:
//
//	export ZTXBAS_URL=https://ztxbas.example.com
//	export ZTXBAS_APP_ID=app_xxx
//	export ZTXBAS_SECRET=hex...
//	export ZTXBAS_USER_EMAIL=alice@example.com
//	export ZTXBAS_ORIGIN=https://app.example.com
//	go run .
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	ztxbas "github.com/corezt/ztxbas/sdk-go"
)

func env(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("required env var %s is unset", k)
	}
	return v
}

func main() {
	baseURL := env("ZTXBAS_URL")
	appID := env("ZTXBAS_APP_ID")
	secret := env("ZTXBAS_SECRET")
	userEmail := env("ZTXBAS_USER_EMAIL")
	origin := env("ZTXBAS_ORIGIN")

	c, err := ztxbas.New(baseURL, appID, secret)
	if err != nil {
		log.Fatalf("new client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// 1. Register the origin (idempotent).
	if _, err := c.RegisterOrigin(ctx, ztxbas.RegisterOriginRequest{
		Origin:      origin,
		DisplayName: "Quickstart",
	}); err != nil {
		log.Fatalf("register origin: %v", err)
	}
	fmt.Printf("[1/4] origin registered: %s\n", origin)

	// 2. Register the user. If they already exist, that's fine — we
	//    just want the user row to be present so challenges succeed.
	if _, err := c.RegisterUser(ctx, ztxbas.RegisterUserRequest{Email: userEmail}); err != nil {
		if !errors.Is(err, ztxbas.ErrConflict) {
			log.Fatalf("register user: %v", err)
		}
		fmt.Printf("[2/4] user already enrolled: %s\n", userEmail)
	} else {
		fmt.Printf("[2/4] user enrolled: %s (check email to complete device setup)\n", userEmail)
	}

	// 3. Create a challenge — this triggers the mobile push.
	ch, err := c.CreateChallenge(ctx, ztxbas.CreateChallengeRequest{
		UserEmail: userEmail,
		Origin:    origin,
	})
	if err != nil {
		log.Fatalf("create challenge: %v", err)
	}
	fmt.Printf("[3/4] challenge %s created (approve on your phone within %ds)\n",
		ch.ChallengeID, ch.ExpiresIn)

	// 4. Poll for approval and verify the returned JWT.
	claims, err := c.PollChallenge(ctx, ch.ChallengeID)
	if err != nil {
		switch {
		case errors.Is(err, ztxbas.ErrChallengeDenied):
			log.Fatalf("[4/4] user denied the request")
		case errors.Is(err, ztxbas.ErrChallengeExpired):
			log.Fatalf("[4/4] challenge expired")
		default:
			log.Fatalf("[4/4] poll: %v", err)
		}
	}
	fmt.Printf("[4/4] ✅ authenticated\n")
	fmt.Printf("      email=%s origin=%s challenge_id=%s exp=%s\n",
		claims.Email, claims.Origin, claims.ChallengeID,
		time.Unix(claims.ExpiresAt, 0).Format(time.RFC3339))
}
