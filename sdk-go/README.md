# ZTXBAS Go SDK

Official Go client for [ZTXBAS](https://corezt.com/docs/ztxbas) — the
Zero-Trust Biometric Authentication Server.

Handles HMAC-SHA256 request signing, JWT verification against the
server's JWKS, and JWKS caching. No dependencies outside the Go
standard library.

## Install

```bash
go get github.com/corezt/ztxbas/sdk-go
```

Requires Go 1.22 or newer.

## Quick start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    ztxbas "github.com/corezt/ztxbas/sdk-go"
)

func main() {
    c, err := ztxbas.New(
        "https://ztxbas.example.com",
        "app_YOUR_APPLICATION_ID",
        "YOUR_HMAC_SECRET_HEX",
    )
    if err != nil { log.Fatal(err) }

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    // 1. One-time: enroll the user (triggers biometric-setup email).
    if _, err := c.RegisterUser(ctx, ztxbas.RegisterUserRequest{
        Email: "alice@example.com",
    }); err != nil {
        log.Fatal(err)
    }

    // 2. One-time: register the origin your app authenticates for.
    if _, err := c.RegisterOrigin(ctx, ztxbas.RegisterOriginRequest{
        Origin:      "https://app.example.com",
        DisplayName: "Example App",
    }); err != nil {
        log.Fatal(err)
    }

    // 3. Every login: create a challenge, poll for approval.
    ch, err := c.CreateChallenge(ctx, ztxbas.CreateChallengeRequest{
        UserEmail: "alice@example.com",
        Origin:    "https://app.example.com",
    })
    if err != nil { log.Fatal(err) }

    claims, err := c.PollChallenge(ctx, ch.ChallengeID)
    if err != nil { log.Fatal(err) }

    fmt.Printf("authenticated: email=%s origin=%s exp=%d\n",
        claims.Email, claims.Origin, claims.ExpiresAt)
}
```

## Error handling

Common failure modes are exposed as sentinel errors — use `errors.Is`:

```go
_, err := c.PollChallenge(ctx, ch.ChallengeID)
switch {
case errors.Is(err, ztxbas.ErrChallengeDenied):
    // User tapped Deny on their phone.
case errors.Is(err, ztxbas.ErrChallengeExpired):
    // Challenge TTL elapsed before approval.
case errors.Is(err, ztxbas.ErrUnregisteredOrigin):
    // The RP asked to authenticate for an origin it never registered.
}
```

The full server response is always available via `*ztxbas.APIError`:

```go
var apiErr *ztxbas.APIError
if errors.As(err, &apiErr) {
    log.Printf("server said %s: %s (HTTP %d)", apiErr.Code, apiErr.Message, apiErr.StatusCode)
}
```

## Verify-only mode

If your architecture receives JWTs from a mobile frontend and does not
otherwise talk to ztxbas, you can skip the `Client` and use the
`Verifier` directly:

```go
v, _ := ztxbas.NewVerifier(
    "https://ztxbas.example.com/.well-known/jwks.json",
    ztxbas.WithExpectedIssuer("https://ztxbas.example.com"),
)
claims, err := v.Verify(ctx, jwtFromMobile)
```

## Concurrency

`Client` and `Verifier` are safe for concurrent use once constructed.
JWKS fetches are serialised inside `Verifier` — the underlying HTTP
call happens at most once per `jwksCacheTTL` (5 minutes) even under
heavy verify load.

## License

Apache 2.0 — see [LICENSE](LICENSE).
