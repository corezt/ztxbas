---
sidebar_position: 1
title: Go SDK
---

# Go SDK

The Go SDK is the flagship — hand-written, zero dependencies outside
the standard library, tested against a pinned known-vector for HMAC
signing and a full suite of JWT edge cases.

## Install

```bash
go get github.com/corezt/ztxbas/sdk-go
```

Requires Go 1.22 or newer.

## Import

```go
import ztxbas "github.com/corezt/ztxbas/sdk-go"
```

## Minimal end-to-end

```go
c, err := ztxbas.New(
    "https://ztxbas.example.com",
    "app_YOUR_APPLICATION_ID",
    "YOUR_HMAC_SECRET_HEX",
)
if err != nil { log.Fatal(err) }

ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

_, _ = c.RegisterUser(ctx, ztxbas.RegisterUserRequest{Email: "alice@example.com"})
_, _ = c.RegisterOrigin(ctx, ztxbas.RegisterOriginRequest{
    Origin: "https://app.example.com", DisplayName: "Example App",
})
ch, _ := c.CreateChallenge(ctx, ztxbas.CreateChallengeRequest{
    UserEmail: "alice@example.com", Origin: "https://app.example.com",
})
claims, err := c.PollChallenge(ctx, ch.ChallengeID)
if err != nil { log.Fatal(err) }
fmt.Println(claims.Email, claims.Origin)
```

## Errors as sentinels

Match against sentinels with `errors.Is`:

```go
_, err := c.PollChallenge(ctx, id)
switch {
case errors.Is(err, ztxbas.ErrChallengeDenied):    // user tapped Deny
case errors.Is(err, ztxbas.ErrChallengeExpired):   // TTL elapsed
case errors.Is(err, ztxbas.ErrUnregisteredOrigin): // programmer error
}
```

For the raw server error envelope:

```go
var apiErr *ztxbas.APIError
if errors.As(err, &apiErr) {
    log.Printf("code=%s status=%d message=%s", apiErr.Code, apiErr.StatusCode, apiErr.Message)
}
```

## Verify-only mode

If your backend receives JWTs from a mobile frontend and doesn't
itself talk to ZTXBAS, skip the client:

```go
v, _ := ztxbas.NewVerifier(
    "https://ztxbas.example.com/.well-known/jwks.json",
    ztxbas.WithExpectedIssuer("https://ztxbas.example.com"),
)
claims, err := v.Verify(ctx, jwtFromMobile)
```

## Repo and reference

- Source: [`sdk-go/`](https://github.com/corezt/ztxbas/tree/main/sdk-go)
- godoc: `github.com/corezt/ztxbas/sdk-go`
- Quickstart: [`quickstarts/go/`](https://github.com/corezt/ztxbas/tree/main/quickstarts/go)
