# Origin binding

Origin binding is the single most important thing ZTXBAS does. It's
why a phished user cannot approve an attacker's login.

## The problem it solves

Traditional push-based MFA looks like this:

1. User types their password on `paypal-secure.example.com` (a phishing site).
2. Attacker forwards the credentials to the real `paypal.com`.
3. Real PayPal sends a push to the user's phone: "Approve login?"
4. User taps Approve because they just tried to log in.
5. Attacker is now inside.

The phone doesn't know which site the login attempt came from. The
approval prompt has no origin to display, so the user has nothing to
compare against.

## What ZTXBAS does

Every challenge is bound to an origin at creation time, and the origin
is what the user sees on their phone.

```
┌──────────────────────────────────────────┐
│   Sign in to                             │
│                                          │
│   ┌────────────────────────────────┐     │
│   │  🔒  Example App               │     │
│   │      https://app.example.com   │     │
│   └────────────────────────────────┘     │
│                                          │
│      [ Deny ]        [ Approve ]         │
└──────────────────────────────────────────┘
```

The RP can only create a challenge for an origin that was previously
registered via `POST /v1/origins`. A challenge for
`https://phishing.example.com` fails with 403 `UNREGISTERED_ORIGIN`
because no honest operator ever registered that origin.

## The three checks, in order

When you call `POST /v1/auth/challenge`, ZTXBAS runs three checks:

1. **HMAC verifies.** The request is signed by an application secret.
   A phishing site doesn't have your secret.
2. **The origin is registered.** The RP-declared origin exists in
   `origins` for this application. A phishing site couldn't have
   registered its own origin under your application because it has no
   admin access.
3. **The user exists.** Prevents challenge storms against enumeration.

Only then does the mobile push fire.

## Origin normalization

Origins are normalized before comparison:

- Scheme and host are lowercased.
- Default ports are stripped (`:443` for https, `:80` for http).
- Trailing paths are rejected — an origin is
  `scheme://host[:port]`, never with a path.

This means `HTTPS://APP.example.com:443` and `https://app.example.com`
are the same origin. The canonical form is what gets bound into the
challenge and echoed back in the JWT's `origin` claim.

## The JWT's `origin` claim

After approval, the JWT carries the canonical origin in its `origin`
claim. Your backend can (and should) cross-check that this matches the
origin you expected:

```go
if claims.Origin != "https://app.example.com" {
    return errors.New("token issued for a different origin")
}
```

This closes a subtle attack where an attacker replays a JWT they
obtained legitimately (for their own account) at a different origin
they control.

## Related

- [HMAC signing](./hmac-signing) — how the RP proves it's really the RP.
- [JWT verification](./jwt-verification) — how you prove the assertion is real.
