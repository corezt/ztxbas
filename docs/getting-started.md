---
sidebar_position: 2
title: Getting started
---

# Getting started

This page takes you from zero to a verified JWT in about fifteen
minutes. It uses the `docker run` smoke-test path — no TLS, ports on
loopback, ephemeral SMTP — which is enough to see the whole flow end to
end. For a real deployment (compose + Caddy, or Kubernetes),
follow [`deploy/README.md`](https://github.com/corezt/ztxbas/blob/main/deploy/README.md)
after you've kicked the tires here.

## 1. Run ZTXBAS

ZTXBAS ships as a signed container image at `ghcr.io/corezt/ztxbas`.
The image is signed with cosign; verifying the signature is optional
for a smoke test but recommended before any real install
(see [deploy/README.md](https://github.com/corezt/ztxbas/blob/main/deploy/README.md#signed-release-artifacts)).

You'll need an SMTP relay reachable from the container — the enrollment
step in section 3 sends a link by email. For a quick local run, a
throwaway [MailHog](https://github.com/mailhog/MailHog) or
[Mailpit](https://mailpit.axllent.org/) container works fine.

```bash
docker run --rm \
  -p 127.0.0.1:8443:8443 \
  -p 127.0.0.1:8080:8080 \
  -p 9443:9443/udp \
  -v ztxbas-data:/var/lib/ztxbas \
  -e ZTXBAS_PUBLIC_URL=http://127.0.0.1:8443 \
  -e ZTXBAS_SMTP_HOST=smtp.example.com \
  -e ZTXBAS_SMTP_PORT=587 \
  -e ZTXBAS_SMTP_USER=user \
  -e ZTXBAS_SMTP_PASS=pass \
  -e ZTXBAS_SMTP_FROM=ztxbas@example.com \
  -e ZTXBAS_CONSOLE_LISTEN_ADDR=0.0.0.0:8080 \
  -e ZTXBAS_ALLOW_INSECURE_CONSOLE=1 \
  --name ztxbas \
  --cap-drop ALL --security-opt no-new-privileges \
  --read-only --tmpfs /tmp:size=16m \
  ghcr.io/corezt/ztxbas:latest
```

Three ports are involved:

| Port      | Purpose                                            |
|-----------|----------------------------------------------------|
| 8443/tcp  | RP-facing API — your app / SDK calls this.         |
| 8080/tcp  | Admin console (SPA + `/admin/api/v1`).             |
| 9443/udp  | Mobile-app transport. **Publish directly** — this  |
|           | is a custom framed protocol; HTTP proxies can't    |
|           | forward it.                                        |

For the smoke test the HTTP ports bind to loopback, so
`ZTXBAS_ALLOW_INSECURE_CONSOLE=1` is safe. The mobile UDP port publishes
on all interfaces because your phone needs to reach it — if you're only
testing the API surface (curl, SDKs) without a phone, drop that
mapping.

Health check:

```bash
curl -s http://127.0.0.1:8443/health
# {"status":"ok","version":"1.0.0"}
```

## 2. Log in and create an application

An **application** is your RP. It gets an id and an HMAC secret that
you sign API requests with.

Grab the first-boot admin password from the container logs:

```bash
docker logs ztxbas 2>&1 | grep -i breakglass
```

Open <http://127.0.0.1:8080>, log in with that password, and set a
proper one when prompted (the breakglass password is single-use).

From the console: **Applications → New application**, give it a name,
and you'll be shown the app id and HMAC secret **once**. Save both —
the secret isn't recoverable.

Prefer the CLI? The same thing works via `docker exec`:

```bash
docker exec ztxbas ztxbas app create "Quickstart App"
# Application created.
#   ID:           app_a1b2c3d4e5
#   Name:         Quickstart App
#   HMAC secret:  5f6e7d8c9b0a...
```

## 3. Register an origin

An **origin** is a `scheme://host[:port]` your app authenticates from.
It's shown to the user on their phone during approval — this is the
anti-phishing anchor.

Easiest path: in the console, open the application you just created and
add the origin (`https://app.example.com`) with a display name (e.g.
`Example App`). The display name is what the user sees on their phone.

If you'd rather do it from code, the SDKs handle the HMAC signing for
you — signing by hand is fiddly (see
[HMAC signing](./concepts/hmac-signing) for the canonical form).

## 4. Register a user and challenge

Pick your language. All three run the same flow: register user →
create challenge → poll → get a verified JWT back.

### Go

```go
c, _ := ztxbas.New("http://127.0.0.1:8443", "app_a1b2c3d4e5", "5f6e7d8c9b0a...")
_, _ = c.RegisterUser(ctx, ztxbas.RegisterUserRequest{Email: "alice@example.com"})
ch, _ := c.CreateChallenge(ctx, ztxbas.CreateChallengeRequest{
    UserEmail: "alice@example.com",
    Origin:    "https://app.example.com",
})
claims, _ := c.PollChallenge(ctx, ch.ChallengeID)
fmt.Println(claims.Email, claims.Origin)
```

### Node/TypeScript

```ts
const c = new Client("http://127.0.0.1:8443", "app_a1b2c3d4e5", "5f6e7d8c9b0a...");
await c.registerUser({ email: "alice@example.com" });
const ch = await c.createChallenge({
  user_email: "alice@example.com",
  origin: "https://app.example.com",
});
const claims = await c.pollChallenge(ch.challenge_id);
console.log(claims.email, claims.origin);
```

### Python

```python
c = Client("http://127.0.0.1:8443", "app_a1b2c3d4e5", "5f6e7d8c9b0a...")
c.register_user("alice@example.com")
ch = c.create_challenge("alice@example.com", "https://app.example.com")
claims = c.poll_challenge(ch["challenge_id"])
print(claims.email, claims.origin)
```

For a real deployment, swap `http://127.0.0.1:8443` for your TLS
front-end (`https://ztxbas.example.com`).

## 5. What just happened

1. The user got an enrollment email; they installed the CoreZT
   authenticator app and paired their phone. The app talks to ztxbas
   over the UDP port you exposed on 9443.
2. Your call to `create_challenge` pushed a biometric prompt to their
   device showing "Example App" (the origin's display name).
3. They approved with fingerprint / face.
4. ZTXBAS minted an ES256 JWT bound to `alice@example.com` and
   `https://app.example.com`.
5. Your SDK fetched the JWKS from `/.well-known/jwks.json`, verified
   the signature, and returned the claims.

## Ready-to-run quickstarts

Full end-to-end demos in each language:

- [Go quickstart](https://github.com/corezt/ztxbas/tree/main/quickstarts/go)
- [Node quickstart](https://github.com/corezt/ztxbas/tree/main/quickstarts/node)
- [Python quickstart](https://github.com/corezt/ztxbas/tree/main/quickstarts/python)

Each is about 30 lines and exercises the same flow you see above.

## Next steps

- Understand what makes the origin binding safe: [Origin binding](./concepts/origin-binding).
- Ship to prod (compose + Caddy, or Kubernetes): [`deploy/README.md`](https://github.com/corezt/ztxbas/blob/main/deploy/README.md).
- Harden the install: [Hardening guide](./guides/hardening).
- Pick a stack: [Go SDK](./sdks/go), [Node SDK](./sdks/node), [Python SDK](./sdks/python).
