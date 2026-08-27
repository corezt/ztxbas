# Deploying ZTXBAS

Production recipes for running ZTXBAS. If you're evaluating ZTXBAS on
your laptop and just want a verified JWT in fifteen minutes, follow
the [quickstart](https://corezt.com/docs/ztxbas/getting-started)
instead — it's a single-command LAN demo, not a real deployment.

Three worked examples, in order of increasing operational complexity:

1. [`docker run` — bare Docker](#1-docker-run--bare-docker) — one container, self-terminated TLS.
2. [`docker compose` + Caddy](#2-docker-compose--caddy--single-host-production) — single-host with automatic Let's Encrypt.
3. [Kubernetes](#3-kubernetes--multi-node) — multi-node.

A separate section on [exposing the console](#exposing-the-admin-console)
covers the three supported ways to make the admin UI reachable off-host,
and [TLS certificates](#tls-certificates) covers the Let's Encrypt story
across the three recipes.

---

## Network ports

ZTXBAS listens on three ports. All recipes below map them consistently.

| Port  | Proto | Purpose                                | Public exposure |
|-------|-------|----------------------------------------|-----------------|
| 8443  | TCP   | RP-facing HMAC-authed API              | Yes, via TLS    |
| 8080  | TCP   | Admin console                          | Gated only      |
| 9443  | UDP   | Mobile-app transport                   | Yes, direct     |

The mobile UDP port carries its own crypto (AES-256-GCM envelope +
device-bound ECDSA attestation — see `SECURITY.md`); it does not sit
behind a reverse proxy because standard HTTP/TLS proxies cannot forward
this framing. Publish it directly on the host and let the mobile app
reach it over the internet.

---

## Verifying image signatures

Every published image is cosign-signed. Verify before pulling to
production:

```sh
cosign verify --key https://corezt.com/keys/cosign.pub \
    ghcr.io/corezt/ztxbas:1.0.0
```

The verification key is served at the canonical URL
`https://corezt.com/keys/cosign.pub` and also attached to each GitHub
release page — pin whichever you already trust. Key rotation, if it
ever happens, is announced on both the release page and `SECURITY.md`,
with the old and new keys published alongside each other for one
release cycle.

---

## 1. `docker run` — bare Docker

One container, self-terminated TLS, no reverse proxy. Suitable for
production when a full compose stack is overkill (single-app hosts,
appliance-style deployments). For most other deployments, prefer
[Section 2](#2-docker-compose--caddy--single-host-production) — it
gives you automatic Let's Encrypt via Caddy in front of the console.

**Prep an env file.** Copy the shipped example and fill in your
production values:

```sh
cp env.txt .env
```

Edit `.env` and set at minimum:

```
ZTXBAS_PUBLIC_URL=https://ztxbas.example.com
ZTXBAS_TLS_CERT=/certs/fullchain.pem
ZTXBAS_TLS_KEY=/certs/privkey.pem
ZTXBAS_CONSOLE_LISTEN_ADDR=0.0.0.0:8080
ZTXBAS_ALLOW_INSECURE_CONSOLE=1
ZTXBAS_SMTP_HOST=smtp.example.com
ZTXBAS_SMTP_PORT=587
ZTXBAS_SMTP_USER=your-smtp-user
ZTXBAS_SMTP_PASS=your-smtp-pass
ZTXBAS_SMTP_FROM=ztxbas@example.com
ZTXBAS_TRUSTED_PROXIES=      # empty for bare Docker; no proxy in front
```

`ZTXBAS_PUBLIC_URL` must be the public hostname the RP, the operator,
and enrolled mobile devices all reach the server at. It's baked into
enrollment links, QR codes, and JWT `iss` claims — a wrong value here
silently breaks enrollment.

`ZTXBAS_CONSOLE_LISTEN_ADDR=0.0.0.0:8080` binds the console inside
the container to all interfaces so Docker's port mapping can reach it;
`ZTXBAS_ALLOW_INSECURE_CONSOLE=1` tells the startup fail-safe that
this is intentional. The console still isn't publicly exposed —
`-p 127.0.0.1:8080:8080` in the docker command restricts it to host
loopback; see [exposing the console](#exposing-the-admin-console) for
how to reach it from another machine.

**Run it:**

```sh
docker run -d --restart=unless-stopped --name ztxbas \
  --env-file .env \
  -p 8443:8443 \
  -p 127.0.0.1:8080:8080 \
  -p 9443:9443/udp \
  -v ztxbas-data:/var/lib/ztxbas \
  -v /etc/letsencrypt/live/ztxbas.example.com:/certs:ro \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --read-only --tmpfs /tmp:size=16m \
  ghcr.io/corezt/ztxbas:latest
```

Port bindings, one at a time:

- **`8443/tcp`** on all interfaces — RP-facing HMAC-authed API, TLS
  terminated by ZTXBAS itself using the mounted cert.
- **`8080/tcp`** on loopback — admin console. See
  [exposing the console](#exposing-the-admin-console) for the three
  supported ways to make it reachable off-host (SSH tunnel, VPN, or
  reverse proxy on a separate hostname).
- **`9443/udp`** on all interfaces — mobile transport. Must be
  reachable from enrolled phones over the public internet.

The cert mount assumes Let's Encrypt via `certbot` on the host; adjust
the source path for your issuer. Ownership matters: the container
runs as UID 10001, so the mounted files must be readable by that UID.
Certbot writes `0600 root:root` by default — either loosen to `0644`
after each renewal (Certbot deploy hook) or copy to a directory
world-readable by design.

Grab the breakglass admin password from the logs:

```sh
docker logs ztxbas 2>&1 | grep -i breakglass
```

SSH-tunnel to reach the console:

```sh
ssh -L 8080:localhost:8080 operator@ztxbas.example.com
# then open http://localhost:8080 in your local browser
```

Rotate the breakglass password on first login.

Health probe (from the host, no cert-chain check):

```sh
curl -sk https://localhost:8443/health
# {"status":"ok","version":"1.0.0"}
```

Renewal reminder: whichever cert issuer you use, wire the renewal into
a `docker kill --signal=SIGHUP ztxbas` or `docker restart ztxbas` so
the server picks up the new cert without operator intervention.

---

## 2. `docker compose` + Caddy — single-host production

The compose overlay adds Caddy in front of ztxbas with automatic
Let's Encrypt TLS.

```sh
# 1. Copy the example Caddyfile and edit the hostname + basic-auth hash.
cp deploy/docker/Caddyfile.example ./Caddyfile
docker run --rm caddy caddy hash-password       # generate the bcrypt hash
$EDITOR Caddyfile

# 2. Start the stack.
docker compose \
  -f deploy/docker/docker-compose.yml \
  -f deploy/docker/docker-compose.caddy.yml \
  up -d

# 3. First-boot admin password.
docker compose -f deploy/docker/docker-compose.yml \
  logs ztxbas | grep -i breakglass
```

State (SQLite + JWT signing key) lives in the `ztxbas-data` named
volume. Back it up like any other stateful volume; the whole thing is a
single directory tree that can be `tar`d while the container is stopped.

### What the compose file does

- Binds `ztxbas`'s HTTP ports and `mailhog` to `127.0.0.1` only. Caddy
  is the only HTTP surface exposed on the public interface. The mobile
  UDP port (9443/udp) publishes on all host interfaces because enrolled
  devices reach it directly — Caddy is HTTP-only and cannot proxy it.
- Mounts `ztxbas-data` for persistence and a tmpfs for `/tmp` so the
  root filesystem can stay read-only.
- Sets `ZTXBAS_TRUSTED_PROXIES` to the compose network CIDR so client
  IPs from Caddy reach admin rate limiting and audit logs correctly.

---

## 3. Kubernetes — multi-node

The manifest in `deploy/kubernetes/ztxbas.yaml` is a starting point, not
a Helm chart. Copy it into your cluster's manifest repo and adjust:

- `ZTXBAS_PUBLIC_URL`, `ZTXBAS_SMTP_*` in the ConfigMap.
- `ZTXBAS_SMTP_USER` / `_PASS` in the Secret (rotate to your secret store
  of choice — Sealed Secrets, External Secrets, whatever your cluster uses).
- `spec.resources` under load; the defaults are generous for a small
  tenant but not tuned.

```sh
kubectl apply -f deploy/kubernetes/ztxbas.yaml
kubectl -n ztxbas logs deploy/ztxbas | grep -i breakglass
```

Exposure is deliberately left to the operator — attach an `Ingress` (or
`Gateway` API resource) for the public API, and a *separately gated*
`Ingress` for the console. See below.

**Do not scale replicas > 1.** ZTXBAS v1 uses SQLite; the store is
single-writer. A future minor release may swap in a networked backend;
until then, one pod, one PVC.

---

## Exposing the admin console

The console is a full admin surface: application CRUD, user management,
webhook configuration, audit-log access. Making it reachable off-host
requires a gate. Pick one of the three paths below.

### Path A — reverse proxy with an added gate (recommended)

Console stays bound to loopback inside the container / on the host;
Caddy (or nginx) fronts it on a subdomain with TLS *and* either basic
auth, an IP allowlist, or mTLS. The `Caddyfile.example` shipped with
this repo includes all three as commented options — uncomment the one
that fits.

This is the model the design doc endorses: "console must not be public
without a reverse proxy."

### Path B — direct bind with TLS

Set the following environment variables and let ztxbas terminate TLS
itself:

```
ZTXBAS_CONSOLE_LISTEN_ADDR=:8080
ZTXBAS_TLS_CERT=/path/to/cert.pem
ZTXBAS_TLS_KEY=/path/to/key.pem
```

The startup fail-safe permits this because TLS is configured. There is
no additional gate in this mode — the console's own login + rate
limiting are the only barrier — so it is only appropriate on a
management network where you already trust the callers.

### Path C — escape hatch

```
ZTXBAS_ALLOW_INSECURE_CONSOLE=1
```

Overrides the startup fail-safe and permits a plaintext console on a
non-loopback address. Intended for local development against
`docker-compose up`; do not use this in production.

---

## TLS certificates

Every production deployment needs TLS on at least the public API (8443)
and the console (8080). There are three ways to get a certificate on
these ports, and the right one depends on which recipe you picked
above.

### Compose + Caddy (recommended, LE built in)

Caddy handles Let's Encrypt automatically. All you need is:

- A DNS `A`/`AAAA` record for your hostname pointing at the host.
- Ports `80` and `443` open on the public interface (ACME `HTTP-01` +
  serving TLS).
- Your admin email in the Caddy global block (see `Caddyfile.example`).

Caddy renews in the background well before expiry; ztxbas itself never
sees the certificate — Caddy terminates TLS and forwards plain HTTP on
the compose network. This is the least-fuss LE path and is the model
`Caddyfile.example` is written around.

### Kubernetes (LE via cert-manager on the Ingress)

The manifest ships as an `Ingress`-agnostic `ClusterIP` Service; TLS
terminates at whatever Ingress or Gateway you point at it. The standard
pattern is [cert-manager](https://cert-manager.io/) with a
`ClusterIssuer` for Let's Encrypt and a `tls:` block on the `Ingress`.
A sketch:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ztxbas
  namespace: ztxbas
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
    - hosts: [ztxbas.example.com]
      secretName: ztxbas-tls
  rules:
    - host: ztxbas.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: ztxbas
                port: { name: api }
```

Same for a separately-gated `Ingress` in front of the console.

### Direct-bind TLS on ztxbas itself

If neither Caddy nor an Ingress fits, ztxbas can terminate TLS itself.
Set the file paths as environment variables:

```
ZTXBAS_TLS_CERT=/path/to/fullchain.pem
ZTXBAS_TLS_KEY=/path/to/privkey.pem
```

Both listeners (API + console) share the same cert/key pair.

**Renewal caveat.** ztxbas has no built-in ACME client and does **not**
hot-reload the certificate — it opens the files once at startup. LE-style
renewals (~monthly with 90-day certs) therefore need:

1. An external renewer that writes to the mounted paths — `certbot`,
   `acme.sh`, `lego`, or a sidecar such as `caddy-l4` or `neilpang/acme.sh`.
2. A container restart after each successful renewal to pick up the new
   files. Most orchestrators will do this cleanly with a rolling restart;
   for `docker run` / compose it's a `docker restart ztxbas`.

For deployments that need zero-downtime renewal, the recommended path is
to add a Caddy or nginx sidecar (or move to the compose+Caddy recipe) —
ztxbas's built-in TLS is meant as a "no proxy available" fallback, not
the primary story.

---

## Health and versioning

`GET /health` is unauthenticated and always available:

```json
{"status":"ok","version":"1.0.0"}
```

The version string matches `ztxbas --version` and the
`org.opencontainers.image.version` label on the image.
