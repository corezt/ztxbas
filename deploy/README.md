# Deploying ZTXBAS

Three worked examples, in order of increasing production-readiness:

1. [`docker run`](#1-docker-run--kicking-the-tires) — kicking the tires.
2. [`docker compose` + Caddy](#2-docker-compose--caddy--single-host-production) — single-host production.
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

## 1. `docker run` — kicking the tires

Ten-minute path from a clean host to a working instance. No TLS — this
is for smoke tests only. A named volume keeps the SQLite DB and the JWT
signing key across container restarts; drop the `-v` line for a purely
ephemeral run.

```sh
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
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --read-only --tmpfs /tmp:size=16m \
  ghcr.io/corezt/ztxbas:latest
```

`ZTXBAS_ALLOW_INSECURE_CONSOLE=1` acknowledges to the startup fail-safe
that binding the console to `0.0.0.0` without TLS is intentional — safe
here because the HTTP ports publish on loopback only. The mobile UDP
port (9443) publishes on all host interfaces because enrolled devices
need to reach it from off-host; drop the `9443` mapping for a pure
API-only smoke test.

Grab the breakglass admin password from the logs:

```sh
docker logs <container-id> 2>&1 | grep -i breakglass
```

Log in at <http://127.0.0.1:8080>, rotate the password.

Health probe:

```sh
curl -s http://127.0.0.1:8443/health
# {"status":"ok","version":"1.0.0"}
```

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
