# Hardening guide

This page covers the ztxbas-specific settings that matter for a
production install. General Linux hardening (kernel sysctls, SSH,
fail2ban, host firewall baseline) is out of scope — the
[CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) and the
Ubuntu Server hardening guide cover that ground better than we can.

If you are still kicking the tires, use the `docker run` smoke test in
[Getting started](../getting-started) first — this page assumes you're
about to put ztxbas somewhere real users can reach.

## 1. Threat model

ztxbas is designed to resist:

- **Phishing.** Origin binding + the display on the phone means an
  approved auth cannot be replayed against a different origin.
- **Replay on the wire.** All API requests are HMAC-SHA256 signed with
  a bounded-skew timestamp and a nonce. TLS provides the outer channel.
- **RP impersonation.** Every application has its own HMAC secret; a
  leaked secret only compromises that one application.
- **Stolen approval tokens.** JWTs are short-lived, ES256-signed,
  bound to `sub`, `aud` (application id), and `origin`.

ztxbas does **not** protect against:

- A compromised admin host — anyone with a session cookie or the
  admin password can create applications and rotate secrets. Treat
  console access like root.
- A malicious RP — a relying party that lies about its origin can only
  phish its own users, but it can do that.
- An unlocked, enrolled phone in an attacker's hand. Device-level
  attestation defends against tampering, not against a legitimate user
  handing over an unlocked device.
- Anything happening below the container (host kernel, hypervisor,
  physical access to the disk holding the SQLite file).

## 2. Verify the image before you run it

Every release is signed with cosign. Verify before pulling to
production:

```bash
# Get the public key once (pin both URLs; either is fine).
curl -sO https://corezt.com/keys/cosign.pub

# Verify the tag you're about to run.
cosign verify --key cosign.pub ghcr.io/corezt/ztxbas:1.0.0
```

Then pin to the digest, not the tag, in your deployment manifests:

```bash
docker pull ghcr.io/corezt/ztxbas:1.0.0
docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/corezt/ztxbas:1.0.0
# ghcr.io/corezt/ztxbas@sha256:...
```

Digests are immutable; tags are not. If our infrastructure is ever
compromised, a tag can be repointed. A digest cannot.

**Key rotation.** If the signing key is ever rotated, we publish the
new key alongside the old one for one full release cycle so integrators
have time to migrate. Announcements go on the release page and in
`SECURITY.md`. Keyless-with-OIDC signing is on the roadmap once
GitHub Actions is enabled; until then, cosign runs from the release
manager's workstation.

## 3. Container runtime settings

The stock `docker-compose.yml` ships with the settings below. If you
copy them into a different orchestrator, keep them intact.

```yaml
cap_drop: [ALL]
security_opt:
  - no-new-privileges:true
read_only: true
tmpfs:
  - /tmp:size=16m
user: "10001:10001"       # non-root in the image
```

Why each one:

- **`cap_drop: ALL`** — ztxbas is a userspace HTTP + UDP server. It
  needs no capabilities. If a bind fails, the port is privileged
  (< 1024); use the mapped 8443/8080/9443 defaults or bind on the host
  with a reverse proxy rather than granting `CAP_NET_BIND_SERVICE`.
- **`no-new-privileges`** — prevents setuid binaries in the image from
  escalating. There aren't any, but future dependencies could add one.
- **`read_only: true` + tmpfs /tmp`** — the container writes only to
  `/var/lib/ztxbas` (the data volume) and `/tmp` (transient). A
  read-only root filesystem defeats a large class of persistence
  techniques cheaply.
- **Non-root user** — the image runs as uid/gid 10001. The data
  directory is created 0700 on first boot; do not `chown -R` it to
  root "to fix a permissions error." That error means the volume was
  created by a different user and needs to be fixed at the host level.

Resource limits are worth adding on top of the security posture:

```yaml
deploy:
  resources:
    limits:
      memory: 512M
      pids: 200
```

A single instance handles hundreds of concurrent challenges well under
that ceiling; the limit exists to contain runaway conditions, not to
size the workload.

## 4. Network exposure

ztxbas listens on three ports. They have very different exposure
profiles.

| Port      | Protocol | What it carries                       | Public exposure                   |
|-----------|----------|---------------------------------------|-----------------------------------|
| 8443/tcp  | HTTPS    | RP-facing HMAC-authed API             | Public, TLS-terminated            |
| 8080/tcp  | HTTP(S)  | Admin console (SPA + `/admin/api/v1`) | **Never** on the open internet    |
| 9443/udp  | AES-GCM  | Mobile app transport                  | Public, direct-published          |

The mobile UDP port carries its own crypto (AES-256-GCM envelope +
device-bound ECDSA attestation — see `SECURITY.md`); it does not sit
behind a reverse proxy because standard HTTP proxies cannot forward
this framing. Publish it directly on the host and open UDP/9443 in
the firewall.

Minimal `ufw` recipe on the host:

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'ssh'
ufw allow 443/tcp comment 'caddy → ztxbas 8443'
ufw allow 9443/udp comment 'ztxbas mobile transport'
# 8080 is NOT opened — see section 6.
ufw enable
```

## 5. TLS

ztxbas has three supported TLS shapes. Pick one.

**Recommended: TLS-terminating reverse proxy (Caddy).** Caddy handles
ACME automatically, so certificate renewal is invisible. The stock
`docker-compose.caddy.yml` overlay wires this up. ztxbas serves plain
HTTP on the loopback side; Caddy handles TLS on the public side.

**Direct-bind TLS.** Set `ZTXBAS_TLS_CERT` and `ZTXBAS_TLS_KEY` to
mounted PEM paths. ztxbas reads them once at startup — there is **no
built-in ACME and no hot reload**. A cert-renewer (external `certbot`,
Let's Encrypt agent, whatever) that writes fresh files must be paired
with a container restart when the files change. In practice this
means a nightly `docker restart ztxbas` on the renewal cadence; the
restart is a few seconds of unavailability.

**TLS-terminating cloud load balancer.** Same shape as Caddy but the
LB owns the cert. Make sure the LB adds `X-Forwarded-For` / `-Proto`
headers and read section 7 on trusted proxies.

TLS 1.2+ only. TLS 1.3 preferred. If you terminate at Caddy, both are
the default. If you terminate at a load balancer, disable everything
below TLS 1.2 explicitly.

## 6. Exposing the admin console safely

The admin console at port 8080 is the single most sensitive surface on
your ztxbas instance. It has no MFA out of the box (though see the
biometric-protection option below). Three supported paths, in
decreasing order of safety:

**A. Loopback + SSH tunnel (safest).** Leave `ZTXBAS_CONSOLE_LISTEN_ADDR`
at its default (`127.0.0.1:8080`). Reach it from your laptop with:

```bash
ssh -L 8080:127.0.0.1:8080 ztxbas.example.com
# then open http://127.0.0.1:8080 in your browser
```

Nothing changes at the ztxbas config. The console is unreachable from
the internet by design. This is the default and the recommendation.

**B. Reverse proxy with basic-auth + IP allowlist.** Expose the
console under a hostname like `console.ztxbas.example.com` behind
Caddy, with basic auth in front of it *and* an IP allowlist for your
office / VPN range. See `deploy/docker/Caddyfile.example`. This is
appropriate for teams; do not use basic-auth alone as your only
guard.

**C. mTLS at the reverse proxy.** For high-value deployments, front
the console with a Caddy or nginx that requires a client certificate.
Same allowlist story on top.

**The console fail-safe.** ztxbas refuses to start if
`ZTXBAS_CONSOLE_LISTEN_ADDR` is bound to a non-loopback address
without TLS. Override with `ZTXBAS_ALLOW_INSECURE_CONSOLE=1` **only**
when:

- The bind address is loopback but Docker's port publishing maps it to
  a private / loopback-only host address (this is the case in the
  stock recipes), **or**
- You are running behind a reverse proxy that itself terminates TLS
  and you have verified the proxy strips inbound
  `Authorization` / cookie headers from unauthenticated paths.

Never set `ZTXBAS_ALLOW_INSECURE_CONSOLE=1` on a container whose
console port is published to `0.0.0.0` without a proxy in front.

## 7. Reverse proxy hygiene

If ztxbas sits behind Caddy / nginx / a load balancer, tell it who to
trust for client IPs:

```
ZTXBAS_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12
```

Effects:

- Rate limits (per-IP on admin login attempts) work against the real
  client, not the proxy.
- Audit-log source IPs reflect the real caller.
- Without this, ztxbas ignores `X-Forwarded-For` — a spoofed header
  from an untrusted peer would let an attacker forge client IPs.

At the proxy, **strip any inbound `X-Forwarded-*` headers before
setting your own**. Otherwise an internet client can lie about their
`X-Forwarded-For` and the proxy will pass it through. In Caddy:

```
reverse_proxy ztxbas:8443 {
    header_up -X-Forwarded-For
    header_up X-Forwarded-For {remote_host}
    header_up X-Forwarded-Proto {scheme}
}
```

## 8. SMTP

ztxbas refuses to start without SMTP configured — enrollment emails
are how users receive their pairing QR, and silent failure here was
a documented failure mode of the old C server.

Required at startup:

- `ZTXBAS_SMTP_HOST`, `ZTXBAS_SMTP_PORT`
- `ZTXBAS_SMTP_USER`, `ZTXBAS_SMTP_PASS`
- `ZTXBAS_SMTP_FROM`

Recommendations:

- Use a dedicated sending domain (`auth.example.com`,
  `noreply-ztxbas.example.com`) with **SPF, DKIM, and DMARC**
  configured on it. Enrollment emails to first-time users are exactly
  the kind of traffic mail providers filter aggressively.
- Prefer a transactional relay (Postmark, SES, Mailgun, an internal
  Postfix that already has DKIM configured) over a shared consumer
  provider.
- Test end-to-end after any change: from the console, resend an
  enrollment email to a throwaway address you can watch land in the
  inbox, spam folder, or a mail log.
- SMTP credentials should be delivered as Docker/Kubernetes secrets,
  not plain environment variables in a compose file that ends up in
  git.

## 9. Secrets on disk

ztxbas writes three sensitive files inside the data volume:

| File                              | Purpose                              | Permissions |
|-----------------------------------|--------------------------------------|-------------|
| `ztxbas.db` (+ `-wal`, `-shm`)    | SQLite: apps, users, origins, audit  | 0600        |
| `jwt-signing.key`                 | ES256 private key for JWTs           | 0600        |
| `breakglass.txt` (first boot only)| One-time admin password              | 0600 → gone |

Rules:

- **Do not chmod these looser** to work around a permissions issue.
  If the container can't read its own data dir, the volume was
  created by the wrong user (see section 3).
- **Back up the whole data directory as a unit.** The JWT signing key
  and the SQLite state must stay in sync — restoring one without the
  other means every existing JWT is either unverifiable or trivially
  forgeable.
- **The breakglass password** is written on first boot only, single-use,
  expires on first successful admin login. Rotate immediately after
  logging in; do not treat it as a durable password.

Per-application HMAC secrets (given to RPs) are shown once at
application-create time and never displayed again. RPs should store
them in their own secrets manager and never commit them to source
control. Rotate with:

```bash
docker exec ztxbas ztxbas app rotate <app-id>
```

Currently a rotation is atomic — RPs experience a brief window where
they must roll out the new secret before the old one stops working.
Dual-secret rotation with a configurable grace window is on the v1.1
roadmap.

## 10. Persistence and backups

SQLite in WAL mode holds everything: applications, origins, users,
audit log, admin account, session store. Backup is a filesystem
operation.

Two supported patterns:

**Online backup with `sqlite3 .backup`.** Runs against the live DB
without stopping the container:

```bash
docker exec ztxbas sqlite3 /var/lib/ztxbas/ztxbas.db \
    ".backup /var/lib/ztxbas/backup.db"

docker cp ztxbas:/var/lib/ztxbas/backup.db ./ztxbas-$(date +%F).db
# Also grab the JWT signing key — see section 9.
docker cp ztxbas:/var/lib/ztxbas/jwt-signing.key ./jwt-$(date +%F).key
```

Encrypt at rest (age, gpg, whatever your backup tool provides). The
JWT key is a P-256 private key; treat it like an SSH host key.

**Offline snapshot.** Stop the container, tar the volume, restart:

```bash
docker stop ztxbas
docker run --rm -v ztxbas-data:/data -v $PWD:/backup alpine \
    tar czf /backup/ztxbas-$(date +%F).tgz -C /data .
docker start ztxbas
```

Simpler; incurs a few seconds of downtime per backup.

**Test restore, quarterly at minimum.** An untested backup is a
statement of intent, not a recovery capability. Stand up the tarball
in a scratch container and confirm the console loads, an application
lists, and a fresh JWT verifies against the restored key.

## 11. Logging and monitoring

ztxbas writes structured JSON to stdout — journald, `docker logs`,
Loki, and every SIEM shipper reads it natively.

Sample line:

```json
{"time":"2026-01-15T10:04:11.812Z","level":"WARN","msg":"hmac.verify.fail",
 "app_id":"app_a1b2c3d4e5","reason":"timestamp_skew","skew_sec":312}
```

Fields worth alerting on:

- `hmac.verify.fail` at high rate for a single `app_id` → probable
  clock skew or leaked-and-rotated secret.
- `admin.login.fail` at high rate from a single client IP → brute
  force attempt against the console.
- `challenge.expired` at high rate → mobile push delivery is degraded,
  or the phone(s) can't reach 9443/udp.
- `smtp.send.fail` at any rate → users are silently not getting
  enrollment emails.

Health probe at `GET /health` returns liveness and version. It
deliberately does **not** check downstream (SMTP, ztxlib) — a health
probe that fails during a partial outage would take healthy instances
out of rotation. Use structured-log alerts for downstream failures.

## 12. Rate limiting

Defaults are sensible for a single-instance deployment:

- **Public endpoints**: per-application, with a burst allowance. An
  application creating a hundred challenges a second is either misusing
  the API or under attack; both cases benefit from throttling.
- **Admin endpoints**: per-client-IP, tighter. Login attempts are
  aggressively throttled per admin username too.

You can raise the public-endpoint limit for high-volume RPs; you
probably shouldn't lower the admin limit. Both are set via env vars
documented in `deploy/README.md`.

If you're fronting ztxbas with a WAF (Cloudflare, AWS WAF), that
becomes an additional shaping layer — ztxbas's built-in limits are the
inner defense, not the primary one.

## 13. Upgrades

1. Read the release notes. Migrations are append-only, so upgrades are
   safe; **downgrade is not supported** because a newer migration can
   add columns the older binary doesn't know about.
2. Cosign-verify the new tag against the same `cosign.pub` you already
   trust.
3. `docker pull` the new digest, back up the data volume (section 10).
4. `docker compose up -d` — the new container picks up the volume and
   runs any new migrations at startup.
5. Watch the logs for a clean startup and a fresh `/health` response
   with the new `version` field.

Because state lives in a mounted volume and the container is
stateless, rollback is: shut down, restore the pre-upgrade backup,
run the previous image tag.

## 14. Incident response

**Leaked application HMAC secret.**

```bash
docker exec ztxbas ztxbas app rotate <app-id>
```

Ship the new secret to the RP's config. In-flight challenges created
under the old secret remain valid (they're bound to challenge ID and
origin, not to the RP's HMAC secret), but any new API call from the
RP with the old secret fails immediately.

**Leaked JWT signing key.** The key lives in `jwt-signing.key` inside
the data volume. Rotation is manual and disruptive in v1:

```bash
docker stop ztxbas
docker exec -u root ztxbas rm /var/lib/ztxbas/jwt-signing.key   # or delete via the host mount
docker start ztxbas
```

A fresh key is generated at startup and published at
`/.well-known/jwks.json` under a new `kid`. **Every JWT issued under
the old key is now unverifiable** — the JWKS endpoint only publishes
the currently loaded key, so RPs that fetched a JWT in the last
five minutes (the JWT lifetime) will see verification failures during
the rollover window. Assume every currently-valid session is
compromised and log every user out at the RP side.

Multi-key JWKS rotation with a graceful overlap window is on the
v1.1 roadmap.

**Leaked breakglass password.** It's single-use and expires on first
login. If it leaked before first use, `docker exec ztxbas ztxbas
admin reset-password --user admin` regenerates a fresh one and
revokes every existing session.

**Suspected admin session compromise.** From the console: Account →
Sessions → *Revoke all other sessions*. Then rotate the admin
password. The audit log preserves session IDs and source IPs.

**Suspected mobile-device compromise (user reports lost phone).**

```bash
# From the RP side, using an SDK — or from the console under Users.
curl -X DELETE https://ztxbas.example.com/v1/users/<user-id> ...
```

The user is deregistered atomically. Their device's keys are useless
against ztxbas immediately. Re-enroll with a fresh device through
your account-recovery flow.

## 15. Air-gapped deployments

Everything works. There is no phone-home, no license server, no
telemetry, no forced updates. The pieces that need adjustment:

- **Image distribution.** Mirror `ghcr.io/corezt/ztxbas` to your
  internal registry. Verify cosign at ingest, then re-tag internally.
- **TLS.** Auto-ACME won't work; use an internal CA and static PEM
  files (`ZTXBAS_TLS_CERT`/`_KEY`, section 5).
- **SMTP.** Point at an internal Postfix / Exchange relay.
- **Time.** Chrony pointed at your internal NTP source. HMAC
  timestamp skew is bounded; a wrong clock breaks the RP flow before
  it breaks anything else, and it does so silently.
- **SDK distribution.** The Go SDK is fetchable via GOPROXY; the Node
  and Python SDKs need mirroring or vendoring for RPs behind an
  air-gap.

## 16. What ZTXBAS deliberately doesn't do

If you need any of these, [ZTXGate](../vs-ztxgate) is the answer —
same mobile app, same crypto backend, superset of features:

- SSO / SAML / OIDC for administrators
- Admin RBAC beyond a single account
- SCIM user provisioning
- MDM posture attestation as a factor
- SIEM export beyond stdout log shipping
- Multi-tenant isolation
- Network-wide enforcement (VPN, RDP, SSH, legacy apps)
- HA across nodes with shared state

Attempting to bolt any of these onto ztxbas breaks its "one process,
one job" shape and inevitably means running an old fork forever.
Migrate to ZTXGate instead; the mobile app on your users' phones is
already the right one.
