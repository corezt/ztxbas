# Security policy

## Reporting a vulnerability

Email **support@corezt.com** with:

- A description of the issue, including the impact you believe it has.
- Steps to reproduce, ideally with a minimal test case.
- The version of ZTXBAS you tested against (`ztxbas --version` or the
  `org.opencontainers.image.version` label on the container image).
- Any patches or mitigations you have already identified, if applicable.

You should receive an acknowledgement within **three business days**.
We aim to publish a patched release within **thirty days** of the first
reproducible report for a high-severity issue; timeline shifts for lower
severities or issues that require an upstream fix.

Please do not open GitHub issues, discussion threads, or social-media
posts for security matters until a fix is shipped.

## Trust boundaries

ZTXBAS ships with a two-listener design that reflects two very different
threat models.

**Public API (`ZTXBAS_LISTEN_ADDR`, default `:8443`).** Designed for
direct exposure over TLS to the public internet. All routes on this
listener are HMAC-authenticated with per-application secrets;
per-application rate limits are enforced; signed-body size is capped;
signatures use constant-time comparison. Assume every byte on this
listener is attacker-controlled.

**Admin console (`ZTXBAS_CONSOLE_LISTEN_ADDR`, default
`127.0.0.1:8080`).** *Not* designed for direct public exposure. The
default bind is loopback and the binary refuses to bind a
non-loopback address without TLS unless
`ZTXBAS_ALLOW_INSECURE_CONSOLE=1` is set. Public exposure requires an
additional gate — a reverse proxy with basic auth, an IP allowlist, or
mTLS. See `deploy/README.md#exposing-the-admin-console`.

**State on disk.** The SQLite database and the JWT signing key both live
under `ZTXBAS_DATA_DIR` (default `/var/lib/ztxbas` in the container,
`./data` locally). The signing key is written mode 0600; the DB inherits
umask 0077 from the systemd unit / non-root container user. Rotating
the JWT signing key today is a manual, disruptive operation: stop the
container, delete `jwt-signing.key`, restart. A fresh key is generated,
and every previously issued JWT (max lifetime 5 minutes) fails
verification during the rollover window because the JWKS endpoint only
publishes the currently loaded key. Multi-key rotation with a graceful
overlap window is planned for a future release.

**Secrets in logs.** ZTXBAS logs application IDs, request IDs, and
event IDs — never HMAC secrets, JWT tokens, signatures, or admin
passwords. If you see a secret appear in `journalctl` or container
logs, that is a bug and qualifies for the disclosure address above.

## In scope

ZTXBAS is closed-source and distributed as a free binary. Reports are
welcome against:

- The published container image (`ghcr.io/corezt/ztxbas`) at the tagged
  release version you're reporting against.
- The `ztxbas` binary distributed on GitHub Releases.
- The bundled admin console served by that binary.
- The mobile-app ↔ ZTXBAS UDP protocol (see *Cryptography* below).
- The default deployment recipes in `deploy/`.

Source code is not published. If your report needs to reference internal
behaviour, describe the observable symptom (request, response, log
line, timing) and we'll correlate it against the source on our side.

## Out of scope

- Vulnerabilities in third-party dependencies that have no ZTXBAS-side
  amplification. Please report those upstream.
- Findings that require an attacker who already holds valid admin
  console credentials, unless they enable a privilege escalation across
  tenants or extract secrets that should be inaccessible to any admin.
- Missing security headers on the public API's JSON responses (the
  console UI carries the CSP; the API is not intended to be rendered
  in a browser).
- Denial of service via unbounded request volume (rate limits apply per
  application; abuse mitigation is the operator's responsibility at the
  reverse-proxy layer).
- Reports generated purely by automated scanners without a reproducible
  proof of concept.

## Safe-harbour

We will not pursue legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, data
  destruction, or service disruption during testing.
- Do not exploit findings beyond what is necessary to demonstrate them.
- Give us a reasonable window to ship a fix before public disclosure.

## Cryptography

ZTXBAS uses well-established cryptographic primitives wherever possible:

- HMAC-SHA256 for RP request signing on the public HTTP API
  (constant-time comparison).
- ECDSA P-256 (ES256) for JWT identity assertions issued to relying
  parties.
- PBKDF2-HMAC-SHA256 (600,000 iterations, per OWASP 2023) for admin
  password hashing.

**Mobile-app ↔ ZTXBAS transport.** The CoreZT mobile app talks to
ZTXBAS over **UDP port 9443** using a custom envelope format rather
than TLS. The choice is deliberate: mobile clients roam across NATs
and captive networks where a single-RTT UDP exchange is materially
more reliable than a TLS handshake, and it avoids shipping a
device-side certificate PKI. Payload confidentiality and integrity
are provided by AES-256-GCM; payload authenticity is bound to the
enrolled device by a P-256 ECDSA attestation signature over the
envelope contents. Security rests on the AEAD key and the attestation
signature, not on the framing being secret — the primitives are
standard (AES-256-GCM, ECDSA on P-256) and would remain sound under
Kerckhoffs's principle even if the wire format were fully published.

An on-path observer sees the source/destination IPs, UDP:9443, and
the encrypted packet sizes and timing; envelope contents (including
device identifiers) are protected by the AEAD.

The envelope, the key schedule, and the attestation binding are
proprietary to CoreZT and are in scope for security reports even
though the wire format is not publicly documented — send observable
behaviour (packet captures, timing, error responses) with your
report and we will map it against the spec on our side.

Note: ZTXBAS is not FIPS-validated. The primitives are FIPS-approved
but the custom framing has not been through validation. Regulated
deployments that require a FIPS-validated transport should evaluate
ZTXGate, which offers a FIPS mode.

All other cryptography uses stock library primitives; we do not roll
our own building blocks.
