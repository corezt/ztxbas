# ZTXBAS

**Phishing-resistant biometric authentication for your applications.**

ZTXBAS is a free, self-hosted authentication server. Run one container,
point your app at it, and get a signed JWT identity assertion after the
user approves a push on their phone with Face ID / Touch ID /
fingerprint. Origin binding stops the assertion from being replayed
against a different site — the phone shows the origin the user is
authenticating to, and the server refuses challenges for origins not
registered to the requesting application.

- **No signup, no license, no telemetry.** The binary runs on your
  infrastructure. Nothing calls home.
- **Ten minutes to a working demo.** See [Getting started](https://corezt.com/docs/ztxbas/getting-started).
- **Single container, SQLite state.** No external database, no message
  broker, no separate admin service.
- **Three official SDKs.** Go, Node/TypeScript, Python — hand-written,
  Apache-2.0.
- **Signed release images.** `cosign verify` against
  `corezt.com/keys/cosign.pub` before you pull to production.

## Get it

```bash
docker pull ghcr.io/corezt/ztxbas:latest
```

Verify the signature:

```bash
cosign verify --key https://corezt.com/keys/cosign.pub \
    ghcr.io/corezt/ztxbas:latest
```

The full deployment recipes — `docker run`, Docker Compose with Caddy,
and Kubernetes — are in [`deploy/README.md`](deploy/README.md).

## Mobile app

The same CoreZT mobile app is used by both ZTXBAS and ZTXGate.

- **iOS** — <https://apps.apple.com/app/id6763044882>
- **Android** — <https://play.google.com/store/apps/details?id=com.corezt.ztxbas>

## SDKs

Each SDK handles HMAC request signing, response parsing, challenge
polling, JWKS caching, and ES256 JWT verification.

| Language | Package                                       | Source        |
|----------|-----------------------------------------------|---------------|
| Go       | `github.com/corezt/ztxbas/sdk-go`             | `sdk-go/`     |
| Node/TS  | `@corezt/ztxbas` on npm                       | `sdk-node/`   |
| Python   | `ztxbas` on PyPI                              | `sdk-python/` |

Each has a runnable [quickstart](quickstarts/) that walks the full
enroll → challenge → verify flow in about 30 lines.

## Documentation

Full documentation is at <https://corezt.com/docs/ztxbas>. Key pages:

- [Getting started](https://corezt.com/docs/ztxbas/getting-started)
- [Origin binding](https://corezt.com/docs/ztxbas/concepts/origin-binding)
- [HMAC signing](https://corezt.com/docs/ztxbas/concepts/hmac-signing)
- [JWT verification](https://corezt.com/docs/ztxbas/concepts/jwt-verification)
- [Hardening guide](https://corezt.com/docs/ztxbas/guides/hardening)
- [How ZTXBAS compares to ZTXGate](https://corezt.com/docs/ztxbas/vs-ztxgate)

The public API surface is documented in
[`api/openapi.yaml`](api/openapi.yaml).

## Support and maintenance

ZTXBAS is offered as a free community tool.

- **Bug reports and doc issues:** GitHub Issues, best-effort. See
  [SUPPORT.md](SUPPORT.md).
- **Security reports:** `support@corezt.com`. See [SECURITY.md](SECURITY.md).
- **Commercial SLA, RBAC, SSO, SCIM, MDM, SIEM, HA, network
  enforcement:** see [ZTXGate](https://corezt.com/ztxgate) —
  same mobile app, same crypto backend, superset of features.

CoreZT is not obligated under the license to provide updates, support,
or feature work; see [LICENSE](LICENSE). In practice
security fixes are prioritized and the latest minor version is
maintained.

## License

The server binary, admin console, container images, and CLI are
distributed under the CoreZT ZTXBAS EULA — see
[LICENSE](LICENSE). Free for internal business and
personal use, including production. Redistribution as part of a
commercial authentication offering requires a separate agreement.

The three SDKs and the sample code are Apache-2.0 — see the `LICENSE`
file in each SDK directory.
