# Support

ZTXBAS is a free, closed-source binary offered by CoreZT to introduce
prospective customers to the CoreZT zero-trust product family. This
page describes what support is available, from whom, and where the
line falls between "community" and "commercial."

## Start with the docs

Most questions are answered in the documentation before they need to
become tickets. In rough order of "where to look first":

1. **[Getting started](https://corezt.com/docs/ztxbas/getting-started)** — smoke-test run, first application, first JWT.
2. **[Concepts](https://corezt.com/docs/ztxbas/concepts/origin-binding)** — origin binding, HMAC signing, challenge lifecycle, JWT verification.
3. **[Hardening guide](https://corezt.com/docs/ztxbas/guides/hardening)** — production settings.
4. **SDK pages** — [Go](https://corezt.com/docs/ztxbas/sdks/go), [Node](https://corezt.com/docs/ztxbas/sdks/node), [Python](https://corezt.com/docs/ztxbas/sdks/python).
5. **`deploy/README.md`** in this repository — compose and Kubernetes recipes.

If the docs are wrong, unclear, or missing something obvious, that's
itself a ticket worth filing — see below.

## Community support

Community support runs on GitHub Issues at
<https://github.com/corezt/ztxbas/issues>. It is **best-effort**, with
no response-time commitment.

**Please file an issue for:**

- A reproducible bug in the ZTXBAS server, admin console, CLI, or a
  published SDK.
- Documentation that is wrong, misleading, or missing.
- A crash or unexpected error you can reproduce from a clean start.
- A concrete feature request. We may or may not build it, but we do
  read them, and they inform ZTXGate's roadmap too.

**Please don't file an issue for:**

- Deployment consulting or environment-specific debugging ("my Caddy
  config doesn't route to ztxbas") — those belong on your infra
  vendor's forum or in Stack Overflow.
- Integration debugging inside your relying-party application ("my
  Express app doesn't verify the JWT") — walk through the SDK's
  README, then a minimal reproduction using the quickstart, then file
  an issue only if the minimal repro fails.
- Security vulnerabilities. Those go to `support@corezt.com` — see
  [SECURITY.md](SECURITY.md).

**How to write an issue that gets answered quickly:**

- ZTXBAS version (`ztxbas --version` or the container's
  `org.opencontainers.image.version` label).
- Deployment shape (docker, compose, Kubernetes).
- Minimal reproduction — a `docker run` command line, the smallest
  API call that triggers the problem, or a copy-pasteable SDK snippet.
- Actual output (log line, HTTP response body, error string) vs. what
  you expected.
- Anything you've already ruled out.

## Contributions

ZTXBAS server + admin console source is closed. We do not accept
pull requests against the server.

The three published SDKs (Go, Node, Python) are Apache-2.0 licensed and
live in this repository under `sdk-go/`, `sdk-node/`, `sdk-python/`.
Pull requests against them are welcome — see each SDK's `CONTRIBUTING.md`
for the style and test expectations. Documentation PRs against `docs/`
are also welcome.

## Version support

- **The latest minor version** receives bug fixes and security patches.
- **Previous minor versions** receive security patches only, for
  approximately three months after their successor is released.
- **Older versions** receive no patches. If you're on one and hit a
  bug, the answer is "please upgrade to the latest and confirm the
  problem still reproduces."

Releases are cut when there is enough to ship — there is no fixed
cadence.

## When ZTXBAS isn't enough

ZTXBAS is deliberately narrow: one instance, one admin, one application
per deployment shape, no SSO for admins, no RBAC, no SCIM, no MDM, no
SIEM export, no HA. These aren't limits we plan to relax — they're the
shape of a free front-door tool for developers.

If any of the following start to matter, ZTXGate is the answer — same
mobile app on your users' phones, same crypto backend, superset of
features:

- Contractual response-time SLAs and named engineering escalation.
- Admin RBAC, SSO / SAML / OIDC, SCIM provisioning.
- MDM posture attestation as an authentication factor.
- SIEM export beyond stdout log shipping.
- Request-approved based JIT access.
- Network-wide enforcement (VPN, RDP, SSH, legacy apps).
- Custom feature engagements or roadmap influence.

For a commercial-support quote or a ZTXGate evaluation, contact
`sales@corezt.com`. If you were already going to file an issue asking
whether ztxbas can do one of the things above, save the round-trip and
email `sales@corezt.com` directly.

---

*ZTXBAS is provided under [`LICENSE`](LICENSE). Nothing
on this page creates or implies a support obligation beyond what is
stated in that document, which explicitly disclaims one.*
