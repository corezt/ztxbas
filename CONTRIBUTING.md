# Contributing to ZTXBAS

Thanks for looking at this repo. ZTXBAS is a closed-source binary
distributed for free — the server, admin console, and CLI live in a
private repository. This public repo exists so that the parts of
ZTXBAS that *are* open can be improved by anyone, and so that bug
reports have somewhere to go.

## What's in scope for contribution

External PRs are accepted against:

| Directory                        | License    | Notes                                        |
|----------------------------------|------------|----------------------------------------------|
| `sdk-go/`                        | Apache-2.0 | Go SDK for relying parties.                  |
| `sdk-node/`                      | Apache-2.0 | Node / TypeScript SDK.                       |
| `sdk-python/`                    | Apache-2.0 | Python SDK.                                  |
| `quickstarts/`                   | Apache-2.0 | Runnable examples.                           |
| `docs/`                          | Doc bundle | Merged into corezt.com/docs.                 |
| `api/openapi.yaml`               | Doc        | Public API spec.                             |
| `deploy/` (except image builds)  | Doc        | Operator recipes.                            |

Anything else — the server binary, the admin console, any Go package
that would live under `internal/` — is not accepted here and cannot
be merged from this repo. If you found a bug there, please file it as
an issue instead.

## Licensing of contributions

By opening a PR against an Apache-2.0 directory (SDKs, quickstarts),
you agree that your contribution is licensed under Apache-2.0 —
matching the `LICENSE` file in that directory. This is the standard
inbound-equals-outbound model. **No CLA is required.** A sign-off in
the commit message (`git commit -s`) is appreciated but not enforced.

Docs and deploy recipes are documentation and inherit the terms of the
public docs bundle.

## Before you open a PR

1. **Search existing issues and PRs.** Someone may already be on it.
2. **For non-trivial changes, open an issue first.** A brief discussion
   about the approach saves a rewrite after the fact. Trivial fixes
   (typos, broken links, obvious bugs) can go straight to a PR.
3. **Keep the diff focused.** One logical change per PR.

## Running tests locally

Each SDK is self-contained. The commands below assume you're at the
repo root.

**Go SDK:**

```sh
cd sdk-go
go test ./...
```

**Node SDK:**

```sh
cd sdk-node
npm ci
npm test
```

**Python SDK:**

```sh
cd sdk-python
pip install -e '.[test]'
pytest
```

For docs changes, GitHub's rendered preview on the PR is usually
enough; there is no local site to run.

## Style and conventions

- **Match the surrounding code.** Formatting is enforced per SDK:
  `gofmt` for Go, `prettier` for Node (config in `sdk-node/`), `ruff
  format` for Python.
- **No new runtime dependencies** in an SDK without a good reason —
  the SDKs are intentionally small and dep-light.
- **No breaking API changes** without discussion. The SDKs are
  semver'd against the ZTXBAS server API; a breaking change means a
  major bump.
- **Tests over asserts.** New behavior should have a test; a bug fix
  should have a regression test.

## What happens after you open a PR

A maintainer will look at it on a best-effort schedule (see
`SUPPORT.md`). CI is not currently wired up on this repo, so please
paste test output in the PR description. If a review takes longer than
a couple of weeks, a polite bump is welcome.

## Security issues

Do not file security vulnerabilities as PRs or issues. Email
`support@corezt.com` — see `SECURITY.md` for what to include.

## Commercial support

If you need SLA-backed support, RBAC, SSO, SCIM, MDM, SIEM, or
network enforcement, those are ZTXGate features. See
<https://corezt.com/ztxgate>.
