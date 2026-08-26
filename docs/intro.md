---
sidebar_position: 1
title: Introduction
---

# ZTXBAS

**ZTXBAS** is a small, self-hosted server that mints short-lived,
origin-bound identity assertions after a user approves a biometric push
on their mobile device.

If you have a login page, ZTXBAS gives you a phishing-resistant "prove
it's you" step without asking your users to enrol in a hardware key or
type a TOTP code.

## What you get

- **Phishing-resistant MFA.** Every authentication is bound to a
  specific origin. A user on `phishing.example.com` can't be tricked
  into approving a login for `app.example.com` — the origin they see on
  their phone is the one the challenge was minted for.
- **A signed container image.** Ships as `ghcr.io/corezt/ztxbas`,
  cosign-signed. Runs on any Linux host, cloud VM, or Kubernetes
  cluster. SQLite for storage; no external database, no phone-home, no
  cloud dependency.
- **A standard proof format.** Every successful authentication produces
  a short-lived ES256 JWT you verify against a JWKS. If you can verify
  a Google or Okta ID token, you can verify a ZTXBAS one.
- **A tiny public API.** Ten endpoints. Three of them are what you'll
  call regularly.

## Who it's for

Teams building a web or mobile product who want a step-up
authentication factor and don't want to run — or pay for — a full
enterprise IAM stack.

If you need per-application access policy, device posture, session
enforcement, admin/helpdesk roles, SCIM provisioning, and a policy
simulator, look at [ZTXGate](/ztxgate). ZTXBAS is the biometric
building block ZTXGate uses under the hood; use ZTXBAS on its own if
that's all you need.

## What's next

- Get a server up and your first challenge running in
  [Getting started](./getting-started).
- Understand the trust model in [Concepts](./concepts/origin-binding).
- Pick an [SDK](./sdks/go) and start integrating.
