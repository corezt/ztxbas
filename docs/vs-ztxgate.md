# ZTXBAS vs ZTXGate

Both products are from CoreZT and both help you prove who a user is
before they get to something. They solve different problems, and it's
worth knowing which one you actually need.

## The short version

- **ZTXBAS** is a **biometric authentication building block**. It gives
  your app a phishing-resistant "prove it's really you" step. That's
  the whole product.

- **ZTXGate** is a **full zero-trust network access (ZTNA) platform**.
  It replaces your VPN, brokers per-application access across your
  fleet, enforces device posture, integrates with your IdP, and
  streams to your SIEM — with ZTXBAS as one of its authentication
  factors.

If you already have an app and you just need to add strong MFA to
your login flow, use ZTXBAS. If you're trying to give your team
secure access to internal apps, servers, and services — the job a
VPN used to do — use ZTXGate.

## Feature comparison

|                                              | ZTXBAS | ZTXGate |
| -------------------------------------------- | :----: | :-----: |
| Phishing-resistant biometric MFA             |   ✓    |    ✓    |
| Origin-bound identity assertions (JWTs)      |   ✓    |    ✓    |
| Self-hosted, single Linux binary             |   ✓    |    ✓    |
| Works offline / airgapped                    |   ✓    |    ✓    |
| Per-application access policy                |        |    ✓    |
| WireGuard-based secure tunneling             |        |    ✓    |
| Device posture (Intune, Defender, SentinelOne)|       |    ✓    |
| Just-in-time and request-and-approve access  |        |    ✓    |
| Continuous policy enforcement (mid-session)  |        |    ✓    |
| OIDC single sign-on and SCIM provisioning    |        |    ✓    |
| Admin / helpdesk / auditor roles             |        |    ✓    |
| Policy simulator                             |        |    ✓    |
| Self-service user portal                     |        |    ✓    |
| SIEM integration (syslog / CEF / JSON)       |        |    ✓    |
| Audit logs and shareable reports             |        |    ✓    |
| Scheduled backups and DR runbook             |        |    ✓    |
| Central fleet updates                        |        |    ✓    |
| Pricing model                                | Free binary | Per-user, per-year |

## When to pick ZTXBAS

- You have your own web or mobile app.
- You want to bolt on strong, phishing-resistant MFA that doesn't
  require a hardware key.
- You're happy running one small binary and calling three API endpoints.
- You want to stay self-hosted with no cloud dependency.

Typical integrations:

- A SaaS login flow that adds a biometric step-up on high-risk actions.
- An internal admin console that requires MFA for every session.
- A B2B product whose customers want strong MFA without the operational
  cost of running their own IAM stack.

## When to pick ZTXGate

- You have 25–2,000 people who need secure access to internal apps,
  services, or servers.
- Your team currently uses a VPN, and you're tired of the "everyone on
  the network can see everything" security model.
- You need to grant per-application, per-role, or time-bounded access —
  not blanket network reach.
- You want device health (from Intune, Defender, or SentinelOne) to
  factor into who reaches what.
- You want a single dashboard for users, devices, policies, sessions,
  and audit — with helpdesk and auditor roles you can delegate to.

Typical use cases:

- Give developers direct, per-service access to staging and production
  without exposing anything else.
- Replace a legacy VPN across offices, home workers, and cloud regions.
- Meet SOC 2, HIPAA, or PCI-DSS access controls without months of
  rollout.

Learn more at **[ZTXGate](https://corezt.com/ztxgate)**.

## Can I use both?

Yes — and if you're a ZTXGate customer, you already are. ZTXGate uses
ZTXBAS as one of its phishing-resistant MFA factors (the others are
Okta Verify Push and Duo Push). You can pick which one applies per
policy.

If you're an existing ZTXBAS integrator and later adopt ZTXGate, your
users don't need a new mobile app.
