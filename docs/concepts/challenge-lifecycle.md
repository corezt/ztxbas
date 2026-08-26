---
sidebar_position: 3
title: Challenge lifecycle
---

# Challenge lifecycle

Every authentication goes through the same short state machine.
Understanding it saves you time when a challenge behaves unexpectedly.

## States

```
                ┌───────────┐  approve on phone   ┌──────────┐
   create ────▶ │  pending  │ ──────────────────▶ │ approved │
                │           │  deny on phone      │  denied  │
                │           │ ──────────────────▶ │          │
                │           │  TTL elapses        │ expired  │
                │           │ ──────────────────▶ │          │
                └───────────┘                     └──────────┘
                                                     ▲
                                             terminal, sticky
```

Three terminal states — `approved`, `denied`, `expired` — are
**sticky**. Once a challenge lands there, subsequent polls return the
same value until the sweeper eventually removes it.

## Timings

| Parameter                | Value  | Notes                                    |
| ------------------------ | ------ | ---------------------------------------- |
| Challenge TTL            | 5 min  | Time between create and `expired`.       |
| JWT lifetime             | 5 min  | Time between mint and `exp`.             |
| JWKS cache in SDK        | 5 min  | Time between refetches.                  |
| Clock skew (HMAC + JWT)  | ±5 min (HMAC) / ±30 s (JWT) | On the RP side. |

The 5-minute challenge TTL is the reason `poll_challenge` defaults its
timeout to 4 min 30 s — so the client returns
`ChallengeTimeoutError` before the server would return `expired`,
giving you cleaner control-flow.

## Rotation isn't a problem

Rotating an application's HMAC secret **does not invalidate
in-flight challenges**. A challenge is bound to its id + origin +
user; nothing about it depends on the RP's secret. The RP fleet may
briefly see `INVALID_SIGNATURE` while a new secret propagates, but
existing challenges keep their state.

(Rotation ergonomics — dual-secret windows for zero-downtime rotation
— land in v1.1.)

## Idempotency and safety

- **Creating a challenge is not idempotent.** Two calls in a row send
  two pushes to the user's phone. Debounce on the RP side if your
  users click Login twice.
- **Polling status is idempotent** and cheap. It's a single indexed
  lookup on the in-memory challenge store, not a DB read.
- **Approving is single-shot.** A user can't approve the same
  challenge twice — the first tap flips it to `approved` and the
  server ignores subsequent taps.

## Failure modes and what they mean

| Symptom                                              | Cause                                                        |
| ---------------------------------------------------- | ------------------------------------------------------------ |
| 404 on `create_challenge`                            | The user isn't registered for this application's tenant.     |
| 403 UNREGISTERED_ORIGIN on `create_challenge`        | Origin wasn't previously `POST`ed to `/v1/origins`.          |
| Status stays `pending` forever, then `expired`       | Push didn't reach the user's phone (Internet? DND?).         |
| `INVALID_SIGNATURE` on `create_challenge` only       | Secret drift between your app and ztxbas. Rotate + redeploy. |
| `TIMESTAMP_EXPIRED` on every call                    | RP host clock is off. Run NTP.                               |

## Related

- [JWT verification](./jwt-verification) — what to do with an approved challenge.
- [Origin binding](./origin-binding) — why `UNREGISTERED_ORIGIN` exists.
