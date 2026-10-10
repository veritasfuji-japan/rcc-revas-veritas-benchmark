# TASK15_GOVERNED_ADMIN_ROOT_LIFECYCLE_V1 — #286

**DRAFT — offline-only synthetic authority. NOT production PROVEN.**

## Rule-of-One

In #285, the *administrator* command was independently signed by a TEST
Ed25519 signer, but the administrator public root was configured by the
trusted host at process startup. That was NOT independently governed.

#286 adds a new mock-only Broker core which pins a DIFFERENT TEST governance
Ed25519 public root. Only a verified, narrow, expiring governance manifest
can enroll an initial admin root, rotate it by precisely one epoch or revoke
the active root. The trusted governance signing key itself is NOT carried
through the worker protocol or persisted in artifact evidence.

Frozen #285 merged-main predecessor:
24a28ee3b6fd058f73fd519653d5c087b3515334.

The admin revoke path now takes one SQLite BEGIN IMMEDIATE writer lock,
loads the *current active admin root* INSIDE the lock, verifies its signed
admin command, and atomically writes one admin command nonce and one request
revocation before committing. Concurrent ROTATE or terminal REVOKE of that
root uses the SAME SQLite writer lock.

## Boundaries

- Initial enrollment: signed governance ENROLL at epoch=1, without predecessor.
- Rotation: signed governance ROTATE, epoch exactly previous+1, previous
  root's SHA-256 pinned, and fresh admin root not equal to ANY historical
  root. Old administrator signatures must be rejected immediately.
- Terminal root revocation: signed governance REVOKE, epoch previous+1,
  no replacement root. Afterwards **no** TEST admin can revoke. Recovery
  after revocation is deliberately out of scope and must not be silently
  reenrolled.
- The only accepted domain is frozen Task15 mock-only; signable statements
  explicitly have no live Provider permission, zero microdollar budget and
  zero bank effects. Governance validity <=300 seconds.
- No worker socket API may enroll, rotate, revoke a governance root or
  bypass a signed admin request.

## Required evidence

30 adversarial unittest cases: forgery, model-signer impersonation, missing
signature, modified scope, spend drift, expired/future/overlong manifest,
wrong epochs, bad predecessor digest, replay, wrong active admin root,
old-root downgrade, terminal revocation, durable restart, audited tampering
and 16 concurrent attempts to commit exactly the same rotation epoch.

Raw SQLite evidence is saved for BOTH separate bounded scenarios:

1. **Rotation then admin revoke**: A enrolled, B rotated, stale A denied,
   B signed admin revoke accepted once. Two governed root epochs, one signed
   admin command and one request revocation. Zero mock model calls.
2. **Rotation then root terminal revoke**: A enrolled, B rotated, B root
   revoked by separate governance signer. B's otherwise valid signed admin
   revoke is rejected. Three root epochs and zero admin command/revoke rows.
   Zero mock model calls.

Archive two test governance public roots, their manifest signatures, distinct
model public roots and A/B TEST admin public roots, exact raw SQLite archives,
JUnit and SHA-256 evidence, with NO private signing keys or real API keys.
A trusted host/operator owns the physical SQLite file; immutable real-world
external enrollment is NOT demonstrated.

## Explicit nonclaims

This is a new **in-process trusted Broker core**, NOT integration into #285's
isolated Docker AF_UNIX broker. A privileged host could replace the root
pin/DB: host-compromise resistance, hardware key custody, production IAM,
real-world operator identity, two-person approval, and actual native AgentDojo
model-wire/source authenticity remain OPEN. The test does not enable real
Provider HTTP, spend, or banking effects.

Next proof round: bind the pinned governance root + durable active-admin-key
reader to the Docker/AF_UNIX mock broker and independently verify old-root
rejection after rotation in an already running broker. Operator enrollment
and Provider egress must still be treated as separate proof rounds.

CI green alone != PROVEN. Manual merge only after exact-head CI and
independent raw SQLite/signature/digest artifact audit.
