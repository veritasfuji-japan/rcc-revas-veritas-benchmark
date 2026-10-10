# TASK15_SIGNED_ADMIN_REVOCATION_V1 — PR #285

**OFFLINE-only / Draft / NOT independently PROVEN pending exact-head CI and raw artifact audit.**

## Rule of One

#284 placed the trusted revocation operation inside a networkless Docker
Broker, but the host with Docker privileges could call a bare revoke CLI.
This PR creates an **additional** broker-owned authorization gate: an exact
Task15 revocation MUST carry a valid, short-lived, single-use Ed25519
**independent TEST administrator signature**, distinct from the MODEL grant
signature root, before any SQLite state mutation is permitted.

This extends the frozen #284 merged main
3f1f7fe3c606a694d7b07330e0a3e2e86752e737.

## Signed administrator envelope

Canonical UTF-8 signed JSON includes an exact bounded administrative action,
domain, frozen request SHA-256, 32-byte nonce, issued and expiry timestamp,
no-live-Provider=true, zero spending and no bank effect. The test root for
administrators is pinned separately from the Ed25519 TEST model approval root.
Maximum permit lifetime is 300 seconds. Repeated nonce, stale permit, wrong
key, altered target, unsafe spending and missing signature are denied.

Only trusted host-side Docker exec can pass the signed permit through a
mode-0600 admin file under the broker's private mount. The public worker
AF_UNIX protocol accepts ONLY signed model proposals with the existing
per-session challenge HMAC, not administrator actions.

## Atomicity and negative controls

Broker verifies TEST signature, time, action, target and signature source
BEFORE entering the SQLite write transaction. In ONE BEGIN IMMEDIATE
transaction it inserts the admin command nonce and SHA-256 into durable
admin_commands, inserts the targeted revocation, and writes both
REVOCATION_COMMITTED and SIGNED_ADMIN_REVOCATION_COMMITTED audit events.
Duplicate permit and fresh-but-duplicate revocation both roll back.

Dedicated proof runs 18 fast adversarial signed-command unit tests
and two isolated Docker/AF_UNIX scenarios, with 20 runtime checks:
- Revoke before a correctly keyed worker with valid signed TEST grant:
  no mock effect.
- Compromised key + valid signed TEST grant claims first:
  one previously authorized mock effect. This cannot be undone.
- In *each* Docker scenario, wrong signing key, expired token, altered
  signed scope, replayed valid token, and new permit against an already
  revoked request must all be refused.

The two raw SQLite databases plus direct Docker inspect files, TEST-only
Ed25519 permits/public roots, JUnit, six worker AF_UNIX decisions and
reason-specific admin negative-case logs are saved for outside audit.

**Critical nonclaims:** A locally generated test administrator signing key
is NOT an independently enrolled human identity. Trusted host/Docker
permissions can control root configuration or ledger contents; this
proof does not provide a production hardware trust anchor, admin RBAC/IAM,
two-person approval, live Provider credential management, independent
image supplier attestation, or native full AgentDojo wire provenance.
No real Provider HTTP, API billing or banking effects.

One proof round, one added invariant. Prior frozen #279–#284 paths are
left unchanged. No historical Provider budget approval carries forward.
