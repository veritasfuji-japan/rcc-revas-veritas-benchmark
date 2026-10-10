# TASK15_WORKER_SESSION_CHALLENGE_V1 — #282

**DRAFT / NOT PROVEN. Offline only. Real Provider API requests, real credentials, billing and banking effects remain forbidden.**

## One invariant

The same Linux UID/GID alone is not authority to enter the trusted mock broker. A separately
containerized attacker with **the same 65534:65534 identity**, the same signed TEST grant,
and access to the same Unix socket must be unable to trigger even one mock sink call
unless it also possesses the independently supplied **per-run worker session key**.

This builds from frozen #281 main `bda9fcd7137cdb504333a20472e6d7ae7dbf4718`.

## Protocol and test-only custody

Broker and workers run in separate `--network=none`, nonroot, read-only-root Docker
containers, drop all capabilities and enable no-new-privileges. The broker holds
its synthetic mock Provider credential and durable SQLite exclusively under
a host-owned private mount, and additionally holds a synthetic 32-byte session key
inside that private mount. The legitimate worker receives a **separate read-only
file bind mount** for that exact session key. The impersonator receives the
public signed grant and Unix socket but NO session-key mount. Secret bytes are
never archived or written in git.

For every accepted-UID connection, the broker first emits a fresh CSPRNG 256-bit
challenge. The client returns the exact proposal and HMAC-SHA256 of a frozen
domain prefix, fresh nonce and SHA256 of the canonical proposal. Broker
checks `SO_PEERCRED`, challenge response, then the #279 pre-pinned test
Ed25519 grant and transactional single-use SQLite claim. Replaying the
old challenge with the correct key must fail. Signed authority still permits
at most **one local mock effect**.

## Six expected connections

1. **Attacker same UID without key:** wrong HMAC → DENIED (before mock).
2. **Legitimate worker with key but wrong/stale challenge:** DENIED.
3. **Legitimate worker correct challenge + test grant:** MOCK_RECORDED (one).
4. **Legitimate worker reuses signed grant:** ONE_SHOT denied.
5. **Legitimate worker with correct key but altered target:** frozen scope denied.
6. **Host runner UID/GID not matching worker:** SO_PEERCRED denied.

Raw evidence includes THREE Docker inspect snapshots, six peer decisions,
test-only signed grant/public root, source SHA, *only SHA-256* of session secret,
raw SQLite snapshot, 15 JUnit runtime assertions and 12 unit-level protocol cases.
All credentials are synthetic. No real API sender is included.

## Critical nonclaims and next steps

The session key is a capability: a different process or malicious code with access
to the legitimate worker's private mount can still use the capability. The
broker cannot cryptographically attest an immutable unique worker process or
Docker image identity from `SO_PEERCRED`. A privileged host or Docker daemon
can remount or read the synthetic key. Thus the result is **not** host-compromise
resistance, real API credential custody, enrolled human operator authority,
or production request/response authenticity.

Default-deny Provider gating stays in force. Exact-head CI success is
necessary but insufficient; independently inspect the saved ZIP, six event
decisions, signed TEST grant, and SQLite integrity before recommending manual merge.

Run from dedicated Ubuntu/Docker CI, Python 3.11 with cryptography==50.0.0:

`python scripts/task15_worker_session_challenge_audit_v1.py --output-dir results`
