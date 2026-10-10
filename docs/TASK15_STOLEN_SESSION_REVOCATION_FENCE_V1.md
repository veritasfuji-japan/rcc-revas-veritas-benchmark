# TASK15_STOLEN_SESSION_REVOCATION_FENCE_V1 — PR #283

**DRAFT / NOT PROVEN — offline-only broker core, no real Provider execution.**

## Rule-of-One

When the worker's HMAC session key and its already-signed test-only grant
are stolen, a normal session HMAC **can still be forged by the attacker**.
A challenge response does not prevent someone who possesses the key from
answering a new challenge. This proof therefore covers a specific containment
property: **after** a trusted-side request revocation commits, *no later*
dispatch claim for the exact frozen Task15 request may enter the mock sink.

The predecessor is #282 merged-main SHA
`384110807d7a5e418b06f06853f23f8c44739e32`.

This PR creates a **new** `RevocableMockAuthorizationBroker` class and
does **not** alter the frozen broker/Unix-IPC paths from #279–#282.

## Atomicity and evidence

Trusted broker code may call `revoke(frozen_request_sha)`. The function
accepts only the exact SHA of the frozen offline Task15 request and uses
SQLite `BEGIN IMMEDIATE` to insert an immutable revocation record with
one durable `REVOCATION_COMMITTED` event. Duplicate revocation is
idempotent.

Mock dispatch performs the inherited Ed25519 grant validation, then
starts a SQLite `BEGIN IMMEDIATE` transaction. **Within this SAME writer
lock**, it reads the revocation ledger before inserting its unique
`DISPATCH_UNKNOWN` claim. If revoked, it rejects without any sink
call or new dispatch row. Only an already committed claim can continue to
the local-only mock sink.

20 adversarial tests cover signed stolen-key HMAC, preclaim revocation,
persistence across reopened Broker instances, identical and newly
re-signed grants, both authorized and impersonating worker denial,
concurrent revocations, 32 concurrent claims after revocation, malformed
authority, grant drift, tampered audit, missing ledger and UNKNOWN states.

The saved proof bundle MUST archive two independently readable SQLite
databases showing BOTH outcomes:

- **Revoke wins first:** durable revoke row=1, dispatch row=0,
  mock sink effects=0.
- **Stolen grant claim wins first:** one already-authorized mock effect
  may be observed before the revoke; future claims denied. This is a
  **negative security result**, not a false pass.

Artifacts contain a canonical TEST grant, test-only Ed25519 public root,
synthetic stolen-session HMAC, source/receipt hashes, JUnit and each raw
SQLite file. This is a deterministic *trusted in-process broker core*
verification, not OS Docker/IPC integration.

## Exact replay

The dedicated workflow pins cryptography==50.0.0 on Ubuntu Python 3.11:

`python scripts/task15_stolen_session_revocation_audit_v1.py --output-dir results`

No billable OpenAI calls, network destinations, API secrets or banking
effects are exercised.

## Explicit limitations

Revocation is not retroactive. If the attacker with a stolen key and
copied, otherwise valid signed grant wins the race before revocation,
the *single allowed mock effect* may happen. That is the accepted bound.
The revocation authority is a **trusted local method**; it has NOT
undergone external operator enrollment, authentic UI approval, privileged
service isolation or authenticated Unix IPC exposure review.

The test uses the identifier-only Task15 frozen request and does not
prove complete native AgentDojo message/tool payload authenticity.
The previous #282 Docker proof is unchanged. The new revocation
class is **not yet wired to the Docker socket broker**, so the result
does not establish production execution-boundary coverage.

Do not claim system-level PROVEN on green CI alone.
Do not merge until exact-head CI and raw ZIP + SQLite evidence are
independently checked. No real Provider usage is authorized by this PR.
