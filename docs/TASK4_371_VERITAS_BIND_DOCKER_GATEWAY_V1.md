# Task4 #371 — SHA-pinned VERITAS OS bind admissibility in Docker broker

## Exact upstream code, NOT a surrogate implementation

The CI checks out exactly `veritasfuji-japan/veritas_os`
`b1835c9f5044855a7b69f82de997056bba8847ab` and copies the unchanged
`veritas_os/core/continuation_runtime/bind_admissibility.py` into the Docker
image as `/app/veritas_bind_admissibility.py`. Git checkout pin, SHA-256 of
the checked-out source, and SHA-256 of the **inside-image** copy must match.

The broker calls the actual upstream
`evaluate_bind_admissibility(BindAdmissibilityInput(...))` at **each execution
attempt** before it calls the existing #370 single-use SQLite broker and
synthetic sink. A positive evaluator result alone is never authorization.

## Trust and synthetic signals

The trusted CI host creates a **test-only HMAC-signed** Task4 grant and a
**separate signed context** for each arm. The context is mounted read-only
into the broker at `/trusted-bind`; the untrusted worker does not have access
to the context or the signing/sink private key.

The broker verifies both signatures and the exact statement SHA before
invoking VERITAS. The following values are **fabricated trusted-host fixtures**,
not production observations or true delegated authority:

- `authority_signal` / required constraint signals
- `live_state_fingerprint` and expected fingerprint
- `runtime_risk_signal`
- TTL expiry and human-approval freshness expiry

Runtime time itself is taken from the broker. A failed source signature or
VERITAS BLOCK/ESCALATE yields HTTP 403 before the SQLite/effect path.

## Negative and positive cases in real Docker isolation

Seven signed-host-fixture negatives exercise real VERITAS reason codes:
`BIND_AUTHORITY_INVALID`, `BIND_AUTHORITY_MISSING`,
`BIND_CONSTRAINTS_VIOLATED`, `BIND_DRIFT_DETECTED`,
`BIND_RUNTIME_RISK_UNACCEPTABLE`, `BIND_TTL_EXPIRED`, and
`BIND_APPROVAL_STALE`. A separate signed-context tamper fails signature
verification *before* the evaluator.

After restoring eligible trusted fixtures, the two independently signed
synthetic A/B operations each pass the VERITAS re-check, then #370's
SQLite one-use consume-before-dispatch gate and backend sink HMAC key.
Exactly **two local mock sink effects** and two durable receipts must exist.
An eligible A replay is independently refused by the one-use ledger.

The Docker front/back internal networks remain isolated. The broker makes
the positive TCP connection to the sink; a front-only agent cannot directly
connect to the **actual backend IP** or external TEST-NET IP. A deliberately
backend-attached rogue lacks the sink credential and receives HTTP 403.
All worker processes run nonroot with read-only rootfs/caps dropped, no
Docker socket and no published ports.

CI emits JUnit + a full evidence bundle with the exact upstream source pin
and digest, Docker network/runtime/mount verification, ten real evaluator
calls (7 BLOCK/ESCALATE + 3 eligible including replay), negative worker
responses, two correlated mock effect records and SQLite rows, and hashes.

## What this does NOT prove

**The actual upstream VERITAS code used here is a deterministic bind-time
admissibility evaluator, NOT the complete VERITAS OS signed authorization,
live authority revalidation, Bind capability consumption and effect
reconciliation runtime.** Input authority, constraints and risk are
controlled signed TEST fixtures; no real administrator, enterprise IAM,
external credential trust, external bank operation or Provider inference
is involved. Test HMAC is NOT a real human approval. Docker daemon/host
remains trusted and privileged. A malicious host or process holding the
Docker socket could bypass test boundaries.

Accordingly, claims such as 'production VERITAS cannot be bypassed' or
'end-to-end real decision-to-effect PROVEN' are **not supported** by this PR.
Real Provider calls, real bank effects, and billed model use are all zero.
No earlier API approval is reused.

## Next stronger proof

Move to a genuinely production-shaped external authorization artifact,
runtime Bind consumption, IAM/credential-scoped execution, independently
enforced network policy and reconciled external effects, with third-party
audit evidence. Repeat untrusted bypass tests at that boundary, not merely
at Python/Docker fixture layer.
