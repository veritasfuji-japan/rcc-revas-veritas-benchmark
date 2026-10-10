# Task15 Mock Broker Authorization Boundary V1 — PR #279

**DRAFT / NOT PROVEN. No real Provider network request is enabled.**

## Central invariant

A worker-proposed mock model capture must not reach the local mock sink until
the trusted-side broker verifies a signature against its PRE-PINNED Ed25519
public root and durably consumes a single-use claim in SQLite.

Predecessor #278 merged-main SHA: 3d0a319931cd4f43a206cb3d1ac6b3d8e6b8384a.
#278 tested isolated worker network/credential access. This PR does NOT change
the Linux network namespace or the historical live-default-deny path.

## Broker ordering

1. Untrusted callers submit only an exact request and a signed grant.
2. Broker itself supplies pinned operator root and UTC clock, never from request.
3. Frozen model, host, path, case ID, arm, archived wire source hash and mock-only
   zero-spend/no-bank-effect properties are checked.
4. Canonical statement Ed25519 signature and <=10 minute validity are verified.
   Here the operator root is a TEST FIXTURE, not an externally enrolled human.
5. Durable SQLite BEGIN IMMEDIATE INSERT claims the unique request SHA and commits
   state DISPATCH_UNKNOWN BEFORE calling the local mock sink.
6. Only exact MOCK_RECORDED receipts are stored, hashed and journaled.
   All ambiguity remains DISPATCH_UNKNOWN; duplicate/modified grants cannot retry.

The broker has NO network sender and NO real Provider credential. The
synthetic test-only credential is privately configured in the broker object
and not returned in any response.

30 adversarial tests cover signature/root drift, target/model/source substitution,
unauthorized live/cost/bank-effect grant fields, expired and future approvals,
double-claims, 16 parallel attempts, persisted claim across restart, UNKNOWN,
ledger disappearance and tampered receipt detection.

The audit archives raw SQLite backups:
- positive: MOCK_RECORDED, claim_count=1, audit events=2
- ambiguous: DISPATCH_UNKNOWN, claim_count=1, audit events=1

Evidence also includes a signed TEST-only grant, public test root,
request hash, JUnit, and case-level results.

## Reproduction

Python 3.11 and cryptography==50.0.0:

    python scripts/task15_mock_broker_authorization_audit_v1.py --output-dir results

Reviewers must independently verify exact PR HEAD, CI, ZIP digest, SQLite
integrity, signed grant, replay rejection and JUnit before merge.
Green CI alone is not independent proof.

## Explicit nonclaims

This is an in-process authorization CORE, not a physically isolated broker
service. Same-process Python control, hostile write access to its SQLite
directory and privileged-host compromise are OUTSIDE its proof domain.
No production operator trust-root enrollment, clock provenance, Unix-socket
authenticated IPC or secret-vault-backed credential custody is proven.
The mock proposal pins the archived native request SOURCE digest but does
not contain the full actual prompt/tool payload. No billable request,
bank transaction, or external Provider receipt has occurred.

Next: isolate the broker process in a separate round, then test authenticated
Unix-domain IPC and authority/credential custody under OS enforcement.
Real OpenAI transport remains disabled until new explicit authorization.
