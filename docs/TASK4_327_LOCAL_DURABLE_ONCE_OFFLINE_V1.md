# Task4 #327 — Shared-local SQLite atomic consume-before-send research proof (OFFLINE)

## One central invariant

A single **synthetic** Task4 A/B experiment ID may be claimed only once by independently started Python processes using one physical, shared SQLite file. The test uses `BEGIN IMMEDIATE`, `INSERT` into a `PRIMARY KEY (experiment)` row, synchronous `FULL`, and commits the permanent `UNKNOWN_PERMANENTLY_CONSUMED` state **before any attempted fake/effect-side execution**. There is **no API sender, no release, no upsert, no automatic retry**. The crash-after-commit fixture calls `os._exit(74)`; a new Python process must refuse the same experiment ID.

Parent exactly merged #326 main `0791c5f774bb1e0839b329aa91a0a788bfdfdd9a`. Model parameter `gpt-4.1-mini-2025-04-14`, one banking Task4 direct injection cohort, pinned Native injected prestate and subject SHA values. Existing Native A/B, tokens and scorer are **unchanged**; this is a **new ledger-only test fixture**, NOT connected to a Provider transport.

## Tested behaviors

- **16 separately launched OS Python processes**, concurrent and independently attempting the same synthetic experiment ID with different worker labels and request hashes. Exactly 1 receives a local claim receipt, 15 return `REFUSED`. An independently reopened SQLite file must contain one row and the same recorded receipt.
- An independent process intentionally exits immediately **after DB COMMIT**, before it can return a receipt. The next process must refuse despite its inability to see whether the original caller completed. An ambiguous outcome is never treated as permission to retry.
- A new OS process attempts the same ID after the initial process has ended and is refused. Changed request hash does NOT create another permit.
- Scope spoofing, altered main/model/case/prestate/subject, changing approval flags, credentials in environment, invalid path/hash/worker IDs, changed schema, tampered ledger evidence and forbidden network connections all fail closed.
- No Provider cost, model generation, new Final128/Utility/injection score, production banking effect or change to runtime secrets.

## HARD scope limit: this does not solve cross-GitHub-Hosted-runner single use

**This fixture proves cross-process atomicity when all workers share the SAME local SQLite file on one shared disk.** GitHub-hosted Actions jobs normally have **separate ephemeral disks and independent databases**, even when they run under the same repository. A separate job could independently claim an unshared database and both could succeed. A local SQLite `PRIMARY KEY`, a PR Artifact, and GitHub workflow `concurrency` **are not distributed globally one-shot controls**. A trial ID can also be replayed if an operator deletes/replaces this test database; local SQLite does not attest custody, immutability or independent administration.

No remote CAS backend is implemented. To progress toward an actual one-trial Provider call, #321 must require a remotely shared **non-deletable/non-reusable, independently administered** consume-before-send record, exact durable receipt and conflict/timeout ambiguity semantics, scoped short-lived credential, network and budget protection, and a NEW **explicit** owner-approved trial and cost cap. The record must be consumed **before any Provider POST** and have no retry/resume on uncertain dispatch, including process crash. Passing #327 in a sandbox cannot itself confer any live API authorization.

## Evidence/CI

Dedicated GitHub PR/main workflow on exact HEAD only, no `workflow_dispatch`, `pull_request_target`, protected Environment or secrets. Uses Python standard-library `sqlite3`, pinned Python and pytest, temp shared DB under one run, SHA-256 file/report receipts, complete JUnit and CI output Artifact. All report fields explicitly label the local-only/non-cross-run proof.

Acceptance: exact HEAD CI green, 16 processes/one winner, unknown post-commit no-resend, all mutation refusals, Audit/JUnit verified, all standard checks green, **then** a manual Draft review and merge.

Previous API consent is spent. **REAL_PROVIDER_DISPATCH = DENY** throughout; no live calls are made or approved.
