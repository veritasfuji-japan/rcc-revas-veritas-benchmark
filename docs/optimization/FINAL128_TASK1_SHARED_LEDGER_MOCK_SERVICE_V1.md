# Task1 — cross-Runner-shaped shared local ledger mock service V1

**OFFLINE NO-EFFECT / NO-GO: Issue #427 OPEN. No paid or actual Provider authorization.**

## Actual executable experiment

Building on #446 and #448, this local test has **four or more independent OS processes**: two simulated Runners with distinct scratch directories, one local fake Executor, and one separately launched durable SQLite ledger server. Each simulated Runner knows only the Executor's UNIX socket and a test-only signed handoff. It does **not** receive the ledger socket, SQLite path, internal HMAC capability or Provider credential. Executor checks the synthetic Ed25519 handoff (#437), the frozen research NO-GO snapshot (#441), and the exact fake first-packet hash (#442), then contacts the ledger service before invoking its own in-memory fake Provider port. No actual Provider call occurs.

The central ledger service performs SQLite `BEGIN IMMEDIATE` with `synchronous=FULL` and commits `UNKNOWN_A` or `UNKNOWN_B` **before** the simulated send. Its A->B state machine permits B only after the ledger confirms A_ACK. Invalid signature, first-B request, duplicate attempt, corrupted fake ACK, fake timeout or a ledger outage denies or stops the local effect. Server restart on the **same host and same DB file** preserves spent A/B attempts; resetting the Executor process does not reset the shared ledger. A direct local client without the ephemeral test-only HMAC capability cannot issue a reserve to the ledger socket.

## Demonstrated positive/negative cases

- Two local simulated Runner processes, each with its own scratch directory and neither holding the ledger path, compete through one Executor and shared ledger. Exactly one fake A is ACK; another is denied, and B can occur after A_ACK.
- Executor and ledger restarts reuse the existing SQLite record and deny replay; unexpected local fake ACK or timeout preserves UNKNOWN and prevents retries.
- A forged local ledger HMAC, modified Ed25519 handoff, incorrect run scope or paid-consent claim is denied before fake effects; a ledger connection outage fails closed.
- **Counterexample:** Two isolated ledger processes using **different ledgers** still both accept the very same signed fake A. In the local test, all services are the **same UID** and a caller with that UID can write the SQLite file. The supervisor holds the shared mock HMAC key. Hence this is **not** a secured credential boundary against malicious same-UID callers and **not real GitHub cross-Runner uniqueness**.

## Critical missing deployment requirements

A real Task1 Executor must have its own independently authenticated principal and exclusive custody of the actual Provider key, a separate remotely accessible and durable atomic ledger under an independent security domain, authenticated caller identity and signature/consent provenance, real VERITAS Bind at the last Provider send boundary, and IAM/egress policy which denies all other Provider traffic. A real independent GitHub-hosted Runner A versus Runner B test is needed. The #423 actual sender still bypasses this mock. Even the existence of one remote ledger would not alone prove that no alternative direct Provider credential or path exists.

Neither this test's UNIX socket, host-local SQLite DB, synthetic HMAC key nor successful CI makes those controls true. In particular, an authenticated party who can create a new approval digest or reset a ledger could still replay absent external controls. These are test-owned data/effects, **no Provider request**, no bank effect, no Native utility scoring and no actual paid billing cap.

## Change and acceptance boundary

Exactly **three new files**: this document, `scripts/final128_task1_shared_ledger_mock_service_v1.py` and `tests/test_final128_task1_shared_ledger_mock_service_v1.py`. No existing workflow, live #423 sender, API client, Secrets, Environment, ref/tag, Ruleset, pinned source or billing setting is changed. Only normal PR CI tests are expected; no manually triggered paid workflow or tag write.

Merge only after the reviewed exact HEAD passes dedicated and inherited tests with no relevant skips/failures, and **do not close Issue #427**. The final claim is *local separate-process ledger centralization with cross-Runner-shaped simulation*, **not** remote/multi-host production enforcement or real IAM/egress isolation. Paid Task1 remains **NO-GO**.
