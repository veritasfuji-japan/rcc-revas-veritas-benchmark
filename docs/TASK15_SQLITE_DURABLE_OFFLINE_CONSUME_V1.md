# TASK15_SQLITE_DURABLE_OFFLINE_CONSUME_V1

**Draft / NOT PROVEN. Do not merge without exact-head CI and independent artifact verification.**

## Central invariant

The same **one non-executable Task15 rehearsal plan** from the exact #270 proof, stored with its pinned source hashes, is issued as an offline-only entry in a **single-host on-disk SQLite database**. Sixteen independent Python interpreter processes must all arrive at a database-backed 16-worker start gate. Exactly one process may atomically claim the entry; the other 15 must be refused. A committed claim survives process exit or process crash and **cannot be automatically reclaimed**.

Unlike #270, which used one Python process and a threading lock, #271 exercises SQLite `BEGIN IMMEDIATE` plus `UPDATE ... WHERE state='ISSUED_OFFLINE' AND claims=0` across **separate processes and connections**. Database WAL mode is configured once during issuance, SQLite synchronous FULL used for all connections, with unique ticket IDs and recorded audit events. No provider client or native bank write function exists.

## State semantics

- `ISSUED_OFFLINE`: a public, non-executable planning entry; not a bearer credential or spend approval
- `CLAIMED_UNRESOLVED`: transaction committed *before* checking timestamp and exact source. A worker crash after claim leaves this state durable and non-retryable
- `CONSUMED_OFFLINE`: claim confirmed, offline rehearsal finished; does not mean provider call or effect committed
- `DENIED_BURNED`: invalid/expired usage was attempted and the ticket remains permanently consumed, with no automatic retry

`CLAIMED_UNRESOLVED` must never be silently turned into `NO_EFFECT`, `ISSUED_OFFLINE`, or `COMMITTED`. This simulates an ownership/claim boundary; it is not reconciliation of real effects.

## Evidence gates

- Predecessor main #270: `ec648458d79ef80f6b508b6a489bcda705426920`. Replays exact #270 proof chain before constructing any new ledger.
- One exact Task15 first-case Arm A planning record; matched original user message, tool schema, native read call ID, source request and predecessor proof hashes.
- Sixteen separately started Python processes independently opening the same local SQLite file, synchronized via durable `arrivals` rows. Exactly **one successful local consume / fifteen durable claim refusals**.
- Three row-event audit entries for the positive proof: ticket created, atomic claim committed, offline rehearsal finished. Exactly one claim count and a persisted `CONSUMED_OFFLINE` row.
- Test process deliberately exits with code 73 **after a successfully committed claim**. Reopened SQLite DB must show `CLAIMED_UNRESOLVED`; another process must be denied.
- Fourteen separate negative tests cover fraudulent previous evidence, duplicate issuance, wrong ticket, wrong owner, crash after claim, wrong/expired time, altered plan or historical budget, false operator approval and live transport.
- 15 new JUnit tests, 14 refusal JSONL entries, pinned Git source blobs, exact case evidence, output summary and downloadable artifact. All checked independently before promotion.

## Scope limitations

- **Single local filesystem and single host only.** SQLite WAL/FULL with an on-disk database is not proof of distributed cross-machine consensus, NFS correctness, physical power-loss protection, trusted time, or durability of real network effects.
- The ticket is a public, deterministic **offline rehearsal marker**, not a cryptographic capability, user credential or authenticated signer. Process owner strings are not identity credentials.
- The historical $5 model-spending maximum is a ceiling only, **not permission to spend**. API calls, charges, scorer invocations, real bank mutations, external effects and authenticated AI response captures must remain zero.
- Atomic local claim does **not** equate to safe execution/receipt reconciliation. There is no real provider call to reconcile; unknown real effects would require a later independently reviewed architecture.
- No injection resistance, real model behavior, paid Final128, production issuance, effect-sink guarantees, or general production readiness claims.

**This PR never authorizes or performs an API call. Actual live provider operations require fresh explicit case/model/budget authorization, trusted issuer, source pin and separate auditable one-shot execution infrastructure.**
