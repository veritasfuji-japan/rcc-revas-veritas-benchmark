# Synthetic Owner backend: independent OS-process race, crash and restart tests v1

**RESEARCH-ONLY / LOCAL SQLITE / NO NETWORK / NO REAL PROVIDER.**

Follow-up to merged PR #588. The existing `ci_mock_owner_backend_atomic_v1`
signed Owner checker and `ci_mock_executor_authority_boundary_v1.backend_store`
SQLite schema are exercised from **real separate OS processes** sharing one
temporary SQLite file. The test does not replace the existing protected
UID/netns HTTP backend integration and makes NO production effect claim.

## Four exact experiments

1. **Revocation wins.** The policy-writer process acquires SQLite
   `BEGIN IMMEDIATE` first. An independent effect process starts while
   that write lock is held. The writer commits revocation, after which
   the effect reader acquires the transaction, validates the same signed
   approval and denies. After closing and re-opening through the real
   mock `backend_store(restart=True)`, counter=0, spent=[], policy epoch=1.
2. **Effect wins.** Effect process validates Owner and holds
   `BEGIN IMMEDIATE`. A second OS process tries to update revocation
   and must observe actual SQLITE_BUSY. The effect process commits one
   signed-Owner-authorized mock counter update/receipt; only then the
   policy writer may acquire the lock and commit revocation. After
   restart, counter=1, spent contains exactly one expected receipt,
   policy epoch=1, and a replay is denied. This is serialization, not a
   guarantee that revocations occurring later can retroactively block
   already committed effects.
3. **Crash before effect commit.** A separate OS effect process validates
   Owner and writes pending counter and spent changes but calls
   `os._exit(73)` *before* SQLite COMMIT. Restart verifies rollback:
   counter=0, spent=[]. A subsequent revocation commits and prevents
   a later attempt.
4. **Crash after effect commit but before acknowledgment.** Effect process
   COMMITs the exact mock receipt/counter, then calls `os._exit(74)`
   without reporting success. A fresh backend open verifies counter=1,
   spent=exactly one receipt; a second OS process cannot replay it.
   This establishes a local unknown-to-caller situation, not a
   validated external provider acknowledgment.

All process exits are checked, all barriers use finite timeouts, and
the workflow requires exactly four named JUnit cases with no skips.
The test cases do not use bank/provider credentials, HTTP clients,
external effects, provider API calls, or a real Owner key.

## What remains unproved

- These are **same-host shared-SQLite process tests**, not independent
  distributed databases, full protected UID/netns traffic, provider
  semantics, or atomicity between Custody and backend.
- The Owner identity and revocation authority are deterministic local
  fixtures, not genuine consent or an externally trusted authority.
- The signed validity interval still relies on synthetic logical ticks,
  not a verified monotonic time source.
- A crash *after COMMIT* must not be interpreted as proof of real external
  effect; this test only verifies the local mock database.
- Combined protected-Custody subprocess faults, backend-kernel isolation,
  multi-node fencing, epoch rollback, and recovery under actual network
  message loss require independent proof before widening claims.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN**
