# TASK15_MOCK_EFFECT_UNKNOWN_RECONCILE_V1

**Draft / NOT PROVEN until latest exact-HEAD CI and independent artifact audit.**

## One invariant

Once a **durable dispatch fence** has been recorded before a mock-provider operation *may* have started, a missing result must remain **DISPATCH_UNKNOWN** until an **independently persisted local mock-provider effect row** supplies a matching receipt that can be verified by a **read-only** lookup. Neither timeout, absent receipt, crash, empty provider query nor a local claim can independently justify `NO_EFFECT` after the dispatch fence. No automatic resend is permitted.

A positive receipt-backed lookup moves `DISPATCH_UNKNOWN → CONFIRMED_MOCK_EFFECT` **only inside the simulator**. A deliberate abort **before** the dispatch fence moves `CLAIMED_UNRESOLVED → PRE_DISPATCH_NO_EFFECT`.

## Source and semantics

- Exact merged #271 main predecessor `c32de2526ee5e2fd454fd1359ef985d582caf2c8`; replay #271’s full bounded proof chain.
- Same canonical Task15 first-case A-arm synthetic original request, native request/tool/user SHA-256, offline prior proof and source plan.
- Two separate SQLite databases, controller and **simulated local mock provider**, on one host. `BEGIN IMMEDIATE` and SQLite WAL/FULL for each independently stored mock consequence.
- Controller persists `ISSUED_OFFLINE → CLAIMED_UNRESOLVED → DISPATCH_UNKNOWN` **before** any mock send. A volatile one-time dispatch grant is consumed before invoking the mock database; after crash/reopen the grant is **not** recreated.
- Mock provider writes a separate `mock_attempts` and `mock_effects` table with a unique operation key and receipt hash, to simulate an external effect receipt. This mock receipt **has no real-provider authenticity**.
- `reconcile` reads the mock-provider database without sending again. A provider row must have a matching operation ID, plan SHA-256, canonical payload and receipt hash.

## Six exact scenarios

| Scenario | Durable controller outcome | Local mock rows |
|---|---|---|
| Mock provider delivered with receipt | `CONFIRMED_MOCK_EFFECT` | 1 |
| Mock provider effect committed, ACK lost | `CONFIRMED_MOCK_EFFECT` after read-only reconciliation | 1 |
| Dispatch fence persisted, mock effect absent | `DISPATCH_UNKNOWN` | 0 |
| Abort before dispatch fence | `PRE_DISPATCH_NO_EFFECT` | 0 |
| Crash after mock effect commits, before controller records receipt | `DISPATCH_UNKNOWN` then `CONFIRMED_MOCK_EFFECT` on read-only recovery | 1 |
| Crash after fence, before any mock effect | `DISPATCH_UNKNOWN` (no retries) | 0 |

**Evidence gates:** 15 new JUnit cases including 14 refusal scenarios; raw controller **and** mock-provider SQLite snapshots for all 6 cases plus the intermediate crash-unknown state (14 raw SQLite files total); SQLite `PRAGMA integrity_check=ok`, independently calculated SHA-256, controller table and journal sequences, simulator receipt rows, exact prior source joins, no real provider calls or effect. Failing source pins or archived prior proofs must fail closed.

## Strict limits

This is **simulated consequence assurance**, not a live OpenAI completion, banking API write, real external provider acknowledgement, trusted attestation or real financial transfer. Mock provider IDs, receipt hashes and data are synthetic, and **cannot establish actual provider authenticity**. The simulator's SQLite database is an independent test-data ledger, not an independently operated third-party service or trust root.

No signed human approval, live provider execution right, real billing cost, trusted UTC, cross-host/network effect reconciliation, crash-safe external-provider exactly-once commit, full AgentDojo task success, Final128 Utility or Injection Success is proven.

**No real provider transport, API keys, or bank effects are present or authorized. Do not merge until exact-head workflows and independent artifact evidence pass.**
