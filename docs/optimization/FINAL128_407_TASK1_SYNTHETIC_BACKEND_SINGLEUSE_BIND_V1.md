# Final128 #407 — cross-UID synthetic effect, real VERITAS Bind COMMITTED, atomic single-use backend

## Scope and parent

Parent #406 merged at \`22f44ea70d8b1625c4af64ff8c11208456ce400e\`.
Frozen AgentDojo banking v1.2.2 pin
\`a75aba7631d3ca5fb7ab938965c97ead2f9ff84b\`,
VERITAS pin \`a1d66aef02262cf8a913295270c3aafd159c6adb\`.
Existing Task1 DirectAttack and 128-case enrollment stay unchanged.
All inherited #406–#377 coverage is retained.

Unlike #406's read-only + all-writes-denied tests, this PR adds a
**separate source-owned synthetic effect** to demonstrate a legitimate
bounded COMMITTED path. It does not change Task1 mutation policy:
**native Task1 still rejects \`send_money\` using real VERITAS Bind**.

## Three Linux principals + test supervisor

1. \`veritas407agent\`: untrusted client, may submit versioned JSON through
   a \`0660\` gateway UNIX socket.
2. \`veritas407gateway\`: holds the authorization logic. It keeps a full
   pinned Native Task1 source+guard, and for exactly one *synthetic* effect
   invokes genuine pinned \`execute_bind_adjudication\` with a
   \`ReferenceBindAdapter\` specialized for an external mock backend.
3. \`veritas407backend\`: separate kernel UID and UNIX socket. This process
   alone owns the simulated ledger state and consumed-grant state; kernel
   \`SO_PEERCRED\` admits ONLY the exact gateway UID to read/apply. Agent
   and unrelated IPC-group member cannot submit backend mutations directly.

The GitHub runner supervises only installation/startup and collects
redacted receipts. It is explicitly privileged and **not an attacker**.

The grant is frozen in test source, clearly labelled
\`offline-fixture-grant-407-ONE\`. It authorizes exactly an increment of 7
units on \`offline://407/only-synthetic-counter\`. It is **not** a human
approval, secret, bearer token, live credential, real external payment,
Native user-task permission or reusable production policy.

## Commit sequence

- Negative cases: forged grant, wrong target, wrong units, type-confused
  boolean, unsupported operation, unknown attribute and extra authority
  field all reject. OS principal restrictions block direct agent→backend
  and stranger→gateway, even with correctly formatted JSON.
- Positive source-owned request: gateway constructs a pinned
  \`ExecutionIntent\`, snapshots the actual backend's prestate, evaluates
  real VERITAS Bind admissibility with exact policy constraints, and only
  **inside the Bind adapter's \`apply\`** asks the separate backend to
  perform the one allowed synthetic effect.
- Backend verifies its kernel-observed gateway UID, exact action, resource,
  integer units, source-owned grant and unspent state. In one serialized
  event-loop branch, the backend **consumes the grant and mutates its
  in-memory counter exactly once**. It returns a synthetic effect receipt
  hash plus poststate hash.
- The Bind adapter independently queries backend state and validates
  postconditions. Real Bind must return **COMMITTED**. The test reconciles
  Bind receipt hash, backend receipt hash, state hashes, exact effect count
  and integer delta.
- Identical replay is refused by gateway and remains consumed at backend.
  No other principal can use backend's effect endpoint.

## Important nonclaims

This is a **local mock effect backend**, not an actual bank, real
transaction processor or external credential store. All child principals
run on the same test machine under the runner's setup; the supervisor
holds \`sudo\`. There are no production credential issuance, network
egress, IAM, remote authentication, root escape, process integrity or
crash-consistent durable ledger guarantees. The backend's consumed state
is **in memory** and not crash-persistent, not an externally verifiable
global single-use capability system.

The positive grant is entirely source-owned in a test fixture; there was
no independently authenticated human or agent authority. A Python-based
\`ReferenceBindAdapter\` is a real shared VERITAS Bind execution path,
but its *authority and runtime constraint inputs are synthetic and
locally provided*. **CI SUCCESS does not mean production-grade
authorization is PROVEN**.

The mock backend is a separate process, so the effect is external to the
agent/gateway memory, but it is still local and synthetic. The Task1
Native bank is never modified, no real financial effect occurs, and
there are **zero real model/Provider calls** and **zero official AgentDojo
Utility or attack-success scorer calls**.

## What #408 should tackle

- Persistent single-use authorization consumed independently of gate
  restart, with forced-crash recovery/reconciliation tests.
- Independent signed issuance and distinct back-end identity with
  enforceable credentials, revocation, expected-state and postcondition
  proofs for an *actual supported* effect interface.
- Adversarial tests of every alternate external effect credential path,
  plus non-mutating observability of denied effects at the true sink.
- Fresh operator approval before any paid model run, independent genuine
  A/B histories and pinned official Native scoring.

## Required merge gate

- Source pin and original frozen Native enrollment unchanged.
- Actual 3 distinct non-root effect/gate/client Linux UIDs and backend's
  \`SO_PEERCRED\` source enforcement; direct bypasses fail.
- Negative fake/changed/replayed permissions fail before a second effect.
- One real \`execute_bind_adjudication\` returns COMMITTED on the source-owned
  mock target and an independently owned backend reflects **exactly one**
  effect, consumed once, with reconciled SHA hashes.
- Same gateway's pinned Task1 Bind still denies protected Native writes.
- No raw attack text or marker content in outputs. No Provider/bank/scorer.
- Redacted evidence + inherited tests all zero failure/error/skip on exact
  HEAD; no IAM/network/real credential/general production PROVEN claim.
