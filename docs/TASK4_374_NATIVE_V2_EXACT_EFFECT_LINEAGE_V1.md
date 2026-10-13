# Task4 #374 — one observed Native-v2 authorization→effect→receipt lineage

## Objective

This PR builds on the already present, opt-in **current Bind ACTION capability
compatibility** integration. It makes the full **same-run, same-target, same
operation** evidence machine-checkable across exact authorization, PostgreSQL
single-use consumption, native immutable final dispatch/permit, controlled
TLS sandbox effect, independent read-only reconciliation and Bind/Outcome
receipts. **No v1 LABA grant from #373 is relabelled or reused.**

The authorization and exact action are **Native Bind Authorization v2**, issued
by the genuine source pinned in
`current-bind-action-capability-compatibility-v1.yml`:
`veritas_os` `9b7376ba0077365b9d89004b06c80e76c8bfadc8`.
Ben's source is pinned separately to
`1d3782d3aae5ff9c88036709c1a5642320cc53c2`.

This is the **same existing TLS sandbox** at the independently configured
`https://sandbox.example.invalid/v1/events`, *not* the distinct HTTP-only
mock-effect sink in #370–371. Crossing from #373's unrelated LABA-v1 billing
fixture or authorizing #371's sink is explicitly forbidden.

## What actually runs (same action)

The pinned integration already exercises the real `/v1/decide` controlled
decision chain, candidate promotion, Native-v2 signed issuance and independent
verification, PostgreSQL atomic `consume_native_bind_authorization`,
`execute_sandbox_bind` pre-effect ownership, a single
`SandboxHTTPSTransport` network send guarded by `BoundExecutionPermit`,
a separate PostgreSQL-backed sink, independent read-only recovery and
reconciliation, and publication of Bind and Outcome receipts.

Task4 #374 adds a strict evidence extractor and validator executed against
those returned **actual runtime objects**, never against a fabricated PASS flag:

1. Verified promotion execution-intent hash, exact signed v2 authorization
   target/action/subject and native authorization ID/hash.
2. Durable consumed authorization ID/hash/intent, and exact dispatched
   authorization ID, consumption ID, payload digest and idempotency key.
3. Target-owned sandbox operation identity, persisted payload digest and
   idempotency key extracted from the independent read-only reconciliation
   archive, not inferred from the HTTP 201 ACK.
4. Archived reconciliation proof hash and terminal confirmed-effect status.
5. Bind receipt `governance_identity` and Outcome receipt `metadata` plus
   observed effect IDs, verified against the *same* target operation,
   authorization, consumed record and payload.
6. Post-reconciliation replay of the same v2 authorization must fail with
   `NABC_ALREADY_CONSUMED` without a second send.
7. A modified target of the genuine signed authorization must fail v2
   signature/governance verification before any consumption or send.

The integration report includes `task4_374_native_v2_trace`,
its canonical SHA-256, seven strict cross-boundary invariants and
explicit nonclaims. The pre-existing compatibility pytest now requires,
revalidates and checks this evidence against exact values. A separate
non-networked unit suite corrupts target, subject, operation IDs, hashes,
durability, dispatch count, archive values, receipt fields and claim flags;
all variants must be rejected. These unit fixtures are regression inputs,
**not** the source of successful runtime evidence.

## Critical nonclaims

- The authorization issuer and policy inputs, credentials, Ben model output,
  action and target are **synthetic controlled test inputs**. Their Ed25519
  signatures are genuine but not independent enterprise approvals.
- Real PostgreSQL and real TLS are used in the bounded CI sandbox; a production
  IAM/credential authority, commercial target, or third-party reviewer is not.
- The sandbox's target-owned persistence and independent read-only lookup are
  part of the same **operator-controlled local testbed**. They are not
  independent business consequence verification.
- No new Docker front/back bypass trial is executed here; #370's network
  proof concerns a **different** mock sink. This PR does NOT claim real
  cross-process / cross-network bypass resistance at the Native-v2 target.
- The existing current-Bind compatibility workflow has previously shown an
  intermittent `CONTROLLED_ACTION_ACK_MISSING` on the local test service.
  This PR does not waive, suppress or reinterpret this failure. A failed
  dispatch ACK or UNKNOWN is **not** evidence that an effect did not occur.
- No live model Provider, real bank effect, paid API, production release, or
  enterprise authority is enabled or authorized.

## Merge gate

Require the exact-HEAD `Current Bind ACTION Capability Compatibility V1`
workflow to generate an actual Native-v2 report **with the new matching
lineage fields**, pass the extended fail-closed compatibility test, and upload
the report artifact. Require separate unit tests, full PR CI and source
SHA matching, then repeat applicable CI after merging. If the intermittent
ACK problem recurs, investigate it rather than removing the equality checks.

**Next stronger proof:** run the exact same Native-v2 signed target and
PostgreSQL consume→effect→reconcile path from a Docker-isolated untrusted
agent, with credentials and network policies that independently forbid
a direct endpoint bypass.
