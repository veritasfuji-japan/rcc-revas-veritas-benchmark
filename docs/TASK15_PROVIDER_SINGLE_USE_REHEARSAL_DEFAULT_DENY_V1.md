# TASK15_PROVIDER_SINGLE_USE_REHEARSAL_DEFAULT_DENY_V1

**DRAFT / NOT PROVEN until exact-HEAD CI and independent artifact verification.**

## Rule-of-One

For exactly one frozen Task15 native-source request, create a **NON-EXECUTABLE local rehearsal plan** that captures the future intended provider/model/cost boundary and can be consumed only once by a single Python-process object. Under 16 concurrent in-process attempts, exactly one may finish the rehearsal and 15 must be refused. An invalid or expired consume must permanently burn that same local rehearsal attempt.

**No live provider authority is issued**; `attempt_live_provider` always raises, regardless of supplied transport or self-attested consent.

## Immutable source and requested scope

- Exact audited #269 merged main: `5206a8e032362f0c362dba444a99ce38dd146a87`.
- Replay the entire bounded #269 predecessor proof chain before any rehearsal.
- Verify all 16 prior `Task15 × A/B` native-source records are structurally closed, source-call IDs unique, model snapshot exact, no prior calls, approvals or live model response.
- Select only the frozen first Task15 case/Arm A for the local rehearsal. Bind its exact native postread request SHA, tool schema SHA, original user SHA and native read Call ID.
- The named `gpt-4.1-mini-2025-04-14` snapshot and historical **$5 ceiling** remain frozen. This is a historical ceiling and **is not permission to spend**.
- The fixed nonce explicitly names itself as a **public offline rehearsal marker**. It is not a secret or signed authorization.
- A fixed UTC `issued_at` and `expires_at` are verified in the local test. No future clock trust is asserted.

## Evidence gates

- `15/15` new JUnit tests pass, no skip/error.
- `14/14` adversarial failures covering 2 incorrect predecessor records, 6 draft-construction violations, 5 consumed-invalid-or-expired cases and 1 direct live transport refusal.
- In a 16-thread simultaneous attempt on the same in-process object, exactly **one** `LOCAL_REHEARSAL_CONSUMED` and **15** refused competitors. A failed consume burns the attempt; even a later corrected request cannot retry it.
- Validate local plan/receipt SHA against exact #269 frozen source manifest, model and historical budget.
- **0** actual Provider calls, charges, native writes, scorer or external effects.
- Source hashes, frozen model configuration Git blob, pinned runtime repository source blobs, cumulative replay proof and ZIP SHA are independently audited.

## Explicit nonclaims and remaining work

This is a *process-local simulation* of the issue/consume semantics, not an authentic provider capability.

It does **not** establish a trusted operator signature, an external human approval record, durable atomic cross-process or cross-machine replay protection, live response authenticity, an actual provider request/response, real billing safety, a production source pin or effect-sink enforcement. A public/deterministic rehearsal marker is not a secure token. A SHA-256 is an integrity comparison, not an issuer signature.

The future independently reviewed real-provider implementation must separately establish: explicit new human consent scoped to exact cases/model/spend ceiling, trusted issuer, persistently recorded atomic one-use ticket, revocation/expiry and material-drift handling, network isolation, actual transport request/response evidence, authenticated capture and unforgeable issuance. Even real AI provider responses must not grant banking effects; RCC + VERITAS Bind approval at the final effect boundary remains mandatory.

**No permission is given by this PR to make even one billable provider call. Do not merge until all latest-HEAD CI and independently downloaded artifact checks pass.**
