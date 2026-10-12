# Task13 #334 — Exact pre-Bind admission handoff and one-use local CAS

## Purpose: a bounded engineering seam, not a new live authority

#333 introduced cryptographic checking of **two separately signed inputs**: the original user request and the actual native file-read bytes. It intentionally returned \`dispatch_allowed=false\`, because the two receipts do not themselves authorize a protected action or prove independent external issuer ownership.

#334 composes that unchanged verifier with a **third separately signed, exactly scoped approval** and an isolated **SQLite compare-and-swap** reference consumer that commits exactly once. The candidate/prestate is checked **immediately before** the local CAS and **again immediately after**. This models the handoff contract a future protected VERITAS Bind executor would need. It **does not call the actual Bind executor**; #330–#332 separately covered local native Bind under test-only authority.

The approved operation is only:
- \`banking:user_task_13:update_user_info:address_only\`;
- exact immutable original request, file content, source-signed receipt digests, full initial native state and original RCC \`CandidateAction\` SHA-256;
- \`allowed_tool=update_user_info\`, \`allowed_fields=[street,city]\`, \`max_uses=1\`;
- an explicit issuer, grant ID, session ID, issue time and expiration bounded to both upstream receipt expirations (up to 5 minutes).

The third approval signature is domain-separated from the first two, and its public key, issuer ID and key ID must all differ from both source signers. The separate public keys are supplied by the caller; this PR **does not prove their owners or provisioning were independent**, only the cryptographic property of **not sharing the same identifiers and keys**.

## Atomic test grant and known limitations

The grant lives only in a freshly created \`*.sqlite3\` file under the system temporary directory, with \`ISSUED_LOCAL\` / \`CONSUMED_LOCAL\` states and one unique attempt. The local consumer opens a SQLite \`BEGIN IMMEDIATE\` transaction, conditionally updates the exact grant bound to the **approval payload SHA-256**, commits, and reads back the durable local fixture state from a separate connection. Concurrent attempts are rejected except one; **reusing the same grant after an error is forbidden**.

That demonstrates **one-use behavior of a local fixture**, not immutable enterprise grant custody, true database role isolation, privileged-admin bypass resistance, a protected TrustLog, external IAM, signed consumption evidence, live approval, an egress fence, or production CAS. Do not substitute the local SQLite database for the separately deployed protected ledger / IAM / Bind executor. In particular, whether a fresh snapshot reader is a truly protected observation is unproven here.

The two snapshots are compared to the original SHA-256. If the prestate changes before consume, the gate rejects without spending. If it changes after a committed local consume, the gate still rejects and the local grant remains spent (no automatic retry / reissue). On missing receipt, wrong signature, untrusted scope, changed request, changed model candidate, stale approval, unknown backend condition, or mismatched digest, **deny**.

**Even when every local condition passes, the return values are always \`execution_authorized=false\` and \`dispatch_allowed=false\`.** Status \`TEST_LEDGER_CONSUMED_BOUND_CANDIDATE_NO_DISPATCH\` means only that a synthetic in-memory signing and local SQLite grant was consumed. No protected callback is exported and this module cannot execute a bank operation.

## Evidence freeze and exact scope

- Parent benchmark \`main\` SHA: \`5c38fa43006b4fb735639ca94563fb38f85cd3d9\` (#333 merged).
- Existing #333 verifier Git blob: \`a3c5d5598c77864ee18ab898c071ef859f4012d2\` (unchanged).
- Original #330 candidate and policy Git blob: \`89da7794ee62bf092a1a7547e1d603c8a92fcbb8\` (unchanged).
- Task4 standalone PostgreSQL local-CAS prior-art source Git blob: \`0b891930f50fc17747a9854666450c9438ef7945\` (no reuse of grant / approval or execution implementation).
- The frozen contract: \`contracts/TASK13_334_TEST_ONLY_PREBIND_SINGLE_USE_V1.json\`.
- The test suite exercises exact signatures, source cross-bindings, session and third-party approval scope, 5-minute bound, out-of-scope and post-candidate tampering, missing receipts and approvals, 12 concurrent local attempts, duplicate grants, TOCTOU before/after CAS, unknown remote condition and explicit non-promotion to production.

Historical V13 Task13 cases #1/#2/#5/#8 did not contain independently signed request/file-read proofs and would remain **DENIED**. This PR does **not** reconstruct or back-sign their historical user request / document, change any global runtime resolver, or claim recovery in the previous two V13 Utility regressions.

The in-process test signers are **locally generated only**, not deployed trusted actors; the signed approvals are **TEST ONLY**, not real authorizations. There are **zero Provider API calls, real bank operations, actual native Bind calls, new user-task or native attack scorer calls, real Utility recoveries, or Final128 remeasurements**.

## Remaining blockers (must be solved outside CI and repository)

A genuinely independent, protected request issuer, native file-read provenance service, approval authority, trusted time and one-use grant ledger must be deployed **outside** ordinary agent/code-editor/PR CI. Production needs proof of trust-root ownership, stable workload identities, IAM/network non-bypass enforcement, durable receipt and consumption under a privileged role, policy admission and actual runtime Bind, reconciliation and original model A/B terminal continuation plus official native scoring. **#334 does not attest any of these.**

The engineering next step after #334 should be to obtain real independent issuer and protected ledger evidence from a cooperating runtime/operator — or clearly stop and treat missing external deployment as a blocked prerequisite. Repeating local simulation cannot alone become the Final128 safety/Utility proof.
