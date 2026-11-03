# Ben Owner Approval: Bind → Single-Use → Effect Sink Trace v0.1

**RESEARCH ONLY / NO AUTHORITY / NO POLICY ACTIVATION / NO PROVIDER DISPATCH**

Follow-up to merged #580. This is a **bounded source-and-evidence gap analysis**, not a successful end-to-end adapter test. Source inspected from the public `veritas_os` default branch on 2026-11-03. Do not publish collaborator-private cases, hashes or fixtures.

## Direct source observations

| Layer | Inspected source | Observation | Limit |
| --- | --- | --- | --- |
| Authority issuance verification | `veritas_os/governance/authority_evidence.py`, `verify_authority_evidence_artifact_to_proof` | Signed claims, approved issuer/key/algorithm, scope, contract, policy, time and revocation are checked before creating proof | Production signer trust root and real invocation path not inspected |
| Authority recheck | Same module, `validate_verified_authority_evidence` | Rechecks proof hash, in-process provenance registry, context, verifier policy, time and stored revocation evidence | In-process registry is **not** durable single-use consumption; fresh dispatch-time revocation source not demonstrated |
| Human approval | `veritas_os/governance/human_approval_receipt.py`, `verify_human_approval_receipt_artifact_to_proof` | Canonical receipt hash, signature result, signer policy, action and policy context verified | Ben proposal is not automatically an issued approval |
| Runtime gate | `veritas_os/governance/runtime_authority.py`, `RuntimeAuthorityValidator.validate` | Secure/prod posture requires verified authority provenance | Does not establish effect sink enforcement |
| Commit gate | `veritas_os/governance/commit_boundary.py` | Commit adjudication invokes runtime authority validator | A `commit` outcome is not a consumed effect permit |
| Synthetic regulated path | `veritas_os/governance/regulated_action_path.py`, `run_regulated_action_scenario` | Builds synthetic decision, execution intent, evaluates commit, creates a synthetic bind receipt and TrustLog-shaped lineage reference | Module explicitly describes itself as **side-effect-free fixture**; `_build_bind_receipt` creates an in-memory dictionary, **not** a proven durable permit or real adapter effect |
| Coverage claims | `docs/en/validation/current-implementation-matrix.md` | Selected operator mutation routes are bind-governed | Matrix explicitly says not all effect-bearing routes are guaranteed covered |
| Architecture | `docs/en/architecture/bind-boundary-governance-artifacts.md` | Describes ExecutionIntent, BindReceipt, FinalOutcome and selected HTTP management-path tests | Documentation is not a direct source-to-sink trace for Ben's chosen target |

## Important correction to avoid false assurance

The AML/KYC fixture's `bind_receipt_id = bind::<scenario>` and `trustlog://bind/...` are generated labels in a side-effect-free fixture. Neither is evidence of an actual persisted Bind authorization, atomic single-use transaction, provider dispatch, or independently observed external effect. Likewise, an official scorer success must not be relabeled as effect confirmation.

## Required source-to-sink investigation

1. Identify the **exact** adapter and effect-bearing operation for the agreed synthetic Ben case, including operation, recipient, amount, date, target and immutable canonical payload.
2. Locate the real Bind issuance call site and prove a permit is scoped to that exact payload and independent trusted owner approval.
3. Locate durable atomic consumption and test replay, concurrent attempts, restart and crash-before/after-dispatch ambiguity. Preserve UNKNOWN where the external outcome cannot be determined.
4. Trace dispatch-time revocation/expiry/clock/policy drift and sink-level rejection; capture a denial before any synthetic effect.
5. Compare audit receipt and externally observable synthetic effect using a separate read-only observer; preserve distinctions between intended, sent, acknowledged and confirmed.
6. Inventory and test bypass paths within a **named deployment and adapter**; no universal closure claim.

## Proposed synthetic negative test matrix (not yet executed)

| Case | Expected behavior |
| --- | --- |
| Trusted owner approval and exact frozen synthetic request | At most one permitted synthetic effect, subject to all checks |
| Unsigned/forged issuer or caller-declared `valid` | DENY, no effect |
| Wrong recipient/amount/date/operation or prestate digest | DENY, no effect |
| Expired/revoked approval or stale revocation evidence | DENY, no effect |
| Post-resolution drift or untrusted clock | DENY or fail closed, no effect |
| Two concurrent consumes or replay after restart | At most one consumption; no second effect |
| Dispatch crash or missing provider acknowledgement | UNKNOWN pending reconciliation, never falsely CONFIRMED |
| Missing/conflicting independent effect evidence | Not CONFIRMED; fail closed for any retry needing certainty |

## Experimental comparison contract

- **L (legacy):** unchanged original authority/policy; paired B and engine on the same frozen cases.
- **O (owner-approved research-only):** independent synthetic signer and verifier; identical new approval conditions for B and engine. Do not attribute L-to-O improvement to engine alone.
- Separate metrics: official scorer, legitimate local state mutation, synthetic effect, SDK attempt/response, and independently confirmed external effect.
- Freeze fixtures, policy digest, harness version, adapter revision and case IDs before the run. No real bank, provider or funds.

## Current decision

**Verified from source:** authority/approval verification functions, runtime provenance gate, and the *absence of real effects in the inspected regulated-action fixture*.

**NOT VERIFIED:** production issuance and trust-root wiring, actual Bind permit/atomic consumption, sink-level matching, dispatch-time revalidation, effect reconciliation, or bypass closure in Ben's adapter.

**REAL_PROVIDER_NO_GO** remains in force. Next deliverable should be a concrete adapter call graph and executable synthetic negatives, not another broad security claim.
