# Ben Owner Approval → Authority-to-Execution Boundary Trace v0.1

**Status: REVIEW ONLY — NO AUTHORITY ISSUANCE / NO POLICY ACTIVATION / NO PROVIDER DISPATCH.**

Follow-up to merged #579. Read-only inspection of selected `veritas_os` source on 2026-11-03. **This is not an end-to-end runtime trace or an independent effect test.** The sections below distinguish inspected code from remaining unknowns. No collaborator private case material is included.

## Source-confirmed code paths

| Boundary | Source | Confirmed code behavior | Evidence limit |
| --- | --- | --- | --- |
| Signed authority verification | `veritas_os/governance/authority_evidence.py:367-465` | `verify_authority_evidence_artifact_to_proof` checks artifact type/version, canonical claims hash, verifier result, approved key/algorithm/issuer, contract identity/hash, actor, policy snapshot, scope, temporal validity, signed time, and revocation checker; emits `VerifiedAuthorityEvidence` | The deployment's actual trusted signer, revocation backend and production caller are **not** verified here |
| Authority revalidation | `veritas_os/governance/authority_evidence.py:474-545` | `validate_verified_authority_evidence` checks proof hash and in-process proof registry, context/contract/policy/scope, approved verifier policy, revocation policy and time | Revalidation of recorded revocation evidence is not proof that a fresh external revocation lookup occurs at every effect dispatch |
| Signed human approval | `veritas_os/governance/human_approval_receipt.py:657-735` | `verify_human_approval_receipt_artifact_to_proof` rejects absent verifier, checks canonical receipt hash, signer policy, signature result, action class and policy, and emits a verified approval receipt | Owner identity and Ben's proposed date are **not** thereby automatically mapped to the execution request |
| Runtime provenance | `veritas_os/governance/runtime_authority.py:145-200` | `RuntimeAuthorityValidator.validate` invokes verified authority revalidation; in `secure` and `prod`, missing verified provenance fails the provenance predicate; non-strict posture has legacy compatibility | Do not extrapolate dev posture acceptance to production security |
| Commit decision | `veritas_os/governance/commit_boundary.py` | `CommitBoundaryEvaluator.evaluate` invokes runtime validator and resolves commit/block/escalate/refuse with consistent pass predicates required for commit | A commit decision alone does not prove the effect-bearing adapter consumed a matching single-use permit |

## Important nuance: verification versus execution

- A caller-supplied `AuthorityEvidence.verification_result = valid`, request SHA, or `signature_verified` field is not trusted authority.
- Verification requires a deployment-trusted verifier and approved issuer/signer policy; the cryptographic verifier implementation and production wiring remain to be inspected.
- The authority verifier checks revocation through `revocation_checker.check(..., now=current)` at proof creation. Subsequent `validate_verified_authority_evidence` checks stored revocation evidence against policy and time. Whether an independently refreshed revocation status is required at the **actual dispatch** boundary remains open.
- Both authority and human-approval helpers accept `now` parameters or default to `datetime.now(UTC)`. A trusted clock source and call-site discipline must be proven, not assumed.
- `_VERIFIED_PROOF_REGISTRY` is process-local. It is not evidence of durable atomic consumption or crash-safe replay protection.

## Missing source-to-sink proof (explicitly NOT VERIFIED)

1. Identify the exact production call site that verifies the owner signer and constructs trusted authority and approval proofs.
2. Prove the request/prestate hash binds the **same** target, recipient, amount, operation and date at the lowest effect-bearing sink.
3. Trace the actual Bind permit issuer, immutable dispatch payload and atomic single-use transaction, including concurrency and restart.
4. Trace post-resolution drift, expiry and revocation rechecks immediately before dispatch with a trusted time source.
5. Trace the adapter's fail-closed path and reconcile independent external effect evidence versus internal receipt, scorer and SDK response.
6. Establish that no bypass route is reachable in the selected deployed configuration; do not infer universal coverage from an inventory document.

## Bounded synthetic experiment proposal

**Legacy L:** original unchanged authority and policy; compare B and engine on identical frozen fixtures.

**Owner-approved O:** a separately issued, signed, independently verified **synthetic-only** owner approval; both B and engine use identical new authority conditions. Never treat the new policy as a retroactive explanation for legacy gains.

Negative controls: wrong issuer/key, caller-declared valid flag, changed request/prestate hash, target/recipient/amount/date substitution, expired/revoked approval, untrusted clock, stale revocation status, concurrent/replayed consumption, drift before effect, missing or conflicting effect evidence.

Measure separately: official scorer pass, allowed local state mutation, synthetic transfer, SDK request/response, and independently confirmed external effect. No real provider, no funds, no production activation.

## Review decision

**Partially source-confirmed:** authority verification, revocation evidence checking, human approval verification and runtime provenance predicates.

**Not yet established:** owner issuance and production trust-root configuration; atomic single-use permit through the selected sink; dispatch-time current validity; independent effect reconciliation. Next work should inspect concrete call sites and add bounded synthetic negative tests before any integration claim. Maintain **REAL_PROVIDER_NO_GO**.
