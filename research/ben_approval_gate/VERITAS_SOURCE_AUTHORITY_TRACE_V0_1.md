# Ben Owner Approval ↔ VERITAS: source-level authority trace v0.1

**REVIEW ONLY / NO AUTHORITY / NO POLICY ACTIVATION / NO PROVIDER DISPATCH**

This follows the documentation-only mapping in #578 with **actual source inspection** of selected `veritas_os` modules (default branch, 2026-11-03). It is a partial source trace, **not** an end-to-end code-path proof or a successful adapter integration. No private collaborator fixture is committed.

## Source-verified interfaces (partial)

| Boundary | Inspected source | Concrete code symbol / observation | Implication for Ben's proposal |
| --- | --- | --- | --- |
| Authority claims | `veritas_os/governance/authority_evidence.py` | `AuthorityEvidence` is an unsigned caller-constructible dataclass; `deterministic_digest()` is a content hash, not authenticity | Ben's proposal and its SHA-256 hashes are not authority evidence by themselves |
| Authority signature envelope | same | `AUTHORITY_SIGNATURE_DOMAIN = "VERITAS:authority-evidence:v1:"`, `authority_signature_payload()`, `AuthorityEvidenceSignatureVerifier`, `AuthorityEvidenceSignerPolicy` | Requires trusted deployment verifier, key/algorithm/issuer allowlist and separate issued signed artifact |
| Runtime authority | `veritas_os/governance/runtime_authority.py` | `RuntimeAuthorityValidator.validate(... verified_authority_evidence, authority_verifier_policy, authority_revocation_policy, now ...)`; `authority_provenance_verified` predicate; secure/prod strict authority posture | Candidate insertion point for **verified**, independently issued owner evidence; not a claim that Ben's current proposal is accepted |
| Human approval | same | `VerifiedHumanApprovalReceipt`, `human_approval_signature_verifier`, `human_approval_signer_policy`, `human_approval_verifier_policy`; raw compatibility dictionaries documented as fail-closed/non-approved | Owner approval needs distinct trusted receipt and action/context binding, not a boolean |
| Commit boundary | `veritas_os/governance/commit_boundary.py` | `CommitBoundaryEvaluator.evaluate(...)` calls `RuntimeAuthorityValidator.validate` and resolves `commit/block/escalate/refuse`; `_resolve_outcome` requires consistent pass predicates | A proposal cannot skip the validator by supplying a claimed `commit` outcome |
| Receipt/lineage | `docs/en/architecture/bind-boundary-governance-artifacts.md` | `ExecutionIntent`, `BindReceipt`, `FinalOutcome` are documented, with decision/policy/actor and TrustLog linkage | Documented only in this trace; persistence and effect-specific receipt code not inspected |

## Key trust distinctions

1. `AuthorityEvidence.verification_result` is legacy caller-declared data; **not a trusted issuer proof** in strict runtime posture.
2. A deterministic request/prestate digest establishes only identity of the hashed bytes, not approval or provenance.
3. A harness-supplied execution date is not a trusted UTC clock or signed owner authorization.
4. `RuntimeAuthorityValidator.validate(now=...)` accepts a caller-provided clock parameter. **Clock trust at the invoking boundary has not been verified**.
5. A `commit` evaluation result is not proof that a concrete external effect sink enforced the same authorization.

## Explicitly not yet source-traced

- Complete `verify_authority_evidence_artifact_to_proof` implementation, trust-root loading, revocation source, and their production call sites.
- Full `human_approval_receipt.py` verification and owner identity-to-approval binding.
- Atomic single-use consumption persistence/transaction, replay and concurrent race behavior **in the target adapter path**.
- Lowest effect-bearing sink and its final target/recipient/amount/date/operation matching; no claim of universal Bind coverage.
- Execution-time expiry, revocation, clock provenance and post-resolution policy drift across the actual adapter dispatch.
- Outcome receipt vs external provider effect, read-only reconciliation, independent host/issuer proof.

## Proposed next jointly controlled experiment

- **Condition L (legacy):** preserve unchanged authority and original policy, measure both B and engine.
- **Condition O (new research-only):** independently issue an owner approval for an exact frozen synthetic request/prestate; apply the **same** approved condition to B and engine. Never relabel old results.
- Independently freeze and verify target, operation, recipient, amount, date, contract, policy snapshot, issuance provenance and expiry.
- Negatives: forged signer; caller-declared `valid`; mismatched request/prestate hash; changed recipient/amount/date; expired/revoked approval; replay/concurrent consume; drift after resolution; missing or ambiguous effect receipt.
- Distinct metrics: official scorer success, legitimate state mutation, synthetic remittance, external-effect confirmation. No real Provider dispatch or bank funds.
- Release gate: **remain NO-GO** until independent issuance, bind-to-sink enforcement and evidence replay are demonstrated and separately approved.

## Decision

**Actual code symbols for claims, cryptographic verification interfaces, runtime predicates, and commit adjudication were inspected. End-to-end owner issuance → Bind consumption → adapter effect → reconciliation remains UNVERIFIED.** This source trace should guide the next narrow implementation review, not be represented as completion of it.
