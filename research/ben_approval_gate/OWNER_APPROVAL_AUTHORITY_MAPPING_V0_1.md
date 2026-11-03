# Owner Approval Profile ↔ VERITAS Authority Boundary: evidence mapping v0.1

**Status: REVIEW ONLY — NO AUTHORITY, NO POLICY ACTIVATION, NO PROVIDER DISPATCH.**

This is a source-linked mapping of the collaborator's **research-only proposal** to the **publicly documented** VERITAS interfaces. It is not a runtime integration, API conformance test, independent reproduction, or proof of issuer authority. The original collaborator's ZIP, private cases, and signatures are deliberately excluded.

## Reviewed source scope

- VERITAS OS `README.md` (default branch, inspected 2026-11-03).
- VERITAS OS `docs/en/validation/current-implementation-matrix.md` (default branch, inspected 2026-11-03).
- VERITAS OS `docs/en/validation/technical-proof-pack.md` (default branch, inspected 2026-11-03).
- Benchmark `research/ben_approval_gate/` (PR #577; research-only syntax gate).
- Collaborator's 2026-11-01 proposal, reviewed privately: `veritas.authority-recovery-review.v1`, `REVIEW_ONLY_NO_AUTHORITY_NO_POLICY_ACTIVATION_NO_PROVIDER`. **No private materials copied here.**

**Limitation:** The matrix below is documentation-level. Concrete runtime symbols, request schemas, adapter sink enforcement and cryptographic verification call sites have **not yet been traced to source**. Do not label them as verified.

## Boundary mapping

| Research proposal concept | Candidate VERITAS boundary | Publicly documented anchor | Evidence level | Remaining requirement |
| --- | --- | --- | --- | --- |
| Owner decision / approval source | Authority Evidence and regulated action governance kernel | `docs/en/validation/current-implementation-matrix.md` → Regulated Action Governance Kernel; `docs/en/architecture/authority-evidence-vs-audit-log.md` | Documented interface family, **not verified issuer mapping** | Authenticate owner/issuer out-of-band; record trust root, scope, signature, and provenance |
| Proposed execution date | Runtime Authority Validation | `docs/en/validation/current-implementation-matrix.md` → Regulated Action Governance Kernel | **Not authorized** by proposal | Independent trusted date/clock evidence; reject date inferred from harness, model, tool payload or scorer |
| Original request/prestate hashes | Canonical decision / execution intent | `POST /v1/decide`; `docs/en/architecture/decision-semantics.md` | Research hash syntax only | Verify digest against independently frozen original request/prestate; bind target, operation, amount, recipient, and date |
| New approval condition | Policy lineage and promotion boundary | `PUT /v1/governance/policy`; `POST /v1/governance/policy-bundles/promote` | **Not promoted** | Separate, explicit owner-issued research condition; never mutate legacy policy implicitly |
| Permission to execute | Bind boundary | `docs/en/architecture/bind-boundary-governance-artifacts.md`; `GET /v1/governance/bind-receipts/{bind_receipt_id}` | Documented partial coverage | Verify actual adapter sink and bind evidence for selected operation |
| Execution-time validity | Runtime Authority Validation / Commit Boundary Evaluator | `docs/en/validation/current-implementation-matrix.md` → Regulated Action Governance Kernel | **Not tested** | Expiry, revocation, policy drift, and execution-time recheck with a trusted clock |
| One-time consumption | Bind Authorization / consumption boundary | `README.md` → Bind Boundary overview | **Not tested** | Atomic single-use, concurrent claim, replay, restart and crash recovery |
| Observed outcome | Bind receipt / audit evidence | `GET /v1/governance/bind-receipts/{bind_receipt_id}`; technical proof pack | Documentation-level lineage | Independent external effect receipt and reconciliation; distinguish scorer pass from effect |
| Test outcome | AgentDojo research score | PR #577 research gate | Format only | Same authority conditions for both arms, separate policy-change gain from engine gain |

## Non-negotiable experiment separation

1. **Legacy unchanged:** compare B versus engine under the original authority conditions; never retroactively authorize earlier results.
2. **New owner-approved research-only condition:** compare B versus engine with identical owner-approved inputs and policy for both arms. Label this as a different experiment.
3. Report **official scorer outcome**, **state mutations**, **remittances**, **independently confirmed external effects** separately.
4. Maintain `NO_PROVIDER` / no real banking effects. Do not treat a proposal, a model-generated date, or a test-harness date as an authorization.
5. Reproduce on independently frozen fixtures and a holdout set before any production claims.

## Next code-level investigation (separate PR)

- Locate concrete authority issuance, provenance and signature-verification implementation symbols in `veritas_os`.
- Trace Bind Authorization from input validation through atomic consumption to **lowest effect-bearing sink**; include negative target/amount/recipient/date/operation substitutions.
- Trace revocation/expiry/current validity and policy lineage at actual execution time.
- Identify which receipts represent internal scoring, state change, provider request, and independently verified external effect.
- Add tests against trusted independent issuer evidence; **never** upgrade `RESEARCH_PROPOSAL_FORMAT_VALID` to `AUTHORIZED`.

## Decision

**Compatible in concept; actual owner-approval issuance and end-to-end execution-boundary compatibility remain UNVERIFIED.** The appropriate next deliverable to Ben is a gap list and proposed jointly controlled synthetic experiment, not a production integration claim.
