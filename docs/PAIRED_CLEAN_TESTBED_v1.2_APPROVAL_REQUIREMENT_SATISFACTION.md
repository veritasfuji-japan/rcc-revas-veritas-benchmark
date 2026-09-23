# Paired Clean Synthetic Testbed v1.2 — Contract-Bound Approval Requirement Satisfaction

Date: 2026-09-23  
Status: **IMPLEMENTATION CANDIDATE / NO v1.2 36-CASE RUN EXECUTED BY THIS PR**

## Historical evidence preserved

This version does not rewrite:

- historical adverse Run `35813291352`;
- v1.1 synthetic testbed Run `35823854662`.

v1.1 demonstrated that the identity-rebinding defect no longer false-blocks the supported approval-required positive subset. It also preserved five approval-not-required expected-ALLOW cases as unsupported.

## v1.2 objective

Close only the explicit approval-not-required compatibility gap by using the pinned VERITAS contract-bound Human Approval requirement-satisfaction path.

The relevant native semantics already exist in the frozen VERITAS treatment pin:

- Action Class Contract;
- Human Approval requirement resolution;
- REQUIRED Human Approval linkage when required;
- explicit zero-reference `NOT_REQUIRED_BY_ACTION_CONTRACT` path when not required;
- final readiness and gate verification bound to the same trusted contract and authority source.

## Critical rule

For approval-not-required cases, v1.2 must **not fabricate Human Approval evidence**.

Expected native evidence:

- `required_human_approval = false`;
- `requirement_state = NOT_REQUIRED_BY_ACTION_CONTRACT`;
- `satisfaction_state = SATISFIED_AS_NOT_REQUIRED_BY_ACTION_CONTRACT`;
- `approval_linkage_used = false`;
- Human Approval reference count = 0;
- Human Approval created = false.

## Cases targeted

- GOV-A04
- GOV-A07
- GOV-A10
- GOV-A11
- GOV-A12

## Frozen inputs unchanged

Contract bytes, dataset bytes, RCC pin, VERITAS treatment pin, labels, scoring semantics, denominator, same-candidate / same-pre-state requirements and all no-effect boundaries remain unchanged.

## Claim boundary

This change is synthetic integration engineering only. It does not establish independent external validation, production readiness, certification, customer deployment, or a paid PoC.
