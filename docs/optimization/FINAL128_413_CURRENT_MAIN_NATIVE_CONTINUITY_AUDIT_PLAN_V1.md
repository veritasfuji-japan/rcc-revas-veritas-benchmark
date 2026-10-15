# PR #413 — Current-main canonical continuity audit v1

Status: **PLAN ONLY / IMPLEMENTATION_PROOF_PENDING**. This document is not a passing proof, a new measured utility recovery, or authorization to dispatch paid models.

## Objective
Re-establish source-pinned same-candidate native wrapper continuity on the **current main**, without silently promoting the older #77 bounded fixture closure or historical V13 outcomes.

## Source anchors
- `contracts/SINGLE_CANDIDATE_UNINTERRUPTED_CANONICAL_CHAIN_V1.json`: bounded local engineering closure, not external validation.
- `contracts/CURRENT_VERITAS_CRITICAL_SOURCE_HASHES_V1.json`: IMPLEMENTATION_PROOF_PENDING.
- `integration/current_veritas_uninterrupted/sandbox.py`: existing native-path harness.
- `contracts/UTILITY_REGRESSION_FAILURE_CLUSTERS_V1.json`: historical 32 regressions, including intentional blocks.
- `contracts/FINAL128_335_OPTIMIZATION_LEDGER_AND_TASK4_GAP_V1.json`: new measured recovery remains zero in recorded ledger.

## Required implementation and merge gates (not satisfied by this document)
1. Pin the exact current RCC main, current VERITAS source commit, dependency commits, SHA256 of critical files and fresh CI run HEAD. Fail closed on drift.
2. Run **one uninterrupted candidate** through original-request capture, factory, decide_request, CDA, promotion, ExecutionIntent, verified authority, actual native Bind, and one bounded mock apply; record matching original_request_digest, request_id, candidate_hash, decision_id, expected_state_fingerprint, execution_intent_id and BindReceipt.
3. Assert exactly one effect on COMMITTED; reject candidate substitution, request substitution, prestate drift, authority tamper/revocation and replay with zero extra effects. Never infer authority from scorer/gold.
4. Re-run inherited tests; archive a redacted evidence bundle with machine-verifiable source pin, runner version, CI run/job IDs, exact case IDs, artifact SHA256, result and failure classification.
5. Distinguish old #77 bounded fixture proof from **current-main proof** and from any production or external validation. No promotion of development runs.
6. Add explicit fail-closed regression tests that break each continuity field or source pin, not just JSON schema checks.

## Separate optimization objective
Preserve Injection Success = 0 while targeting Arm B Utility >= 92/128 in a **new, same-run, independent native A/B official scorer evaluation**. Record all 128 case-level outcomes and 32 historical regression explanations; legitimate authority must remain a prerequisite. The historical 92/128 vs 60/128 and V13 93/128 vs 64/128 are not a new improvement claim.

No new provider/API spend, external bank effect, or real production credentials are approved here. Request explicit fresh authorization and a cost ceiling before any paid evaluation.

## Exit
Do not mark this PR's objective PROVEN until executable current-main proof, negative tests, full CI and independent artifact review exist. This initial PR only records a testable implementation plan.
