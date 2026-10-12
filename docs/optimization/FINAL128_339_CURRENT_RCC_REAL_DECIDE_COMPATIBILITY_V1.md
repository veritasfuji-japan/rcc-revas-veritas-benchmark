# #339 — Actual current RCC request → real local VERITAS /v1/decide → independently verified CDA

## Single invariant

The unmodified, released, upstream-produced RCC `/v1/decide` request must be sent through **the actual VERITAS route** and its native CDA examined without conflating a request correlation, echo or unrelated `chosen` output with the original RCC candidate being selected or promoted.

The current RCC upstream main `353ad9e6a17cda8874a129493fe0f8f4fe4427bc` is **different from the historical `external-eval/v0.3.9` branch**. The current VERITAS OS `299a3c4987668091f50ab3e45165bcccd1ae193f` is independently pinned, with five exact source blob hashes on top of the #338 pin.

## What runs

1. Execute unchanged current RCC v0.1.0 `preflight → register-takeshi → evaluate → verify-artifacts → prepare-veritas` on all 36 partner cases. Reverify all released original-source, candidate, prestate, and request hashes. Select one released case using the deterministic lexicographic `case_id` rule.
2. Pass the **exact same JSON payload** prepared by current RCC (not a rebuilt permitted candidate) to the real `POST /v1/decide` FastAPI route, via an in-process TestClient. The controlled test transcript replaces the LLM's provider response only; the actual route, kernel, policy verification, canonical artifact construction, synthetic KMS sign and WORM test path execute. Test-only credentials are injected in an isolated interpreter after checking there are no real provider credentials.
3. Independently run native `verify_canonical_decision_artifact` on the actual HTTP result. Verify the native `decision_id`, `decision_hash` and `request_id`. A verified CDA has **structural content integrity**, not independent validation or execution authority.
4. Check whether the returned selected `chosen` option preserved both RCC's exact alternative `id` AND the exact canonical candidate JSON `description`, and whether the CDA has a native `selected_action_evidence`. Only this narrow conjunction is treated as a candidate-selection signal; mere correlations and echo are not. Even this signal is not Bind execution.
5. Attempt native `try_promote_verified_canonical_decision_candidate_to_execution_intent` on the actual chosen object and native CDA. No missing target, human-approval status, required authority, or identity may be filled from gold labels or synthetic test fixture. Even a schema-promotable candidate would need native CDA candidate-selection equivalence and the separate exact promotion packet before the run could legitimately record a source-bound intent.
6. Emit real route/CDAs/candidate-linkage status and explicitly `NOT_PROVEN` / null for any missing source-bound ExecutionIntent. No `NativeBindAuthorization`, consumption, Bind, dispatch, real bank, real model, new final128 scorer or external effect.

## Critical limitation

This PR is an **actual live-code route compatibility audit**, not a promise that the existing current RCC `alternatives`-only request can already produce an execution-grade structured VERITAS candidate. That question is decided by the executable evidence. A green job means the **actual route and verification were observed and any missing lineage was reported honestly**, not that an ExecutionIntent was necessarily promoted.

A standalone VERITAS local synthetic candidate that passes promotion would **not** count as the same RCC candidate. If a native-compatible projection is needed, its authority and trusted policy metadata must be addressed under a separate exact-source, fail-closed adapter specification without substituting candidate meaning.

The original request's synthetic evaluation prestate is **not a physical/bank prestate**. A test-only secure-pipeline fixture does not issue an authority grant. A structurally verified CDA is not itself a cryptographically signed approval to execute.

## Guardrails and next stage

Rule-of-One; pinned source and hashes; no actual provider credentials; 0 paid API requests; 0 external effects; 0 Bank transactions; no invented utility recovery. Historical V13 scored **A 93/128, B 64/128, B injection 0/128** remains unchanged.

Do not merge until dedicated + global checks succeed and the report/Artifact shows true selected candidate and promotion state. If `rcc_to_native_execution_intent_proven=false`, the next PR must resolve the exact-compatible trusted structured-candidate mapping, not present this #339 as a complete positive integration.
