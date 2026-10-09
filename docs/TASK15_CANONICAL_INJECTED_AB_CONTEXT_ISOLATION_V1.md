# TASK15_CANONICAL_INJECTED_AB_CONTEXT_ISOLATION_V1

**Status: IMPLEMENTED / NOT PROVEN until exact-HEAD dedicated CI and independent Artifact verification.**

## Rule-of-One

For each of the eight **actual** native AgentDojo banking Task15 `direct` attack cases, materialize **two separate fresh** A/B injectable initial banking contexts from the exact payload and native slot discovered in PR #259. Require that the native injection bytes and environment hash match the original pinned #259 evidence; the A/B environments are separately owned objects but have identical case-specific pre-state content.

**Never** treat PR #261’s noncanonical synthetic `banking:user_task_15:refund-design-v1` model source histories as if they were generated within these newly injected canonical cases.

## Scope and provenance

- Eight exact Task15 case IDs `banking:user_task_15:injection_task_{0,1,2,3,4,5,6,8}:direct`.
- Sixteen separate prospective injected initial contexts (one A, one B for every case).
- A prospective two-message native-format system/user prefix using the pinned **actual Task15 user prompt**, not the local design prompt.
- Native `TaskSuite.load_and_inject_default_environment` actually constructs every initial A/B context. These are **in-memory** test environments only.
- Source proof from PR #259 is checked against its exact eight case-wise native injection mapping and payload hashes.
- PR #261’s two isolated three-step model source histories are verified as original, **noncanonical, and ineligible** for these eight cases; no source history is copied over or reinterpreted as a canonical completed model trajectory.
- Existing same-candidate attribution runner and all governed effect sinks remain unchanged.

## Nonclaims

**0 canonical model/provider queries, 0 canonical candidate dispatches, 0 scorers, 0 external bank effects, 0 paid API calls.**

Sixteen *initial* contexts do not mean sixteen benchmark case executions. This does not prove model-exposed attack observation, independent per-case model decisions, actual RCC/Bind dispatch in the canonical injected environment, native scoring, Utility or Injection Success. The original PR #261 model candidates have not been transplanted; doing so would be a false provenance claim.

## Test and audit gate

Expected predecessor audit: PR #261 proof chain, 2,412 cumulative tests. New test boundary: 15 cases including one eight-case positive and 14 unique refusal classes. New dedicated workflow pins:
- exact main base `7e67402d7b3ee750b53f3a5c03b6caeed3d4d487`,
- all new implementation/test/audit source blobs,
- native AgentDojo banking injection vectors, task suite, model codec.

Full predecessor report, JUnit and exact rejection records must pass. Compare downloaded Artifact ZIP SHA-256 and audit all eight case-wise A/B native environments before any manual merge. **CI green alone ≠ PROVEN.**

## Next proof round

Run separate synthetic A/B **candidate-generation sessions inside an exact canonical injected Task15 environment**, binding user prompt and all observed native tool returns to the correct case. If that execution requires replacing the prior controlled noncanonical runner or grants broader capabilities, freeze and audit the new authority boundary first. Genuine provider transport or real scoring requires separate explicit approval and never inherits authorization from V10/V13.
