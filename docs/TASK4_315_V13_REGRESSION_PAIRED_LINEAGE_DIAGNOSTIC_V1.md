# PR #315 — V13 Case-Level Regression × Paired-Lineage Diagnostic V1

## Rule of One

**Do not count historical model trajectories or a syntactically identical
A/B pair as recovered Arm B Utility, independently authorized execution,
or proof of current-production canonical continuity.** Record every one
of the 30 frozen V13 A-success/B-failure cases and require matched
original request, independently issued context, candidate identity and
immediate pre-state **before** any future causal comparison.

This adds a real executable pairing-shape validator and case-level
triage report. It does **not** call any model/provider, score new cases,
change VERITAS policy, repair candidates, dispatch banking actions, or
claim any new measured Utility.

## Exact parent / old authorization

- Parent: merged #314 main `81a8e9aca2fc0309b86889cd1a613a97c6671d35`.
- Pinned Git blob SHA-1 for eight prior immutable sources: V13 diagnosis,
  historical 32-case corpus, pairwise RCC V1.1, bounded canonical-chain
  fixture, current VERITAS source-hash pending contract, prior claim gate,
  and #314 infrastructure decision record.
- The real Provider consent from earlier Task4 runs is **already consumed**.
  CI verifies consumed tag target
  `95ff6be8c5875ed3827a00fe71fb54bd9de48130`.
- No new consent, paid Provider call, cloud provisioning, fresh bank
  effect, production authority, or official Final128 result.

## Two distinct historical baselines — never combine as one trial

| Evidence | Arm A Utility | Arm B Utility | Arm B attack success | A-only regressions | B-only gains |
| --- | ---: | ---: | ---: | ---: | ---: |
| Older frozen 128 | 92/128 | 60/128 | 0/128 | 32 | Not used in #315 |
| V13 frozen 128 | 93/128 | 64/128 | 0/128 | 30 | 1 |

V13's **raw** net Utility gap is 29 (30 A-only minus 1 B-only).
That difference is not a pure estimate of VERITAS false blocks:
only 9/30 regressions had identical **raw** protected-call sequences
and 21/30 did not. Even a matching sequence cannot prove the source
of execution authority.

V13 is a **historical development corpus**. Re-reading it is not
a new paired or held-out observation.

## Four locked V13 lanes and decision boundaries

| Lane | Cases | Correct engineering next step |
| --- | ---: | --- |
| MODEL_OR_TRAJECTORY_VARIANCE | 3 | Capture same original request, same source candidate and prestate across independent A/B execution before treatment attribution |
| AUTHORITY_PROTECTIVE_BLOCK | 10 | Preserve refusal until original-user request or trusted pre-state independently authorizes **all effect-critical values** |
| SEND_MONEY_PARAMETER_AUTHORITY_UNRESOLVED | 10 | First probe Task4's 8 owned-date cases; the remaining 2 Task15 cases need their own parameter-authority analysis |
| CONDITIONAL_PREDICATE_NOT_PREREGISTERED | 7 | Establish an independent, deterministic suspiciousness predicate before interpreting prior scorer wins as authority |

**Task4 is the first prospective paired-experiment cohort: 8 cases.**
This is an investigation plan, not a prediction of eight recoverable
production Utility results. The prior #288 prospective controlled-date
local observations and #305 local native completions remain local and
cannot be automatically credited to the historical V13 benchmark.

## Executable diagnostic proof added here

The new auditor emits 30 case-level records and accepts a prospective
**untrusted test pair** only if it has:

1. Same canonical case ID and proposal ordinal.
2. Same 64-hex original request digest.
3. Same 64-hex issuer/context digest.
4. Same immediate prestate SHA-256.
5. Exactly identical full normalized candidate payload and RCC V1.1
   candidate SHA-256, including `content:null` and `metadata:{}`.
6. No scorer/gold field masquerading as an execution candidate.

It delegates identity comparison to the existing
`ProtectedCandidateControlV11` mechanism and tests each class of
tampering. A locally invented pair may satisfy these **shape**
constraints. That output is always
`STRUCTURALLY_PAIRED_NOT_AUTHENTICATED`,
`permission_to_execute=false`, and `new_utility_recovery_credit=0`.
There is no forged independent trace authentication, no generated
Provider output, and no actual native-run scoring in #315.

**Important:** This is an intermediate gate toward a true prospective
A/B fixture, **not** itself a replacement for native RCC + Bind execution.
The existing single-candidate chain contract says
`PROVEN_WITHIN_BOUNDED_LOCAL_ENGINEERING_SCOPE`; the separate current
VERITAS source-hash contract still says
`IMPLEMENTATION_PROOF_PENDING`. Neither is promoted.

## Ben's single optimization objective and next experiment

A real next development iteration should:

1. Freeze new Task4 original request and *separately authorized*
   owned-date context from trusted inputs, **before** the candidate
   arrives; scorer/gold is observation only.
2. Obtain one independently attributable immutable normalized candidate
   from the frozen preparation run and fork it into two independent
   **in-memory** same-prestate native A/B executions.
3. Compare exact request/candidate/prestate hashes and continuity of
   factory, decide, CDA, promotion, ExecutionIntent, authority,
   BindReceipt and apply, plus native detached AgentDojo scorer results.
4. Preserve each attempt's runner version, source commit, hashes,
   case-level delta, reason, and run/Artifact provenance; retry and
   repair inside the unified optimization program.
5. Do not label smoke/development runs external validation. Only after
   stabilizing/freeze, obtain fresh independent held-out validation
   and eventually an authorized Provider-bound Final128.

The goal is **B Utility at least the current matched A benchmark**
while keeping injection-task success at zero, all authorization
bindings intact and the actual canonical chain continuous.
The V13 historical reference is A=93/128, but comparisons must
use appropriately matched/new measurements. This PR records **zero
newly observed successes**.

Debugging across multiple offline development rounds does not require
a fresh management approval per micro-fix. **Any real API expense,
credential issuance, external effect, or release of production
execution authority remains a separate explicit authorization gate.**
A prior paid-call approval may not be reused.

## Evidence, stop and merge conditions

- All 17+ applicable PR-head checks must complete green.
- Independently review exact HEAD JUnit counts, full JSON report
  including 30 exact cases + 8 Task4 priorities, artifact digest,
  and frozen parent SHA.
- No rerun of V13, new bank effects, Provider POSTs or score changes.
- Keep **Draft** until those exact-head checks complete.
- Merging this PR does not close the unresolved current-source
  implementation continuity proof or improve the historical Utility
  score. It only provides a bounded, testable next-experiment gate.
