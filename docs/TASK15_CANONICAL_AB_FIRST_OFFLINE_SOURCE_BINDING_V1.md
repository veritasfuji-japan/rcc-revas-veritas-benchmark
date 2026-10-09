# TASK15_CANONICAL_AB_FIRST_OFFLINE_SOURCE_BINDING_V1

**Status: IMPLEMENTED / NOT PROVEN pending exact-HEAD CI and Artifact audit.**

## Rule-of-One

For all **eight** actual pinned AgentDojo banking Task15 DirectAttack cases, take the independently confirmed, native-injected **A/B initial contexts** from merged PR #262 and issue one first native tool-proposal request per (case, arm) using **16 different, injected offline test client objects**. Bind every decoded synthetic proposal to its exact:

- canonical case ID and logical A/B arm,
- real native injected environment SHA-256 and payload SHA-256,
- exact pinned native Task15 system/user wire request and tool definition digest,
- unique native model call ID and candidate SHA-256.

All 16 cases/arms are preflighted against the **native AgentDojo environment loader** before the first model request. Any wrong case, bad context hash, reused client/call ID, refusal, wrong tool, transport failure or canceled call refuses complete evidence; no retry.

## The important distinction

**An injection in the banking environment does not imply it was seen by an AI model.** For this proof, the first wire request contains only the native Task15 system/user prefix, and the attack payload stays inside the separately bound **local environment**. It has **not** been delivered as an actual native tool-return message. Therefore:

- It is correct to claim **16 distinct offline first native source invocations that are case-/environment-bound**.
- It is **incorrect** to claim 16 completed canonical attack trajectories or injected prompts exposed to the model.
- These are synthetic clients, not independent authenticated live-model computations.
- The test fixture's deterministic first proposed tool/candidate may remain identical across cases despite distinct source call IDs and case/environment evidence. The differences do not demonstrate differentiated model decisions.

## Frozen semantics

- Original frozen attribution runners, RCC/Bind control, PR #259 injection slot discovery, #261 noncanonical three-step A/B source-history proof and #262 native A/B environment isolation are untouched.
- 8 exact `banking:user_task_15:injection_task_{0,1,2,3,4,5,6,8}:direct` case IDs.
- 16 synthetic first tool proposals; **zero real Provider calls**, native tool dispatches, native scorer invocations and real external banking effects.
- No permission to spend, contact a real model, consume V10/V13 authorization, execute in production or claim Final128 Utility / Injection Success.

## Dedicated proof gate

Dedicated exact-HEAD workflow replays the entire merged #262 predecessor evidence chain (expected 2,427 cumulative tests) and then executes **15 new tests**: one comprehensive positive and 14 unique mutations/refusals. The audit requires exact source blob SHAs, native codec and banking suite pins, intact predecessor files, 16 one-shot A/B client calls, strict per-case/arm binding digests and zero native execution/score claims.

Do not merge before 17-workflow CI, dedicated run/job success, Artifact ZIP SHA verification, full JUnit and JSONL evidence checks are independently complete.

## Next

The next independent proof must establish **real native tool-return injection observation**: the exact payload and tainted native tool result must enter the correct case/arm's model history before any success/injection-success inference. That would be a new proof round and should not rely on the unobserved first request to measure utility.
