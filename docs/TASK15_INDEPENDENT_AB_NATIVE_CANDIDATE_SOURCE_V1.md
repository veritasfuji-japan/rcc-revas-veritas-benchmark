# TASK15_INDEPENDENT_AB_NATIVE_CANDIDATE_SOURCE_V1

**Status: IMPLEMENTED / NOT PROVEN pending exact-HEAD CI, artifact download and independent verification.**

## Rule-of-One

At the *first* protected Task15 proposal (ordinal 3), the original noncanonical local request must produce **one separate native-formatted model query per arm** through two distinct test-injected client instances. A complete read-only pair is accepted only if both native-decoded assistant responses contain one exact expected function proposal, with different call IDs and request/response provenance bound to each arm. Shared client aliases, recycled call IDs, request modifications, failures or extra choices must not become paired evidence.

## What is deliberately preserved

- PR #259 remains unchanged. Its eight native DirectAttack payload-slot/environment checks and evidence remain authoritative for their *own offline scope*.
- The previous B-sourced A/B native governed six-step local replay and same-candidate controlled comparison remain frozen. This proof does **not** silently rewrite those histories.
- The new layer uses the pinned native AgentDojo message/tool codecs, frozen OpenAI single-attempt adapter and the original Task15-owned **noncanonical** local test instruction.
- Two client instances are injected by the test harness; source records retain exact per-arm request, native response, candidate and baseline hashes.
- No model-generated call becomes execution authority. No native tool, RCC/Bind sink, external database, scorer or paid API is invoked.

## Explicit limitation

This is a **first-proposal A/B transport-source isolation proof**, not a complete independent three-action model trajectory. Both offline clients are deliberately synthetic; separate calls do not authenticate independent model computation, independent model providers or genuine external replies. Identical candidate arguments are permitted and do not imply source reuse; distinct identities, native message evidence and client invocations are what this narrow test checks.

The previous six committed *local* A/B native effects remain **B-source candidate driven**. Their historical provenance cannot be retroactively relabeled as independent A/B candidate generation. Task15's earlier design fixture is `banking:user_task_15:refund-design-v1` and is **not** a canonical Final128 case.

## Audit gate

The dedicated exact-head workflow replays the full PR #259 predecessor audit (2,382 predecessor tests reported), requires 15 new tests, a positive evidence row, 14 distinct refusal evidence rows, Git source blob pins, pinned native AgentDojo codec, and immutable historical artifacts.

Provider calls = 0. Scorer calls = 0. New governed dispatches = 0. Real external effects = 0. Canonical Final128 Utility and Injection Success are **unmeasured**.

A green CI run alone is not PROVEN. Verify the exact HEAD, job, artifact ID, downloaded ZIP SHA-256 and case-level report before merging. User manual merge only.

## Following bounded work

Establish a fully independent A/B source history at each *actual* subsequent tool result, bind that evidence to the exact eight injected canonical Task15 environments, and only then consider authenticated provider transcripts and native scoring with a new explicit spend authorization. Do not combine same-candidate attribution experiments with independent A/B model-performance comparisons.
