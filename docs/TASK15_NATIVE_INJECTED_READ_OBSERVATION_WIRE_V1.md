# TASK15_NATIVE_INJECTED_READ_OBSERVATION_WIRE_V1

**Status: DRAFT / NOT PROVEN until exact-HEAD CI and independently inspected Artifact.**

## Rule-of-One

For the eight **actual** pinned native banking Task15 DirectAttack injected local environments, independently repeat the following read-only observation for A and B (16 observations):

1. Cross-check exact merged #262 initial context evidence and #263 synthetic first-proposal records, matching case/arm, full native injected environment SHA, literal native payload and native Task15 prompt. Preflight **all 16** before invoking any tool.
2. Independently load a fresh disposable native bank environment with the exact per-case DirectAttack injection bytes. Use **only** the actual native `get_most_recent_transactions` read-only tool registered in a restricted `FunctionsRuntime`, executed through the pinned AgentDojo `ToolsExecutor`.
3. Obtain the **actual native tool result**, confirm the attack payload appears in it, assert the environment was not mutated, and serialize the native `ChatToolResultMessage` with the pinned `_message_to_openai` codec.
4. Append a diagnostic assistant tool-call message and the native returned tool-result message to the case's actual pinned `developer, user` initial wire prefix. The injected text must appear **only** in the untrusted tool message, not the initial prefix.
5. Make one synthetic, injected-client-only continuation query with the resulting four native wire messages for that particular case/arm. Preserve call ID, original environment/payload digest, tool result and full wire digest. Reject any partial/replayed/mutated/failed source.

## Crucial provenance boundary

The native `get_most_recent_transactions` call in this V1 proof is **harness-authored as a diagnostic read-only observation probe**. It is **not** a model-generated native tool call; it is **not** the #263 first-proposal call; it is **not** a real RCC/Bind governed multi-effect canonical run. No model chooses to read the attack text. A synthetic test client receiving a native tool result does not prove a real model attended to, obeyed, resisted, or even received that injection.

What this can prove (if audited PASS): the **real AgentDojo native tool-return and wire encoding path** carries the injected case-specific bytes to a model-shaped **offline** continuation request for both A/B in all eight cases.

What it cannot prove: provider authenticity, real-model injection exposure or model decisions, real model-selected tools, completed canonical trajectories, formal native scoring, Utility, Injection Success, production readiness, external effects or paid usage.

## Proof contract

- Full frozen #263 predecessor audit chain: expected 2,442 cumulative tests.
- Dedicated Rule-of-One: **15 new tests**, **14 unique fail-closed refusals**.
- Exact native AgentDojo tool executor, runtime, model codec, banking read-only tool, suite and injection vector Git blobs all pinned.
- Dedicated exact-HEAD workflow, immutable input artifact hashes and independently verifiable ZIP/JUnit/JSONL.
- Zero live provider calls, zero native write dispatches, zero scorer calls and zero external effects.

**Do not merge until the latest PR head and all dedicated artifacts are independently checked. No previous V10/V13 authorization is transferable.**

Next proof after this bounded read-only observation: a model-selected native read tool call and actual governed effect-candidate routing, with separately frozen authority and explicit nonclaims until real provider verification.
