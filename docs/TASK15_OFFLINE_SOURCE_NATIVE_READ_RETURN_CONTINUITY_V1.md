# TASK15_OFFLINE_SOURCE_NATIVE_READ_RETURN_CONTINUITY_V1

**Status: DRAFT / NOT PROVEN pending exact HEAD CI and independent artifact audit.**

## Rule-of-One

Verify 16 isolated **source-call-ID → native tool-return → continuation** joins for the eight pinned native banking Task15 DirectAttack cases × separate logical A/B arms.

Unlike #264, in which the harness *authored* a diagnostic `get_most_recent_transactions` call before executing it, this V1 proof gets each first tool request from a **distinct synthetic offline test client**. The first response is decoded by pinned native AgentDojo `_openai_to_assistant_message`, and only the narrow, read-only `get_most_recent_transactions` function is exposed to pinned `FunctionsRuntime` and `ToolsExecutor`. That native tool's real return is bound to **the exact same returned tool call ID** in the subsequent native assistant/tool wire history, and then delivered back to the **same arm's offline client** for an artificial terminal response.

All 16 injected environments and their #262 context, #263 offline first-source and #264 genuine native read-return evidence are independently reconstructed/preflighted **before** the first invocation. The new synthetic first read response is not a transplant from #263's noncanonical source histories or #264's harness-authored diagnostic read.

## Evidence expected

- Eight frozen native Task15 DirectAttack case IDs, each with independent A/B local environments.
- **16** test-client-native shaped read proposals with a unique source call ID, **16** actual pinned AgentDojo read-only tool returns and **16** model-shaped synthetic continuations.
- Actual native YAML-formatted tool results, safely decoded, deep-equal to exact pinned injected bank transaction lists; transaction ID 5 contains the exact malicious `subject`. No mutation of bank state.
- Request, native response, tool result, tool wire and four-message continuation digests bound to each original case/arm.
- **15** new tests, **14** unique fail-closed refusal tests, full replay of #264's predecessor audit (2,457 cumulative tests).
- Source and pinned AgentDojo Git blobs verified in dedicated CI; zero permitted external effects.

## STRICT nonclaims

**Offline synthetic source clients are not authenticated live model inference.** Saying their stub-generated `get_most_recent_transactions` call is “model-selected” without qualification would be incorrect. This proof shows only that a **synthetic model-shaped native proposal** can be linked to actual native AgentDojo read-only results and subsequent same-arm synthetic continuation. It does not show a real AI picked that read, that real AI read/obeyed/resisted injection, a completed canonical task trajectory, RCC/Bind effect governance over this diagnostic read, bank write, real provider call, actual scorer, measured Final128 Utility or Injection Success. The earlier #263 and #264 proofs retain their bounded original meaning.

No production credentials, no real bank action, no paid API, no reuse of V10/V13 spend approval.

**DO NOT MERGE** before exact-head CI, independent archive ZIP/digest, 15 JUnit tests, 14 refusals and all 16 same-call-ID joins are verified.

## Next boundary

The subsequent proof must establish an **independently sourced effect candidate** following the native read result, with fresh RCC/Bind execution authority and explicit eligible/blocked effect sinks. Until then, no benchmark effect execution or scoring is claimed.
