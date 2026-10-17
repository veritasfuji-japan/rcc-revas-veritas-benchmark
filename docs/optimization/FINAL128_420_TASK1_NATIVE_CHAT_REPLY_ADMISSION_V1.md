# Final128 #420 — Native Chat Completions reply admission (untrusted, zero Provider calls)

## What is already implemented and deliberately NOT duplicated

- #350: `Responses API` budgeted transport, with a **caller-provided boolean lease**, not an independently verified authorization.
- #381/#382: `Responses API` first-response and HTTPS capture contracts (sender stub/isolated fake connection only). This protocol is **not** Native Chat Completions.
- #389/#391: GitHub Environment waiting/approval and **test-only** protected tag create observed; not a protected task1 paid sender, global production once proof, or verified cloud billing hard stop.
- #395: real Native scoring *on different offline synthetic terminal trajectories*, never official utility.
- #403: pinned real Native `AgentPipeline`, `ToolsExecutor`, experimental B-only read-only context, guarded B Bind; scripted local model calls.
- #418/#419: exact original Attack/Candidate/Native input and six 3-stage full-tool Chat Completions request SHA256s, with arm-owned IDs; NO Provider response.

The remaining technical mismatch: all provider capture validation from #381/#382 expects **Responses API**, while the source-pinned Native AgentDojo runner uses **Chat Completions** and its *full banking tool catalogue*, not the single read-only-tool pilot.

## #420 one scoped change

`scripts/final128_420_task1_native_chat_reply_admission_v1.py` inspects ONE **untrusted** Chat Completions response body against ONE source-owned #419 packet from an actual in-process #403 run; it DOES NOT send or authorize the response.

- First re-run #418 + #419 exact frozen original, A/B, source state and output checks, without altering the Native pipeline or Bind.
- Inspect strict bounded JSON input, duplicate-key refusal, finite numeric values, exact one choice, assistant role, model, stop/tool_calls finish reason, output text shape, bounded usage counts.
- Require every model-proposed function name to exist in the unchanged actual Native full-tool catalog. Require unique call IDs, bounded JSON argument objects, no ambiguous duplicate parameters. Inspecting a proposed protected tool does **not** execute it or mint authority.
- Emit only hashes, stage/arm, call counts and function names, **never** model text, raw response/call IDs, attack subject or bank data.
- Never treat a claimed `chatcmpl-...` ID, preserved request SHA or forged HTTPS/approval field as authenticated Provider provenance. Strict top-level schema rejects inserted fake approval/origin fields. A future trusted sender must attest actual connection/TLS, source, independent A/B origin, durable consumed authorization and verified hard budget cap.
- `eligible_for_provider_dispatch=false`, `eligible_for_official_utility=false`, score=null, new Utility recoveries=0. The script includes NO Provider client, token, workflow_dispatch, IAM effect or actual scorer call.

All model bodies in tests are deliberately local **shape fixtures**. They cannot be reinterpreted as model inference. This PR changes NO historical V13 scores and no policy.

## Exact controlled CI

Dedicated PR-only workflow pins AgentDojo `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`, VERITAS `a1d66aef02262cf8a913295270c3aafd159c6adb`, reuses existing #419/#418/#403/#395 tests and adds #420 refusals. No external Provider key or paid API. Strict dedicated CI forbids skipped tests; generic CI without pinned Native skips only the integration tests.

## Practical next milestone, not accomplished here

Provide a separately approved **protected Native Chat Completions sender** and genuine source-bound model response receipts, independently run A and B through the actual Native tool executor/Bind, acquire independent genuine final model terminal and use the actual same-run User/Attack native scorer. `#420` alone never proves Utility recovery or independent Provider provenance. Before enabling any sender, require fresh owner consent, an actual one-use protected issuer and enforced billing cap. Avoid any new offline scripted assistant instead of executing the real pilot.

**Do not merge without review of exact PR HEAD, full CI and artifact.**
