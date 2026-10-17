# Final128 #422 — Native Chat first A/B HTTP capture bridge, NOT live dispatch

## Why this is the smallest nonduplicative change

Merged #421 freezes the exact source-owned FIRST two Native Chat Completions requests from pinned actual AgentDojo. Its subsequent #403 post-read and post-mutation requests are **scripted** and are not valid genuine model continuations. #420 checks one hand-crafted **minimal** untrusted Chat response with just four top-level keys; real OpenAI Chat Completion JSON typically has additional `object`, `created`, `logprobs`, `refusal`, `system_fingerprint`, usage `total_tokens`, etc. Passing raw actual server bytes directly to #420 would fail. Do not reimplement the already-tested #420 full Native tools/arguments checker.

#422 **only adds** the missing real-format-to-#420 adapter with **paired A/B** provenance quarantine:

- Parse bounded *externally supplied* full Chat Completions HTTP 200 JSON. Require `object=chat.completion`, positive integer `created`, one choice, typed usage with `total_tokens=prompt_tokens+completion_tokens`, known passive metadata only. Refuse unknown data, nonzero refusal, logprobs, audio, deprecated function_calls and duplicate JSON keys.
- Reduce allowed provider metadata to the strict #420 four-field representation; call #420 unchanged on the exact source-owned #419 FIRST A or B packet. The entire Native **full tool catalog** is retained, model proposals do NOT execute.
- Require bound exact first request A/B SHA from unchanged #421; distinct client request IDs with arm/run scope, distinct server `x-request-id` and model response ID hashes for each arm. Neither HTTP header nor model response ID authenticates origin: the future protected sender must supply trusted actual TLS connection receipts in the SAME protected process.
- Require observed postcall token usage <= 12k prompt / 256 completion per arm, local frozen-rate estimate <= proposed USD 1.00. This is **postcall refusal and LOCAL SOFT estimate**, not a provider-enforced hard cap or token upper bound before send; a successful usage check cannot authorize an earlier call.
- Outputs only hashes, tool names, and locally derived cost estimates. Actual bank/attack text, full model output, argument JSON, client/server IDs and secrets never enter the public artifact.
- Reject replayed cross-arm request IDs/response IDs, forged origin/approval fields, missing/ambiguous model and tool metadata. All artificial HTTP test bodies are fake shape fixtures.

## Specifically what this PR DOES NOT build

No network sender; no `http.client`, Provider SDK or `workflow_dispatch`; no GitHub protected environment deployment, new secret, production tag issuance, actual paid call, real authenticated Provider reply, new Native bank effect, subsequent genuine model turns or scorer. Public status always `TWO_UNTRUSTED_NATIVE_CHAT_HTTP_FIRST_CAPTURES_QUARANTINED`, `eligible_for_official_scoring=false`, `new_utility_recoveries=0`.

**The previous #389–393 GitHub Environment and test-only tag experiments are not the Task1 production authority**. Hard provider project spending limits, credential route containment and global one-use production lease are not proven. No old approval may be reused. No version of Task4's dedicated fixed-hash sender may act as a Task1 authority.

## To make this a real measurement

The next separately reviewed production-bound job needs fresh explicit authorization covering exact Task1 case, 2 initial A/B native Chat calls, the model, count and dollar target. The job must enforce the protected Environment, a genuinely single-use production issuer, credential/egress policy, immutable source/request digest, real TLS-owned request/response journal and provider billing controls **before** any network POST. It must use this #422 adapter to quarantine genuine response bytes without executing their proposed native Tool calls, and only then build each arm's REAL Native Tool continuation and eventual official User+Attack scorer. Never import #403's scripted subsequent histories or #395's unrelated mock-score booleans.

## Testing

Dedicated PR-only CI at pinned AgentDojo and VERITAS commits reruns #403/#418–#421 plus the #422 positive/negative real-format fixtures. Dedicated strict test mode forbids skips; generic CI skips only integration tests without source-pinned Native. The workflow has read-only permissions, no secrets/provider, and publishes SHA-only redacted evidence. CI success remains **offline shape and source checks only**. Validate exact PR HEAD, every inherited check, uploaded JUnit zero-failure/zero-skip and artifact SHA before manually merging.

Historical V13 Utility A=93/128, B=64/128, B injection success=0/128. New measured genuine Utility recovery=0.
