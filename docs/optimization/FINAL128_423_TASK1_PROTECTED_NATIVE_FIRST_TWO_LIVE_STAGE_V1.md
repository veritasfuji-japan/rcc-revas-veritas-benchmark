# Final128 #423 — protected Task1 FIRST two Native Chat A/B sender (STAGED, NOT DISPATCHED)

## Difference from #418–#422

This PR adds the **real HTTPS POST implementation and manually gated GitHub workflow** for ONE initial A and ONE initial B Native Chat Completions request. #421 already freezes the actual pinned `AgentDojo` first requests with the full Native banking tool catalogue, and #422 validates real-format Chat completion HTTP bodies by feeding them to #420's existing untrusted tool parser. This PR does **not** add another mock agent/scorer.

The first Native packets can be regenerated in process from exactly pinned AgentDojo and VERITAS, original Task1 case, original attack/corpus and full Native functions. **No follow-up packet from scripted #403 is sent.**

## What is actually implemented

- `scripts/final128_423_task1_protected_first_native_chat_sender_v1.py` provides an offline `preflight`, then a protected `send` entrypoint. Only the `send` path can construct a true `https://api.openai.com/v1/chat/completions` connection, with TLS default root validation. Exactly TWO posts maximum: A once, then B once, max 256 completion tokens per call, `store=false`, `stream=false`, `n=1`. **No retry** on 429, timeout, 500, bad JSON, missing receipt, unknown outcome or rejected local postcall usage.
- `task1-real-model-pilot` protected GitHub Environment, **workflow_dispatch only**, main-only, exact actor and one run attempt, independently supplied consent phrase **at dispatch** and Environment approval. No PR or merge event can trigger a paid action.
- A DIFFERENT **production** globally fixed consumed ref `refs/tags/final128-task1-first-two-real-responses-v1-consumed` is checked for prior absence; its active tag Ruleset must explicitly deny update/deletion/nonfastforward with an empty bypass-actor list. A single GitHub POST creates the fixed consumed tag against exact `GITHUB_SHA`; an exact GET must read it back. Unknown/ambiguous GitHub status is a permanent stop; no retry/reset. The earlier `#391` test-only tag is never used.
- The job checks out original frozen Native AgentDojo SHA `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`, VERITAS SHA `a1d66aef02262cf8a913295270c3aafd159c6adb`, identical pinned corpus, verifies source, and computes first requests before issuance.
- Two NEW Environment-scoped secrets must be configured, `TASK1_OPENAI_API_KEY` and a random 32-byte base64 `TASK1_CAPTURE_AES256_KEY`. Previous Task4/Repository keys are NOT used. Raw model response bytes are encrypted with AES-256-GCM (nonce per arm; AAD ties case, workflow run, arm and exact native input SHA) before any artifact is uploaded. The 1-day Actions artifact contains only encrypted raw model bodies, redacted hash-only journal and presend source proof. The AES key is never uploaded.
- After each successful receipt, #422 validates HTTP metadata and source-owned Native full tool names/args without executing any proposed tool. A/B independently observed client ID, server `x-request-id` and model response IDs must be distinct. Model-selected writes are NEVER dispatched and are NOT an authority grant.
- Tests use an injected local HTTP connection stand-in with socket connections blocked. CI verifies exact two calls, stops after unknown A/B errors, forbids retry, rejects mismatched user/Environment/tag/rerun, encrypts and can decrypt only with the separate test key. Actual production test of the Environment, tag, model origin and spend boundary is **not** conducted merely by passing tests.

## CRITICAL: no new paid authorization in this PR

**PR creation, CI success and merge consume ZERO production tags and send ZERO Provider requests.** Do not manually dispatch the new workflow until explicit fresh permission is obtained from the operator for case `banking:user_task_1:injection_task_2:direct`, model `gpt-4.1-mini-2025-04-14`, **two initial requests (one per arm)**, exactly this commit, and an additional maximum TARGET USD 1. The exact new manual phrase is:

`APPROVE_TASK1_FIRST_NATIVE_A_B_TWO_CALLS_MAX_USD_1`

Also require the independent conscious billing review phrase:

`I REVIEWED PROJECT BILLING AND APPROVE MAX USD 1`

**These strings are not cryptographic consent and do not prove that the provider account has an enforced hard billing stop.** Manual GitHub Environment self-review is not an independent security reviewer. The historical #350 estimate assumes token inputs, historical prices and exactly two calls; API-side prompt token counting, billable features, other account usage and billing lag can differ. Before manually dispatching, independently verify the real account/project spending controls with the provider. Do not present a postcall local estimate as a hard ceiling or spend guarantee. The repo's contents:write GitHub token and Environment settings do not prove complete credential, network or IAM bypass-resistance. Stronger production claims remain DENY.

## Exact behavior and limitations

A successful separately approved run would produce two real first Provider replies, encrypted source records and hash summaries. **This is not a genuine full same-run A/B Utility case** because it does NOT run any model-selected Native tool, follow-up model turn, genuine terminal, Native User/Attack Scorer, or any bank effect. Even a model-selected legitimate Tool call in A or B is just untrusted data. If only A completes and B is unknown, the singleton stays permanently consumed; **never rerun**. A secure new consent/session plan is needed for any recovery.

Only after distinct provider-origin evidence is reviewed and decrypted in an isolated trusted environment should the next separate work pass each real arm's model-selected read-only native tool call to the pinned Native executor and construct the next true model-visible packet. Protected writes must continue to pass VERITAS Bind; never import the scripted second/third model histories from #403 or join the unrelated #395 offline scorer diagnostic.

Historical V13 frozen Final128 A Utility 93/128, B Utility 64/128, B injection success 0/128 are UNCHANGED. Newly measured official recoveries = **0**.

## Review and CI gate

Separate PR-only `final128-423-task1-protected-first-native-chat-offline-ci-v1.yml` has only `contents:read`, NO Environment, NO encrypted secret, no workflow_dispatch and socket-blocked tests. Native AgentDojo and VERITAS pinned checkouts are required by strict dedicated CI. Validate 18/18 or current exact HEAD checks and downloaded JUnit, Artifact SHA, source safety/refusal tests. The protected workflow `final128-423-task1-protected-first-two-native-chat-live-v1.yml` is a distinct manual workflow: DO NOT click Run workflow during PR review or immediately after merging. No paid execution is authorized in this conversation.
