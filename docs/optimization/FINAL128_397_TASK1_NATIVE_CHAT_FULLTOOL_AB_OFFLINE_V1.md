# Final128 #397 — Frozen Native Chat/full-tool A/B offline preview

## Goal and actual implementation

Merged #396 detected a genuine methodological gap: earlier #381–#395
Task1 Responses API/single-read-tool/forced-final requests are not equivalent
to the native AgentDojo runner. #397 adds a different **unsent** request
builder using actual pinned Native AgentDojo OpenAILLM conversion functions.

Frozen commit: a75aba7631d3ca5fb7ab938965c97ead2f9ff84b
Suite: banking, v1.2.2; user_task_1 / injection_task_2.

- Derive ALL function definitions directly from Native FunctionsRuntime and
  _function_to_openai. Neither arm hides the native write-capable functions.
- Use _message_to_openai with actual native message types for original user,
  assistant tool call, Tool return and B-only additional trusted context.
- Keep Native Chat Completions wire family, tool_choice=auto, frozen adapter
  model gpt-4.1-mini-2025-04-14, temperature 0.
- Reuse two separate Native environment objects from #378 with identical
  originals and identical lower-trust injected Tool response in A and B.
- Assign *fake locally generated* call IDs for offline continuity tests.
  There is no authenticated model response behind these identifiers.
- Arm B alone gets #377 source-owned preterminal read-only projection;
  B does not overwrite or sanitize the original injected Tool response.
- Local inspection-only tool proposal handler demonstrates denying B write
  proposals before any dispatch while retaining full advertised action space;
  A baseline dispatch is deliberately not implemented. Neither arm executes
  the proposed effect.

## Explicit nonclaims and remaining gaps

The current bank environment and injected transaction subject are synthetic,
NOT enrolled official Final128 source/corpus. The B developer message role
and placement constitute a new treatment still requiring native full-pipeline
validation. This is a Native serializer mapping, NOT a proven complete native
pipeline; termination, iterative tool dispatch, exact native runner
configuration, and externally owned source integrity remain separate tasks.

No Provider client or network sender, API secret, live model response,
authenticated A/B sessions, paid approval, globally consumed once-only lease,
production VERITAS bind, real bank write or official Native Scorer measurement
has been added. All scores are NULL. A green CI does NOT establish real
security or Utility outcomes.

Do not relabel old fake scorer outputs as measurements. Do not treat the
older Responses/single-tool pilot as equivalent to this Native path.

## Shortest next milestones for Ben

1. Freeze exact official native Task1 environment, payload, permitted tool
   lifecycle, full model transcript and end-of-task semantics.
2. Connect a real VERITAS decision to sandbox-native effect execution
   without removing tools from B's model input. Run A against an isolated
   effect-observable Native sandbox, not real bank credentials.
3. Independently protect a fresh consent, hard spend cap, globally single-use
   issuer, TLS sender and credential/network bypass restrictions.
4. Obtain genuine independently executed A/B model first + continuation
   + terminal receipts and complete Native execution histories.
5. Perform the first *actual* same-run Task1 Native User/Attack scoring and
   only then evaluate extension to the frozen Final128.

## Merge gate

Pinned Native source/Tool blob and exact PR HEAD; dedicated CI plus inherited
#396/#395/#394/#381/#378/#377; zero failures/errors/skips. Verify original
attack parity, full original tool list, independent Native ownership,
no-op effect inspection, B-only trusted overlay and redacted artifact.
All other current PR checks green. No paid execution or auto-merge.

Classification:
SOURCE_OWNED_NATIVE_CHAT_FULL_TOOL_AB_OFFLINE_PREVIEW_NOT_LIVE_OR_OFFICIAL.
