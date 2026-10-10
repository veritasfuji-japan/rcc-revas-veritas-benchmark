# TASK4_LIVE_FIRST_TWO_CALL_CAPTURE_ONEUSE_V1 — PR #294

**This PR does NOT perform or automatically schedule any billable API request.**

The user has explicitly approved real API usage, narrowly interpreted
as the preceding published Task4 DirectAttack A/B *initial* two calls
and a **proposed $0.50 total ceiling**. A broader 128-case run,
additional real model/tool turns, native bank writes or a larger
budget is not authorized.

The immutable source is #292's successful proof Artifact 11672698922
(run 38060638006), including exactly two complete 5,282-byte first
request payloads; both are SHA256-pinned to
\`3c9ef1c4fa4d58f8969df723b40b99298fc08a9d44acfc6609f086fc0d7c5b13\`.
Their different synthetic source owners do NOT mean existing live model
responses; this workflow makes distinct actual HTTPS POST attempts only
after manual dispatch.

## Steps needed from the human GitHub owner

1. Merge this PR only after exact-head CI, fake transport tests and
   independent offline artifact checks are green.
2. In GitHub Settings → Environments, create or verify
   \`task4-real-provider-first-two-calls\` and restrict it to protected
   main, enabling required reviewer approval. These controls cannot
   currently be verified through the connected GitHub interface.
3. Configure a NEW, limited-use OpenAI project API key as environment
   secret \`TASK4_OPENAI_API_KEY\`. Never send the key in the chat or PR.
   Separately review project spending controls. The workflow assumes
   input $0.40/M and output $1.60/M tokens for the exact frozen model.
4. Run Actions → **Task4 First Two Real Provider Calls V1** → Run
   workflow → main. Enter exact approval phrase:
   \`APPROVE_TASK4_ONE_CASE_A_B_FIRST_2_CALLS_MAX_USD_0.50\`.

The workflow verifies the pinned #292 artifact, limits all request
JSON bytes and output tokens, checks a dedicated secret exists and then
ATOMically creates the fixed consumed Git ref before any Provider
network call. An existing ref blocks the run, and the same workflow
cannot automatically retry after timeout / uncertain outcome. Protect
this tag against force update/deletion to preserve single-use strength.

It attempts exactly one Chat Completions API POST for A and then one
for B. Full response bodies, server request IDs, input source SHA and
reported token usage are saved as CI evidence (never an API key).
Usage-based spending is *estimated*, not an authoritative billing
receipt or hard provider cap. Hard spend limit enforcement can slightly
overshoot while provider accounting updates.

**Scope gap:** the first request is BEFORE malicious transaction data
enters a tool response. Even if both real requests succeed, this does
not demonstrate attack exposure, actual utility or Final128 safety.
The human must separately authorize further genuine model/tool turns
and native controlled execution before claiming those outcomes.

The standard PR/push CI has no Provider secret and tests only a fake
HTTPS transport. No live API use happens on PR creation or merge.
