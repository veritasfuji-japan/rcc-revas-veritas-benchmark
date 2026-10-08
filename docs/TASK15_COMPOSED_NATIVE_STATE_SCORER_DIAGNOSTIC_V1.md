# Task15 completed local native state scorer diagnostic V1

## Status

**NOT PROVEN until exact-head CI, downloaded artifact and independent review.**

This additive module runs AgentDojo's real native utility and injection
rubrics, but only as an **offline state-only diagnostic** on a completed,
provider-free three-step native Task15 run from merged PR #246.

It is **not** the actual model conversation, is **not** a scored AgentDojo
pipeline, and must never be represented as recovered Final128 Utility.

## Rule-of-One

The native rubric must not run until the actual stored RCC candidate,
A/B original immediate pre-states, final native effects, B-side Bind
receipts, refund one-use consumption and all three native post-states
have been independently recomputed and validated.

Unlike a generator or authorization adapter, the read-only observer
accepts **no** issuer, store, native runtime, model provider,
dispatch callback, fallback, repair, replay, approval or scorer-derived
permit. It accepts a completed observation and separately trusted
initial state, case ID and original request envelope.

For every arm and step, the validator derives the adopted native
candidate from the previously captured RCC journal, checks the
candidate hash against the saved exact pairing identity, and recomputes
the exact native address, rent and refund state transformations.
All prior native effect and scope evidence is required and terminal
failure or incomplete sequences are refused *before rubric lookup*.

Only after the entire A/B sequence validates may the observer call
the exact AgentDojo scorer (two calls) using detached final native
environment states.

## Crucial transcript limitation

PR #246 generated controlled CandidateAction proposals from trusted
fixtures. It did **not** record an actual model conversation, native
assistant messages or AgentDojo pipeline function stack trace.

Therefore the actual native rubric is called with:

- `model_output=[]`
- `functions_stack_trace=[]`
- `pre_environment=owned_initial_native_state`
- `post_environment=recomputed_native_final_state_for_arm`

The results are labeled `utility_state_only` and
`security_state_only`. Any boolean positives are **not** treated
as a new Final128 score, injection benchmark result or full
conversation success. The module makes no inference about actual
AI-generated intent or untrusted injection behavior in a new run.

`native_step_evidence` is only a digest-linked **local native effect
projection from actual recorded runner journals**, not AI-generated
messages or an authenticated external receipt chain.

## Stop conditions

The observer rejects changed proposal hashes, native arguments,
A/B pairing, missing effects, mid-sequence interruptions, incorrect
ordinals, state substitutions, missing current final sinks, failed or
missing B Bind, refund consumed-slot reopening and missing local
observations. Scorer output cannot reset a failure or authorize a
later native dispatch. The sandboxed provider/database transport and
scorer gold/ground-truth have no authority role.

The original merged #246 code, V13/Final128 result, model adapter,
provider configuration and all production controls remain unchanged.

## Verification

The dedicated Actions workflow replays #246's exact pinned proof
chain (2,224 tests, including earlier 15 governed native tests),
then runs 18 new tests and inspects recorded local evidence,
14 deliberate corruption refusals, and a native interrupted-run
refusal. It rejects missing test cases or scorer use before complete
validation. The accepted scope is still local only.

## Next proof

`TASK15_ACTUAL_NATIVE_MODEL_CONVERSATION_CAPTURE_AND_PROTECTED_CONTINUATION_V1`:
record independently acquired actual native assistant/user/tool messages
and function stack trace at source, bind every proposed tool to current
generation ordinals and authority checks, and only then score the
complete captured conversation. Any new provider run needs separate
explicit approval, exact cost cap and new permission.
