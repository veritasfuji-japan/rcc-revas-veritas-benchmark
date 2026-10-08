# Task15 Native Model Response Capture Boundary V1

## Status

**IMPLEMENTED / NOT PROVEN** until latest-HEAD CI and artifact inspection.

An additive **offline-injected native OpenAI assistant response capture
boundary** connects three independent native tool-call proposals to
the unchanged owned Task15 RCC + Bind + native final sinks from PR #246.

The source is a **test-only injected `ChatCompletionMessage` client**.
No actual model or provider response is obtained. The recorded model ID
is a request configuration, not evidence of provider use.

## One invariant

At each step, the existing owned runner issues its scope and component
profile (and independent signed refund authority for the refund step)
**before** calling the candidate generator. The generator:

1. Checks that all prior steps were actually locally COMMITTED in both arms.
2. Supplies the original user request in the native message encoding.
3. Calls the isolated, injected offline native client once.
4. Requires exactly one original native assistant function call of the
   step's frozen type; parses raw JSON without repair, duplicate keys or
   NaN/Infinity, and binds the exact candidate to current generation
   ordinal 3/9/14.
5. Returns the exact `CandidateAction` only to the original trusted runner.
   RCC, profile authority, Bind and the native tool sink stay unchanged.
6. Records the original decoded assistant message and request hashes.
   Failures and cancellation are terminal, with no retry or new authority.

## Important limitation: no synthetic tool-return messages

The merged address runner records native state and dispatch outcomes,
but does not expose its original returned native tool value. Therefore,
after the address step, the exact original native tool message **cannot
be reconstructed from authoritative captured return bytes**.

This V1 deliberately performs **three independent proposal queries**
against the same immutable system/user prefix. It does **not** append
a guessed native tool result to a fake continuous conversation, does
**not** request final A/B model continuations and does **not** claim
actual AgentDojo full conversation or native function-stack capture.

The positive fixture yields three source-captured proposals and three
real bounded local native steps, not a complete source-authenticated
multi-step model conversation.

## Failure cases

13 malformed/forbidden first responses, plus a failure on the second
candidate after the first native A/B effect: no retry, no rollback,
no permit promotion, previous native effect evidence retained.

The exact CI proof tests provider, database, network and production
trustlog calls as forbidden. The previous 2,242 proof-chain tests must
succeed before 15 new cases execute.

## Scope exclusions

Provider calls: 0. Scorer calls: 0. New external effects: 0.
No actual authenticated provider generation, continuous model history,
full native utility measurement, attack remeasurement, Final128
score improvement, recovery claim, persistent global duplicate
exclusion or production readiness.

## Next Rule of One

`TASK15_EXACT_NATIVE_RETURN_CAPTURE_AT_FINAL_SINK_V1`:
record the **actual bytes** of native address/rent/refund return results
before discarding them, without changing dispatch admission, and
prove that subsequent model history can use these real returns rather
than reconstructed state. Until that proof, no continuous model
conversation evaluation is admissible.

Any real provider execution must be separately approved and cost-capped.
