# Task15 Native Model Response Capture Boundary V1

## Status

**IMPLEMENTED / NOT PROVEN** until exact-head CI and artifact inspection.

This is an additive **offline-injected** native OpenAI response/codec bridge
into the already proven, bounded local RCC + Bind + native Task15
address / scheduled-rent / refund composition.

A permitted source response in V1 is a trusted harness-provided,
injected offline chat completion object (OpenAI native schema), **not**
a real provider response, independent model-provenance attestation,
a new Final128 candidate or a production authorization.

## Rule of One

A protected native proposal passed to the prior composed runner must be
derived directly from one native assistant response obtained **after**
current owned profile/scope/signed authority issuance. The bridge
strictly parses raw function-call arguments without repairing fields,
rejects duplicate and nonfinite JSON, binds exact candidate hash,
function and real generation ordinal (3 / 9 / 14), and allows the
unchanged prior runner to execute RCC, Bind and its native final sink.
The wire cannot grant or return an execution permit.

Before the next proposal is requested, the prior A/B native result
must already be committed and the two returns and pre/post states
must match. Only the **returned native tool value** is inserted into
shared model history; no model or test creates a fictitious tool
success receipt. The three proposals are recorded with their original
assistant-message SHA-256, IDs, requests and native schema identity.

After all three steps are complete, two terminal continuations are
requested with **no tools exposed**, and any extra effect proposal is
refused. All returned native messages share the same pre-final history
and are never fed back into admission.

## Offline evidence vs real-model evidence

CI uses a completely injected, deterministic `StrictOfflineClient`.
The model ID `gpt-4.1-mini-2025-04-14` is pinned in the native
request format, but there are **zero actual GPT-4.1-mini requests**.

This V1 proves **source-at-capture wire and native-effect linkage only**
under the owned recording-client assumptions. It does NOT prove:
- that an external model really authored the responses;
- a complete real provider conversation, grounded native reads or injection challenge;
- new utility or injection scoring, or a Final128 run;
- external bank/account payment effects, authenticated receipts, durable
  network bind enforcement or production readiness.

Injected offline tool results and terminal text are not grounds to
relabel this work as real model evaluation.

## Failure semantics

Unsupported function, malformed or duplicated JSON, response role or
choice tampering, history/tool schema mutation, provider exception and
cancellation are terminal. No retries. If a failure happens after any
native effect, the underlying composed runner observation is preserved
as unresolved evidence; no rollback, compensation, NO_EFFECT claim,
slot reset or automatic re-execution is offered.

## CI

The dedicated workflow replays the exact merged #247 proof chain
(2,242 earlier tests) before 15 new tests, then validates offline
transcripts, native steps, 14 refusal cases, and the zero-provider
claim boundary. An exact git blob contract pins all dependencies.

## Next proof

`TASK15_AUTHENTICATED_PROVIDER_CAPTURE_AND_FULL_NATIVE_CONVERSATION_SCORE_V1`
requires a separately approved provider run and cost cap. It must
first add genuine native read-only tool observations and verifiable
provider response source/pinning, then score source-captured actual
conversation + function stack trace. **This PR authorizes no spend.**
