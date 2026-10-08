# Task15 Offline Source Tool-Call ID → Native Return History V1

## Status

Implemented / **NOT PROVEN** pending exact-HEAD proof CI and artifact.

## Rule-of-One

For each of the three offline source-captured assistant function calls,
bind its **exact, unique tool-call ID** to both A and B actual native
tool returns from the already admitted and executed RCC/Bind/native sink.

The linkage is constructed only after all three native A/B steps have
completed locally. It is exact-candidate, ordinal, original-request,
pre-state, post-state, receipt, and native-return bound.

An unsuccessful or partial run must never publish an apparently complete
model-tool-return history. No automatic retry is permitted.

## Architecture

- Inherit the frozen #248 native source capture and actual native message
  codec; do not mutate its source or contracts.
- Require the exact #251 versioned composed native return runner at the
  constructor. It retains original address/rent/refund RCC/Bind and final-sink
  authority, the single-use refund receipt and UNKNOWN semantics.
- Three **offline injected** assistant responses are captured using the
  original native OpenAI codec. Each proposal is governed and dispatched
  once per arm through the #251 composed runner.
- Post-completion, verify native candidate SHA, source assistant digest,
  unique tool-call ID, executed step ordinal and local return integrity.
- Create A/B-separated histories with one assistant tool call followed
  by its corresponding *actual native return*, rendered using pinned
  AgentDojo's `tool_result_to_str` and native tool-message codec.
- Compare all six return digests with actual performed native effects.
- Refused source, corrupt ID, return substitution or candidate mutation
  terminates as unresolved (no replacement history and no retry).

## Nonclaims

The model-source responses are **injected synthetic fixtures**, not
provider-authenticated completions. The source assistant proposals
were obtained with **three independent initial request histories**.

Although this proof constructs a syntactically native A/B tool-message
history after actual local effects, **no model query has yet consumed
that history**, and no final assistant continuation has run.

Therefore this does NOT prove continuous model conversation, Final128
utility recovery, authentic external banking effects, production readiness,
or paid-provider behavior. Provider/API/scorer calls: 0.

The next proof, `TASK15_OFFLINE_CONTINUOUS_NATIVE_MODEL_HISTORY_REPLAY_V1`,
must verify actual model queries consume the previous *governed native*
tool-return history, with no extra execution authority or reuse of receipts.

## Merge gate

Exact-HEAD run and immutable artifact plus independent inspection of
9 new cases and the entire predecessor proof chain are required before
labeling this frozen **bounded offline** scope as tested.
