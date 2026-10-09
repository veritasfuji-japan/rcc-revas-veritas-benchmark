# TASK15_OFFLINE_CONTINUOUS_NATIVE_MODEL_HISTORY_REPLAY_V1

## Status

**NOT PROVEN** pending exact-HEAD dedicated CI / auditable artifact.

## One central invariant

The second and third **offline injected** native assistant candidate query
must genuinely receive the previous protected candidate's committed native
result (from the owned selected **B** arm) as the preceding tool message in
its actual native OpenAI request, with the original assistant's exact
tool-call ID and original user instruction.

A refused/partial/unpaired/failed preceding attempt must never be converted
to an apparent completed tool result or trigger a subsequent model query.

## Implementation

- Additive successor `Task15OfflineContinuousNativeHistoryReplayV1` extends
  the exact #252 offline-call-ID-to-native-return capture. Source and
  RCC/Bind/native effect implementations and their proof pins remain untouched.
- At each `_query`, before requesting a candidate, the adapter reads
  the trusted native composed runner's actual completed steps, checks the
  original captured response IDs, candidate/state digests, terminal A/B
  commit and B-side Bind receipt, and creates fully typed AgentDojo
  assistant/tool messages with **B's in-process native return**.
- The parent native OpenAI codec sends **2, 4, 6 messages** at the three
  ordinal-pinned source calls (3, 9, 14).
- A digest and full wire snapshot capture proves that each later query
  actually consumed the prior executed B result, with no unsupported
  permissions or retries.
- The third native call and both A/B arms still execute entirely through
  the frozen guarded composed runner. No query after the final operation
  and no terminal assistant response are included.
- Bad prior native return, blocked prior B arm, duplicate source call ID,
  invalid late proposal, transport failure or cancellation terminates.

## Evidence / precise exclusions

Positive: 3 offline model source queries; 2 later requests consume
1 and 2 prior native results (3 cross-query prior-result messages in total);
3 native steps; 6 A/B local native commits.

Negative: 7 fail-closed scenarios; no complete history published on failure.

Not proven: live/paid provider behavior, source response authenticity,
terminal assistant answer, full multi-turn task completion, Final128
utility gain, external bank effect, independent third-party validation
or production readiness. All provider, scorer and external effects: zero.

A bounded sequential **offline candidate source** is now tested in this
proof scope, not full model conversation/production assurance.

## Merge policy

Only consider merge after dedicated CI and its artifact pass on the exact
head SHA, and the predecessor PR #252 immutable audit chain succeeds.
