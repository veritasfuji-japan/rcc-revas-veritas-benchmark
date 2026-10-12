# Task4 #363 — Native wire-to-scorer continuity for existing #323 scripted sources

## Scope
Exactly the existing two **scripted** A/B OpenAI SDK/MockTransport sessions from #323,
not any new real model run or source of execution authority. Existing #323 tests
and post-native actual local AgentDojo scorer remain unchanged. The #363 auditor
rebuilds OpenAI wire messages for the completed Native arm using the pinned
AgentDojo codec, and requires each of its four outbound SDK request histories
to equal the corresponding Native message prefix **byte-equivalent JSON**.

Checks include read-return provenance across turns, phase-specific response
candidate digests, one-to-one native tool-call ID matching, the identical tool
schema across model turns, selected Native poststate/scorer-binding equality,
and arm-local history divergence after identical first requests. Replacements,
swapped sources, mismatched call IDs or missing terminal messages fail closed.

No real Provider POST, credentials, model inference, external bank effects,
new score on canonical Final128, fresh approval or production authority claim.
Passing #363 means **offline scripted lineage consistency only**.

## Reproduce
Use existing `.github/workflows/task4-323-single-arm-source-offline-v1.yml`.
Its #323 dedicated tests generate native A/B JSONL evidence under a denied
socket/SQLite context. The additional #363 audit consumes the same evidence
after #323 validation and writes `results/task4-363-native-wire-to-scorer-report.json`
to the existing artifact. It never starts a model client or scorer itself.

## Next meaningful gate
One-arm-per-source **genuine model** responses, post-read continuation and
native scorer input provenance remain unproven until a separately authorized,
bounded, non-retryable provider experiment is conducted.
