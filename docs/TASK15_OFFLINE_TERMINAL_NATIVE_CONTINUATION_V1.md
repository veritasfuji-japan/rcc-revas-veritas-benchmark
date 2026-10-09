# TASK15_OFFLINE_TERMINAL_NATIVE_CONTINUATION_V1

## Status

**Implemented / NOT PROVEN** until the exact PR HEAD workflow and its complete
evidence artifact are independently inspected.

## Single central invariant

After three ordinal-pinned source assistant tool calls and six governed
A/B local native commits, construct the selected **B arm**'s exact native
conversation history: initial request + 3 native assistant tool calls + 3
actual executed B native tool returns (8 messages). Submit that exact history
to the pinned native OpenAI message adapter once, with **zero tool definitions**
and require a **text-only terminal assistant response**.

Every model request sent before terminal must equal the corresponding
prefix of the terminal request. All tool-call IDs must match the exact
source call ID and native output hashes verified by #252/#253.

## Frozen controls

- #248 native assistant message capture remains unchanged.
- #251 RCC/Bind/native sink and governed composed runner remains unchanged.
- #252 tool-call ID/native receipt hash correspondence remains unchanged.
- #253 prior native output inputs to subsequent candidate source queries
  remain unchanged.
- New V1 successor runs terminal **after** completed local composed A/B
  execution, never as an agent-authorized tool invocation.
- A one-shot terminal attempt cannot dispatch tools, issue authority,
  reset a prior receipt, mutate a committed native state or cause retries.

## Negative cases

Provider exception, cancellation, refusal, terminal tool-call proposal,
empty terminal content, extra completion choice, input mutation, forged
prior tool-call ID, and forged prior native tool content fail closed.

All already completed local native effects remain visible as committed.
No error path may claim NO_EFFECT or rollback after the fact.

## Exact limitations

The source is an **offline injected synthetic client**. This proof
demonstrates wire transport of full B native history and decoding of a
synthetic text-only final answer; it does **not** show a real provider
authenticates or semantically understands the effect, any A-arm terminal
answer, real external-bank effects, utility scoring, Final128 recovery,
production readiness or third-party verification.

Provider calls: 0. Scorer calls: 0. The final query exposes no tools.
Synthetic terminal text is not the bank task's scored completion.

## Merge gate

Replay full #253 predecessor proof chain (2,291 frozen tests), verify
11 new tests (1 positive, 9 refusal variants, 1 constructor), source blob
pins, terminal original wire and B effect hash provenance; inspect artifact
on exact PR HEAD before accepting the bounded proof.
