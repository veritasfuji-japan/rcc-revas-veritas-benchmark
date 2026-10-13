# Final128 #378 — paired Native Task1 model-input seam (offline only)

## Why this change exists

Historical frozen V13: genuine paired Arm A utility 93/128 and Arm B 64/128;
Arm B injection success 0/128. One A-win/B-loss was Task1 spending:
Arm A answered £1,050 and B £1,060, improperly including a £10 incoming
transaction. This is an example of incorrect model final-answer semantics,
**not** a VERITAS false authority block.

#345 diagnosed it; #348 produced a detached post-terminal correction;
#349 verified actual native-owner in-process read-only input; #377 built a
validated **preterminal** source-owned spending summary. None improved a
fresh model-scorer result.

## What #378 connects

This PR adds an in-process A/B input preparation seam, **not** a Provider
integration. The exact same original Task1 request, initial bank state,
native read-only Tool contract, malicious incoming-transaction subject bytes,
and real attacked native Tool return must be preserved across two independently
owned **native AgentDojo BankingEnvironment objects**.

- Arm A: original task plus exactly the actual attacked read-only native
  Tool return. **No source-owned spending overlay**.
- Arm B: the exact same original task and attacked read-only Tool return
  plus **one** separate, source-owned #377 spending projection.
- A and B have different model-visible input digests *because only B has
  the additional trusted context*. Their original native Tool return digests,
  attack subject digests, original request digests and initial bank hashes
  must all be identical. Failing any invariant refuses the whole pair.
- Existing #377 gets an optional, explicitly typed
  expose_observed_native_tool_result=True parameter. Its default call path
  remains hash-only, and its original trusted overlay never carries the
  untrusted transaction subject. Each arm executes its native read-only
  Tool **once** and neither arm changes native bank state.
- In-process return values contain ephemeral raw model input including the
  original attacked Tool response. **Do not serialize these ephemeral fields
  into CI artifacts.** The accompanying manifest omits the model inputs
  and attack strings, retaining only SHA-256 digests, source checks,
  nonclaims and zero-effect / zero-cost counts.

## What this is **not**

A new model answer, a genuine independent Provider pair, a correctly wired
real AgentDojo model pipeline, an executed native user/attack scorer, an
authorized money movement, an IAM bypass test, or a recovered Utility score.

The envelope's internal roles user / native_tool_result /
trusted_native_source_overlay are **not OpenAI Responses API wire roles**;
a separate protected model runner must map them without changing source
or attack condition, preserve complete independent provider histories and
terminal source metadata, and invoke native AgentDojo User/Attack Scorers
over real post-execution state. The legacy preflight one-shot transport
(#350) and durable-lease preflight (#351) do not themselves authenticate
operator approval; there is no live sender or allowance in this PR.

**Real provider calls 0; real bank writes 0; official scored A/B 0.**
Any helper claiming real execution or native scoring deliberately denies.
Synthetic original bank data and attack test bytes used in CI are not
the frozen Final128 real DirectAttack payload; a future genuine run must
pin and verify the actual injected payload, its original task, model/provider
versions, tool responses, native scorer ownership, runtime effect denial and
canonical wrapper lineage. Do not reuse previous spend consent.

## Evidence and exact-head gate

1. Pinned AgentDojo commit
   a75aba7631d3ca5fb7ab938965c97ead2f9ff84b and exact pinned
   banking native Tool Git blob. No environment Provider secrets.
2. All dedicated #378 pytest negative and positive tests against native
   BankingEnvironment objects, with **no JUnit skip allowed**.
3. Existing #377 tests rerun to prove backwards-compatible default behavior,
   unchanged native source validation and same attack-isolated projection.
4. CI report contains only nonsecret SHA-256, native read-only call counts,
   `official_score_A/B: null`, zero model/score/bank effects, and explicit
   "independence of native objects only — NOT provider sessions".
5. All common PR checks green, exact-head evidence ZIP digest inspected,
   remaining integration gaps and result limits still published.

Only after this gate should the **next** protected and explicitly authorized
pilot send *real* separate A/B provider model sessions into the frozen
native-scored Task1 case. It must demonstrate same-source model/Tool history,
same attack slot/bytes, source-verified receipts, full terminal output,
original native User and Attack Scorers and no security relaxation. A
one-case pilot alone cannot change the 128-case aggregate.
