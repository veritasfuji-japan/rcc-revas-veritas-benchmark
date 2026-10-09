# TASK15_OFFLINE_PAIRED_TERMINAL_NATIVE_HISTORIES_V1

## Status

**Implemented / NOT PROVEN** pending exact-HEAD dedicated CI and artifact inspection.

## One invariant

After an exact three-step composed Task15 candidate-source sequence (sourced
from the **B** history only) and six guarded local native A/B effects, each
arm's *terminal* offline request must independently contain that arm's three
actual native tool results and original source assistant tool-call identities.
One text-only synthetic terminal assistant answer per arm may be published as
a complete paired result **only if both requests succeed exactly once**.

Each history has 8 native OpenAI messages, with three original assistant
tool calls and three actual native results, with separate A/B environment
pre/post hashes. The frozen candidate-generation model saw B results; this
proof **does not** claim A-side candidate regeneration.

## Failure handling

Both complete wire histories are validated before the first terminal
request. A terminal rejection, mutation, new tool proposal, cancellation,
duplicated choice or provider exception on A prevents any B query. The
same failure on B leaves the earlier A response available in the
provisional transport journal but does not publish paired completion.
Neither failure changes already committed native effects, retries the
request, or claims rollback/no-effect.

## Testable outcome

- Three original offline candidate source queries.
- Two final offline text-only queries in deterministic A → B order.
- Five offline client calls total; final message counts 8 each.
- Six local A/B governed native executions, with six final native result
  references in the two terminal histories.
- No tool exposure in the final calls.
- Twenty new parameterized tests (1 positive, 18 negative cases,
  1 constructor), plus full 2,302-test predecessor proof chain.
- A/B reply contents are intentionally different synthetic strings to
  detect false reuse.

## Explicit exclusions

No OpenAI API network call; no paid provider/scorer calls. No AgentDojo
Task15 utility or injection score, no independent A candidate generation,
no real bank effects, no external provider response authenticity, no
production readiness, no Final128 improvement.

The next separate proof round can assemble authoritative full output,
function trace, pre/post environment and exact scorer inputs **after**
this bounded paired terminal transcript is closed.

## Merge gate

Require dedicated exact-head 20/20 tests, 18 refusal evidence records,
full predecessor replay, pinned source blobs and independent matching
of both arm histories in the uploaded artifact. CI green alone is
insufficient.
