# PR #308 — Proposed Provider single-use admission preflight (OFFLINE ONLY)

## Rule of One

Prove that a **single issuer-frozen prospective Task4 model-request proposal**
can be consumed by **at most one local SQLite worker**, even with ten
parallel contenders, while real-Provider dispatch remains **unconditionally
DENIED** and no API sender or Provider credential is introduced.

**This PR does NOT issue real authorization or call OpenAI.**

## Why not reuse #307's consumption journal as if it were a real permit?

#307 proved local \`O_EXCL\` single-file evidence recording. That is neither
global permission consumption nor a Provider credential boundary. #308 adds
a separate **transactional collision and restart rehearsal**, using
\`BEGIN IMMEDIATE\`, a unique \`slot_id\` primary key and a committed
\`CONSUMED_BEFORE_VALIDATION\` record. In a local test, one of ten workers
can insert it; the other nine are rejected. Errors after consumption leave
\`UNKNOWN_CONSUMED_NO_RETRY\`. A stale unfinalized attempt is still consumed.

SQLite here is **a toy local proof only**. It does not implement
distributed, protected, replay-proof production authorization; users with
filesystem access could rewrite its journal and hash. No local permission
may ever be promoted into an actual Provider permission.

## Exact immutable proposed scope

The preflight generates a *new* harness-controlled Task4 issuer context
using the unchanged #303 wire and the #307 \`proposed_manifest\`.
It fixes the case, original request digest, date/context digest, wire SHA,
model, proposed **one** future call (not authorized), output ceiling,
historical-cost estimate and the previously consumed genuine third-run
tag. Mock acknowledgement explicitly says
\`real_execution_authorized=false\`, with no Provider request ID and no
human attestation.

The cost estimate comes from #306's frozen **historical** rates:
10,000 hypothetical input tokens + 256 output tokens, or $0.0044096
against an offline $0.005 predicate. This is *not* a quote for a current
model, measured token count, or a billing hard limit.

## Test-only execution sequence

1. Build and freeze one local Task4 manifest before a candidate exists.
2. Simultaneous worker instances try to consume the **same local slot**.
3. SQLite records the initial consumption transaction *before* checking
   the offered mock acknowledgement, date/expiry, model, budget or old tag.
4. Verify proposed fields match exactly. Any forged human approval,
   live credential/old consent phrase, changed date/wire, token/cost/call
   bound, or unknown outcome fails and remains consumed.
5. Emit **local integrity-only** receipt with 0 API calls, 0 bank effects,
   0 native Bind decisions. \`always_deny_real_api()\` always returns
   \`DENY\`, even for seemingly valid mock acknowledgements.

No Provider SDK is instantiated in #308; the actual SDK serialization
was **independently** tested in #306 under \`MockTransport\`. The actual
native VERITAS Bind simulation is independently bounded by #305.
The previous third-run real human consent
\`task4-third-two-real-provider-v1-consumed\` cannot be reused.

## What is still necessary before *any* live API POST

Separate fresh human approval with explicitly bounded *real* spend and
number of calls, strong protected distributed single-use store independent
from this SQLite mock, production credentials isolation and egress controls,
fresh model pricing/usage ceilings, no-retry handling for uncertain sends,
genuine Provider-origin request and usage receipts, binding actual model
candidates to a trusted production date/prestate/Bind, and a separate
independently audited live sender. None are implemented or authorized here.

**DRAFT — do not merge on intent or unit tests alone.** Verify exact
HEAD dedicated CI, JUnit, structured Evidence and artifact digest, plus
all existing PR checks. Merging #308 MUST NOT enable a real Provider call,
human authorization issuance, bank effect, official Task4 result or Final128.
