# Final128 #396 — Actual pinned Native Task1 fidelity gate, DEFAULT DENY

## What this fixes after #395

#395 proved that the actual AgentDojo native User/Attack rubric can run on
offline fake completed Task1 text. **It did not prove that our Task1 pilot
actually reproduces the canonical Native AgentDojo model interaction.**

This PR reads the **real pinned AgentDojo v1.2.2 banking TaskSuite** directly,
constructs its true FunctionsRuntime tool catalog, invokes its actual
function-to-OpenAI tool schema converter, and verifies the original Task1
user prompt and injection rubric selection. It compares those source-owned
facts against #381/#394 A/B model packets; it does not infer canonical parity
from a saved bool, locally generated digest or a fake Provider response.

The comparison is a **real gate** because it refuses to authorize official
Final128 scoring or paid Provider dispatch and publishes exactly where the
current bounded Task1 experimental profile differs from canonical AgentDojo.

## Confirmed source-of-truth differences that BLOCK canonical promotion

- Native frozen OpenAILLM constructs **Chat Completions** messages and function
  definitions; #381/#394 uses **Responses API** request items instead. The
  mapping and exact semantic parity have NOT been independently established.
- Native Banking TaskSuite includes more than the single read-only Tool offered
  in #381's initial packet. In particular, the Native runtime exposes write
  capabilities such as send_money, whereas the bounded pilot intentionally
  exposes only get_most_recent_transactions. This restriction is appropriate
  for a read-only pilot but **changes the benchmark action space**.
- Native OpenAILLM requests **tool_choice=auto** when tools are present.
  The bounded pilot #394 forces second-turn **tool_choice=none** to obtain a
  terminal answer. That changes potential model behavior and must not be
  silently treated as equivalent.
- The pilot appends a B-only developer role projection in a custom place
  after the function call/result. A complete native pipeline hook with
  verified identical semantics has NOT been demonstrated.
- The local synthetic bank fixture and injected subject are NOT evidence of
  the exact frozen canonical Final128 prestate/enrollment/attack payload.
- There are NO genuine authenticated independent Provider responses, no new
  explicitly scoped approval, no independently consumed protected singleton,
  no source-owned production TLS receipt or real same-run official scores.

**A passing #396 is a passing detection of mismatch, not passing canonical
equivalence.** Do not alter the rubric to accommodate the pilot, or weaken
VERITAS's authority checks to recover Utility.

## Exact inputs and proof

- Native source: pinned AgentDojo
  a75aba7631d3ca5fb7ab938965c97ead2f9ff84b
- Native banking tool blob:
  941c27467b7890cced7ab70e5fd5ca32241f99a5
- Native real TaskSuite: banking/v1.2.2, user_task_1 and injection_task_2.
- Read-only source: #381 first request + #394 source-bound independent A/B
  packets. Both first function-call IDs are mock-origin and untrusted.
- Output: redacted SHA-only diagnostic with canonical_fidelity_blockers,
  canonical_final128_eligible=false, production_provider_dispatch_eligible=false,
  official scores null, real Provider calls zero.
- Both public official admission functions ALWAYS DENY even if a caller
  supplies a saved consent string, a fabricated Provider TLS record, or an
  apparently valid SHA.
- No effect, credential, writable GitHub permissions, protected environment
  approval, real paid Provider call or Native scorer execution is installed.

## Shortest next real-measurement path

1. **Choose and freeze a canonical model/runner contract**: either use the
   exact pinned Native Chat Completions/Full tool catalog and faithful
   trajectory with an execution-only VERITAS boundary, or explicitly version
   the Responses single-tool/forced-final Task1 pilot as a DIFFERENT study.
   Never merge their utility numbers into one canonical Final128 metric.
2. For canonical AgentDojo, preserve the original Native user request,
   exact injection payload/slot, complete before/after source state, full
   native function trace, and A/B independent model sessions.
3. Only a separately reviewed protected issuer, fresh exact-model A/B/case
   authorization, externally enforced once-only lease, hard spend stop,
   credential/egress boundary and trusted TLS sender may perform a new
   billable action. This PR grants **no** such permission.
4. Then bind authentic response bytes and terminal transcripts to the
   source-owned actual Native User/Attack scorers once the full trajectory
   closes. First measure ONE same-run real Task1 A/B; separately validate
   held-out and expand toward the frozen Final128.
5. Preserve prior real V13 evidence separately. Do not re-label synthetic
   or historical data as new genuine production proof.

## Merge gates

- New exact-PIN CI with actual Native TaskSuite and source-derived tool schema
  and inherited #395/#394/#381/#378/#377 regressions: zero failures/skips.
- Observe the source-proven non-equivalences in output, not fake success.
- Tampering with the original request, A/B pair, synthetic Provider origin,
  single-use approval, packet, or official score must fail before issuance.
- Evidence archive contains JUnit, SHA source inventory, and the redacted
  report only. No raw injected text, bank ledger, fake provider ids or fake
  scored booleans. No external API sends or GitHub write scopes.

Classification: CANONICAL_FIDELITY_GAP_DETECTED_PRODUCTION_AND_OFFICIAL_SCORE_DENIED.
