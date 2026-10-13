# Final128 #395 — Task1 post-terminal REAL Native Scorer bridge on OFFLINE synthetic responses

## What this adds after #394

Previous #394 constructed two Responses API-shaped, **unsent** second-turn
messages that retain the identical attacked Native AgentDojo Tool result in A/B
and a verified read-only spending projection in B alone. It quarantined fake
terminal JSON, explicitly never scoring it.

#395 is an **offline diagnostic connector to the actual pinned AgentDojo native
scoring implementation**, rather than another fake scorer or documents-only audit:

- Reject any promoted "authenticated", "approval", "paid", "actual Provider"
  or "official scoring" fields **before loading the scorer**.
- Re-read two *independent* in-process Native AgentDojo banking environments,
  compare the original request, injected lower-trust Tool rows, call ID binding,
  read-only function and bank state to the exact #394 packets.
- Build full detached NativeScorerInput instances with actual native environment
  models, each function call converted to the pinned AgentDojo FunctionCall
  type, model outputs obtained from #394's quarantined final-text parser,
  and an explicit ExecutionBarrier after the local read-only trajectory.
- Invoke the **actual** suite._check_task_result through the existing
  invoke_native_agentdojo_scorer twice per A/B pair (User and Attack rubrics).
- Detect any scorer mutation of detached source, model output or function
  trace. Do not construct, modify or repair answers using scorer expectations.
- Retain the local diagnostic booleans in an EPHEMERAL return object for code
  verification. Public CI evidence includes ONLY counts, native pin,
  source hashes and explicit **null official scores**, never fake answers,
  model data, attack text, or positive/negative fake Utility flags.

The diagnostic is source-bound within a **local synthetic Task1 banking test
fixture**. The bank fixture is NOT the unchanged full canonical frozen
Final128 corpus. The fake first Provider function calls and fake second
terminals are not model inferences or authenticated TLS responses. The
FunctionCall trace originates from the offline fixed Tool contract, not an
independent Provider-side transcript.

## Trust/authority boundary

This code does not authenticate TLS receipts, check an independently issued
source signature, issue or consume the actual Task1 protected singleton, use
any Provider key, or permit a paid request. The #393 test-only GitHub tag
does not grant the final experiment authority. GitHub CI green establishes
the software seam and rejection tests ONLY.

Both public functions deny_real_provider_execution and
deny_official_measured_utility **unconditionally reject** arbitrary objects,
saved approval strings and asserted 'provider verified' flags.

There is no new official Task1 score, no new same-run genuine real-model A/B,
no Final128 measurement, and no recovered Utility claim. The existing historical
V13 scores (A 93/128, B 64/128, B injection 0/128) remain unchanged.

## What #396 and subsequent work must do

The shortest trustworthy route to Ben's result is NOT to add more fabricated
answers. Connect a protected, fresh-consent, budget-limited one-time sender
to source-owned real first response IDs and real second terminal receipts in
A/B, preserving the exact frozen native task and injected Tool bytes. Verify
source authenticity at TLS observation (not claimed JSON), durable one-time
consumption and no-retry semantics, the complete genuine native trace and
native source before/after. *Only then* feed the authenticated completed
pair to Native User and Attack Scorers, and separately report measured
same-run one-case Utility before scaling up to Final128.

This first controlled Task1 two-turn pilot is not automatically full
AgentDojo benchmark faithful: the #394 forced terminal tool_choice and
developer-message placement still require full-canonical equivalence review.

## Merge gates

1. Dedicated, pinned AgentDojo v1.2.2 source with exact commit
   a75aba7631d3ca5fb7ab938965c97ead2f9ff84b and exact bank
   Tool Git blob 941c27467b7890cced7ab70e5fd5ca32241f99a5.
2. Actual native User/Attack scorer invoked for both offline fake arms; all
   source, pair, false-authority and false-scoring refusals pass; JUnit
   errors=failures=skips=0.
3. SHA/JUnit artifact excludes raw bank/attack/model output and score flags.
4. Entire PR HEAD's ordinary workflows successful and exactly-scoped changes
   inspected; no workflow_dispatch, secret, network sender, GitHub mutation,
   real bank effect or external API spend.

Classification: REAL_NATIVE_RUBRIC_ON_QUARANTINED_OFFLINE_FAKE_NOT_OFFICIAL_UTILITY.
