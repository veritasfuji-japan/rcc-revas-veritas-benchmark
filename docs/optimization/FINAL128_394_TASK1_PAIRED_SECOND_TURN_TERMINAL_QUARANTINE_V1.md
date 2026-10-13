# Final128 #394 — Task1 paired second-turn Responses packets and untrusted terminal quarantine

## Goal: advance Ben's measured Utility path without a paid run

Predecessors #377–#378 create real, separate, source-owned Native AgentDojo
banking read-only responses, with the original attacked Tool return identical
in A/B and a read-only outgoing-spending projection supplied to B alone.
#381 validates **untrusted** Responses-shaped first function-call captures,
and #382 rehearses first A/B POST transport with local fake connections.
Neither completed a genuine model's post-Tool final answer.

This PR closes the **offline second-turn formatting and terminal shape seam**:

1. Independently use the pinned real Native AgentDojo bank Tool for each arm.
2. Preserve each arm's claimed first function_call item and exact call_id;
   attach the unchanged attacked Native Tool output to the corresponding
   function_call_output.
3. Build real Responses-API-*shaped* second request dictionaries for A/B.
   Store is false, one read-only Tool schema, tool_choice none (for a bounded
   final-answer pilot), parallel_tool_calls false and max output explicit.
   B alone receives the #377 source-owned spending projection; A does not.
4. Accept separately fabricated offline final HTTP response bodies through a
   strict parser; retain terminal text in memory as a **quarantined** potential
   Native model_output with type text.
5. Emit SHA-only manifest with 0 actual Provider calls, 0 authenticated
   final responses, 0 actual Native Scorer calls and null official scores.

This is a **bounded Task1 research pilot wire profile**, not yet a verified
full-catalogue AgentDojo-native equivalent. A forced terminal and placement
of B's developer message still require benchmark-fidelity assessment before
formal canonical Final128 scoring.

## Why a fake terminal MUST NOT enter the official Native Scorer

Anyone can forge JSON IDs beginning with resp_ or call_, as well as the
x-request-id header. A checksum protects equality of bytes, not Provider
origin. The existing #381 untrusted first-capture admission cannot be silently
promoted by building a valid second request or receiving a valid-shaped fake
final message. Accordingly:

- deny_real_provider_dispatch() ALWAYS refuses.
- deny_official_native_scoring() ALWAYS refuses.
- The normal output is explicitly labeled UNTRUSTED / QUARANTINED.
- No official Utility, injection success, scorer lineage, or new V13/Final128
  result is produced, even when fake final text happens to match Task1's answer.

This PR does **not** launch or alter protected GitHub manual workflows,
create refs, read secrets, invoke the paid Provider, dispatch banking effects,
or call the Native scorer. Only controlled local Native read-only Tools run.

## Next milestones that actually produce Ben's result

A separately reviewed protected runner must:

1. Bind fresh operator approval, precise one-time case/A/B model and cost,
   isolated environment and externally consumed singleton to a trusted sender.
   Historical approvals cannot be re-used. The #393 test tag is not the
   production Task1 singleton.
2. Verify real TLS origin, exact outbound request bytes and distinct A/B
   Provider receipts **inside the protected sender**, not from untrusted JSON.
   Preserve raw protected evidence, never include secrets in public artifacts.
3. Link genuine first function call to the pinned Native Tool and real second
   Provider response for each arm; keep original attack bytes identical.
4. Bind independently generated completed terminal, actual full Native
   before/after environment and function trace to pinned native User and
   Attack Scorers after execution. Do not hard-code expected answers/scores.
5. First measure one actual Task1 A/B pair, then expand under renewed
   approvals and bounded budgets to fixed Final128 with original case/attack
   comparability and common same-run baselines.

Measured V13 A=93/128, B=64/128, B injection success=0/128 remain historical,
not a new score. This PR does not authorize or claim Utility recovery.

## Merge checklist

- Exact HEAD, pinned AgentDojo Git SHA
  a75aba7631d3ca5fb7ab938965c97ead2f9ff84b and bank Tool blob
  941c27467b7890cced7ab70e5fd5ca32241f99a5.
- Dedicated Native #394 adversarial tests + inherited #381/#378/#377
  regressions succeed with 0 errors/failures/skips.
- Verify SHA/JUnit artifact: no raw attack, banking rows, untrusted terminal
  text, secret, or authenticated/scored claim.
- Other repository checks green at exact PR HEAD.
- No workflows with workflow_dispatch, no Provider secret, no GitHub write
  token, no real external requests and no newly enabled live path.

Classification: UNSENT_REAL_NATIVE_TO_SECOND_RESPONSES_SHAPE_AND_UNTRUSTED_TERMINAL_ONLY.
