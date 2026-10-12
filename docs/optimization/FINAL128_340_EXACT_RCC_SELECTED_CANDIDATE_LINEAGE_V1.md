# #340 — Exact RCC-origin Candidate Selection by Real VERITAS CDA (controlled transcript)

## Rule of One

Prove that the **exact same** released RCC candidate can become VERITAS's `chosen` alternative in a real local `POST /v1/decide`, and that a verified native CDA records the selected option while **without** creating or suggesting execution authority.

The current RCC release (SHA `353ad9e6a17cda8874a129493fe0f8f4fe4427bc`) produces 12 real released candidates / 24 withheld cases from 36 pinned synthetic governance fixtures. It **does not independently authenticate policy authority**, issue grants, or contact a bank. The frozen VERITAS source (SHA `299a3c4987668091f50ab3e45165bcccd1ae193f`) is the same pin as #339 to isolate candidate-selection changes.

## Why #339 found a gap

#339 used VERITAS's existing controlled provider transcript, which told the model to choose a synthetic **review** step. As a result, its actual native CDA was verified but `candidate_selected=false` / `verified_rcc_intent=false` for the released RCC candidate. A valid CDA is **not enough**: the native `chosen` value must agree with the actual source candidate's identity.

#340 tests the missing positive **selection capability**, but does not assert that uncontrolled live models will select correctly:

- Run unchanged RCC `preflight/register-takeshi/evaluate/verify-artifacts/prepare-veritas`, reverify hash pins, select first real released case, and use its **unchanged original** `/v1/decide` JSON request.
- Build a **controlled test-only model transcript** by copying the *exact* `id,title,description` of that one original RCC request alternative. No other option or action is introduced. That controlled response only chooses the candidate; it is not a trusted authority source.
- Send the original, unmodified request to actual VERITAS `POST /v1/decide` via the official `run_decision_to_external_bind_poc._decide` route driver. No network API provider, bank, Bind or billing. Route/kernel, native policy and generated CDA use the pinned real implementation.
- Independently verify the native CDA and **check actual returned** `chosen.id` and `chosen.description` byte-for-byte against the RCC-prepared alternative, with direct validation that `description` is the canonical JSON serialization of the original RCC candidate. The native CDA's chosen-value binding hash is extracted and checked against its own verified artifact.
- Require positive chosen identity. Unlike #339's diagnostic, #340 **fails its CI** if the native CDA selected another option.
- Attempt native `try_promote_verified_canonical_decision_candidate_to_execution_intent` on that actual `chosen`; require refusal and a **null** ExecutionIntent until independently valid structured actor/target/action/authority/approval and native selected-action evidence are available. Never generate those fields from RCC source labels.
- Tamper tests forbid modifying candidate JSON, choice, CDA status or evidence claims.

## Exact proof/nonproof boundary

| Claim | #340 |
|---|---|
| Original RCC candidate description and identity preserved in the HTTP request | Asserted |
| Native route actually executes | Asserted |
| Controlled local model can select precisely that original RCC candidate option | CI must observe true |
| Native CDA structurally valid with matching chosen option | CI must observe true |
| Independent / live model candidate selection | **NOT PROVEN** |
| Native selected-action evidence sufficient for execution promotion | **NOT CLAIMED** |
| Verified Native ExecutionIntent / v2 Authorization / Bind / consumption | **NOT PROVEN / not run** |
| Bank environment, IAM bypass refusal, real Effect, scorer Final128 | **NOT RUN** |
| Real Provider calls, external effects, new billing | **0** |

The model transcript is **instrumented**, not independent. The RCC candidate remains in its native typed RCC schema. An ID/description match is not a proof of a signed action authority. A verified CDA may still lack `selected_action_evidence` and a native promotable structured `DecisionCandidate`; this is expected and the script refuses to create an ExecutionIntent.

## Merge gate

Draft until dedicated CI + global CI SUCCESS, inspection of `selected_id_exact`, `selected_canonical_description_exact`, `native_cda_verified`, `native_promotion_result=REFUSED_NO_EXECUTION_INTENT`, and Artifact provenance SHA. Never describe this as an end-to-end positive execution-authority proof.

After #340, separately specify a trust-bound, immutable **RCC typed action → VERITAS typed DecisionCandidate** mapping that gets independent policy authority and required human approval from an actual trusted VERITAS source. Then prove the CDA `selected_action_evidence` and exact Native ExecutionIntent chain, and only then the Native v2 Bind and bypass/Effect evidence.

Historic reference only: AgentDojo V13 A=93/128, B=64/128, B injection=0/128; not rescored in #340.
