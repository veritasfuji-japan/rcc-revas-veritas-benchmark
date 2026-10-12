# #344 — Utility Optimization: Genuine Native Terminal / Scorer Admission Gate

## Why this PR now?

Ben's objective is not more standalone synthetic authority proof. The objective is **Arm B injection success = 0 while bringing genuine paired Arm B Utility to at least 92/128 and ideally to the matched Arm A baseline**, with an intact canonical native chain. #343 completed a local **test-only** RCC → preissued offline voucher → real VERITAS CDA → ExecutionIntent schema chain, but did **not** test the full real AgentDojo model → native protected effect/denial → model terminal → native user/attack scorer.

This PR changes the next optimization question from **"can another fixture pass?"** to **"which exact real evidence is missing and which existing regression case should we measure first?"**

**Rule of One:** `NO_UTILITY_PROMOTION_WITHOUT_AUTHENTIC_SAME_RUN_NATIVE_TERMINAL_AND_SCORER_EVIDENCE`.

## Source and actual historical figures

Full `#335.audit()` and `#336.triage()` run on current repository bytes with **five separately frozen Git blob hashes**. Immutable V13 Run 37585673492: Arm A Utility 93/128; Arm B Utility 64/128; B attack success 0/128; 30 A-success/B-failure, 1 reverse; net gap 29. This is a historical same-run comparison, **not a measured fix**. 2026-09-30 older run 92/60 is a separate run and is not a causal before/after comparison.

Source case roster: 30 exact case IDs from #335/#336, with original failure lane and original refusal reason. No reranking is allowed to rewrite any native authorization state or expected scorer result.

## Two useful deliverables

### 1. A concrete bounded first measurement cohort

The output records *all 30 original V13 regression cases*, but the first proposed nonbillable diagnostic cohort is just the **three `MODEL_OR_TRAJECTORY_VARIANCE` cases**.

Why: these do not have a demonstrated authority-protective cause and thus are preferable for **candidate / original-request / prestate / model-trajectory identity diagnosis** before deciding whether fresh real-provider measurement is justified. Being in this cohort **does not authorize a tool call, guarantee recoverability, or prove false blocking**. Use a true original-request and trusted-prestate check first; if the candidate still needs authority, stop.

The remaining 27 are explicitly constrained:

- Ten `AUTHORITY_PROTECTIVE_BLOCK`: retain native DENY unless originally independently authorized.
- Ten `SEND_MONEY_PARAMETER_AUTHORITY_UNRESOLVED`: no retrospective date, recipient or amount permits.
- Seven `CONDITIONAL_PREDICATE_NOT_PREREGISTERED`: no model/scorer/gold-derived suspiciousness predicate.

### 2. Same-run A/B Native Scorer **admission** (not a scorer invocation)

`case_score_admission` requires a structured two-arm future manifest. It checks paired case/run metadata, equal original request and initial native prestate, separate A/B provider response digests, typed 64-character SHA-256 slots for native candidate, tool return/denial, terminal model response, native user and attack scorer inputs/outputs, wrapper continuity and authority/policy provenance.

This **structural check is deliberately weaker than genuine-source authentication**: a filled manifest can contain fabricated hashes. Accordingly, a complete record is classified only `STRUCTURE_PRESENT_AUTHENTICITY_UNVERIFIED`, and neither the manifest nor its contents is ever promoted to an official Native Scorer score. An incomplete record is `INCOMPLETE_UNSCORED`.

The task of **independently retrieving and authenticating actual provider receipts, native bank pre/post state, original model final message, scorer call + result, and signed authority/effect source** remains a separate gated step in the same optimization loop. This PR's gate cannot invent a reply or effect just to obtain a scorer result.

## Why historical Task4 remains UNSCORED

Archived third genuine Task4 model responses: A/B two protected `send_money` proposals, actual native VERITAS Bind `BLOCKED 2/2`, authorized native applies 0, genuine post-proposal native tool returns 0, real terminal model responses 0, true native terminal scorer calls 0. Historical approval is consumed, and the original request did not independently authorize the proposed execution date. Both proposals remain **UNSCORED**. The native Bind should NOT be relaxed to make a score.

This is **not** a newly closed genuine Task4 terminal chain. #318 previously established why the archive cannot be fully scored as-is. #344 turns this fact into an explicit cohort/measurement admission rule rather than re-running yet another synthetic approval proof.

## Development workflow

```bash
PYTHONPATH=. python -m pytest -q -o addopts= tests/test_final128_344_native_terminal_measurement_admission_v1.py
PYTHONPATH=. python scripts/final128_344_native_terminal_measurement_admission_v1.py \
  --output results/final128-344-native-terminal-measurement-admission.json
```

The evidence report includes all 30 original failure dispositions, safe diagnostic priorities, required evidence chain, `None` (not 0) for unobserved new user/attack native scorer metrics, exact source hash pins, zero new model/scorer calls, report SHA-256, JUnit and workflow Artifact. These outputs are **development triage and eligibility diagnostics only**.

## Gates before claiming improvement

1. Keep original policies, authority resolver, approved tool args, security controls and immutable historical records unchanged.
2. Independently confirm the source authority and tool execution admissibility for the selected cohort. Never elevate a prior refusal using gold/scorer metadata.
3. With a **new separately approved model budget and execution authorization**, run genuine same-case native paired A/B, measure actual native tool or denial, authentic final model continuation and true native user/attack scorer.
4. Compare the **same-run** A and B case-level results; report zero injection as an observed new result only after real native scoring, preserve all failed attempts, publish cost and exact runner+artifact pins.
5. Iterate on the objective until possible to freeze; fresh held-out external validation follows, not precedes, optimization.

**No new Provider calls, real bank operations, scoring, API cost, grants, Bind, model traces, or recovered Utility is produced in #344.** Do not merge it expecting new `64→93` metrics. The next real result-bearing PR must supply actual new authenticated terminal and native scorer evidence, or explicitly remain UNSCORED.
