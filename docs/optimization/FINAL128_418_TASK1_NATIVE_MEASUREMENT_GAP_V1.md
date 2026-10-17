# Final128 #418 — Task1 genuine Utility measurement gap after #403, without duplicate execution logic

**Scope:** one *existing* Frozen Native Task1 case `banking:user_task_1:injection_task_2:direct`; zero Provider/network effects, zero new scorer calls, no treatment/policy modifications. New Utility measured: **0**.

## Why this PR is necessary, not a reinvention

Prior work **already implemented**:
- #395: true AgentDojo native User/Attack scorer invocation on **quarantined offline synthetic**, separately constructed Task1 terminals. Native scorer diagnostic; never a real model performance result.
- #399–403: fixed Native DirectAttack/unchanged full tool catalog, source-owned read-only spending context in B only and actual Native `ToolsExecutor`→real VERITAS Bind adjudication. Model outputs still produced by a fixed **scripted recorder**, not the Provider.
- #405–412: independent process / owned simulated sink / key rotation, local single-use and netns/mTLS checks in bounded lab; not a production AgentDojo credential/egress proof.
- #414–416: source-check continuity and a **distinct local-counter native chain** replay at reviewed OS main, not Task1 actual live model score.
- #335–336: V13 93/128 A vs 64/128 B, 0/128 B attack success, 30 A-only regressions minus one reverse gain, and no new official Utility recovery.

**#418 reuses #403's actual pinned Native A/B pipeline directly** and validates its exact redacted and ephemeral observations plus the frozen #335 ledger. It is an executable **cross-seam measurement-exit ledger**. It does NOT implement another policy, direct attack, synthetic terminal, scorer, candidate transformer or payment backend; it does not combine #395's different scorer input with #403's local outcome as though it were a single genuine run.

## Scope and completion behavior

1. Pin unchanged AgentDojo commit `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b` and original VERITAS adapter commit `a1d66aef02262cf8a913295270c3aafd159c6adb`. Reuse `#403` suite, roster and original attack.
2. Invoke `run_frozen_task1_integrated_native_ab(..., write_count=2)` unchanged. Require actual Native pipeline, identical first request and attacked read response, exactly one B-only read-only overlay, original full tool catalog and real B Bind refusal before each local mutation.
3. Check neither arm has a Provider-origin response or genuine terminal, model steps are synthetic, and B had 0 protected Native mutations. Confirm official score values are `null`, not false, and all original #335 V13 historical counts are pinned unchanged.
4. Emit a redacted standalone machine-readable report with source hashes, local synthetic dispatch/Bind counts and precise missing prerequisites. Crucially **status is UNSCORED and `eligible_for_official_scoring=false` regardless of caller-supplied model-looking data**.
5. Adversarial tests alter native history, V13 scores, scores purportedly recovered, origin/approval/lease flags, mutated tool responses, Bind disposition and scorer fields. Such altered observations fail closed before any score claim.

## What is ACTUALLY missing for the first genuine Task1 Utility measurement

- Fresh **explicit** owner permission with model/case/budget cap. Historical approvals are consumed, not reusable. Do not call a paid Provider in this PR.
- An independently protected A/B model sender with genuine TLS request/response receipts and trusted one-use consent/lease. **Do not** treat previously mocked `Responses` JSON, fake call IDs or a copied request ID as source proof.
- Independently generated, separately authenticated A and B tool proposals and terminal responses using actual AgentDojo Native context and the same frozen attack/legitimate request, including B-only controlled source projection, exact full-tool schema, current Native source/VERITAS chain.
- Real per-arm tool effects or refusals, saved native tool output and final response, uncompromised pre/post states. Preserve legitimate refusal and never rewrite candidate arguments or restore blocked effects to increase Utility.
- An actual, same-run **Native User/Attack Scorer** invocation on each fully completed, genuinely sourced arm; joined to original request and source, native effect/no-effect and candidate/Tool ID lineage. Compute a case-level delta with B attack success 0 before expanding to 128.

None of the independently operated Provider or customer IAM boundary has been proven by #418. The B read-only overlay remains experimental. A native scorer diagnostic from #395 **cannot be attached to #403's separate scripted trace** to fabricate a scored outcome.

## Run and CI

```bash
PYTHONPATH=. python -m pytest -q -o addopts= tests/test_final128_418_task1_native_measurement_gap_v1.py
PYTHONPATH=. python scripts/final128_418_task1_native_measurement_gap_v1.py \
  --agentdojo-root _pins/agentdojo \
  --veritas-root _pins/veritas \
  --output results/final128-418-task1-measurement-gap.json
```

Dedicated Actions workflow clones **pinned** Native AgentDojo and VERITAS, installs existing #403 dependencies, runs the new tests plus the original #403 and #395 suites, and writes only SHA/JUnit/readiness-gap evidence with `manifest.sha256`. It has no secrets, no Provider credential, no paid call, no new bank effect. Inspect PR HEAD, all inherited CI, exact artifact digest and negative tests before merge.

**Next actual development:** one new, independently authorized and protected real-model Task1 A/B measurement with authentic same-run native history and scorer. A single paid model request is not automatically a scored Utility measurement; a partial continuation stays `UNSCORED`.

**No claim:** Utility improvement, Final128 rerun, restored historical V13 successes, independent RCC validation, production bypass resistance, or real-world payments.
