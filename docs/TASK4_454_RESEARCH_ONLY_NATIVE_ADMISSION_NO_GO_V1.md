# Task4 #454 — Research-only native A/B admission (offline, NO-GO)

## One source-level objective

Provide an **actual newly defined GitHub Actions research-only workflow** that confirms the EXISTING #323 independently started local scripted A/B model-shaped sessions proceed through the pinned native RCC/VERITAS Bind paths, one selected native arm each, authentic *local* AgentDojo scorer once per arm, and the EXISTING #363 wire/history-to-scorer provenance audit. Then join both reports with additional strict evidence admission without suggesting this is a genuine model result.

This is **not** a second homegrown LLM simulator, a replacement native scorer, an external Executor or a prospective live sender. Existing tested #323/#363 Python is used unchanged; the real-model continuation / cost / credential isolation remains blocked in Issue #321. Do not repair any historical #318 model refusal after the fact.

## Actual code and Workflow

1. `.github/workflows/task4-454-research-only-offline-native-admission.yml` is a **pull_request-only** read-only standard-hosted workflow. It has **no** `workflow_dispatch`, `push`, schedule, `pull_request_target`, protected Environment, Provider Secrets reference, native real Provider sender code, delegated credential or write token. It pins the same checkout/setup/install and three native source repository commits as the existing #323 workflow. All Provider environment variables are forced to the empty string.
2. `scripts/task4_454_research_admission_offline_v1.py` takes the actual #323 and #363 emitted local result JSONs after those earlier auditable routines run. It requires both source-arm identities, the *same initial request* across local scripted A/B, diverging real native **local** terminal histories, exact first-wire, native post-state and scorer-result SHA-256 joins, two and only two selected local scorers, zero shadow arms and exactly zero genuine Provider model completions or banking effects. The output is explicitly `OFFLINE_RESEARCH_PRESEND_ONLY_NOT_APPROVED`.
3. `tests/test_task4_454_research_admission_offline_v1.py` uses only Python/pytest and *fake structural reports* to mutation-test refusal of forged Provider attempts, model independence, real Utility score, mismatched first request, swapped arm, missing terminal, post-state/scorer splice, reused response and shadow-arm execution. This does **not** replace the native integrated test.
4. This document states proof boundaries and the next genuine measurement gap.

The new workflow re-runs #323's actual pinned local Native + post-only scorer tests and #363's actual lineage auditor. It then calls the additive #454 checker; it archives JUnit, local JSONL, provenance reports, pinned dependency information and failure evidence for review.

## Operator-verified config from screenshots (not API-read attestation)

As of 2026-10-18, the owner supplied screenshots showing a **separate** OpenAI API project `VERITAS-Task4-Research` at **USD $0.00/$1.00 monthly, "Limit enforced"**, along with project model allow-list showing `gpt-4.1-mini-2025-04-14` and shared rate-limit UI. These observations do **not** prove current account model POST succeeds, per-run billing protection or that the model endpoint is enabled for this key. The owner also showed GitHub Environment `task4-provider-protected` permitting only `main`, zero tags, zero secrets/variables, Required reviewers OFF, administrator bypass checkbox OFF. These are **UI observations**, not cryptographically attested independent controls.

No API key was issued or registered as part of #454. The research Environment is **not** attached to the new offline workflow so that it cannot unlock secrets by a simple GUI operation.

## What this does NOT enable or demonstrate

- **NO Provider calls, NO new GPT-4.1 mini usage, NO spend.** The test uses actual OpenAI SDK serialized requests intercepted by a LOCAL MockTransport, not the real Provider.
- **NO original Final128 V13 remeasurement.** Frozen A=93/128, B=64/128, B injection successes=0/128 stay historical. New authentic Utility recoveries = **zero**.
- **NO trusted real wall-clock issuer, full new genuine A/B Provider histories, post-tool real-model continuation or newly scored genuine Task4 terminal.** The existing fixture uses the explicitly synthetic date 2031-07-08.
- **NO independent cross-Runner single use**, IAM/credential/network egress isolation, external Executor, third-party bypass test or guaranteed USD limit for a single experimental run. An OpenAI monthly hard project limit is not an exactly enforced per-run cap and can slightly overshoot on propagation.
- **NO real bank operations**, account numbers, secrets, tools from injected content with real-world effects, historical one-use consent reuse or case enrollment.
- **NO GitHub Actions Environment/Ruleset/tag/Secrets change.** Issue #321 and Task1 #427 remain OPEN/NO-GO. This PR is never permission to run paid research.

## Next genuine Task4 result

A separately reviewed, **freshly consented** isolated research-only sender must start both A and B genuinely from the first user request under legitimately preissued date/amount/recipient authority, carry its **own unmodified model choices and tool results** through unchanged native RCC/Bind and detached native scorer, and preserve Provider IDs, usage, immutable exact refs and cost/replay/UNKNOWN evidence. Before any Provider call, independently confirm available model + Project permission, real billing limits/fees, zero production bank endpoints, a sender that cannot be reached by PR code, and the precise one-experiment budget/attempt ceiling. Genuine outputs must never be joined with local scripted scorer results. There is no standing $0.10, $0.50, $1 or historical $5 consent.

The first single-case result would still be development evidence, not a new Final128 or independent held-out proof. Freeze treatment and get third-party repeatability before making a broad Utility/safety claim.

**Merge review:** keep Draft until latest HEAD overall CI and dedicated #454 workflow green with actual native receipts. CI green only proves offline prewire readiness, not research live readiness.
