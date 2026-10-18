# Task4 #460 — True-model measurement readiness contract (offline NO-GO)

## Objective

Freeze the exact gaps between merged #459 and one new genuinely independent Task4 A/B model-to-Native-to-Scorer experiment. This PR does **not** run the model, alter #455 HARD DENY, create a sender or spend money.

## What is already implemented

- #323: scripted independent A/B Native execution and detached scorer, not real-model utility.
- #455: pinned original Native first request serialized by the real OpenAI SDK, intercepted and unconditionally refused before egress. No genuine model output.
- #457/#458/#459: local scripted response encryption, independent OS-process Broker, one-use SQLite, capture-before-parser, Native continuation, scorer and restart recovery. All run on one hosted Runner.
- #335/#344: historical third-turn genuine responses are incomplete and cannot be promoted to Utility; previous valid date-authority failures remain valid refusals.

These distinct proofs must not be spliced into a fictional real same-run trajectory.

## Scope of this PR

1. Source pin eight actual existing files, plus the frozen AgentDojo/RCC/VERITAS/prestate/case/model references. Fail closed if they drift.
2. Freeze eight pending **research** readiness requirements: trusted before-first-request date/scope, isolated sender, one-use/UNKNOWN boundary, authentic raw response and custody, independent real A/B native histories, genuine terminal scorer, model/rates/budget checks, and explicit fresh owner consent.
3. Keep three **production** requirements separate: independently operated IAM/egress executor, remotely protected atomic ledger and evidence/key custody, third-party high-privilege bypass/effect reconciliation.
4. Explicitly keep true Task4 Utility and attack outcome **UNSCORED**, not numerical zero.
5. Refuse an attempted promotion of two differently originated offline reports (#455 and #459) to a genuinely authenticated model experiment, even if their reported hashes or case names match.

The validator only checks source identities and the shapes of **reported** provenance; hashes and copied text are not Provider authentication. Even a passing validator does not establish a genuine experiment. The status has no dynamic switch to GO.

## Planned test boundaries, not approval

Case: banking:user_task_4:injection_task_0:direct.
Model candidate: gpt-4.1-mini-2025-04-14; new account availability is not attested.

The earlier discussion suggested at most 5 attempted POSTs per arm, at most 10 total, and 256 output tokens per request. A historical token-price arithmetic estimate of USD 0.044096 is not a billing cap or permission to charge anything. The actual model/price and project limits need to be independently checked before asking the owner to approve a later experiment.

2031-07-08 is only a synthetic fixture date. An actual experiment would need a fresh, trusted issuer source, before the first model request, with the original task and legitimate target/date/amount/scope fixed independently of model/scorer output.

## CI and non-claims

The added GitHub workflow is PR-only, read-only, standard runner, 0 Provider credentials, 0 paid calls, no manual paid trigger, no Environment, no branch/ruleset/tag/secret mutation and no external bank effect. It runs a source-byte check and refusal tests only, recording a sanitized hash report. Existing frozen code and CI jobs are unchanged.

Issue #321 and #427 stay OPEN / NO-GO. A merge of this PR is neither a sender implementation nor a consent to use a Provider; it does not satisfy any listed research or production readiness item.

## Decision after review

Do not build another fake scorer or mock model. Separately design and review the minimal genuine response/capture adapter, independently isolated research sender, evidence retention and correct Native follow-on histories; subject them to failure injection with dispatch kept disabled. Only after exact-code, cost, trust and operational review may fresh owner approval be requested. No historical approval is reusable.
