# Task4 #451 — One-case Native Utility provenance join (offline NO-GO)

## Rule of One

**Ben's requested optimization objective is a new measured one-case Utility recovery without permitting injection or diluting execution authority.** Before it can be claimed, the exact-source gap between real model output, canonical Native execution, and detached official scoring must be closed in the **same prospective A/B run**.

This PR does **not** pretend to achieve that measurement. It creates an executable, byte-pinned and mutation-tested **cross-origin evidence verifier** for the one frozen Task4 source case, deliberately refusing to combine historical incomplete real responses with *different* locally scripted completed Native/scorer traces.

Target: `banking:user_task_4:injection_task_0:direct`. The user remains the only party who can issue new paid permission. No provider execution, payment, live banking, replay of consumed approvals, or credential handling is introduced.

## Why a new local scorer run alone would be redundant

- **#316** already exercised 8 Task4 historical *labels* in freshly generated offline scripted Native A/B development trajectories. It used actual Native AgentDojo scoring after terminal completion.
- **#320** already intercepted ten real OpenAI SDK request serializations in `httpx.MockTransport` for two local scripted candidates, carried them through local Native RCC/Bind and four detached AgentDojo scorer calls. It explicitly generated **zero** genuine Provider responses and **zero** new canonical Final128 scores.
- **#318** replayed two archived genuine third model proposals and their Native Bind refusals. The genuine archived source **lacks the post-tool result and final assistant answer**. Hence it cannot produce an authentic completed official Task4 Utility score. The old proposals also lack independently pre-issued date authority.
- **#344** prohibits treating structural scorer fields, disconnected histories or untrusted hashes as true same-run measured Utility. **#364** documents an unapproved future one-case experiment with every operational gate still unmet.

Taken together, the already-proven scripted success must **not** be joined to the real archived proposal to manufacture a new model Utility recovery. #450's merged local Linux cross-UID proof is a separately bounded safety result; it is **not** deployment attestation, nor is it a newly scored benchmark run.

## What this PR executes

Exactly three additive files: this document, `scripts/task4_451_one_case_utility_provenance_audit_v1.py`, and `tests/test_task4_451_one_case_utility_provenance_audit_v1.py`.

The standard PR pytest lane actually loads **five Git-blob SHA-1 pinned original source contracts** (#318 genuine result, #320 scripted SDK mock, #344 scorer admission, #364 real-run preflight and #287 V13 frozen claim gate). The checker independently derives a Task4-specific gap report. It cross-checks all hard requirements against the existing source records, including old V13 A=93/B=64, B injection success 0, 29 net gap and zero newly accredited recovery. Byte-level modification of any original source contract fails the audit.

A separate read-only function accepts **one untrusted structural A/B evidence pair** and checks the exact case, distinct A/B ordering, request/candidate/prestate hashes, same candidate and prestate for each arm, two clearly distinguished source classes and terminal/scorer digest shape. Deliberate malicious edits (new Authority fields, claimed official score, forged source, changed candidate, switched arms, fabricated genuine terminal, NaN, duplicate JSON keys) are rejected.

**Even a structurally valid pair has zero new measured Utility credit**, because a caller-controlled JSON structure is not a source-attested provider receipt or actual native scorer invocation. The checker never uses a scorer label, RCC selection, tool output or candidate to issue Authorization/Approval/Bind. Its source mode cannot be promoted to “authentic prospective” by changing a JSON field.

Running `python -m scripts.task4_451_one_case_utility_provenance_audit_v1 --offline-audit` emits one JSON report with `CROSS_ORIGIN_JOIN_REFUSED_AUTHENTIC_TERMINAL_MISSING`, the pinned source digests, gap list, and `external_provider_dispatch=DENY`. This is an actual inspectable diagnosis, **not a new provider execution or scored result**.

## Next *measurement*, not another mock

1. Start from first model turn under a separately verified pre-issued original request and date/recipient/amount authority. Preserve task-4 case identity, independent A/B inference, identical frozen candidate/prestate when claiming treatment causality, and the actual native wrapper continuity.
2. With **fresh explicit user permission** for bounded API use, source-owned Provider key in an independently controlled Executor, persistent cross-Runner one-use ledger, egress-deny bypass tests, current price/call/token caps and preserved uncertain-send evidence, capture actual Provider responses and native read/effect/Bind receipts for both arms.
3. Continue the authentic tool result to a genuine terminal assistant response, execute the real post-native detached AgentDojo scorer, and store full exact HEAD/pins, input/output digests, usage receipts, case-level deltas and injected attack-success checks.
4. Only a genuinely observed, externally independently verified same-condition result can be described as newly recovered Utility. Repeated development scoring must not become final external validation; freeze optimized treatment before fresh held-out measurement.

Until those external requirements exist, **Issue #427 remains OPEN, PAID TASK1 and any real Task4 Provider execution are NO-GO**. Ben's unified optimization objective remains the driving goal; the claim boundary is not a new approval checkpoint for routine offline engineering.

## Exact acceptance and exclusions

No change to `.github/workflows/**`, live #423 sender, Provider code, existing contract/source/benchmark pins, secrets, Environment, Rulesets, tags, production permissions or billing. No new Runner/Provider/network/effect, no new official native scorer, no external artifact download. This audit is runnable in the existing normal CI with only the repository source and Python stdlib, plus pytest for its tests.

Keep Draft until all normal exact-HEAD CI checks pass, no new test is skipped, and the three-file diff and **zero new measured recoveries** claim are independently reviewed. Avoid a claimed Utility score from mere test-count growth.
