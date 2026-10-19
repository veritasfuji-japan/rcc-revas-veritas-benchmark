# Task4 PR #468 — First authentic SDK wire vs scripted full-turn Native: real-origin seam review (NO-GO)

## Goal
Establish precisely why the existing **real SDK first-wire pre-dispatch** and **complete simulated Native terminal/scorer** cannot be combined to claim a real-model A/B result. Review actual unchanged source files and freeze the minimal engineering work needed for one *future* user-approved research-only real-model experiment. **No new fake model, real provider sender, issuer, scorer, key or bank connection.**

## Verified source boundaries

| Existing artifact | Source actually owned | Number of turns | Proven | Still missing |
| --- | --- | --- | --- | --- |
| #455 | Real OpenAI SDK serialization of frozen Native first request; rejecting HTTP transport | 1/arm | Exact first wire and HARD DENY | Real response bytes, tool continuation |
| #463/#465 | Same Native first SDK wire + signed **synthetic** fixture and local broker consume | 1/arm | Local pre-send denial, no dispatch | Same-run real-model first response, trustworthy issuer |
| #456 | #323 **local MockTransport** raw response journal | 4/arm | Immutable response bytes in RAM from local mock | Actual Provider-authenticated source |
| #457/#458 | Local mock response pre-parser AEAD + separate same-runner SQLite Broker | 4/arm | Local ciphertext custody/restart replay denial | Cross-runner durable owner-controlled storage/real response |
| #459 | One continuous **scripted local** SDK→Broker→AEAD→Native→terminal scorer path | 4/arm, 8 total | Two local complete Native arms and two detached scorer calls from same script-owned origin | Real model continuation and independently attributable A/B |
| #467 | Exact source-pinned AgentDojo Task4 expected refund, amount 10.0, injection subject isolation | N/A | Original benchmark expected result | Currency/real bank permission |

**Crucial distinction:** the two first requests created in #455/#463 are genuine *SDK-generated requests*, not genuine provider responses. The full Native A/B sequences from #459 are separately generated **scripted** model replies. Identical first-request SHA or frozen case ID does not turn these into a single genuine execution. The #459 local scores are NOT new real-model utility scores.

## What #468 actually adds
- Source-pin the exact unmodified production-relevant offline seam modules #323/#455/#456/#457/#458/#459/#463/#465/#467.
- Validate honest, locally-produced provenance structures for the first-only #463 and full-scripted #459 histories. Refuse missing or duplicate arm/ordinal, false Provider identity, upgraded status, false budget or date proof, live dispatch, or claims of real score.
- Deliberately return `genuine_same_run_real_provider_join=false` even if source hashes are identical.
- Emit a *sanitized* 7-gap integration contract and refusal tests only. There is no API endpoint, Provider identity verifier, receipt issuer, scorer invocation or permissions upgrade in #468. These tests are contract-validation tests over representative static data, **not new Native execution or fresh Provider evidence**.

## Minimal missing actual integration work (in logical order)

1. **Reviewed Native generation-to-SDK response seam:** preserve unchanged Native model messages, per-arm tool calls and role ordering. After a genuine first response, continue with the *same* provider-native run to the next SDK request. Keep all four possible turns per arm independently owned; do not splice together A and B responses from different providers/runs.
2. **Original response capture and origin:** for each successful real Provider response, bind the real transport attempt, arm, ordinal, request bytes SHA, response status, response bytes SHA, response ID and usage to one trial. Hash labels, locally generated response IDs or a dummy bearer key are not Provider identity. Encrypt/custody genuine raw response bytes before SDK parsing, and attach an independently controlled evidence receipt for any external-origin claim.
3. **Single-use send boundary:** define an independently reviewed isolated Sender, credentials/egress and monotone attempt journal *before* each POST. On crash, timeout or unknown result, consume the slot and do **not** retry. The #458 local broker alone does not prove cross-Runner durability.
4. **Research-specific authority and date:** derive exact frozen task/transaction ID 5/amount 10.0 from source-pinned AgentDojo environment, not lower-trust subject. The official benchmark amount has no recorded currency field. #465's synthetic one-dollar claim cannot be reused as an authority grant. Make actual trusted date and scope evidence prior to a live first query, not the 2031 test date.
5. **Genuine independently generated A/B:** produce distinct run identity and true Provider-origin continuations per arm with unchanged Native RCC/VERITAS boundary and in-memory bank; no real money or live bank endpoint.
6. **Detached terminal scorer:** only after verified **same-run full histories** and original terminal model responses, pass correct native state and tool trace to the frozen official scorer. Missing, partial, inconsistent, or source-faked = `UNSCORED`, not a fabricated 0/128 or PASS.
7. **Budget/owner review:** freeze exact case/model snapshot, source commit, token/turn caps, current model prices, worst-case charge and no-retry rules. Obtain **new explicit scope-specific user approval** separately, only after reviewed code and external facts. Historical consumed tag and Project dollar setting do not count.

**The upstream source's “10.0” expected amount and reference 2022 date do not themselves authorize bank transfer; account currency and a trusted execution clock remain unresolved.** The first research-only model experiment can operate within a disposable in-memory bank if properly scoped and newly approved, and must never be claimed as production no-bypass proof. Independently operated issuer/IAM/egress, remote one-use ledger and independent effect reconciliation are further requirements for production authority claims, not automatic prerequisites for every bounded research model inquiry.

## CI / review

Four new files only: this document, a source-pinned and fail-closed *offline* seam checker, negative tests, PR-only read-only workflow. Standard runner, no `workflow_dispatch`, no GH write permissions, secrets, Provider credentials, real sender, native bank effects or external calls to a paid model. Source hash read-checks are local; tests do **not** run mocked Native trajectories anew.

Evidence: JUnit + non-sensitive source-hash/NO-GO manifest. The validator's “two offline sources” output can never be promoted to real utility evidence.

**Issue #321 and #427 remain OPEN/NO-GO. Merge requires exact HEAD, all checks green, 4-file diff, sanitized artifact and manual owner review.** After merging, prioritize actual Native all-turn transport/custody adapter under separately reviewed NO-GO controls rather than another synthetic claim audit.
