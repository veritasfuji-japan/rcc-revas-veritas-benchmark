# Task4 #471 — Same-run capped SDK → local Broker → pre-parser AEAD → original Native scorer (NO-GO)

## Objective and actual addition

This PR integrates the **two separate** offline research seams from merged #469 and #470 into **one source-pinned, same-run, locally scripted Native A/B execution**, without live model connectivity or new Sender.

The existing #325 genuinely serializes all Native OpenAI SDK requests with `max_completion_tokens=256`. #470 checks those *exact SDK request bytes* and records a local one-use attempt in the unchanged #458 separate-process SQLite Broker. **Only after** consumption does the original unchanged #325.GuardedMock generate its local scripted fake response. #457 encrypts the raw fake HTTP response bytes with AEAD, fsyncs an append-only ciphertext file and #458 attaches it to the same request's original Broker receipt. #456 audits the exact local fake response source, arm/turn and SHA before returning the response bytes to the SDK parser; the original Native/RCC/VERITAS tools advance to the next SDK request, finally reaching the existing detached Native scorer. On a Broker restart, all 8 ciphertext records are recovered and all 8 request slots deny replay.

The original #325 local fake model only accepts its historic, uncapped *internal* test sub-request. Therefore that exact pinned mock strips the output-cap field internally before generating a fake response. The #471 transport binds the **unchanged raw response bytes** back to the **original SDK request containing the 256-token cap**, before AEAD and returning to the SDK. This is expressly **test-only response rebinding**, not Provider-origin data reconstruction, and it does not bypass the external SDK cap inspection. The original #325 WireInspector still verifies all real SDK capped request bodies. The only response origin allowed in the dedicated integration is the exact pinned #325.GuardedMock type. No HTTPTransport, network Sender, endpoint fallback or key loader is constructed.

## What is proved / what is NOT

| Evidence | Status |
| --- | --- |
| Capped Native SDK request wire, model and original user/developer prefix | Local source-pinned proof |
| Same-run #470 attempt admission → #458 once-only local Broker | Local source-pinned proof |
| Same-request AEAD ciphertext and Broker attachment before SDK parse | Local source-pinned proof |
| Same-run Native A/B terminal and detached scorer | Scripted local responses only |
| Broker SQLite restart and eight replay refusals | Single local Runner only |
| Real Provider-authenticated response | **NOT ATTESTED; zero real calls** |
| Independent off-runner atomic attempt ledger, issuer or credential egress | **NOT ATTESTED** |
| Trusted actual date/currency/refund authority | **NOT ATTESTED** |
| True real-model A/B Utility or injection result | **UNSCORED** |

A successful same-run local result **must not be promoted to a genuine model experiment**. The pinned AgentDojo benchmark's legitimate refund expectation is amount 10.0, currency unspecified, and its synthetic 2031 test clock is not actual authority. The historical 100 synthetic USD cents from #465 is not equivalent to this target and never grants real financial permission.

No user approval has been obtained for a real Provider call. Historic $1 research project limits and earlier explicit consents are not reusable. The proposed 5 per-arm and 10 total request limits are **local planning gates**, not a verified billing hard limit; actual input token consumption and model price still need independent verification. The code has no live mode, no API key, no new paid workflow and no real bank effects. The entire test uses an isolated in-memory AgentDojo bank.

## Evidence construction and checks

- Freeze the exact Git blob SHA of original #320/#323/#325/#456/#457/#458/#459/#469/#470 sources. Fail closed on drift.
- For each arm/ordinal 0..3, bind the identical **original capped SDK raw request SHA**, original local fake response bytes SHA, AEAD ciphertext SHA, and one-use Broker receipt hash in a **single in-memory event**.
- Require all eight SDK responses to pass AEAD encryption and local Broker attach *before SDK parsing*. Deny missing/duplicate/cross-arm ordinals, mock source substitutions, unreadable/tampered ciphertext, wrong source/request association or attempts to send a fifth turn.
- A negative test scaffold deliberately uses fake local stubs solely to verify pre-parser ordering and terminal failure refusal; the dedicated Native test actually executes the frozen OpenAI SDK, AgentDojo, RCC, VERITAS, #457 crypto and #458 broker. These stub tests are **not independent security proofs**.
- Only sanitized hash receipts, no response plaintext, key material, message text, account numbers, ciphertext or real bank state go into GitHub Artifacts.

## Exact engineering boundary after this PR

**If** CI validates this PR, then the **local** request-side cap and response-side AEAD are genuinely proven in one Native run, removing that *specific* integration gap. Remaining work for the first actual paid, bounded research-only model A/B test is separate: issuer/date and research scope, independently isolated Sender and Provider-authenticated source, durable independent attempt/evidence custody, billing/rate verification and fresh owner consent; production no-bypass/reconciliation remains a further bar.

Issue #321 and #427 stay OPEN / NO-GO. No existing Sender, Native, Broker, Scorer, Secrets, Environments, Rulesets, tags or branch settings are modified.

Four **additive** files only: this runbook, new transport integrator, adversarial tests and PR-only offline CI. Owner reviews exact HEAD/CI/JUnit/Artifact and manually merges if appropriate; never auto-merge.