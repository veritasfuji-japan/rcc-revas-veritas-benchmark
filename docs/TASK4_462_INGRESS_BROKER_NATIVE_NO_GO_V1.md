# Task4 #462 — Direct local SDK Ingress → Broker → AEAD → Native Scorer (HARD NO-GO)

## Narrow purpose

Implement one **direct** local integration of the merged #461 ingress contract and the original #458 separate-process Broker / #457 AES-GCM response vault / #323 one-arm-per-scripted-source Native + scorer. This is a deliberate extension of #459 and does not authorize or implement a Provider sender.

## Which request bytes are being preserved?

Two SHA-256s exist for **each** of eight offline responses, and must never be spliced:

1. Original **capped** request serialized by the pinned OpenAI SDK using the existing #325 `CapOnlyOfflineSDKProxy` (`max_completion_tokens: 256`). #461 consumes this request, #458 consumes its SHA **before mock response generation**, and #457 seals its returned raw HTTP response under the capped request SHA.
2. **Uncapped** local-only request intentionally reconstructed solely for the unchanged historical #323 scripted responder (as the existing #325 offline bridge already does). #456 records it as the source-owned local mock request and response, and the original Native + scorer operate unchanged. A new SDK-visible response object binds the exact same local response bytes to the original capped request. #461 returns that exact response object unmodified to the SDK.

The different request hashes are deliberately checked and exposed as separate hash-only records. Both requests exist only in RAM, use a visibly fake SDK key, and never reach `api.openai.com` or a real Provider. Do **not** mistake request JSON byte fidelity or response matching for authenticated Provider provenance.

## Evidence expected in pinned CI

- Two separately constructed scripted source sessions, one selected Native Arm A and one selected Native Arm B.
- Exactly four capped SDK queries per arm; every request flows through #461 `before_response`, the actual #458 broker `consume`, the original local scripted source, the actual #457 AEAD vault, the actual broker ciphertext `attach`, and #461 `after_response` before the SDK parser.
- The #456 original scripted source journal is checked against the **uncapped** mock request, and all eight responses must match the **capped** SDK ingress, AEAD and Native by response SHA.
- Both Native terminal sessions and two detached scorer calls remain **synthetic results**, never genuine model Utility.
- A fresh broker process reopens the original local SQLite file; ciphertext recovers byte-for-byte with only an ephemeral in-process test key; repeat consumption is denied.
- Only hashes, refusal test outcomes and intentionally explicit false attestation fields go to the CI artifact.

## Strict limits

- This validates only local software ordering and **same-runner** durability. There is no independently administered CAS, cross-runner custody, egress enforcement, authentic Provider response or authority to execute a real banking transaction.
- #461 accepts callback declarations; this patch grounds them in actual #458 and #457 **local** actions. It does not promote them to external authentication.
- #457 is frozen at 4 local responses per arm and its archive accepts **only** synthetic-origin envelopes; this test must not claim the prospective 5 calls per arm are integrated.
- The date `2031-07-08` is a synthetic fixture, not a trusted real-world issuance.
- A/B `true_utility` and `true_injection` are **null/UNSCORED**. The existing frozen historical Final128 metrics are untouched.
- #455 remains a HARD DENY and is not called or rewritten. No Provider API key, live/dispatch flag, GH write token, Environment, Secrets, tag, Ruleset or paid workflow is changed. Issues #321 and #427 remain OPEN / NO-GO.

## Follow-on decision (separate authority)

Before any genuine single-case experiment, independently review the real research Sender/egress boundary, pre-first-request independent date/target authority, durable consume/UNKNOWN controls, authentic full-response evidence, eligible Native termination/scorer provenance, model/account access, and actual billing controls. Only then request a fresh exact commit, case/model, call cap, cost, expiry, residual-risk owner approval. Do not reuse consumed historical approvals.