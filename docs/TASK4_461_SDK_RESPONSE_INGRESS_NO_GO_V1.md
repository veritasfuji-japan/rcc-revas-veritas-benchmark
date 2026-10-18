# Task4 #461 — Source-neutral SDK response ingress boundary (offline, Provider NO-GO)

## Motivation and scope

The merged #459 integration proves that **scripted** #323 A/B Native histories reach the scorer after local atomic consume, response encryption and ciphertext recovery. Its capture wrapper is coupled to `OneArmMock` and assumes four scripted responses per arm. The independently merged #455 stages the **real SDK-shaped Native first request**, but always rejects egress. Neither proof contains a genuinely authenticated model response.

This proposal extracts a **reusable, source-neutral request/response ingress state machine** so the future, separately reviewed research sender can pass its exact SDK `Request` and already-obtained `Response` *without the ingress reconstructing, rewriting or generating either*. It does not connect or enable a provider sender. All test responses remain synthetic. This is not a final integrated real SDK/Native proof.

## Interface

`SDKResponseIngress(arm, trial_id)` owns exactly one arm; `trial_id` is a 64-character source identifier, **not authorization**.

1. `before_response(ordinal, request, claim)` validates actual byte-oriented SDK request fields, checks the **same trusted initial two messages and append-only history** across up to five attempts per arm, and calls an injected consume-before-observation callback. Only a local response `LOCAL_CONSUMED_NO_SEND`, plus its sha256 receipt, is accepted. An exception or uncertain result permanently poisons this arm; no retry.
2. `after_response(response, seal)` checks that the original HTTP response references the **exact request object**, then asks an injected archive callback to commit its **raw bytes before any JSON parsing**. The callback must return matching request/response SHA-256, arm, ordinal, and a local fsync observation; a callback's fields are **claims**, not proof of external custody or Provider authentication. Bad HTTP status, malformed JSON, changed bytes, duplicated completion ID or malformed message fail closed after sealing attempt. Successful cases return **the very same Response object**, ready for the normal SDK parser.
3. `unknown()` permanently blocks further submissions of an uncertain arm; `report()` contains hashes and `UNSCORED`, never reconstructed model text or purported real utility.

Existing frozen #323, #344, #455, #457, #458, #459 and #460 source code and policy are **not modified**. #457/#458 currently label their input strictly synthetic, so a future truly authenticated sender must supply a separately designed archive/authorization implementation; their labels must not be simply changed or copied to claim authentic Provider results. Native tool results and final scoring remain owned by unchanged AgentDojo/VERITAS boundaries.

## Test and proof ceiling

- Unit tests use only caller-generated local byte fixtures; one test uses real `httpx.Request` and `httpx.Response` object identity.
- Reject wrong A/B/trial/ordinal, model/endpoint/cap/Native initial messages, rewritten history, invalid or ambiguous consumption, malformed responses, status errors, missing sealing, seal mutation, duplicate completion IDs and retries.
- No SDK client or network transport is created by this module. No API key, GitHub Environment, external bank, protected tag or secret is touched. Workflow runs on PRs only with read-only repo permissions.
- The finite-state machine enforces **local software ordering only**. Callback-provided evidence is not cryptographic Provider authentication, real external CAS, external durable retention or a production execution boundary.
- An untrusted Provider response is never allowed to override date, target, amount, issuer or Bind decision. True Utility / attack scoring remains `UNSCORED` until complete, independently attributable real A/B Native histories and official scorer evidence exist.
- Preserve issue #321 Task4 and issue #427 Task1 OPEN / NO-GO. `REAL_PROVIDER_DISPATCH = DENY`, `OWNER_PAID_CONSENT = NOT_GRANTED`. A merge is only a code change, not approval to send.

## Follow-on, **not included in this PR**

A separate design review must (a) establish a real, pre-first-request trusted date and authority; (b) separately authenticate a dedicated secret/egress Sender and real HTTP raw response origin; (c) commit consume/UNKNOWN/response archive under bounded actual research permissions; (d) connect each genuinely observed Native tool result to the next model query, then official scorer. Do not substitute historical responses or scripted text. Validate pricing, availability and obtain a new exact owner consent before any paid POST.
