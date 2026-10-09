# TASK15_REAL_PROVIDER_PREFLIGHT_DEFAULT_DENY_V1

**DRAFT / NOT PROVEN — DO NOT MERGE until exact HEAD CI and independently downloaded artifact proof pass.**

## Central invariant

The sixteen Task15 native post-read requests and their proven offline A/B governance records (#266–#268) must be pinned to a frozen explicit model snapshot, source request and original user message hashes, native tool schema hashes and a maximum cost ceiling **without creating authority to call any live provider or to execute any effect**.

This is an **offline-only preflight**. It has **no OpenAI client, no network execution, no provider key, no provider response, no signed response attestation and no single-use authorization issuer**. An offline client-generated `call_id` or JSON response is not evidence of authenticated AI provenance. Existing authenticated human budget authorization for a DIFFERENT Final128 workflow does not extend to this future experiment.

### What is frozen

- Exact #268 merged-main predecessor: `f96051f7afd0395b8f4d4707b544023c06ba28ec`.
- Eight frozen AgentDojo v1.2.2 banking Task15 DirectAttack cases, both synthetic A/B arms, preserved previous native read call ID and native tool-result SHA-256, four-message `developer,user,assistant,tool` request SHA and tool-schema SHA.
- Previous A local native Bind COMMITTED / B native Bind BLOCKED receipts remain separate and explicitly synthetic.
- Historical frozen model snapshot: `gpt-4.1-mini-2025-04-14`, temperature 0, no fallback, no retries.
- Historical model configuration has a **$5.00 USD hard cost ceiling**. This is **not** a grant to spend $5, **not** an API call authorization and **not** a quote of today's prices.
- 16 case-arm records expressly mark `provider_response_authenticated=false`, `provider_request_issued=false`, `provider_response_received=false`, `provider_executable_authority=false`, `bind_permit_from_future_model=false`.

### Hard fail-closed requirements

- Reject credentials or self-declared consent in the offline proof constructor.
- Reject any alteration to the frozen source read history, call IDs, A/B bindings, prior COMMITTED/BLOCKED receipts, request schemas, model snapshot, sampling or budget ceiling.
- `attempt_live_provider` **always rejects**, including when a transport and consent value are injected. It **cannot** issue a provider call.
- A one-time preflight attempt; partial invalid evidence cannot be promoted or retried.
- No model/source response is described as authenticated; no Authority/Bind permission for a new model response can be manufactured from the offline candidate or previously approved benchmark fixture.
- CI requires **15/15 passing JUnit tests**, **14/14 negative refusals**, **16/16 historical case-arm source joins**, exact Git source blob pins, complete replay of #268 proof chain, and a cryptographically verified audit artifact ZIP.

## Next separately authorized phase

The next future step is a **new**, user-approved budget-limited real provider source-capture attempt with explicit target case count, spend ceiling, no retries, source/response authenticity bound at trusted transport capture, exact provider request/response IDs, environment/source commit pins, and one-shot issue/consume semantics. Such a step must be designed and audited in a **different** PR and must require fresh explicit authorization. Even a real authenticated provider response must not grant banking execution authority: RCC and VERITAS Bind remain distinct checks.

## Nonclaims

This PR does **not** authenticate model responses, run a provider, measure Injection Success, produce official Final128 Utility, authenticate a real bank/user, prove production-sink coverage or authorize real external effects. Only a source lineage and **closed** future transport/permission boundary is eligible for PROVEN in this round.
