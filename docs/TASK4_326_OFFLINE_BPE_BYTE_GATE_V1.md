# Task4 #326 — Exact local SDK-wire UTF-8 byte + pinned BPE gate (OFFLINE)

## One central invariant

**Deny a model-shaped request before receiving any local fake assistant response if the actual OpenAI SDK serialized JSON bytes or the frozen local BPE token count exceed the scoped ceiling.** A refusal freezes that local session; an identical request SHA cannot be reused.

Frozen parent #325 main SHA `5b32fee871bf8b445fa03b5ee91c453d5fc485b8`. Reuse #325's actual `openai==1.109.1` SDK serialization, `httpx==0.28.1` MockTransport, and #323's original frozen isolated AgentDojo Native A/B RCC/VERITAS Bind and detached native scorer. No underlying native policy/effect/scorer files are modified.

## Counting and limits

- SDK-generated actual **raw JSON UTF-8 body** includes model, complete user/developer + prior assistant/tool history, tool schemas and `max_completion_tokens=256`.
- Before any fake response, the independent strict gate checks `len(raw_body) <= 10,000 UTF-8 bytes`. This is a **deterministic local wire-size limit** (unlike #325's exploratory JSON-byte/4 estimate).
- The gate independently runs pinned `tiktoken==0.12.0` / `o200k_base` on the **complete raw JSON string**, and checks a local BPE count <= 10,000 plus <=100,000 across each local session, with <=5 SDK attempts per Arm and <=10 total.
- It records early receipts with raw JSON SHA-256, exact byte length, local BPE count, tokenizer/version, scope of the check, and `real_provider_post_allowed=False`. Read-only audit recomputes the SHA, the BPE counts and rolling receipts and binds them to the actual #325 SDK raw wire bytes, native bank effect/terminal/scorer for both origins.
- Special negative tests use purposely tighter limits to independently trigger both gates, mutate entire messages and tool schemas to exceed byte limits, attempt replay/unknown resumes, wrong model/output cap/auth/path, malformed UTF-8, duplicated JSON keys, tampered evidence and fake real-provider promotions. All must fail **before a local fake-model reply**.

**Important proof limit:** This is an exact locally pinned BPE encoding of the client JSON bytes, NOT OpenAI's authoritative chat prompt-token usage. Server-side message/tool framing may differ, and the SDK HTTP envelope can differ from billed prompt tokens. Even if a local body uses <=10,000 JSON bytes and <=10,000 local BPE tokens, no mathematical guarantee about actual billed input tokens, provider hard budget, or true monetary upper bound is made. Such a guarantee must be separately certified or denied in the future live execution protocol.

`2031-07-08` is still the pinned **synthetic test-only date**. Prior one-use API consent is consumed; no new human approval, Provider secret, live client or credential broker exists. This test explicitly **cannot send** to OpenAI and **cannot authorize** a POST.

## Expected Native scope

Two independently initialized scripted SDK source roots (A RCC, B RCC + VERITAS), four locally intercepted messages each, one native simulator effect plus one native detached AgentDojo scorer per selected source, **zero shadow native effects**. The static mock script can produce the same proposal from both sources. No new genuine inference, held-out Final128 result or production bank effect.

## CI and evidence

A dedicated PR/main workflow pins Python 3.11.16, the native external AgentDojo/RCC/VERITAS commits, OpenAI SDK 1.109.1, httpx 0.28.1 and tiktoken 0.12.0; it has no Provider Environment, secrets, `workflow_dispatch` or `pull_request_target`. CI checks out the exact PR HEAD, verifies JUnit, independent audit of actual JSONL + local BPE receipts, and ZIP SHA-256. No automatic merge or real Provider dispatch.

**Post-merge gap remains:** an independently controlled cross-job one-attempt ledger, account-authoritative model/token availability, a carefully bounded research sender, protected API credentials and fresh exact spending consent. The local gate is an additional research engineering safeguard, not proof of Provider-side limits.

Related [Issue #321](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321), #322–#325.
