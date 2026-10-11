# Task4 #325 — Actual SDK JSON request + completion cap, local-only

## Central invariant

Observe the **actual `openai==1.109.1` SDK serialized HTTP POST JSON** for each separate locally scripted Task4 Arm A/B model start, **before any fake MockTransport response**. Require `max_completion_tokens=256`, the frozen model, trusted user/date roles, native tool schema, and full same-source native read/proposal/terminal. Deny malformed or rewritten requests. **No network sends.**

Baseline: merged #324 main SHA `1c0b67ab342abf0313d593aeb6dde32943d4cf51`.

The original #323 frozen native **one-arm-per-source** dispatch and the Native AgentDojo scorer are unchanged. This PR temporarily wraps the frozen SDK adapter **inside the offline test only** to insert an explicit completion-token cap. Its real SDK serialization produces JSON including this cap. An in-process `httpx.MockTransport` inspector consumes and hashes the actual serialized request; it removes the newly introduced cap **only when presenting the request to the original unchanged scripted #323 fake model**, which otherwise rejects extra fields.

Two source roots: A (RCC baseline) and B (RCC + VERITAS Bind), each expected 4 local SDK interceptions (read-only/read-only/proposal/terminal), one native simulated banking dispatch and one post-only native scorer. Exact native injection prestate SHA-256 `8b653f253d3b2b033ad2baebc938bb66cb09719be8b488a470e7e82d25abbe14`; frozen lower-trust attack subject SHA-256 `0d5011fb8b275e313c83da127698f19a77095d44e82a81b4d5804046c3cb61a9`. Model parameter `gpt-4.1-mini-2025-04-14`, temperature 0, tool choice auto.

## Important correction about input tokens

**Raw SDK JSON is verifiable byte-for-byte. Input tokens are not.** The server's actual prompt-token accounting may differ because messages and tool definitions undergo provider-side formatting and counting. This proof deliberately calls its local diagnostic `CEIL(real_sdk_json_utf8_bytes/4)+512` a **proxy**. It is **NOT** a rigorous upper bound or an authoritative model token count. Therefore a successful local proxy <=10,000 cannot prove a billed prompt-token cap <=10,000, nor a hard account cost ceiling. The header, tool schema, and conversation history are *included in the captured SDK JSON*, while the token proxy is merely a planning signal.

The previous #324 count A<=5, B<=5 and input<=10,000/output<=256 remains **a research proposal**. This proof checks 4 scripted SDK attempts/arm, not the number of turns a real model will choose. It makes no promise that a real model will propose `send_money`, terminate in 4 requests, or recover Utility.

## Audited local fields

- Frozen exact `POST https://api.openai.com/v1/chat/completions` target in **local MockTransport only**, OpenAI SDK pinned `1.109.1` / httpx `0.28.1`, fake key `task4-320-local-fake-do-not-use`.
- Exact seven request JSON keys: `model`, `messages`, `tools`, `tool_choice`, `temperature`, **`max_completion_tokens`**.
- Every original native trusted developer/user header unchanged; lower-trust injected transaction is present only after read in the tool result.
- Per-request SHA-256 of the **actual SDK JSON bytes**, exact byte length, tool schema byte length, message/tool count, and local proxy estimate; hash-chained audit receipts. Original #323 native result retains the prestate, candidate, poststate and detached scorer.
- The scanner rejects any extra developer/system/user message from model/tool output, wrong model or output cap, malformed/duplicate keys, altered path/host/headers, missing native tool schema, replay/over-limit calls and missing terminal history.

## Non-claims

This proof **does not implement or authorize any real Provider request**. It does not independently verify the existence/permission of the named model in the user's API project, exact server token billing, true max input tokens, durable cross-workflow atomic spend ledger, egress isolation, separate credential administration, external account billing hard cap, genuine LLM outputs or real-world bank effects.

Provider calls=0, genuine model generations=0, new Final128 scores=0, real bank effects=0; historical consent is spent. No GitHub Actions secret/environment/dispatch used. The only injected API key is the static, visibly fake key on a network-disabled local `MockTransport`. A passing PR cannot justify changing #321 to API_DISPATCH_ALLOW.

## Review gate

Exact Draft PR HEAD + 17 regular/dedicated workflows PASS, JUnit and independent artifact JSONL/log/ZIP SHA-256 verified before merge recommendation. No automatic merge.

Next task after this work is to replace this *non-guaranteeing* proxy with an auditable vendor/model-compatible token-budget technique, and independently enforce a single-use durable pre-send permit, **before seeking fresh explicit cost-limited real Provider approval**. Related [Issue #321](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321).
