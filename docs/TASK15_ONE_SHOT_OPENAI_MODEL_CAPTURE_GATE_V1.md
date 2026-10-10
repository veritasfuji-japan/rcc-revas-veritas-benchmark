> **POST-#276 SECURITY REMEDIATION NOTICE:** The live `DirectOpenAIHTTPSOnce` helper described in the historical #276 document is now default-denied by #277. All `capture(live=True)` calls are also refused before durable claim. The original offline proof remains recoverable at merged SHA `677a65721fb44d11618a0f906b71eb1931166b44`. Current code is **offline-only**, and no real provider transport should be inferred from the older design below. See `TASK15_DIRECT_OPENAI_HTTPS_BYPASS_DEFAULT_DENY_V1.md`.

# TASK15_ONE_SHOT_OPENAI_MODEL_CAPTURE_GATE_V1

**DRAFT / NOT PROVEN until latest exact-HEAD CI and independent artifact review.**

## One invariant

Before any **possible** first real OpenAI Chat Completions request for the frozen Task15 first case A-arm:

1. Reconstruct the **actual historical native OpenAI wire input**, independently archived in `task15-offline-postread-rcc-quarantine-v1.evidence.jsonl`: exactly four messages and two tool declarations. Canonical SHA-256 of `{"messages": ...,"tools": ...}` MUST be `a09c777b94e6e86edc274983fac8e447343749d7312e88397b39941741899d19`.
2. Verify an **independently pre-enrolled operator public key** and a **fresh Ed25519 approval**, specific to the exact rendered request hash, original native-wire digest, first case, Arm A, one request, model `gpt-4.1-mini-2025-04-14`, output 256 tokens and proposed maximum US$0.25. The earlier historical US$5 cap **is NOT authorization**. Local operator clock trust and signer identity are external requirements, not solved by this module.
3. Commit a **SQLite single-use claim before the request can leave the process**. Any HTTP error, transport timeout, crash, validation mismatch or loss of response must retain `DISPATCH_UNKNOWN`. No retries, no silent `NO_EFFECT`.
4. Save returned JSON, response ID, model name, usage and canonical response SHA. Tool calls returned by the model are **data only**: there is **no handler capable of dispatching bank writes**. A tool-call instruction such as `send_money` does not execute.

## Narrow optional real transport

`DirectOpenAIHTTPSOnce` is a single-use, fixed-host, direct standard-library TLS transport to `https://api.openai.com/v1/chat/completions`, using `store=false`, `stream=false`, `n=1` and `max_completion_tokens=256`. It has **no redirect, SDK retry or external banking adapter**. A real credential must be supplied only to the later, separately authorized local runtime by the operator. **No credentials, human approval or real transport invocation exist in CI.** This PR does NOT provide a ready-to-use live CLI or mint a trusted operator signature.

OpenAI's published GPT-4.1 mini standard token pricing when this contract was created was US$0.40 per 1M input tokens and US$1.60 per 1M output tokens. These are used only for **post-hoc cost estimates**. The US$0.25 cap is **not a provider-enforced hard dollar budget**: before any real call, revalidate account/project billing limits, exact endpoint availability, model and pricing and ensure enough reserved headroom. A single time-limited, signed human approval is necessary, not sufficient for trusted issuance.

## Reconstructed source, not inferred text

The #275 source SHA-256 alone was not the provider HTTP body. We resolved its origin from the prior **native client-call archive**: the hash covers only the original messages+tool schemas and matches exactly. The full Chat Completions payload adds the pinned model and non-executable output-only generation options. This new HTTP payload receives its own canonical digest, referenced by the separately signed approval. The two-tool declaration never grants native effect dispatch.

## Offline dedicated proof

- Exact predecessor #275 merged main SHA: `aee25a92d105183aafd07fecc63f1c614b5ab8f4`.
- Dedicated workflow replays all prior proof scripts and pinned native AgentDojo/VERITAS/RCC sources.
- Exactly **15 new JUnit test cases**: a positive proof using 16 competing threads and a transport-timeout UNKNOWN, plus 14 independent denials including missing/expired/fake approval, wrong public key, source/model/limit substitution, forbidden fake-live transport, response mismatch and replay.
- Two actual SQLite database snapshots preserved: one successful MOCK capture and one post-send timeout UNKNOWN; independently verify raw row/journal sequence, digest, single claim, and one mocked tool-call that is **not dispatched**.
- The test-only Ed25519 private signer exists only in memory. The mock grant and public key, never its private key, are archived for independent signature verification.

## Explicit nonclaims

Passing these tests will prove only the **specified single-host one-shot boundary with mocked model transport**. It does NOT prove trusted real operator custody/clock, independent execution authority, provider-side atomic execution, cryptographically provider-signed responses, true provider billing cap, production-grade external receipt reconciliation, inter-machine consensus, arbitrary caller enforcement, external bank effect or Final128 Utility/Injection Success.

**This PR makes no actual OpenAI request and must not be treated as authorization to charge an API account.** It must remain Draft until dedicated CI and full downloaded artifact independent verification pass. Even after merge, live invocation requires new, explicit scoped human approval and validated real trust-root onboarding. Do not publish any secret or signed live grant in a public PR or CI artifact.
