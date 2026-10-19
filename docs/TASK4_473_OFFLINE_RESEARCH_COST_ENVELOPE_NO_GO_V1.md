# Task4 #473 — Offline pre-send cost-envelope proof, **NO-GO**

**Scope:** A research-only, always-deny Sender preparation step. Adds a deterministic Decimal cost envelope to **original capped OpenAI SDK request bytes** in the same source-pinned #472 Native A/B run, before they reach the separate-process AF_UNIX claim worker. No Provider POST, credential, billing authorization or genuine model output.

## Evidence available 2026-10-19 JST (user-read API Platform screenshots)

- Project: `VERITAS-Task4-Research`; project **enforced** limit $1.00; displayed spend $0.00.
- Organization: **enforced** limit $1.10; displayed spend $0.60; **remaining snapshot $0.50**.
- Model selection: allow all, `gpt-4.1-mini-2025-04-14` listed. Build tier model group `gpt-4.1-mini` **2,000,000 TPM / 5,000 RPM**.
- These are **UI snapshots**, not API billing evidence at execution time. Other projects may consume the $0.50. Spend caps can have delayed enforcement and overshoot. Neither displayed balances nor model allow-list is approval to spend.
- Research planning price assumption (standard text): $0.40 per million input tokens, $1.60 per million output tokens. Price and model availability must be rechecked at execution.

## Conservative offline planning envelope, not a provider hard cap

| Dimension | Offline preflight bound |
| --- | --- |
| Case | AgentDojo banking UserTask4, direct injection, **no external banking effect** |
| Model | `gpt-4.1-mini-2025-04-14` |
| Arms | A/B; at most 5 calls each; 10 total (planning) |
| Current frozen scripted Native | 4 calls each, **8 total** |
| Original SDK JSON body bytes | ≤ 96,000 per request, checked on actual SDK bytes |
| Estimated overhead beyond body bytes | 2,048 token proxy per request |
| Input-token *proxy* | 98,048 per request, **NOT provider token count** |
| Output cap | 256 tokens per request on original SDK JSON |
| Ten-call upper-bound *proxy* cost | **$0.396864** |
| Proposed future research ceiling | **$0.45**, NOT approved |
| Current org remaining UI snapshot | **$0.50**, NOT reserved |
| Provider sends / genuine scores | **0 / UNSCORED** |

The proxy deliberately budgets up to 96,000 SDK JSON bytes plus 2,048 estimated overhead tokens per call; this **cannot prove actual provider input tokenization**, billable tool/schema overhead, request retry charges, cached-token pricing or actual spend. It is a **cost-planning preflight**, not a billable input cap. The snapshot headroom must be checked again immediately before any proposed future execution. No code path here can send, and all live key / approval environment markers cause refusal.

## Original-source integration

The #473 wrapper intercepts #472's `claim_packet` in the **Native parent** (not in the separate worker process). For the eight first-use claims it validates the *original* capped SDK bytes using #472's existing strict scope validator and a conservative byte bound. The worker independently revalidates the original SDK bytes before its local write-once SQLite claim. Original #470 Broker, #457 pre-parser AEAD and the scripted Native scorer are unchanged. The resulting SHA-only report binds the budget preflight receipts to #472's isolated worker receipts **from the same run**. Restart replays remain denied. No payloads, keys, API response bodies or provider calls are included in the report.

**Limits:** this does not solve true independent A/B model generation, token accounting, remote CAS, issuer/egress isolation, provider response provenance or real Utility. This is intentionally a bounded, useful pre-send preparation, not a live Sender.

## Next actual execution gate

A **new and exact owner authorization** is required with: immutable code HEAD, project, model, case and A/B methodology, maximum **real** attempts and per-request tokens, hard independent retry policy, fixed run window, maximum dollar exposure, and explicit permission for paid Provider POST. Any "はい", past $1 project limit or previous Task1 API approval is not such authorization. The live Sender requires separate review and independently verified runtime egress/credentials and input-token accounting. Keep Task4 #321 and Task1 #427 OPEN/NO-GO.

This PR is **Draft** and owner-only manual merge after all dedicated and inherited checks pass. Only four additive files; no existing workflows, Secrets, environments, rulesets or tags changed.
