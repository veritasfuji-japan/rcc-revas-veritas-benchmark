# Task4 #324 — Offline pre-dispatch planning guard; UNKNOWN means no resend

## One central invariant

**Task4 #324** is an entirely offline *research planning* proof that prospective model-shaped requests are bounded **before** a simulated request reservation, with local duplicate/UNKNOWN fail-closed refusal. Nothing here can send a network request or authorize an actual Provider bill.

Exact frozen parent \`main\`: \`6554d0faaef979038ec8b300b7dca759a2f274d7\` (merged #323).

This PR does not touch any frozen RCC/VERITAS Bind, AgentDojo native trajectory, model generator, scorer, deployment Environment or existing approval. It creates pure-standard-library, offline-only \`OfflineReservationJournal\` and a PR-triggered isolated self-test.

## Frozen research-only scope

| Attribute | Test-only upper-bound assumption |
| --- | --- |
| Benchmark | \`banking:user_task_4:injection_task_0:direct\` |
| Native starting state | SHA-256 \`8b653f253d3b2b033ad2baebc938bb66cb09719be8b488a470e7e82d25abbe14\` |
| Native lower-trust attack subject | SHA-256 \`0d5011fb8b275e313c83da127698f19a77095d44e82a81b4d5804046c3cb61a9\` |
| Model name parameter | \`gpt-4.1-mini-2025-04-14\` (**account access NOT checked**) |
| A/B call count | Each arm <=5, both together <=10 local reservations |
| Prompt tokens per request | <=10,000 **caller-estimated** tokens, including any tool schemas/history |
| Maximum completion tokens per request | <=256 **caller-declared** output reservation |
| Whole test budget | 100,000 estimated input + 2,560 reserved output tokens |
| Price assumptions | Standard input $0.40/1M, output $1.60/1M; not a real quote or account hard cap |
| Absolute arithmetic at all maxima | $0.044096 estimated **not invoiced** |
| Larger planning budget ceiling | $0.10 **SIMULATED**, NOT owner spending approval and NOT an OpenAI hard billing cap |
| Intended execution context | \`main\` / \`refs/heads/main\` / protected Environment name \`task4-provider-protected\` / simulated \`workflow_dispatch\` first attempt |
| Native effects | No native tool dispatched by this guard; all bank destinations forced to in-memory-only |
| Human approval | **FALSE**, explicitly \`TEST_ONLY_NOT_REAL_HUMAN_APPROVAL\` |
| Provider POST | **DENY**, no sender, no OpenAI client, no API key, no network connection |

**The test simulates future workflow_dispatch context; the actual GitHub Actions proof triggers on PR/main push only** and has no workflow_dispatch handler or protected Environment. This is not live permission, IAM attestation or model billing validation.

## Tested invariants

- Reject untrusted branch/ref/SHA, reruns, wrong Environment, model, case, original native prestate/attack identity, bank destination or test-only authorization marker.
- Reject any live approval, API credential or assertion that the external spend cap is proven. Secrets present in the test process cause fail-closed refusal.
- Reject bool-as-int, invalid request SHA-256, zero or excessive per-request tokens, duplicate/nonmonotonic ordinal, extra requests per Arm, aggregate planned budget overflow.
- Locally consume each unique \`(arm, ordinal)\` reservation with lock and hash-chain receipt, then freeze the entire in-process trial for simulated ambiguous/UNKNOWN state. Refuse any further reservation and all replay. Concurrent identical claims produce only one in-process winner.
- Verify simulated receipt chain/summary SHA-256 and JUnit evidence.
- Zero real Provider calls, zero real model completions, zero external effects, zero canonical Final128 scoring.

## Critical limitations

This is NOT a ready-to-use sender or a production-grade pre-dispatch authorization gate. \`request_sha256\` is caller-supplied in the simulation; the guard does NOT independently tokenize actual wire JSON, verify OpenAI project permissions, enforce a network allowlist, enforce account billing ceilings, persist an atomic cross-workflow one-use ledger or hold actual human approval.

An in-memory mutex only protects one process; it cannot protect multiple Actions jobs, reruns, Github admins, forked workflows or external billing. In a real implementation these properties need their own evidence, native integrations and user-approved spending scope. Do not wire the guard as a green light for real Provider POST. The only 'success' is \`LOCAL_DRY_RUN_RESERVED_NO_SEND\` with \`real_provider_post_allowed=False\`.

## CI and review

The self-test only imports Python's standard library and pytest. Workflow explicitly passes empty Provider credentials, uses GitHub-hosted Ubuntu and pinned checkout/setup Python/upload-artifact actions, no \`secrets.*\`, no \`environment:\`, no send trigger. Review exact Draft PR HEAD, JUnit, hash chained report, GitHub artifact SHA-256, and all usual CI. **Do not merge automatically.**

The next step after this PR, still without external API use, must verify the actual serialized request/model token-counting procedure, a separately durable one-attempt decision, and a protected research sender design. That would be a *new*, separately scoped step — **not** implied by #324's local success. Only then seek **fresh exact user consent** for model calls and a capped spend.

Related [#321](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321); #322 and #323 remain frozen as offline model provenance proofs.
