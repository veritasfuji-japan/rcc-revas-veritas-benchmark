# Task4 #470 — Capped Native SDK attempt admission into local Broker (NO-GO)

## Newly implemented

This is a working, zero-egress **pre-Sender admission seam**. The unchanged #325 code constructs four actual OpenAI SDK serialized HTTP request bodies for each original locally scripted Task4 Native arm, all with max_completion_tokens=256. Before the existing **local model mock** receives each request, #470:

1. Refuses any live credential or payment-approval environment.
2. Examines the **actual SDK-created request**: exact HTTPS chat endpoint, locally-known dummy token, strict unique-key JSON, exact model/version, temperature zero, tool_choice=auto, 256 output-token parameter, expected developer/user prefix, trusted original request and tool schema, no later system/developer/user roles.
3. Requires per-arm monotone native turn order (message counts 2, 4, 6, 8), no repeated SDK-body digest or changed tool schema, bounded raw JSON bytes, at most 5 planning attempts per arm and 10 total. The pinned #325 trajectory presently uses four per arm.
4. Calls the unchanged #458 separate-process **local Unix-socket SQLite Broker** to atomically record each unique (synthetic_trial, arm, ordinal, request_sha256) attempt. It refuses a duplicate or forged decision. This local consume marker is **not** a send license.
5. Only after the Broker records LOCAL_CONSUMED_NO_SEND allows the unchanged #325 GuardedMock to return the original **scripted local** SDK-compatible reply; Native advances within that exact originating arm.
6. Checks each arm's original detached native scorer and SDK-body SHA lineage. Restarts the same local Broker against its SQLite file, verifies all 8 slots remain unavailable, and emits only hash/ordinal and fixed non-sensitive metadata.

The implementation does not patch the original Native, Broker or mock source files. The hook is scoped around the existing frozen #325 GuardedMock.__call__ only, and always routes to the same original local fake responder. There is no real Sender, HTTP transport, Provider API, live authentication, network delegation, key loader, approval switch, production authority or real bank connection.

## Relative to #469

- **#469 (already merged):** unmodified #323 Native SDK response transport → local Broker → encrypted raw scripted HTTP response **before SDK parsing** → next Native turn → scorer, all 8 locally-scripted responses. Its original SDK request profile does not include the future-live output-token cap.
- **#470 (this PR):** actual **capped** #325 serialized SDK requests → local Broker consume before the local scripted response → same source's Native terminal and detached scorer.

**This PR DOES NOT prove that the capped SDK wire and #469 pre-parser AEAD response capture operate in the SAME RUN.** A later source-pinned zero-egress integration must unite these without bypassing either guard; do not splice their separate reports.

## Scope and nonclaims

Case: banking:user_task_4:injection_task_0:direct.

Original frozen AgentDojo baseline contains incoming transaction ID 5, amount **10.0 with no currency specified**. #465's historical synthetic 100 USD cents and 2031 test clock confer no real authority. In this offline proof, a 2031 test execution date is only a fixture; no independent issuer or current wall clock is attested.

The 256 output cap is present in the actual local SDK JSON body, but a request field does not prove Provider acceptance or billable usage. Raw JSON sizes and cap arithmetic are not independently enforced hard Provider spend limits. Max 5/arm and 10 total are prospective **local** count guards, not a new owner-approved budget. Any future live research experiment must first pin model availability/price, external spend controls, real issuer/session ownership and exact fresh owner approval.

- Genuine Provider responses: **0**.
- External Provider POSTs: **0**.
- Real bank effects: **0**.
- True A/B Utility and injection outcome: **UNSCORED**.
- Broker is local to one GitHub Runner, not independently administered, cross-runner atomic or production-grade evidence custody.
- Issue #321 and #427 remain OPEN / NO-GO.
- No changes to Secrets, GitHub Environments, Rulesets, tags or existing workflows.

## CI and owner review

Four additive files: scoped local preflight script, adversarial tests, PR-only offline workflow, and this document. The dedicated CI clones the exact frozen AgentDojo/RCC/VERITAS sources and uses the pinned SDK/runtime. It executes the actual Native SDK request serializer and a local Broker, producing sanitized JUnit and hash receipts only.

Do not merge without dedicated test PASS, all inherited checks green on final SHA, exact four-file diff and sanitized evidence artifact. Even after a manual merge, any actual billed experiment requires **new scope-specific explicit owner approval**, not a PR merge or generic affirmative.
