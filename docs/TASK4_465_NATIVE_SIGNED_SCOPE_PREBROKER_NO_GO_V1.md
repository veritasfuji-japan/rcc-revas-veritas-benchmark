# Task4 PR #465 — Native first SDK wire ↔ signed fixture ↔ local Broker, HARD NO-GO

## Purpose
Join #464's **synthetic Ed25519-signed issuer envelope** to the genuine, frozen #455 Native Task4 first request **inside the #463 SDK-inspector call, before the local #458 Broker consume**. The unchanged #463 transport still always raises and cannot forward to a real Provider.

This is **NOT** true live authorization. A valid synthetic signature demonstrates local integrity against a supplied key, not an independently enrolled issuer, permitted recipient/amount, reliable real date or paid owner consent.

## Frozen execution and strict boundary
1. Verify Git blobs of existing #455, #463 and #464 scripts; use current repo source, not editable claim metadata to select baseline.
2. Under the original non-network #455 hard-denying SDK transport, stage genuine Native first-request digests for arms A and B. This preliminary request is local-only.
3. Create two arm-specific synthetic claims using an ephemeral test-only Ed25519 key, a 2031-07-08 fixture issuer/clock, the staged actual SDK hashes, the frozen original user request, and a synthetic **100 USD cents** amount. The user's original refund instruction does NOT authorize that amount. No signing key is persisted or enrolled.
4. Start the unchanged #463 integration. The wrapper calls the actual #455 wire inspector, then checks the real SDK-generated raw body digest, exact frozen first developer date and original user message, signed Ed25519 claim, expected arm, pre-staged digest, original-request SHA, frozen original-request-derived recipient digest, synthetic amount/currency and 2031 fixture-time expiry. The raw SDK wire is never logged.
5. Only after successful checks, #463 invokes the unchanged local #458 Broker's atomic consume; #463 then denies Provider transport. Restarted same-host Broker rejects duplicate A/B attempts.
6. Emit digest-only evidence; Utility and injection outcomes remain **UNSCORED**.

If a signed claim refers to a **2026 real calendar date**, it mismatches the frozen Native 2031 fixture request and must be refused. Re-signing a substituted sender-controlled user message, recipient, amount, currency, date, model or arm must not turn a bad request into a valid claim. A signature check never grants real send permission.

## Critically unproven
- The **original trusted request** here is an existing frozen test string, not independent authorization by a user/enterprise policy owner. The recipient hash is inferred only from that string and has NOT been established as an approved payment recipient. The amount is wholly synthetic.
- The **2031 signing/observed clock is a test fixture**. There is NO actual trusted issuer clock, pre-first-live-SDK enrollment or externally verified date. The temporary test key is not a real authority.
- The synthetic claim is created *after an earlier offline SDK pre-staging*. Thus the experiment does not establish genuine pre-first-request issuance in a deployed model sender.
- The bridge relies on local Python monkeypatch wiring to intercept the existing #463 inspection seam. This is an offline research harness, not an independently operated, non-bypassable enforcement boundary.
- Same-Runner SQLite + Unix socket is NOT cross-Runner durable one-use execution permission. No authenticated Provider responses, real A/B model continuations, external custody, real Native terminal/scorer results or external bank effects.
- The source pin in #464 refers to its own frozen earlier main commit by design; do not reinterpret it as current main or as a fresh approval.
- All numbers are local test assertions only: Provider POSTs **0**, paid calls **0**, real Utility **UNSCORED**. Issues #321 and #427 remain OPEN/NO-GO.

## Operational no-change scope
Four new files only: bridge, rejection tests, PR-only read-only CI workflow, this document. Reuse untouched #455/#458/#463/#464. No Environment, token, secret, tag, Ruleset or main modification until owner's separate merge. Workflow runs on ordinary PR events with read-only permissions, empty Provider key variables and no Provider sender. The publicly cloned frozen repositories are source/dependency inputs only, never real bank connections.

## Review before merge
- Verify exact 4-file diff and Git-pinned source inputs.
- Dedicated negative and actual Native integration tests PASS on the PR HEAD.
- Verify the negative test proves an invalid signature rejects **before even a local Broker consume**.
- Check hash-only Artifact (no raw request, signature private key or secret).
- Confirm all inherited CI SUCCESS, NO paid Provider calls and no claims of real issuer/date/recipient authority.
- Keep PR Draft until reviewed; no automatic merge or paid Provider dispatch.
