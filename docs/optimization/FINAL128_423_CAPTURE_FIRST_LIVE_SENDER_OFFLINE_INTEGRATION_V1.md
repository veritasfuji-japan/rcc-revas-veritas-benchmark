# Task1 #423 — Capture-First integration in the existing protected sender (offline verification V1)

**STATUS: CODE CHANGE IN PAID-CAPABLE SENDER; NO PAID EXECUTION. ISSUE #427 OPEN / NO-GO.**

This PR repairs an evidence-custody gap in the **existing** #423 manually protected first-A/B Chat Completions sender. It changes only response-handling code plus offline tests and this document. The manual workflow remains workflow_dispatch-only; **nothing here dispatches it, consumes a tag, authenticates a real GitHub job/issuer, or authorizes a Provider request.**

## Before / after: response evidence ordering

**Before:**
1. `one_post` rejects a non-200, missing/unrecognized `x-request-id` or over-limit response before returning its body.
2. `execute` invokes strict `shape.capture_one` first; invalid or unusual received HTTP bytes can be lost.
3. Encryption occurs after parsing and uses a nonexclusive `write_bytes` file write.

**After:**
1. `one_post` makes the same **single** bounded transport call and returns the observed body (up to `MAX_BODY_BYTES+1`), status and the *untrusted* request-ID value. It does not treat non-200/invalid-ID as authorized or valid.
2. `execute` computes the first request digest from its **source-owned exact packet**, AES-256-GCM encrypts the returned HTTP bytes in memory, and writes an envelope into an existing **0700 output directory** using a fresh ciphertext-only temporary file at **0600**, file `fsync`, create-only hard-link of the exact final filename and directory `fsync`.
3. Only **after** encryption and local persistence does `execute` reject oversized/partial body data or invoke `shape.capture_one` for status, server request ID, Native response schema and usage checks.
4. If validation fails, retain the sealed bytes and a *redacted* `UNKNOWN_PROVIDER_OUTCOME_STOP_NEVER_RETRY` event. Do not call B if A failed. The ciphertext's authenticated associated data bind the Task1 case, Run ID, arm, source-owned first-request digest, observed HTTP status, SHA256 of the untrusted server ID (if present), and whether capture was truncated.
5. A completed response that exceeds the cap is saved only as a **PARTIAL capture** with `http_body_truncated=true`, then rejected. It is never promoted as full native reply, independent Provider receipt, bill or scored evidence. A zero-byte response is sealed and then refused by response validation; a read/TLS failure before bytes return is UNKNOWN with no inventable body.

**Important:** Local file/dir fsync is not proof of physical crash durability across hosts, successful Actions Artifact upload, independently durable archival custody or a retained Provider receipt. The unchanged workflow's existing encrypted artifact upload currently retains for one day; upload can also fail. Decryption and key custody must be separately assessed.

## Offline acceptance tests

- Regression suite: `tests/test_final128_423_capture_first_live_path_offline_v1.py`.
- Existing sender tests: `tests/test_final128_423_task1_protected_first_native_chat_sender_v1.py`; the positive A/B test's AAD fixture is updated to include authenticated observed HTTP metadata.
- In the new suite, `source_pair`, runtime credentials and the Native response parser are **replaced by explicit source-owned test fixtures**. No actual Native model pair, real credentials, GitHub job/Environment authentication, or Provider network access is exercised.
- Only injected in-memory `connection_factory` replies are used, and the tests monkeypatch socket connect methods to fail. They check ciphertext-first ordering, reversible decryption with a **public fixture key**, exact raw-body preservation for non-200, bad JSON, missing ID and empty body, partial-body quarantine above the size limit, A/B order, exclusive/no-overwrite output, private directory requirement and refusal to send a subsequent arm after uncertainty.
- The source's real HTTP function is not invoked with its default network factory by these tests. Existing normal PR CI must never run the protected manual #423 workflow.

## Related existing PRs

- PR #434 provided a **different mock-only** encrypt-before-parse reference. This PR does not import that mock as production authority.
- PR #441 freezes bounded research-tag readback and denies false Run authority. PR #442 exercises a mock-only pre-send gate. **Neither is wired to this live sender by this PR.**
- **Draft PR #443** separately adds three `pytest.mark.xfail(strict=True)` contracts for the *old* sender. After this fix, these become **XPASS**, which is a CI failure **if #443 is subsequently merged unchanged**. Its author should close/supersede or review and update those xfail markers before merge; this PR does not alter another open PR's branch or assumptions.

## Hard exclusions / retained gaps

1. **No modification** to `.github/workflows/final128-423-task1-protected-first-two-native-chat-live-v1.yml`, tags, Rulesets, Actions Environments, GitHub PAT, Provider/AES secrets, billing settings or issue state.
2. **No manually dispatched workflows, new GitHub tag issuance, old-run retry, Provider API request or scorers**. The separate production consumed tag remains unused.
3. No independent issuer/sender principal split, real GitHub Run/job attestation, privileged secret-holder isolation, production network/IAM protection, remote durable per-arm send lease, cross-run reconciliation or strict enforced spend ceiling is introduced.
4. The exact Task1 first A/B requests are still only pre-read packets; they do not establish post-read injection resistance, B-only VERITAS utility, independent final responses or official Final128 scoring. This is an evidence-ordering repair, **not a production execution-boundary proof**.
5. The original iPhone-created **research-only tag** is not reused for live authorization. Issue [#427](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/427) stays **OPEN / PAID NO-GO**. No old or hypothetical operator consent carries forward.

**Conclusion: Capture-First response evidence ordering is testable using local fake responses. No live Provider outcome, globally single-use send or production bypass resistance is PROVEN.**
