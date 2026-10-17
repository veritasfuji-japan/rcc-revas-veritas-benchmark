# Task1 B-pilot — one-shot local mock execution gate V1

**STATUS: DESIGN/LOCAL OFFLINE TESTS ONLY. NO LIVE MODEL / NO PROVIDER AUTHORITY / NO PRODUCTION SINGLETON.**

## Objective

Rehearse *one* attempt to capture Arm A then *one* attempt to capture Arm B under an immutable mock plan, with a durable local record **before** each potentially irreversible simulated action and no automatic reattempt after an unknown result.

This is an extension of merged [PR #434](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/434), which introduced offline encrypted capture-before-parse. The future *real* limited research pilot is **not** implemented or authorized by this PR.

### Evidence limitation before anything else

The first Native Chat packets for A and B are **byte-for-byte identical inputs** (though independently owned objects). At that stage the attacked Native tool result and B-only VERITAS post-read overlay are still absent. A future 2-call "first A/B" study can show model access and encrypted response capture only, **not** actual prompt-injection success, VERITAS blocking, Native Utility recovery, a full 128-case score, or a terminal trace.

## Source and execution boundary

- \`scripts/final128_task1_research_one_shot_offline_gate_v1.py\`: imports only the existing **mock** encrypted capture primitive and Python stdlib. Its plan captures a caller-asserted Run ID, main SHA, and identical A/B first-packet SHA256. It checks syntax and equality, **not GitHub authentication**.
- \`tests/test_final128_task1_research_one_shot_offline_gate_v1.py\`: all fake bytes, local fake test encryption key and private temporary directories. Network calls explicitly blocked and environment credentials removed.
- No runnable workflow, CLI, Provider SDK, GitHub REST client, token access, production issuer, scorer, bank effects, or real transport exists in these new files.
- The mock gate has a literal \`live_dispatch_allowed=False\`. No state transition makes it \`True\`.

## Local mock transition contract

| Prior state | One allowed action | Next state |
| --- | --- | --- |
| UNCLAIMED | Exclusive local mock claim | CLAIMED |
| CLAIMED | Record Arm A intent (durable, before any simulated response) | A_INTENT_UNKNOWN_STOP |
| A_INTENT_UNKNOWN_STOP | **Only the same in-memory gate instance** may capture and validate **one** mock Arm A response | A_MOCK_CAPTURED, or A_VALIDATION_REFUSED_STOP |
| A_MOCK_CAPTURED | Record Arm B intent | B_INTENT_UNKNOWN_STOP |
| B_INTENT_UNKNOWN_STOP | Same instance may capture and validate **one** mock Arm B response | MOCK_PAIR_COMPLETE_NO_REAL_AUTHORITY, or B_VALIDATION_REFUSED_STOP |

The journal uses create-only \`O_EXCL\` files, private 0700 directory checks, file and directory \`fsync\`. The mock response is AES-256-GCM encrypted and persisted using the PR #434 primitive **before** the injected JSON parser is called. Separate A/B authenticated data binds response to run, main SHA, arm and first packet digest; wrong AAD/key refuses decryption.

A process restart after an intent, a failed file commit, an unknown extra file, or invalid/missing journal content is an **unknown-outcome STOP**, not an invitation to retry or "repair" the attempt. A failed A parser stops B. A successful mock pair cannot be repeated by reopening the directory. No plaintext mock body is written.

## Why this is NOT a global once-only lease

GitHub-hosted Actions runners have independent ephemeral filesystems. A local \`O_EXCL\` claim on Runner X does **not** exclude a duplicate job on Runner Y. An owner or administrator may change workflow or Environment settings, artifacts can be deleted, and two manual dispatches can use unrelated local directories.

This does **not** prove globally unique Provider traffic, credential isolation, cost-control hard stop, trusted source identity, GitHub tag issuance, or resistance to an administrator changing Rulesets.

**NEVER** transplant this local mock claim as the authority condition for a real send. GitHub \`concurrency\` and \`run_attempt==1\` are also insufficient substitutes for a persistent globally atomic one-shot control.

A future research-only implementation must first obtain a separately reviewed and enforced single-use claim mechanism that is durable *across independent runners*, with recorded ambiguity/partial-effect semantics, and clearly state which administrator changes it cannot resist. If such a mechanism is infeasible at zero cost, a less robust human-operated pilot must be separately risk-accepted and **cannot claim strong once-only, no-bypass evidence**.

## Mock tests and pass criteria

Run:

\`pytest -q tests/test_final128_task1_research_one_shot_offline_gate_v1.py\`

Verify full A/B synthetic sequence, claimed plan drift refusal, concurrent local claim competition, no B before A, crash after either intent, duplicate send refusal, loss of result journal after encrypted capture, parsing failures preserving ciphertext, wrong key/AAD, invalid identities, 0700 directory and symlink restrictions, and absence of Provider/network/credential functions.

Tests simulate only private, local, untrusted inputs. Successful tests mean "offline state machine behaves as modeled" and **nothing more**.

## Research pilot gates still OPEN

1. **Authority and uniqueness:** decide on a separate non-production durable external lease, or explicitly accept that a human-only pilot carries unavoidable duplicate/override risk. Do not use production Task1 singleton \`refs/tags/final128-task1-first-two-real-responses-v1-consumed\`.
2. **Transport and origin:** independently review an actual TLS sender, pins, model availability, first two equal Native packets, distinct genuine Provider receipt identifiers and no retries on ambiguous HTTP outcome.
3. **Evidence:** encrypt raw body *before* strict parse; verify key custody and decryption in a separate environment; secure artifact retention long enough for independent review, prevent plaintext exposure and replay.
4. **Bounded billing:** isolate a dedicated research project/key with account/project billing restrictions reviewed by the operator. USD 1 is a proposed tolerance, **not an enforceable hard cap demonstrated by code**.
5. **Decision and consent:** separate PR/security approval and a fresh explicit human authorization bound to the *then-current 40-character main SHA*, exact model/case, at-most-two-call first stage, billing uncertainty and irreversible unknown responses. A green CI run or merge is not consent.
6. **Scientific validity:** follow-on true Native tool read, original attacked tool response, VERITAS B-only overlay, additional genuine model turns and same-run official scoring are a separate future experimental stage.

**STOP / NO-GO:** Current paid-capable workflow \`.github/workflows/final128-423-task1-protected-first-two-native-chat-live-v1.yml\` remains unchanged and MUST NOT be dispatched. Its Ruleset \`bypass_actors\` read is deliberately fail-closed. Never treat MISSING as empty. Tag Ruleset #24921425 and main Ruleset #25299895 are untouched. Issue [#427](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/427) remains OPEN/NO-GO. No Provider API, ref write, credential action, or future spending consent is part of this PR.
