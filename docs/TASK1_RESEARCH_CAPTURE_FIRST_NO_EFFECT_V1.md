# Task1 B-pilot: encrypted capture-FIRST rehearsal, no effect V1

**STATE: OFFLINE RESEARCH ONLY; PAID DISPATCH NO-GO; PRODUCTION TAG NO-GO.**

## Why this work exists

The existing paid-capable #423 workflow must NOT be run as-is: its least-privileged GitHub Actions token receives a Ruleset detail with the critical bypass_actors field MISSING, so the original production tag issuance check rightly fails CLOSED. An out-of-band privileged GET and an unsigned or signed snapshot do not eliminate the Ruleset administration change race between GET and tag POST. Do not weaken that check.

The original Native Task1 initial A/B request packets are **identical** (different locally owned objects). The prompt-injected Tool response and the B-only VERITAS post-read overlay occur *after* the first model turn. Therefore, getting two first model responses is only a transport/capture/protocol milestone. It is NOT a test of actual attack success, the VERITAS effect boundary, complete utility, or official scorer outcomes.

The current #423 sender parses/validates a returned HTTP body **before** persisting its AES-GCM encrypted raw response. If a response was actually sent/billed but fails a strict schema check, the raw body may be lost. This offline-only PR rehearses the safer order:

1. Receive **in-memory fake bytes supplied by the caller**, without any network.
2. Bind the bytes to the fixed repo/case/model, caller-supplied arm, mock Run ID, pinned main SHA and initial packet SHA256.
3. AES-256-GCM encrypt in memory. Commit a canonical ciphertext-only JSON envelope to a private (0700) directory using an exclusive final filename and file/directory fsync. No plaintext output is written.
4. **Only then** invoke an injected local mock validator. On a parser refusal, return a fixed, non-sensitive status and retain the ciphertext.
5. Attempting the same arm and mock Run ID again fails without replacing the first saved ciphertext. This simulates no-overwrite, **not** global GitHub single-use issuance.

## Implementation and tests

- Library: scripts/final128_task1_research_capture_first_offline_v1.py
- Tests: tests/test_final128_task1_research_capture_first_offline_v1.py
- Offline invocation: pytest -q tests/test_final128_task1_research_capture_first_offline_v1.py

The module has **no executable CLI, no provider client, no network code, no GitHub API calls, no credential loader, no real issuer, no scorer and no production capture integration**. It is imported only for mock use. A test key is deterministic and used only for publicly known fake response bytes; never deploy that key or treat it as a secret. The tests block socket connection attempts and clear relevant provider/token environment variables.

### Tested failure and integrity cases

- Separate A/B fake responses, same owned initial packet digest, arm-specific authenticated associated data (AAD).
- Parser/validation failure AFTER a durable encrypted file exists; raw fake response recoverable locally with the correct key/AAD.
- Incorrect arm, main SHA, request digest or AES key fails AES-GCM authentication.
- File collision refuses overwrite; no retries or change to an existing encrypted file.
- Invalid arm/run ID/SHA/key/raw size, unprivileged output-directory permissions, and symlink output directory fail closed.
- The mock validator has no model authority; a success remains synthetic, unscored and unauthenticated.

## Limits that must remain visible

- The caller-supplied bytes and run/SHA information are not authenticated by GitHub, TLS, OpenAI or a third party. The file metadata **is not** a signed Provider receipt.
- This rehearsal does not prove actual model access, billing, prompt token bounds, network behavior, true response durability on a different disk/storage service, or decryptability after operator loses the key.
- Process/disk failure may leave an encrypted temporary file and an UNKNOWN completion state. Do not automatically retry an uncertain Provider request. On a future real sender, use an explicit recovery inspection path with protected key custody and no plaintext logs.
- An encrypted blob can be present without any usable parsed or scored Native trace. Successful storage is NOT an effect or Utility proof.
- No project spend-cap enforcement or Ruleset change-control guarantee is established.
- No first-turn A/B difference in VERITAS's defense should be inferred from these equal initial inputs.

## Later research-only real-call design, NOT implemented by this PR

A future, separately reviewed research-only transport may run at most two one-shot first Native Chat requests, one A then one B, with exact frozen inputs, independently controlled credential and billing, no retries, durable encrypted response BEFORE strict parsing, private key custody, and explicit Run/main/code hash binding. It must use an explicitly designated *research* lease or independently reviewed operator-only one-shot control; it must NOT consume the production Task1 singleton tag or change Ruleset #24921425 to avoid an expected refusal.

That research lease is a **weaker risk-control and cannot be renamed production-grade no-bypass issuance**. A separate independent bounded design and audit are mandatory before any such code or manual call is allowed. OpenAI billing account/project actual hard-cap behavior must be checked by the operator before approval; USD 1 is an operator target, not a hard upper bound.

After the first pair, a *different* authorized research stage would have to execute a real read-only Native tool, preserve actual distinct per-arm call IDs, send the original attacked tool response, insert the B-only VERITAS post-read context, obtain further model turns and collect authentic same-run utility/injection scoring. No such work is authorized here, nor can it be inferred from the first two responses.

## Unchanged boundaries

**MUST NOT** modify or run:
- .github/workflows/final128-423-task1-protected-first-two-native-chat-live-v1.yml
- scripts/final128_423_task1_protected_first_native_chat_sender_v1.py
- Tag Ruleset #24921425 or branch Ruleset #25299895
- refs/tags/final128-task1-first-two-real-responses-v1-consumed
- Secrets, credential scopes, Environment protection, or previously failed paid runs

Issue #427 remains OPEN/NO-GO. Approval to merge a no-effect PR is NEVER approval to spend or send. Any later paid execution requires a new human authorization naming the exact then-current main SHA, case, model, at-most call count, applicable risk and a cost tolerance, after a separate code/security review.
