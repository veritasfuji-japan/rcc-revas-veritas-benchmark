# Task4 #457 — Pre-parser AEAD evidence envelope for the existing Native A/B research seam

## Target and honest limit

#455 stages the *real Native→OpenAI SDK first request* but hard-denies egress. #456 verifies eight **local scripted** SDK HTTP responses can pass unchanged into the original #323 pinned Native A/B, terminal text and detached post-only native scorer; #456 does not persist their raw bytes.

This PR **does not implement a live Provider sender, actual Provider authentication, or a real persistent record-recovery service**. It adds a narrow encrypt-before-deserialize/fsync proof into that existing unchanged **local MockTransport** seam only. Independent actual Provider one-case Utility remains BLOCKED / Issue #321 OPEN NO-GO. Historical Task1 #427 is likewise NO-GO.

## Four newly added files

1. `scripts/task4_457_local_response_aead_v1.py`: `SealedLocalVault` takes a *recipient X25519 public key*, generates a fresh ephemeral X25519 sender key per response, derives AES-256-GCM material with HKDF-SHA256, authenticates exact AAD including Task4 case, A/B, ordinal, raw actual SDK request/response SHA256, untrusted HTTP status and offline source class, then writes **only ciphertext** to a 0700 local temp directory as 0600 create-only `.enc.json` files with file+directory fsync. It never writes a plaintext copy. Its only caller intercepts the original #323 MockTransport response, encrypts it **before #456 checks/parses it or the SDK gets that exact response object**, then invokes unchanged #456 Native↔scorer provenance audits after both local arms finish.
2. `tests/test_task4_457_local_response_aead_v1.py`: sealed byte recovery, corrupted envelope failure, wrong-recipient rejection, duplicate/overwrite denial, nonprivate directory rejection, real Provider Secrets and sockets forbidden, and pinned unmodified Native SDK/scorer test.
3. `.github/workflows/task4-457-local-raw-aead-no-provider.yml`: PR-only read-only GitHub Actions runner, pinned original AgentDojo/RCC/VERITAS commits and SDK/cryptography packages. No `workflow_dispatch`, Environment, Secrets, API key, production bank, network Provider POST or GitHub write token. Uploads only JUnit, audit summary and SHA receipt metadata, **not ciphertext, keys, raw request/response, or recovered plaintext**.
4. This document.

## Identity and authenticated origin limitations

- The AEAD associated data (AAD) guarantees cryptographic detection of accidental/malicious ciphertext/metadata tampering **relative to its key**. The current source is a local scripted MockTransport and an ephemeral local recipient, not a Provider-signed, externally verified receipt or production trust anchor.
- The private test recipient key is generated freshly in process and **never persisted or included in a GitHub Artifact**. Each run decrypts locally for test verification, destroys the temporary directory on exit, and discards its only test recipient key. This is intentional: it prevents CI from becoming an undeclared plaintext retention sink.
- File and directory fsync prove best-effort local filesystem completion, **NOT durability across GitHub Actions jobs/runners, off-host encrypted archival, cloud retention or independent key custody**. Do not label this a production-correct durable provider capture.
- The fake local response contains zero usage tokens by construction; **NO authentic model, billable tokens, fresh User approval, new actual Utility result, independent production authority, Provider credential, external real banking effect or Provider network calls** are made.
- The local native clock `2031-07-08` is a synthetic fixture, not a real preissued date. Encryption cannot retroactively repair old captured genuine proposals with missing terminal replies.
- The existing #323 Native and detached scorer are not edited. Their local completions do not grant new canonical Final128 Utility or injection claims.

## What remains needed before paid A/B one-case trial

1. Independently managed **real recipient public-key distribution and private-key custody**, key rotation/retention policy, off-runner encrypted artifact custody and custody verification. Untrusted PR job code must not be able to fetch real Provider credentials.
2. **Fail-closed durable cross-runner send-attempt allocation** (atomic once only), unknown-response no-resend, issuer/source SHA attestation and exact one-case A/B spend/attempt policy. The $1 OpenAI project monthly limit is NOT a per-experiment exactly enforced dollar cap.
3. Freshly reviewed protected real sender and actual raw Provider response handling, including abnormal HTTP/non-200/truncated/corrupt body preservation before validation. Do **not** add live egress to this PR to shortcut the deny boundary.
4. New genuine independent A/B conversations **from first model token**, original preissued date/amount/recipient authority, same-origin native tool result through genuine terminal response, followed by unchanged official Native scorer.
5. **Fresh exact owner paid authorization** covering the verified model availability, GitHub commit/run/case, attempts, expenditure risk and cancellation. Old approvals/tags have been permanently consumed.

**Review gate:** Keep Draft until latest HEAD dedicated pinned Native #457 CI and full normal CI pass, archive SHA verified and no secret/Environment/workflow/source edits. CI green proves only an offline cryptographic pre-parser seam, not readiness to spend or proven Utility.
