# Task4 #456 — Actual SDK Raw HTTP Response Bytes → Frozen Native Terminal → Detached Scorer (OFFLINE)

## Scope: a response-capture seam, NOT new synthetic model behavior

The critical genuine Task4 one-case gap is that the prior **real** Provider third-turn proposals have no authentic post-tool terminal model output. Existing #323 already runs *independently scripted* A/B SDK sessions through one actual frozen Native arm each and detached genuine local AgentDojo scorer; #363 audits exact Native wire/history lineage. Neither source supplies genuine LLM inference. #455 stages a REAL SDK first request but deliberately refuses before Provider network delivery.

This PR adds a **byte-exact local response capture bridge** at the actual #323 OpenAI SDK MockTransport response boundary, WITHOUT changing existing Native, scripted model, archived Provider evidence, scorer, authority contract, sender, credentials or environments.

**Four additive files**:

1. `scripts/task4_456_raw_response_native_lineage_offline_v1.py`: independently run the unmodified #323 A and B SDK source through pinned Native+post-only scorer. Interpose only a wrapper on the #323 *local* `OneArmMock.__call__`; it returns the exact original `httpx.Response` object, byte for byte, to the SDK. A `RawResponseJournal` records the exact original HTTP **body bytes temporarily in RAM** and safe SHA-256 receipts. It refuses duplicate/unknown IDs, non-200 replies, wrong model/arm, missing terminal, invalid binary or JSON, fake/nonzero usage, a wrong Native conversation, and cross-origin mixing. It verifies original source report identities, timestamps are synthetic, calls the original #323 scorer auditor and #363 Native-history-to-scorer lineage auditor.
2. `tests/test_task4_456_raw_response_native_lineage_offline_v1.py`: local source fail-closed tests + pinned real Native/SDK/AgentDojo scorer integration, no external sockets and zero real secrets.
3. `.github/workflows/task4-456-native-sdk-raw-capture-no-provider.yml`: standard PR-only workflow with original exact frozen AgentDojo/RCC/VERITAS checkout, no write token/Secrets/Environment, zero `workflow_dispatch`, no real Provider POST and artifacts consisting of **hash receipts/JUnit only**.
4. This document.

## Response/raw bytes and evidence claims

- The raw HTTP response bytes are **not emitted to logs or archived in CI artifacts**. No durable encrypted real capture has been implemented; this run only proves in-memory retention for SDK continuation, identical raw response-object pass-through, and hash linkage through Native terminal and detached scorer.
- The source is **LOCAL_SCRIPTED_SDK_MOCK_NOT_REAL_PROVIDER**. The fake OpenAI model responses have IDs `offline-323-A-0...3` and `offline-323-B-0...3` and fake usage 0 tokens. Fake data does not prove actual OpenAI access, billing, real-model identity, genuine terminal model output or model independence.
- The test dates are 2031-07-08 **offline fixture**, not real authenticated issuance. In a future properly consented real run, the trusted date and authority must be frozen before the **first** model query; old real partial third turns cannot be reclassified.
- The test should generate eight local SDK HTTP responses for two sources; each source proceeds through one selected Native arm, its own tool result and terminal, and one post-only Native scorer invocation. The original frozen #323 + #363 strict source audit determines internal trajectory/scorer validity. The new journal neither repairs model responses nor intervenes on Native decisions.
- No local mock Utility, injection result or raw response ID is promotable to one new genuine Task4 score or canonical Final128 evidence. Historic V13 A=93/128, B=64/128, B injection success=0/128 remain unmodified. **Zero new genuine recoveries**.
- No OpenAI Project key issued or stored, no billing, no real bank, no protected GitHub Environment accessed, no persistent one-use cross-run ledger, no authenticated Provider receipt or encrypted full original captures. Explicitly no real Provider transport created.

## Remaining bottlenecks to an authentic one-case study

1. **Future approved sender** (separate reviewed implementation, with independent credential reachability and no PR-triggered live path) must associate the SHA of exactly the serialized request sent with a raw Provider **HTTP response** returned in the same call, binding its source/attempt/response ID and actual usage. Ambiguous timeout or nonreceipt permanently consumes the attempt, no retry.
2. Capture raw response into **durably encrypted private evidence** before it can be discarded. In-memory-only SHA receipts are insufficient for a real experiment. Do not put decrypted chats, bank state, API keys or ciphertext keys into GitHub public artifacts.
3. Preserve each **genuine** model's own tool call/read result/VERITAS Bind adjudication and next model continuation through final terminal text. Native policy cannot be relaxed to rescue legitimate Utility.
4. Call the **unchanged** AgentDojo scorer only after terminal completion. Verify cost/model access independently; enforce per-arm/total attempt limits and fresh real date/amount/recipient authority. Request new exact owner consent only when all gates are ready.

Both Issue #321 Task4 and #427 Task1 remain OPEN / real Provider **NO-GO**. New PR CI success cannot change their status.

**Review:** Draft until latest HEAD ordinary CI, new pinned native/SDK response-capture CI, hash-only evidence and source diff all pass. Manual merge is separate. No live consent is implied.
