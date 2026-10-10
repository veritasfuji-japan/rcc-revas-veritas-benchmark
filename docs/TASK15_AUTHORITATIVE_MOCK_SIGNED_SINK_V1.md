# TASK15_AUTHORITATIVE_MOCK_SIGNED_SINK_V1

**DRAFT / NOT PROVEN pending exact-HEAD CI, full predecessor replay and independent raw SQLite artifact checks.**

## Rule-of-One

**Only the new bounded signed effect-sink's status counts as authoritative within this proof.** An independently stored mock-provider receipt and a valid Ed25519 signature bound to the exact prior Task15 request, provider mock operation, frozen model and predecessor proof must pass a previously pinned offline test trust-root verification **before** an effect can enter `CONFIRMED_SIGNED_MOCK_EFFECT` in the signed-sink ledger.

The existing generic `LocalMockConsequence.reconcile()` is intentionally **NOT** removed or rewritten by this PR. It can mark its legacy controller as `CONFIRMED_MOCK_EFFECT` without a signature. This new proof shows that the same legacy controller state is **not** enough to change the separate signed effect-sink's status from `DISPATCH_UNKNOWN`.

Reading an already-confirmed signed sink rechecks source identity, mock-provider signature row, pre-enrolled public key and the Ed25519 signature. Direct SQLite state/envelope tampering is detected at the audited status-reading interface. Attackers granted database write or process-code modification rights are not excluded at the storage boundary; no production-wide enforcement is claimed.

## Fixed source and test-only trust

- Frozen predecessor #273 merged main SHA: `4a5c6cedef2944fd6e15c1eea4ecbb17dfd125f6`.
- Exact prior canonical Task15 source, model `gpt-4.1-mini-2025-04-14`, and source hashes.
- Ephemeral Ed25519 mock signing key generated inside CI, with pre-enrolled **local test** public root in separate SQLite file. This is not a real provider's identity or certificate.
- All database files and mock receipts are **local** and test-owned. No live provider credentials or API access is issued.

## Four audited scenarios

| Scenario | Legacy controller | New signed authority sink |
|---|---|---|
| Signed mock receipt and provider row | May confirm | `CONFIRMED_SIGNED_MOCK_EFFECT` |
| Generic legacy unsigned reconciliation | `CONFIRMED_MOCK_EFFECT` | **`DISPATCH_UNKNOWN`** |
| Recorded mock effect without signature | `DISPATCH_UNKNOWN` | **`DISPATCH_UNKNOWN`** |
| Fenced send without provider row | `DISPATCH_UNKNOWN` | **`DISPATCH_UNKNOWN`** |

## Evidence acceptance

- Latest exact HEAD: all repository checks and the dedicated replay/audit workflow succeed.
- New JUnit: **15/15 pass**, no skip/error; fourteen named adversarial refusals in JSONL, including generic legacy bypass, wrong signing root, invalid signature/scope, unsigned/missing source, replay, direct SQL tamper detection and live-provider transport denial.
- **16 actual SQLite snapshots:** controller, provider, test root, signed sink for each of four scenarios. Independent auditor must open each raw DB read-only, `PRAGMA integrity_check=ok`, verify SHA-256, source binding, sink/controller disagreement and test-root Ed25519 signatures, not trust JSONL self-assertions.
- Full replay of prior #273 and its bounded predecessors; source Git blobs, native runtime Git blobs and frozen model configuration pinned.

## Nonclaims

This is **only a separately scoped, opt-in offline signed sink**. There is still a legacy generic mock entrypoint that can confirm its *own* controller state without a signature. This PR does **not** make all callers use the new sink, isolate direct SQLite writers, establish database credentials, prove system-wide enforcement/bypass resistance, or establish independent real-provider signer identity.

No actual OpenAI response, real-world bank write, external provider effect, production trust, cost-incurring provider call, paid Final128 Utility or Injection Success is proven. The earlier $5 maximum is not spending permission. A future real-model-only capture requires a new explicit authorization of case, model, spend ceiling and one call, and an independently reviewed isolated transport.

**Manual merge only after exact-HEAD CI plus independent JUnit/JSONL/SQLite verification.**
