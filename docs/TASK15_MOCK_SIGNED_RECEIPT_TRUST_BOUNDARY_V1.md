# TASK15_MOCK_SIGNED_RECEIPT_TRUST_BOUNDARY_V1

**DRAFT / NOT PROVEN. Do not merge before exact-HEAD CI + downloaded raw SQLite artifact independent audit.**

## One invariant

For the **named, opt-in offline mock signed-reconciliation adapter** only, a persistently fenced `DISPATCH_UNKNOWN` may be promoted to `CONFIRMED_MOCK_EFFECT` only if **both** of the following exist and match:

1. A real row in the independent *local SQLite mock-provider* table (operation ID, frozen source plan hash and receipt JSON/hash).
2. An Ed25519 signature over that exact receipt's SHA-256, operation ID, frozen model, predecessor evidence SHA-256 and intent/source plan SHA-256, verified under a test public key **enrolled before the simulated response was created** in a separate local trust-anchor SQLite database.

An unsigned observation, unverifiable signature, moved source, swapped signer, changed root or missing provider effect must not be promoted. After post-fence uncertainty there is **no automatic resend**, even when the simulated provider reports no row.

### Source pin

Predecessor #272 exact merged main `10ed8d1c5fd37e0712b3b33aa33cdec8b34620ce`. Replay predecessor #272, including #271 cross-process SQLite and all earlier Task15 source/Binds, at exact frozen pins before exercising this test.

### Six scenarios

| Scenario | Outcome from signed mock adapter |
|---|---|
| Mock effect + registered-root-signed receipt | `CONFIRMED_MOCK_EFFECT` |
| Mock effect + lost ACK + signed receipt | `CONFIRMED_MOCK_EFFECT` via read-only recovery |
| Mock effect + missing signature | `DISPATCH_UNKNOWN` |
| Post-fence no simulated provider row | `DISPATCH_UNKNOWN` |
| Pre-dispatch abort | `PRE_DISPATCH_NO_EFFECT` |
| Unauthenticated mock effect initially UNKNOWN, later a valid test-only signature arrives | UNKNOWN then read-only `CONFIRMED_MOCK_EFFECT` |

A signed envelope is a detached `statement` and `signature_hex`; canonical JSON with sorted keys, UTF-8, explicit scope and an Ed25519 raw public key. In this **test only**, `Ed25519PrivateKey.generate()` creates ephemeral mock issuer keys at runtime, and private key material is neither committed nor saved to artifacts. A distinct test-root SQLite file is enrolled from its public key **before** any fake provider effect.

**This is NOT an actual third-party provider trust root:** the mock issuer and trust onboarding are owned by the same test setup. The test-root identity proves algorithmic verification under a pre-registered local key, not that any real provider is who it claims to be. Do not represent the signed simulation as a real, externally authenticated receipt. Merely matching a SHA-256 or signature cannot establish external issuer identity without independent onboarding and custody.

### Evidence and refusal gates

- Exact Git source blobs, frozen model profile and #272 full evidence chain.
- 15 dedicated JUnit cases: 1 positive six-scenario proof + 14 independently recorded negative cases (wrong signer, altered signature, changed operation/plan/proof/model/receipt digest/key ID/issuer, claimed real authenticity, switched local root, tampered stored envelope/digest and duplicate signature submission).
- 18 raw SQLite snapshots: controller, mock provider and trust root **for each of the 6 scenarios**, inspected directly by independent audit for DB integrity, exact root public bytes, source joins, detached signature, receipt hash, event journal, claims and true signed/unsigned state.
- **No real provider client, credential, API call, bank write, billing event or scorer invocation.**

### Hard limits

This is an **explicitly scoped wrapper path**, not a system-wide enforcement proof. The predecessor generic simulator reconciliation method remains separately callable: **no global bypass resistance is asserted**. No production trust root, trusted external issuer, independent third-party signing, user authorization, multi-host network delivery, real provider authenticated provenance, actual bank effect reconciliation, power-failure guarantee or Canonical Final128 Utility/Injection Success is proven.

The historical $5 ceiling is NOT permission to spend. A future live provider proof requires separate explicit consent, real provider identity onboarding and non-bypassable effect and receipt boundaries. **Do not merge before 17/17 latest HEAD SUCCESS and independent ZIP/JUnit/refusal/DB signature audit.**
