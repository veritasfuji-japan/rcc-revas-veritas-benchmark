# Final128 #343 — Preissued Offline Test Voucher to Real Native CDA / ExecutionIntent Packet

## Single proof invariant

**PINNED_PREISSUED_OFFLINE_TEST_ISSUER_RCCR_SOURCE_NATIVE_CDA_PROMOTION_SINGLE_LINEAGE**

Use the exact same RCC released typed action and the **preissued signed voucher** pinned by #342. The verifier must validate the Ed25519 signature with #342's **frozen public key**, audience, source case, expiry, actor, operation, target and scope *before* constructing the native candidate or calling the native route. No offline issuer key generation or new issuer signature is permitted in this CI or runtime.

Run actual source-pinned VERITAS `POST /v1/decide` with a **controlled** model transcript, then independently verify the native CDA's selected-action binding and actual native `ExecutionIntent` schema promotion packet. Fail closed on any mismatch. **This is not a production authorization proof.**

## Fixed sources / boundary

- RCC upstream SHA `353ad9e6a17cda8874a129493fe0f8f4fe4427bc`
- Native VERITAS OS SHA `299a3c4987668091f50ab3e45165bcccd1ae193f`
- Benchmark parent main SHA `320b52ade0d346756a72f03c048fa072804207cd`
- Original release case `fixture:30a220e37794e975131841bff70fc271e1a441b39efd95b93e45bc248b30ceef`
- Frozen preissued voucher SHA-256 `93c40d0c25b2a019b253826cb3aaa362fc6d5c07465cd82396fd0e32a883e6bd`
- Test issuer public-key SHA-256 `f0945df663c54edd3c9dc7033d1d8702975489175c02fbbc8d97c77ce4fca612`
- Fixture validity `2026-10-12T06:15:00Z` to **before** `2027-10-12T06:15:00Z`

## Exact execution

1. Re-execute 36 native current RCC synthetic governance cases at the frozen upstream SHA, verify 12 released / 24 withheld, and independently verify the selected source handoff exact object, candidate ID and canonical original request.
2. Reject raw RCC `DecisionCandidate` without signed test voucher via actual `validate_decision_candidate`. Raw candidate authorization remains refused even **after** a valid CDA from the voucher-backed candidate is available.
3. Verify the #342 signature against its previously pinned test issuer public key, issuer ID, key ID, audience, case, clock, SHA256, actor/action/target/scope/parameters. Reject tampered voucher, wrong target, wrong scope, expired and not-yet-valid case. The validator does **not** create a signing key or issue a new test grant.
4. Project exactly the source RCC typed action to the native `DecisionCandidate`, with `required_authority` and `required_human_approval` taken from the verified **test-only** mandate. No original RCC request mutation. Record a **separate hash** for a derived native request including the structured typed alternative.
5. With a controlled local model transcript that chooses the existing candidate, run the **actual native FastAPI route**, decision kernel, native policy and native CDA creator. Native synthetic KMS and WORM adapters still sign/store **CDA test evidence** locally; they are distinct from and never substitute the offline issuer's private key.
6. Verify the actual CDA independently; compare CDA `selected_action_evidence.candidate_hash`, `chosen`, native `DecisionCandidate` hash and chosen binding. Require native schema-level `ExecutionIntent` promotion to carry exact CDA decision ID/hash/request ID and original source actor/action/target. Independently verify `CanonicalVerifiedDecisionPromotionPacket` and candidate/decision hashes.
7. Tamper test: the untrusted RCC candidate and a chosen candidate with another target cannot promote against the valid native CDA. No v2 authorization, Bind, consumption, approval receipt or external effects.

## What success does—and does not—prove

| Stage | Positive proof allowed |
|---|---|
| Original released RCC action | Hash and identity match |
| Offline synthetic test voucher | Valid preissued signature under pinned public root |
| Native `DecisionCandidate` | Source-exact fields and signed **test** requirement |
| Real local `/v1/decide`, CDA | Native route/kernel and actual verified selected-action binding |
| Native ExecutionIntent schema and promotion packet | Same candidate/action/decision lineage verified |
| Independent enterprise IAM issuer, real human approval | **NOT PROVEN** |
| Native v2 one-use execution authorization and Bind | **NOT ISSUED/NOT EXERCISED** |
| Direct-bypass denial in IAM/credential/network boundary | **NOT TESTED** |
| Production effect and reconciliation | **0, NOT TESTED** |
| Live-model independent candidate choice | **NOT TESTED** |
| AgentDojo Final128 scoring | **NOT RE-RUN** |

The fixture is author-controlled; its published verifier/root share administrative control with the benchmark repository. Neither Ed25519 signature verification nor the native schema's `promotable` flag is an enterprise-issued execution permit. The boolean `required_human_approval=true` means **approval is required but never granted here**. CI green is not proof of deployment-grade authority.

Historical V13 A utility 93/128, B utility 64/128, B injection success 0/128 unchanged.

## Merge gate

Keep **Draft** until dedicated #343 source-pinned CI + all shared PR checks SUCCESS, JUnit/artifact/report/hash inspected; insist on recorded negative proof, zero unapproved external effects, no issuer signing private key at runtime and no false claim of production approval. Next independent work: customer/third-party managed issuer and trust anchor, lifecycle/revocation and human approval receipts, then Native v2 Authorization → single-use Bind → bypass-denial → actual effect/reconciliation.
