# #341 — RCC Typed Action + Separate Signed Synthetic Mandate → Native CDA and Promotion Packet

## Objective and Rule-of-One

**Rule:** `SOURCE_BOUND_RCC_TYPED_ACTION_AND_SEPARATELY_SIGNED_TEST_MANDATE_TO_NATIVE_CDA_PROMOTION`.

Take an **actual selected candidate** released by the current RCC upstream (36 partner fixtures; 12 released/24 withheld at pinned source), preserve its exact action/target/source provenance and test an isolated **separately signed, predeclared synthetic governance mandate** against VERITAS OS native structured candidate, real `POST /v1/decide`, canonical CDA and verified promotion packet.

Never infer actual authorization from RCC router/adoption/ground truth/evaluation labels. Never use real API credentials, real external effects or bank actions.

## Implementation

1. RCC main pin `353ad9e6a17cda8874a129493fe0f8f4fe4427bc`; VERITAS pin `299a3c4987668091f50ab3e45165bcccd1ae193f`; main parent pin `cecbf484556c364842f0f1a7adc811d1c80a7cce`.
2. Execute published `preflight → register-takeshi → evaluate → verify-artifacts → prepare-veritas` with 36 synthetic governance fixtures, build unchanged RCC handoff and request, reverify original candidate and source hash.
3. Select exactly one released source candidate matching the **predeclared** isolated test mandate. The predeclared action is `saas_permission_change / grant_admin_role`, actor `operator:iam-admin-01`, target `saas-directory/user:contractor-17`, scope `role:admin` with no extra parameters. This contract is **not** generated from or inferred from RCC selected metadata at runtime.
4. **Untrusted baseline:** Construct real native `DecisionCandidate` from exact typed action as an *untrusted proposal*, without authority/approval; run genuine `validate_decision_candidate` and assert hard refusal (`AUTHORITY_UNSPECIFIED`, `HUMAN_APPROVAL_UNCLEAR`).
5. **Synthetic signed test gate:** Generate an ephemeral Ed25519 keypair and detached signature over the predeclared separate test mandate. Check exact issuer-side trust anchor, SHA-256, signature, exact typed actor/target/action/parameters/scope, and negative mutations. **This verifies a local test fixture only**, not production IAM or a third-party authorization provider.
6. Build a native typed `DecisionCandidate`, retaining original RCC object/hash in metadata and proposed action exactly as signed test manifest declares. `required_authority` comes **only** from that test mandate (not from RCC), while `required_human_approval=true` means **required and still ungranted**, not approved.
7. Build a **new derived native request** with a single typed candidate option. Explicitly preserve the original RCC request separately, record both hashes, and do not claim the request itself was byte-for-byte unchanged across this adapter transformation. Controlled local LLM transcript selects this known same option without constructing independent authority.
8. Run the actual VERITAS local `POST /v1/decide`, native kernel, test KMS/WORM, verified native CDA. Require `selected_action_evidence.candidate_hash` to match native `hash_decision_candidate(chosen)` and the exact typed candidate. Run native `try_promote_verified_canonical_decision_candidate_to_execution_intent`, verify CDA/intent decision identity, then build and independently verify native `CanonicalVerifiedDecisionPromotionPacket`. This is a **schema-level/cryptographic-lineage** proof in an isolated synthetic environment, not authorization to execute.
9. Attempt using the untrusted RCC candidate against that valid CDA; require refusal. Record zero v2 authorization issuance, consumption, native Bind, human approval receipts, real API, bank effect and new scoring.

## Evidence interpretation

| Boundary | Meaning |
|---|---|
| Real RCC current-main candidate | Unmodified source identified and hash-verified |
| Separate synthetic test Ed25519 mandate | Signed and matched; not real trusted authority |
| Native typed candidate | Exact proposed action preserved, authority field supplied only by signed test fixture |
| Actual native CDA | Independently verifies selected action binding and signed local policy fixture |
| Exact Native ExecutionIntent / promotion packet | Schema promotion and immutable lineage only; **not** execution grant |
| Human approval | Required, **never granted** |
| Production IAM / credential / network bypass blocked | **NOT TESTED** |
| Live model independent candidate selection | **NOT TESTED** |
| Native v2 Bind, Effect, reconciliation | **NOT TESTED; zero executed** |

## Limitations and next PR

The signed test mandate is generated in-process with a fresh ephemeral private key and a local trusted public key; it is not issued by an independently operated organization. Treat this as **controlled integration capability**, not independent authority validation or a positive production effect demonstration.

If #341 passes, the next independent step requires a trusted **external issuer** of scope/target/human approval artifacts (or a properly isolated customer IAM authority) with a pinned verifier/issuer identity that cannot be changed by the candidate producer. Then separately test v2 one-time authorization issuance, consumption, Bind, bypass-denied controls, effect and reconciliation.

Historic V13 A utility 93/128, B utility 64/128, B injection 0/128 unchanged. No new provider/scorer calls. **CI green ≠ PROVEN for production**.

## Merge gate

Keep Draft until dedicated CI success plus all shared CI. Confirm run/job/artifact SHA, exact candidate hashes, native CDA + promotion packet verified, no source-to-auth fabrication, no external effects. Never describe a green synthetic test as externally issued permission.
