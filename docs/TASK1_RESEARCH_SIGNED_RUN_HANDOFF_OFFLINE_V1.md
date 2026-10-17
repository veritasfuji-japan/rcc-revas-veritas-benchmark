# Task1 research-only signed Run handoff — offline design V1

**NO-EFFECT. SYNTHETIC Ed25519 SIGNATURES ONLY. NOT AN ENROLLED ISSUER, GITHUB IDENTITY, TAG CLAIM, LIVE MODEL AUTHORITY OR SPENDING APPROVAL.**

## Purpose and scope

Merged PRs #434–#437 demonstrate mock encrypted capture before parse, local mock A/B one-shot journaling, in-memory fake Git ref compare-and-create, and synthetic Ruleset/issuer/sender privilege shapes. None proves that a **specific** GitHub Run owns the right to use the same research ref or to initiate model traffic.

This PR tests a mock handoff envelope binding one fixed Task1 experiment, research-only ref, main commit, Run ID, run attempt 1, issuer job ID, sender job ID and SHA256 of each first Native Chat request. The initial A/B request bytes are **identical** (the attacked tool response and VERITAS B-only post-read overlay occur *after* these first calls). The envelope sets maximum first-model POSTs to 2 and no_retry=True, but contains **no executable transport** or actual network enforcement.

The module accepts only caller-supplied **ephemeral in-memory Ed25519 keys** and mock job contexts. It does not load credentials, call GitHub, create or read a real ref, alter a Ruleset, configure an Environment, run a workflow, dispatch paid API requests or persist protected keys.

## Signed envelope contract

| Contract field | Offline check |
| --- | --- |
| Schema/purpose/signer label | Fixed SYNTHETIC_EVIDENCE_ONLY_NO_PROVIDER_AUTHORITY domain |
| Repository/case/model | Exact Task1/Native initial request scope |
| Research ref/target | Fixed refs/tags/final128-task1-research-first-two-once-v1 pointing at the exact signed main SHA; production singleton never accepted |
| Run ID / attempt | Exact intended run and run_attempt=1 |
| Issuer/sender job IDs | Two different mock jobs; handoff bound to expected sender |
| First-packet A/B SHA256 | Exactly A and B, with equal digests |
| Model budget flags | Exactly two intended initial POSTs, no retry; NOT a hard network/billing limit |
| Live authority flags | synthetic_only=True; paid_consent=False, ruleset_enrolled=False, provider_secret_access=False, production_tag_consumed=False |

The recipient verifies an exact mock context, allowed field set, strict scalar types, canonical JSON, Ed25519 signature and a same-process replay ledger. A fully valid match returns SIGNED_OFFLINE_MOCK_MATCH_NO_LIVE_AUTHORITY, with provider_dispatch_authorized=False, claim_origin_authenticated=False and github_identity_authenticated=False.

The signature establishes only integrity under the **supplied test key**. The test key is **not enrolled** under trusted IAM, and the expected context is also user-supplied mock data. A malicious job could sign a new envelope with its own key unless key provenance is independently established. A brand-new in-memory replay ledger can accept the same signed mock envelope again; this is an intentional counterexample to global replay prevention.

## Real issuer-to-sender handoff: outstanding security work

1. **Sender discovery:** an issuer job may not know the sender's job ID before that job is created. A real handshake needs independently verified GitHub job identity, a two-phase enrolment/challenge or another immutable recipient identifier. Do not invent or trust a recipient job ID from an artifact name.
2. **Authenticated source:** use a separately reviewed GitHub API/OIDC verification design binding repository identity, protected workflow ref, run ID/attempt, job identity, event, main commit and intended Environment. Raw GITHUB_RUN_ID, github.* metadata, artifact JSON and self-supplied values are not independent provenance.
3. **Independent signing trust:** pin a real issuer identity or verifier key outside attacker-controlled branches. Note the #437 proposed issuer has **no secrets**: placing a software Ed25519 private key there would change that security design and requires a separate privilege review. A dedicated attestation service or verified GitHub-signed identity could be investigated instead; neither is implemented.
4. **Actual one-shot claim:** the research ref is still absent and not covered by existing production Ruleset #24921425. A real research Ruleset must be independently approved, exact-name protected and inspected with bypass_actors: [] explicitly present; do not interpret a redacted/missing field as empty. The real claim must be demonstrably one-winner and bound to the authenticated run—not merely present at a particular commit. Admin mutation and Ruleset read-to-ref-write TOCTOU remain unresolved.
5. **Global replay and secret release:** a Python set is not durable across independent GitHub runners. Any real send must require separately enforced at-most-once consumption before access to the dedicated Provider secret. Issuer must have no Provider secret; sender no ref-write/admin capabilities; audit IAM and artifact provenance independently. An unknown claim/Provider result must stop with **NO RETRY**.
6. **Evidence, cost and operator consent:** encrypt raw HTTP response before strict parsing; establish key recovery and provenance, independently verify API billing controls, and require fresh explicit human consent tied to the current 40-hex main SHA, model, Task1, run, at most two first POSTs, non-retry and financial risk. A USD 1 operator target is not an enforceable hard cap; previous USD 5 permissions are not reusable.

## Tests

Run locally, without credentials:

    pytest -q tests/test_final128_task1_research_signed_run_handoff_offline_v1.py

Tests generate ephemeral Ed25519 key pairs and block outbound socket connections. They test exact Run/job/main/request binding, malformed envelopes, wrong key, tampering, extra fields, A/B hash drift, rerun rejection, same-process concurrent replay refusal and **acceptance after reset of the local ledger** (demonstrating the missing global guard). No real external evidence is generated. A valid mock signature is **never** an authorization to run a Provider call or a proof of injection resistance, Utility or official 128-case scoring.

## Decision point — stop expanding synthetic-only PRs after this

The next useful evidence requires an actual, separately approved **no-Provider GitHub research Ruleset/ref experiment** or a documented human-risk-accepted pilot that openly abandons claims of strong once-only enforcement. Before either, review the proposed permissions, exact ref, rollback/risk, audit path and administrative attack surface with the owner. Neither approval is implicit from this design PR.

**Issue #427 remains OPEN / PAID NO-GO. No real research or production tags, Rulesets, credentials, paid runs, old #423 workflow dispatch, or Provider calls are authorized by this PR or by its merge.**
