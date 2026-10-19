# Task4 #466 — Real issuer, owned refund scope and clock: evidence gap audit (NO-GO)

**Purpose:** Establish the exact evidence required to move from merged #465's correctly bound *synthetic* signed issuer fixture to a genuine, narrowly scoped, research-only Task4 A/B measurement **without** confusing proof of a signature with proof of the right to perform an action.

**This PR contains NO new execution authority or Provider sender.** This is a read-only, source-pinned gap assessment: every outside fact is `NOT_ATTESTED`, there is no input for promoting a gap to PASS, and all downstream real-Provider paths remain DENY. #321 (Task4) and #427 (Task1) remain OPEN/NO-GO.

## What existing code actually establishes (frozen provenance)

| Source | Established within its scope | Not established |
| --- | --- | --- |
| #455, Native SDK first request | Genuine frozen Native prompt serialized by OpenAI SDK; an unusable real-network transport | Provider completion, trusted real date |
| #458, Unix Broker | Atomic one-use local SQLite receipt, replay refusal after restart on one machine | Cross-runner ledger or live send grant |
| #464, signed envelope | Ed25519 integrity under supplied **ephemeral test key**; bounded fixture date/amount/recipient checks | Independent issuer enrollment, genuine owner approval, wall-clock trust |
| #465, combined bridge | Pinned SDK wire validated against synthetic signed envelope before #458 local consumption, followed by **HARD DENY** | Recipient legitimacy, real refund amount, first-live-request issuance, authentic A/B result |
| `task4_trusted_execution_date_profile_v1.py` | Harness-held HMAC and fixture date profile | Real independently attested clock or issuer |

Source-pinned Git blobs ensure reviewers know what was inspected; they do **not** authenticate external actors, real dates, user decisions, execution or billing.

## Critical discovery: refund instruction is not an amount authorization

The original frozen request identifies a *refund target* and refers to a prior incoming transfer. **It contains no fixed refund amount.** Extracting an account-like string from this request does not prove the account belongs to an authorized recipient. #465's `AMOUNT_SYNTHETIC_ONLY = 100` and date `2031-07-08` are test-only values.

To issue a real authority record, a trusted operator or bank-provided source must identify the **specific eligible incoming transaction(s)**, original payer/beneficiary and destination, allowed refund amount and currency, applicable business policy, and immutable prestate. Those fields must be verified outside the model and attacker-controlled transaction descriptions. In particular, an injected `injection_incoming_transaction` field must never be promoted into refund authority merely because it came through a Native bank tool.

In a **disposable synthetic research bank**, the operator may specify an independently controlled ground-truth approval scenario. The proof must be explicit that it is synthetic research, not actual authorization to move anyone's money. No real bank endpoint, real funds or real beneficiary can be involved.

## Minimal evidence packet for a future bounded *research-only* run (not yet present)

Before considering a live-model request, freeze a **privately stored**, reviewer-inspectable evidence packet that includes:

1. **Provenance & original request:** a single exact case ID; native AgentDojo, RCC and VERITAS commits; original user-request digest; authentic, unmodified initial banking state and attack-slot digest; trusted source identifier independent of model/tool payloads.
2. **Refund scope:** immutable transaction ID(s) and account/recipient linkage; amount in explicit minor units; currency; allowed action type; eligibility check; and an independent authoritative source of these facts. An unspecified amount is a *blocker*, not permission to infer or choose one from lower-trust content.
3. **Research issuer:** documented operator role, identity and key enrollment/custody with exact limited authority; signature over request/case/source/recipient/amount/date/model; explicit binding to A/B and first genuine SDK request; immutable record of revocation and expiry policy. A transient local Ed25519 test key does not qualify automatically.
4. **Actual issuance chronology and time:** trusted UTC time source evidence and an issuance receipt **before the first real model request** (not staged after a mock first request), including a date-freshness check at execution and clock rollback/expiry rejection.
5. **True-model boundary & failure handling:** immutable reviewed Sender source; strictly limited scoped credential; full token/call budget; atomic attempted-consumption receipt before any Provider POST; hard no-retry on UNKNOWN/timeouts; isolation of A and B; original encrypted response bytes with no unverified source promotion.
6. **Fresh owner approval:** exact model snapshot, case, A/B call cap, input/output token budget, cost ceiling/overshoot policy, allowed destination, execution window and source HEAD SHA; a separate deliberate approval AFTER review. Prior permission or a $1 monthly Project limit is not approval.
7. **Native scoring:** two genuinely independent model-chosen action trajectories through Native tools/RCC/VERITAS Bind to terminal responses and detached canonical scorer, with missing/partial session marked **UNSCORED**.

No secrets, bank identifiers, nonpublic user account values, raw prompts or protected financial records should be posted to public issues, public CI logs, artifacts or this document. Share only sanitized digests, metadata and a separately protected evidence custody reference as appropriate.

**Proof of independently operated production control is separate.** Commercial no-bypass claims additionally require independently operated issuer/security principal, atomic cross-Runner non-resettable one-use ledger, independently controlled secrets/egress, external audit custody and real high-privilege effect/reconciliation tests. **These are not blanket GitHub requirements to run an explicitly consented, safely isolated research-only LLM experiment**, but neither may that research run claim the production guarantees.

## Gate ownership, fail-closed tests and next choices

| Gate | Who must supply the evidence | Specific fail-closed condition |
| --- | --- | --- |
| R1 Request and prestate | Native harness operator | Source comes from model, injected tool description, scorer, or unresolved branch |
| R2 Amount/currency | Validated bank/controlled research fixture plus authorized policy | Refund amount absent, inferred from attacker text, mismatched, excess or wrong currency |
| R3 Recipient & transaction | Original task + independently verified beneficiary/transaction lineage | String/account extraction only; contradictory owner, target or transaction |
| R4 Issuer and key | Authorized research issuer/custodian | Only locally generated unregistered test key; signer authority not verified |
| R5 Clock and chronology | Trusted operator-run clock and append-only issuance records | 2031 fixture, unverifiable time, issuance after first model request, expiry/rollback |
| R6 Live sender & wire | Reviewed Sender/isolated executor | Sender source drift; mismatched payload, model, arm, source or original request |
| R7 Consent and spend | Owner and provider-account/operator records | Past consent reused; limits unverified; no current scoped project authorization |
| R8 Native scoring | Frozen native harness & detached scorer | Synthesized tool calls or historical response stitched to a different run |
| P1–P4 Production claim | Separately operated control owners & third-party reviewer | No independent IAM/egress, cross-Runner consume, external evidence or reconciliation |

**Decision for this PR:** FREEZE REQUIREMENTS / NO NEW CAPABILITY / REAL PROVIDER DENY. Do not implement a new fake clock, fake refund approval, “true issuer” boolean, disposable self-proclaimed reviewer or second synthetic scorer merely to mark a gate green. The next work should focus on obtaining genuinely *owned* research authorization inputs, then a frozen Sender design with no live transport until approval.

## CI contract

Four files are added: audit script, unit tests, this review document, and a PR-only `contents:read` workflow. The script source-pins #455/#458/#464/#465 and the date profile; checks code-level limitations and produces a sanitized NO-GO manifest. CI has **no Provider credentials, no paid SDK calls, no GH write scope, no manual dispatch, no real bank effects**. JUnit and sanitized JSON are the only artifacts. Passing this CI does *not* upgrade the audit's truth claims, issue status, a production deployment or owner spending authorization.

### Review gate

- Verify current PR HEAD/source pins, 4-file diff and all mandatory CI checks.
- Check all 8 research gaps and 4 production-only gaps remain `NOT_ATTESTED`.
- Verify no original bank account or raw prompt appears in the output and no “ALLOW” workflow, environment or secret.
- Keep Draft until review; do not auto-merge; leave Issue #321/#427 unchanged.
