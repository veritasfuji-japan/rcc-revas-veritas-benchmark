# Task15 prospective refund execution authority profile V1

Rule-of-One: a distinct controlled-root mandate must be issued before candidate
generation, authenticate exact request/principal/receipt/metadata scope relative
to the configured root, and close terminally on authenticated capture/review
failure or revocation. A matching signed mandate never becomes a native permit.
The #231 local evidence profile and #233 inert specification remain unchanged.

## Explicit controlled root

Trusted harness code bootstraps a separate Ed25519 issuer and configures the
verifier from its immutable root pin. The issuer internally generates its private
key. Neither a packet's public key nor model-provided `verified`/authority bools
select that root. The verifier checks the domain-separated signature, exact
schema, frozen policy, boundary hash, configured key/root identity and owned
issuance/capture registry. It has no signing method. An exported key permits
signature checking relative to that declared key; it does not independently
authenticate the key's owner or original registry.

| Root assumption | Bounded meaning |
| --- | --- |
| Bootstrap/principal | Harness owns root selection and requester/account/alias mapping |
| Acquisition | Harness acquires the original request and complete current native ledger |
| Receipt facts | Harness asserts target receipt friend/recency/ownership and no ID recycling |
| Metadata policy | Harness reviews UTC day within fixed validity, subject `Refund`, exact native append scope |
| Clock | Injected harness clock is second-precision UTC, monotonic and within the fixed validity window |
| Isolation | Key, registry and scripted generation adapter are outside model control |

These are frozen trust assumptions, not external attestations. The module cannot
establish actual user identity, friend relationship, complete external ledger,
non-recycled bank receipt IDs, authentic wall clock or deployed process isolation.
Calling the root constructor is a trusted-harness operation; arbitrary trusted
Python access is outside the bounded model-input threat domain.

## Distinct mandate and prospective capture

Root bootstrap rederives the unchanged candidate-independent #233 boundary. Its
full original request/native pre-state, ordinal two, native send_money definition,
namespace/account/typed receipt ID/fingerprint/stable correlation key, explicit
refund recipient/amount and fixed policy window are bound before any candidate.
The approved controlled-root policy is separately identified; it does not mutate
the earlier metadata draft into authenticated authority.

The signed profile is registered once in the root before one owned generation
callback. The callback receives no profile, key or verifier. Exactly one full
native-normalized RCC CandidateAction and V1.1 pair identity can be captured.
Recipient, amount, date, subject, content or metadata mismatch is refused without
repair. Success exposes authorized date/subject *under this controlled policy*;
it keeps execution permission, payment reservation/consumption and admission False.
Existing supported_profile=False/date_authority_present=False remain unchanged.

Authenticated capture or review failure closes the profile. Generation exceptions
(including BaseException), scope/clock drift, rollback, expiry and owned revocation
cannot be reset by retrying. Forged/foreign profiles cannot invalidate an owned
profile. Read-only A/B verification may repeat for the same captured candidate;
it neither spends nor supplies an execution capability. Parallel issuance/capture/
generation has one winner in one process/root. Fresh roots can reissue the same
receipt, so this does not establish durable or global duplicate refund exclusion.

## Proof and limits

Dedicated tests guard provider/client/network/database/scorer/gold/native dispatch/
native Bind/trustlog access. The audit checks the actual native schema, original
signature relative to its exported root, fixed full candidate/pair/pre-state and
recorded binding hash, then independently issues and verifies with a fresh owned
root. It reconstructs terminal candidate refusals, time/material drift, revocation,
cross-root refusal and parallel observations. Random keys/signatures are evidence
only; deterministic reports omit random root/profile hashes for exact reproduction.
The prior 1210 dedicated tests/reports are retained and re-audited.

The #233 eight required proof obligations are not relabelled globally PROVEN.
This proves a bounded controlled-root signature/issuance component under explicit
assumptions. No payment store, reservation/consumption, RCC/Bind/final-sink admission,
external effect/reconciliation, composed Task15/Final128, actual provider ordering,
Utility/injection remeasurement, V13 reuse, held-out/external validation or production
claim is made.

## Next Rule-of-One

`TASK15_REFUND_RECEIPT_RESERVATION_CONSUMPTION_V1`: prove owned atomic stable-key
reservation/consumption and terminal UNKNOWN handling separately. Mutable request,
case, candidate and fresh issuer must not reset a consumed receipt. The later
execution-time RCC/Bind/final-sink proof is still required before activation.
