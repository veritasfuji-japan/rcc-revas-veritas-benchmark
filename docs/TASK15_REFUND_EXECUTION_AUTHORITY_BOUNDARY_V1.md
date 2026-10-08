# Task15 refund execution authority boundary V1

Rule-of-One: a candidate-independent refund authority specification and its model
PASS labels must never become execution authority. This additive pure module
freezes exact authority obligations and checks an inert one-use lifecycle model.
It accepts no authenticated witness, signing key, issuer callback, receipt-store
handle, native dispatch capability or scorer. All actual authority/admission,
reservation/consumption and dispatch fields remain False/zero.

## Prospective scope

The boundary derives the unchanged original-request refund, metadata, correlation
and local profile scope before inspecting a candidate. It binds original request,
full native pre-state, ordinal two, exact native definition, namespace/account,
typed receipt ID/fingerprint/stable correlation key, explicit refund amount and
recipient, and draft policy validity/date/subject. Date and subject are proposed
policy values; effective_date/effective_subject remain null. Both fields persist
in native send_money and cannot be treated as inert or supplied from scorer/gold.

| Required proof | Exact boundary |
| --- | --- |
| Request/principal | Original requester, account and native owned alias |
| Receipt identity | Current complete ledger, typed ID, sender relationship/recency, no ID recycling |
| Metadata policy/clock | Reviewed policy, exact date/subject, bounded clock window and rollover |
| Prospective issuance/capture | Separate authority issuer before first candidate, full RCC candidate/pre-state linkage |
| Reservation/consumption | Atomic stable receipt-key reservation and consumption before dispatch |
| Execution-time recheck | RCC, actual Bind and exact final sink; expiry, revocation, material drift, one-use capability |
| Effect/reconciliation | Consumed/unknown attempts stay closed; reconciliation never restores spent permission |
| Task15 continuation | Earlier effects and later actions; one refund does not complete the whole task |

All eight obligations are explicitly UNPROVEN here. Trusted Python acquisition,
local HMAC, declared AVAILABLE slot, matching candidate, model event label,
benchmark authority bool and development utility success cannot satisfy them.
An edited plan claiming PROVEN/authorized/effective values is refused by exact
rederivation. Existing validator and #232 runner remain unchanged. The profile
matching fixture retains supported_profile=False/date_authority_present=False.

## Inert lifecycle model

The checker accepts bounded plain event lists and uses one identical candidate
and pre-state. The declared normal order is:

issue before candidate → capture → authority review → receipt reservation →
Bind review → final recheck → consume → dispatch attempt → effect observation.

Stopping before consumption is a terminal NO_DISPATCH model branch. Reservations
are not released within this model. Failure after consumption, dispatch exception
or return without effect proof ends UNKNOWN. UNKNOWN accepts effect reconciliation
but cannot issue, reserve, consume, retry or dispatch again. An observed effect is
terminal. CONSUMED + NO_DISPATCH reclassification is rejected. This is a declared
specification, not proof of actual NO_EFFECT, an authenticated result or a durable
store. The checker is stateless; repeating it does not consume a real receipt and
cannot prove global duplicate exclusion.

## Validation

63 new tests cover scope/clock drift, candidate mismatch, self-attested plans,
complete/incomplete lifecycle branches, bypass/replay and unknown reset. Thirteen
valid terminal traces keep execution/admission/actual reservation/consumption False
and native dispatches zero. Twelve invalid trace populations are freshly rejected.
416 one-event trace variants are recomputed: 415 reject; one valid insertion merely
moves a pre-reservation stop to a reserved stop, still without authority/dispatch.
Provider/SDK/network/database/scorer/gold/native dispatch/native Bind/external
trustlog access is guarded in the new proof. Native normalization is checked via
the actual pinned schema without running send_money.

The audit reproduces all 1147 prior dedicated tests/evidence and independently
rederives boundary/projection/hash/legacy refusal, eight unrepaired candidates,
thirteen terminal traces, twelve invalid traces and all 416 variants. The reference
lifecycle result is checked against a separate bounded language/order oracle.
This is local specification validation; no external witness is authenticated.
No refund activation, safe relaxation, historical recovery, new model Utility or
Injection measurement, V13 reuse, external/held-out or production claim is made.

## Next Rule-of-One

`TASK15_REFUND_PROSPECTIVE_EXECUTION_AUTHORITY_PROFILE_V1`: design and prove a
separate controlled authority issuer/verifier with exact frozen root assumptions,
clock/policy review, scope and terminal lifecycle. It must not repurpose the local
#231 evidence profile. Reservation/consumption and the final activation boundary
require their own reviewed proofs before #232 or Final128 can allow a refund.
