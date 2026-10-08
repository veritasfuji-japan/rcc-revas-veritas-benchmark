# Task15 controlled refund composed admission policy V1

The original-request validator cannot derive a required send_money execution date
from the request. Its unsupported-profile and absent-date predicates remain false.
This proof specifies a separate controlled profile: the owned #234 root explicitly
signs the fixed UTC-day/Refund-subject policy and receipt/request assertions before
the one normalized candidate is captured. #235 owns the shared receipt registry;
#236 already proved the actual closed RCC/Bind/final-apply integration.

The new policy qualifies only a current registered controlled signature/capture,
the unchanged original request/refund amount, exact native-normalized recipient,
amount, subject/date, full CandidateAction V1.1 pairing/pre-state and the original
configured verifier/store's exact RESERVED/unconsumed receipt registration. The
entire reservation payload is compared with independently derived key/scope/capture
bindings. The policy preserves the four original legacy values verbatim. It never
changes the original validator or promotes #231 local HMAC evidence to authority.

This is an explicit new controlled-policy interpretation, not a claim that the
original request alone authorized the date/subject. Sender relationship, recency,
principal/account ownership, complete ledger acquisition and clock authenticity
still rely on the stated trusted controlled-root harness assumptions. Signed data
authenticates those assertions relative to a configured root, not their external
truth. Edited/exported packets, scorer/gold, success booleans and alternative policy
inputs cannot establish eligibility. A returned review must be rederived against
the current original objects, authority, clock, candidate/state and reservation.

An ELIGIBLE review is never a native permit. It implements no actual Bind/RCC
adjudication, token, mutation callback, payment consumption, dispatch or effect
reconciliation. Many read-only reviews may qualify; that is not single-use
execution. A review returned before another caller consumes the slot becomes
unusable on recheck. Reads share the original store lock, but no review is a
cross-stage reservation or durable execution capability.

Positive activation requires actual exact RCC review, actual Bind adjudication,
final-sink exact intent/action/state/native-definition/root/clock/revocation review,
atomic once-only consumption in the original shared store after all live admission
checks and before any dispatch, and a one-thread/one-use native capability. After
consumption, failures remain consumed/UNKNOWN; no NO_EFFECT, release, reset or
retry follows from a returned bool or missing effect. Exact native transition
reconciliation must not restore spent authority. The existing #233 lifecycle
specification and #235 UNKNOWN behavior remain unchanged; this policy does not
implement or claim that future consuming sink or reconciliation path.

Sixty provider-free tests cover the qualifying case, 49 independently recomputed
refusals, extra supplied witnesses, fixed specification mutation, 32 read-only
reviews, stale reviews after consumption/UNKNOWN, original verifier configuration,
and substituted all-true legacy results. The audit verifies exported signatures
relative to their root pins and reconstructs qualification/refusals with fresh
owned roots/stores plus an independent native-normalization, receipt-key, policy
requirements and legacy-results oracle. Native calls and actual Bind are forbidden
in the new policy proof; the immutable prior chain supplies the closed native proof.

No positive B runtime admission, utility/injection measurement, historical recovery,
whole Task15 address/rent/refund continuation, Final128 integration, durable/global
exclusion, restart persistence, independently authenticated original registry,
external or held-out validation, or production readiness is claimed. V13 and its
authorization/confirmation remain closed and unused.

Next Rule-of-One: `TASK15_REFUND_CONTROLLED_COMPOSED_ADMISSION_RUNNER_V1`.
Implement the separately scoped consuming final sink under this policy, preserve
legacy refusal entry points, and prove exact dispatch/UNKNOWN behavior before any
full trajectory or provider execution.
