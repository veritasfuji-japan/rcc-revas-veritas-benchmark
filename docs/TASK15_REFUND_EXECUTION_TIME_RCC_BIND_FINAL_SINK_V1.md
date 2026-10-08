# Task15 refund execution-time RCC / Bind / final-sink boundary V1

This provider-free development proof composes #234's separate controlled Ed25519
mandate and #235's owned shared in-memory receipt store with #232's actual native
RCC/Bind runner. The legacy runner and original-request validator are unchanged.

The harness issues the signed mandate before the sole candidate callback, performs
the actual native Pydantic normalization, captures that exact RCC CandidateAction
in both registries and reserves the stable namespace/account/typed receipt key.
RCC-only A and VERITAS B use the same normalized candidate and immediate pre-state.
At every inherited B binding check, including the independent guarded final apply,
the runner reviews the current registered signature/capture/scope/clock/revocation,
the original owned root/store identities and the exact unconsumed reservation.

The signed mandate and reservation are not composed native execution permission.
The original `supported_profile=False`, `date_authority_present=False`, and the
old runner's `separate_refund_execution_authority_present=False` remain intact.
The eligible B reaches actual Bind and is BLOCKED. A is an isolated native replay
baseline: its simulated transaction append is outside the B payment store and is
not a real payment or permission proof. Native-valid field mismatches remain in
the common pair; they are never repaired to satisfy policy or a utility scorer.

All terminal B attempts close an owned RESERVED slot before consumption, including
RCC refusal, Bind refusal, exceptions and cancellation. Duplicate or concurrent
losing arm calls cannot close the winner's slot. If a negative fault probe has
already consumed the slot, cleanup records UNKNOWN and never NO_EFFECT or retry.
Final-sink fault probes force only the upstream adapter constraint return to true
so actual Bind reaches guarded apply; the independent final checks still reject.
These probes do not establish a positive permit, consumption-to-dispatch path,
effect reconciliation or activated admission.

The audit reruns the immutable prior proof chain, verifies original signatures
relative to their exported controlled root pins, creates fresh owned roots/stores
and recomputes 9 actual paired native RCC/Bind replays and 12 final-apply refusal
probes. Registration/authenticity is established locally under harness ownership;
exported evidence does not independently authenticate the original registry.

The trust boundary remains a trusted Python harness, its configured root/store
objects, principal/account assertions, acquired complete ledger and owned UTC
clock. Arbitrary replacement of private implementation or trusted bootstrap is
outside the model-input threat boundary. No durable/global uniqueness or restart
persistence, external principal/ledger/clock authenticity, provider ordering,
historical candidate recovery, new utility/injection measurement, whole Task15
execution, Final128 admission, held-out/external validation or production claim
is made. V13 and its authorization/confirmation remain closed and unused.

Next Rule-of-One: `TASK15_REFUND_COMPOSED_AUTHORITY_ADMISSION_POLICY_V1`.
It must explicitly specify a separately reviewed admission policy for this new
controlled profile and the consume-before-dispatch/effect boundary before any
positive B activation. It must not silently set frozen legacy predicates true.
