# Task15 refund controlled composed admission runner V1

This additive provider-free harness activates a separately scoped local native
refund path under #234–#237's explicitly controlled root, request, ledger,
metadata-policy, UTC-clock and shared in-memory-store assumptions. The same full
normalized candidate and immediate native pre-state are captured once and replayed
through actual RCC-only A and actual RCC plus actual Bind B. A qualifying B has
one native append, an actual local `COMMITTED` Bind receipt, and exactly one owned
receipt consumption before any native dispatch. Eight native-valid mismatches
retain their own A transitions and have zero B dispatches or reservations. No
candidate repair or scorer-derived authority is used.

The original-request validator's supported-profile and date-authority results
remain false. Existing runners and policies are unchanged. The new executor uses
#237's separate owned-current-profile requirements; it does not overwrite the old
four predicates. Signature, registered capture, full CandidateAction V1.1 hash,
pairing, exact intent, immediate state, pinned native source/schema/tool identity,
current native conditional policy, authority/risk, root scope, revocation/expiry/
clock rollback and original registered reservation are checked independently at
the final sink. The actual Bind thread owns one opaque dispatch token. Direct,
retained, foreign-thread and repeated callbacks cannot dispatch.

After all live admission checks, #235 atomically consumes the original owned
reservation and rechecks its authority. The executor rechecks exact current
signed authority, native admission primitives, candidate/state and live private
capability again after consumption and immediately before its one native call.
There is no injected provider or model callback in that interval. Native counters
count dispatch attempts, not externally authenticated payments.

Every B exit closes an unconsumed reservation or retains a consumed one as
`UNKNOWN`, including ordinary local commit, cancellation, transport failure before
or after append, and incorrect observed native effect. No boolean native return
or local Bind receipt establishes external EFFECT/NO_EFFECT. Consumed/UNKNOWN
slots never reopen; every arm attempt is terminal. A does not consume the B store.
The owned environment is never mutated; each arm runs on its detached native copy.

The 58 dedicated tests cover one actual positive pair, eight mismatch pairs,
24 final negative probes with upstream constraints forced true, 11 failures
between consumption and native call, three native failures, two 32-attempt
parallel populations, private callback boundaries, forged commit, RCC refusal,
and six cancellation cases. The audit separately reconstructs nine actual pairs,
24 final probes, 11 post-consumption probes, three native failures and both
parallel populations, verifies exported signature/capture/reservation binding,
and independently checks consumption-before-call order. It reruns all 1,458
previous dedicated tests and pins their deterministic report bytes.

This proves a bounded controlled local native refund path. It does not prove the
external principal/complete-ledger/friend-recency/no-ID-recycling assertions,
authenticate the exported original registry independently, establish durable
cross-process duplicate exclusion or restart persistence, reconcile an external
payment, or support a whole Task15 trajectory. There is no provider execution,
database access, new Final128 execution, V13 reuse, measured Utility recovery,
injection-success remeasurement, held-out/external validation or production claim.

Next Rule-of-One: `TASK15_REFUND_NATIVE_SCORER_OBSERVATION_BOUNDARY_V1`.
Native scoring may observe immutable post-execution state only; its results must
never issue authority, change candidates, reopen receipt slots or trigger retries.
