# Task15 receipt reservation and consumption V1

Rule-of-One: a shared owned store reserves and consumes the stable receipt key
once across configured issuers; consumed/UNKNOWN records never reopen. A local
consumption observation is audit data and never a native execution permit.

The harness configures exact #234 verifier objects before store use. Reserve and
consume recheck signed registered/captured profiles, exact full candidate, original
request/pre-state, metadata window, clock and revocation. The earlier local profiles,
authority specification, validator, runner and Final128 remain unchanged. Root
bootstrap/acquisition/principal/receipt/policy/clock/isolation assumptions still apply.

The key is the unchanged namespace/account/typed receipt ID. Request wording,
case, candidate, root, full pre-state and receipt fingerprint cannot reset it.
Reservation retains an exact registered bearer plus root/profile/candidate/pair/
boundary/fingerprint scope. A forged or foreign bearer cannot close an owned slot.
An authenticated consumption recheck failure closes its reservation before
consumption. All store operations are guarded by one RLock; concurrent reservation
or consumption has one winner. Closing versus consuming has one atomic winner.

| State | Meaning | Allowed subsequent transition |
| --- | --- | --- |
| RESERVED | Owned local reservation exists | Consume once or terminal preconsume close |
| CLOSED_BEFORE_CONSUMPTION | No local consumption occurred | None |
| CONSUMED | Local receipt slot spent before any native dispatch | UNKNOWN only |
| UNKNOWN | Consumption outcome remains uncertain | Hash-only note; state stays UNKNOWN |

There is no release/reset/retry/dispatch/NO_EFFECT API. Notes neither authenticate
effects nor restore authority. Returned observations are detached copies. No
actual dispatch is performed, no outcome authenticity is established, and the
consumed observation cannot bypass the later RCC/Bind/final-sink proof.

The store is in memory. Its guarantee holds across configured issuers sharing
this one instance/process. A fresh store can reserve the same receipt again,
explicitly tested. Restart persistence, multi-process/global uniqueness, storage
rollback resistance and durable recovery remain UNPROVEN. The later runtime must
own and share the chosen store; caller-selected fresh stores cannot be an execution
path. This round makes no deployment or persistent-database guarantee.

71 new tests plus 1296 prior tests cover 28 mutable-scope/issuer duplicate refusals,
nine terminal recheck failures, forged/foreign bearer refusal, revocation/time drift,
three 32-attempt parallel populations, identity separation, unknown notes and state
replay. Provider/client/network/database/scorer/gold/native Bind/dispatch/trustlog
access is guarded. Audit checks the native schema and recorded signature relative
to its exported root, reconstructs reservation/capture scope with fresh owned roots
and store, and independently verifies the consume/UNKNOWN order and refusal cases.
Original live store registration is not independently authenticated by exported
evidence. Random nonces/keys are omitted from deterministic reports.

No safe relaxation, new Utility/injection measurement, V13 reuse, full Task15 or
Final128 admission, external/held-out validation or production claim is made.

Next Rule-of-One: `TASK15_REFUND_EXECUTION_TIME_RCC_BIND_FINAL_SINK_V1`.
Exact execution-time authority and one-use sink enforcement require their own
reviewed proof before refund activation.
