# Task15 Exact Native Address Return Capture V1

## Status

**Implemented / NOT PROVEN** pending exact-head CI, artifact and review.

PR #248 proved three independent *offline injected* model-shaped native
candidate responses feeding frozen RCC/Bind/native sinks. The next missing
component was the **actual return of the native address function**:
the original address replay method retains the runtime result in a
local variable, but returns only the resulting state and dispatch evidence.

The rent and refund runners already return their actual native-result
JSON projections. The address runner does not.

## Rule-of-One

Without editing the frozen address runner or changing any of its existing
source/blob pins, `Task15ControlledAddressReturnCaptureRunnerV1`
extends it, overriding **only** the single-arm replay method.
Its method retains the legacy control flow. The existing address loop
reused the name `value` while verifying post-state and thereby overwrote
the original native return. In this successor **only**, that loop-local
variable is renamed `field_value` to preserve the actual tuple. The
final result also gains three fields:

- `native_return`: `jsonable(value)` from the **same original**
  `runtime.run_function()` call, after the final native sink
- `native_return_canonical_json`: canonical JSON of that runtime value
- `native_return_sha256`: deterministic hash of that runtime value

No second simulation, reconstructed return from post-state, external
transport, callback authorization, modified RCC candidate, change
to original Bind policy, or source mutation is permitted.

Refused/B-blocked operations emit **null return fields**. Even the
baseline Arm A native COMMIT cannot turn into a B-side permission.

A test verifies replay-method source equivalence to the frozen parent
modulo **only** the loop-local rename and those three fields. Tests also
verify A/B exact equality, current state transitions, the Bind COMMIT,
6 ineligible B rejection scenarios and the single-use replay barrier.

## Precisely bounded conclusion

This is an **additive native address replay V2 value-capture**.
The previous composed runner intentionally insists on
`type(runner) is Task15ControlledAddressRunner` and therefore does
**not** yet accept this new class. This PR is **not** a complete
Task15 composed conversation or an upgrade of production dispatch
authority. Integration will be a **separate next Rule-of-One** after
exact-main evidence and independent review.

The retained value is a faithful **canonical JSON projection** of the
Python runtime return, not original network bytes or an independently
authenticated external effect receipt.

## Trust boundaries

Provider calls: 0. External effect authentication: no. Production:
no. Final128 Utility or injection attacks remeasured: no.
No use of V13 authorization, no refund retry, no autonomous compensations.

## Next

`TASK15_COMPOSED_NATIVE_RETURN_V2_BINDING_AND_HISTORY_V1`
can permit exact new address return capture in the bounded composed
runner without weakening existing native RCC/Bind eligibility. It must
validate A/B exact returns across all three steps before building
actual model/tool histories. A future live-provider run requires its
own authorization and spending cap.
