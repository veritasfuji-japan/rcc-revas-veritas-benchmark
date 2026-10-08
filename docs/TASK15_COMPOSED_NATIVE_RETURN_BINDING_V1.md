# TASK15_COMPOSED_NATIVE_RETURN_BINDING_V1

## Status

**Draft / NOT PROVEN until exact-head dedicated audit and Artifact.**

Previous completed proof rounds:
- PR #248: three independently sourced *offline injected* native response proposals, each admitted and dispatched under the original frozen composed runner
- PR #249: versioned exact native return capture for address update; B-side blocked outputs never claim a native return

## Rule-of-One

Every completed locally governed Task15 action must retain the native
`FunctionsRuntime` **in-process result** as a JSON projection, tied
to its exact executed candidate, original state, final state, native dispatch
and original local RCC/Bind journal. An interrupted, unpaired or refused
action cannot be promoted into the **completed** native result history.

Three steps, each in A and B:
1. `update_user_info` — address return-capturing versioned runner
2. `update_scheduled_transaction` — unchanged rent runner
3. `send_money` — unchanged refund runner with consumed/UNKNOWN receipt semantics

## Implementation boundary

`Task15ComposedNativeReturnBindingRunnerV1` is a versioned subclass of the
frozen composed runner. Its `run` method is intentionally copied and
tested for identity to the source except for the exact runtime type-guard:
the address class changes from frozen address V1 to native-return address V2.
All prior candidate issuance, RCC review, Bind admission, exact native sink,
compensation limits and refund receipt closure remain unchanged.

After each successful arm, `_check_result` validates its actual native return,
including address SHA-256 and user-account projection. The `observation()`
sidecar provides `local_native_return_history`, in ordinal order, containing
candidate hashes, A/B pre/post-state hashes and in-process native JSON results.

**This sidecar is NOT a model conversation.** It has no source-authenticated
OpenAI tool-call IDs, no AI-issued tool messages, no terminal model turn, no
real provider calls and no externally authenticated banking effect. It does
not consume the offline #248 captured calls. That connection belongs to the
next separate Rule-of-One:

`TASK15_MODEL_CALL_ID_TO_NATIVE_TOOL_RETURN_HISTORY_V1`.

No live provider call, paid API traffic, Final 128 benchmark scoring,
source authenticity, production certification or Utility recovery is claimed.

## Proof gates

- Exact Git source/blob pins of new V2 source and all original protected runners
- Replay of the existing #249 proof chain unchanged
- One full three-step A/B native execution using trusted local fixtures
- Six executed source-bound return values, zero extra dispatch attempts
- Bounded invalid factory/generation/cancellation refusals
- No retry, model messages or inferred no-effect on partial effects
- Seven dedicated cases, evidence, JSON/lineage report and uploaded artifact

## Merge policy

CI green alone does not imply globally proven external effect assurance.
Merge only once exact-HEAD dedicated workflow and artifact have been reviewed.
