# Task15 standing-order request profile issuance V1

This is local prospective evidence issuance and immutable candidate capture for
the frozen rent design. It grants no payment mandate, native dispatch permission,
runtime admission, refund/date/password authority, or complete Task15 action.
The existing runner, Bind rules and original-request validator stay unchanged.

## Central invariant

The trusted harness derives and registers one context from its independently
owned complete original request and full current native prestate before invoking
its generator adapter. It fixes the #222 design projection, recipient/amount,
unique owned rent ID, preserved fields, native definition, case and ordinal.
The context has a local HMAC and session/registry binding. The generator receives
no signing key, context or session. It supplies one complete already-normalized
five-field RCC candidate, which must satisfy the unchanged strict rent design.
Capture hashes the full candidate and the V1.1 same-candidate/prestate identity.

Ordinal one is the fixed first-standing-order slot in this bounded proof. This
does not prove an earlier address action occurred, nor provide a full ordered
multi-goal trajectory. Future native runner/trajectory integration must bind the
actual prior history, current prestate, normalization and generation ordering.

The trusted adapter and owned orchestration establish the program order tested
here. Manual issue/capture methods are harness primitives, not an authentication
oracle for previously generated proposals. Retrospective use is outside this
contract. No historical profile is issued or candidate recovered by this proof.

## Local failure and concurrency ownership

One context can be issued per case/ordinal in a session. After authentication, the
first capture attempt closes that slot before checking scope/state or candidate.
A malformed authenticated proposal cannot be repaired and recaptured. A failed
authentication cannot consume the genuine registered slot. Generation exceptions
and BaseException cancellation also close the slot and remove any captured
binding; the orchestrator does not retry or restore mutated caller state.

An RLock protects local issuance/capture registries. Thirty-two parallel issuance,
capture and owned-generation attempts each have one winner; generation has one
callback invocation. Both arms can verify the same immutable registered binding
without consuming or receiving execution permission. Context/binding/candidate,
request, full prestate, definition and source/session substitutions are refused.

These are process-local evidence slots. They are not durable authorization
consumption, revocation, trusted clocks/expiry or per-arm execution ownership.
All of those require separate native sink/runner proofs.

## Definition and authenticity boundary

Native tool/parser source blobs, the #222 design blob, V1.1 pairing identity,
original-request lineage, Pydantic/docstring-parser versions and actual native
schema digest are fixed. The proof loads the pinned native schema and confirms
the positive candidate already contains all six normalized arguments. This
module never repairs or normalizes candidates. Future integration must reject
unknown raw arguments before Pydantic normalization can discard them.

HMAC authenticates local issuance under a harness-owned key only. It does not
authenticate a real user, external ledger, beneficiary, bank ownership or rent
classification. Those remain assumptions from the design; mandate_authenticated
stays false. The key/registry/adapter must stay outside agent-accessible inputs.

## Evidence and limits

101 dedicated tests cover prospective ordering, exact native schema and A/B
candidate/prestate identity, optional-field preservation, bad candidates and
shapes, scope/context/binding substitution, authenticated drift, invalid owned
inputs, generator failures/cancellation/mutation, concurrent ownership, valid
MACs lacking registration, cross-session replay and immutable evidence objects.
New tests forbid native dispatch, Bind adjudication, provider construction and
calls, network/database access, scorer/ground-truth and external evidence writes.

The #222 proof and all earlier frozen reports are reproduced. Its two detached
native semantic probes and earlier scorer diagnostics remain evidence for their
own stages, never authority inputs to this profile.

The dedicated audit independently rederives the design and fixed definition,
checks the full RCC candidate/control hashes and recorded context/binding linkage,
and reproduces issuance/capture with a fresh private key/registry. It does not
cryptographically validate an exported original HMAC without its private key or
claim byte equality of fresh signatures/session IDs. Stable reports are compared.

Execution_permission, native_dispatch_authorized, runtime_admission_activated,
full_action_admissible and mandate_authenticated remain false. New-stage native
dispatch/provider/database use, candidate repair, scorer/gold-derived authority,
V13 reuse, historical recovery and safe-to-relax-existing-runner remain zero.
No utility recovery, injection remeasurement, full Final128/Task15 integration,
external/held-out validation or production readiness is established.

Next Rule-of-One: TASK15_STANDING_ORDER_PROFILE_CONTROLLED_RUNNER_V1.
Only that later proof may integrate the locally verified profile with unchanged
RCC/Bind Authority/Constraint/Risk checks and the final native execution sink.
