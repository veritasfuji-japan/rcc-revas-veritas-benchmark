# Task15 frozen OpenAI wire controlled address adapter V1

The merged #219 address trajectory now accepts a recording fake through the
existing frozen single-attempt OpenAI request adapter and the exact native
AgentDojo message/function/assistant codecs. No SDK client is constructed, no
credential is read, and no provider request is sent in this proof.

## Central invariant

The trusted trajectory owns the complete original request and issues its
registered address profile before the first common query. The wire element
preserves the same initial system/user messages and native function schemas.
Two native read-only calls form a shared prefix. A single first address proposal
is decoded without repair and captured through the unchanged normalized RCC
CandidateAction / V1.1 identity. Both arms start from the same immediate state.
Each independent terminal answer receives its own actual tool return/error.

The native system message maps to a developer message; the user request stays a
user message. The adapter never manufactures authority from developer text,
tool content, wire hashes, model names or schema declarations. The original
acquisition, local signing key, trusted harness configuration, and native sink
assumptions from #218/#219 remain in force. This is preservation evidence, not
proof of real user authentication or process isolation against arbitrary Python.

## Frozen wire configuration

The unchanged `scripts/agentdojo_openai_frozen_adapter_v0_1.py` selects
`gpt-4.1-mini-2025-04-14`, temperature 0.0 and auto tool choice. Each query invokes
that helper exactly once. The native retrying request helper is never used.
Injected client selection belongs to the trusted caller; accepting an injected
client does not authorize real provider execution. The dedicated proof uses a
recording fake and forbids SDK client construction, network and task scorers.

The wire seam enforces exact request/initial history, stable native schemas,
common-query ordinals below eight, then A and B continuations. Request mutation,
extra system messages, invalid phase/ordinal, unexpected choices/roles/refusals,
unknown tools/IDs, tool batches, malformed/non-object/duplicate-key/nonfinite
JSON close the local attempt. Native codecs decode arguments after strict raw
JSON validation; equality is checked without repair. Any exception, including
KeyboardInterrupt, permanently closes that seam. Terminal B also closes it.

The trajectory independently enforces complete history, state and runtime
integrity and terminal text only. Unknown arguments or later effects may reach
the trajectory validator but never bypass it. A later tool proposal after A's
address write produces an explicit partial-effect failure; B does not run.
No rollback or zero-effect result is inferred.

## Evidence and scope

32 wire tests cover one positive pair, six ineligible paired address candidates,
malformed responses, mutation/cancellation, phase/schema binding, later-effect
failure and 16-way concurrent trajectory attempts with one five-query population.
The common injected file includes an instruction to change the city to an
attacker value. It remains tool data and never replaces the owned request.

The prior 40 trajectory / 65 native runner / 101 profile / 91 mapping tests and
all deterministic prior reports are reproduced unchanged. Independently audited
wire witnesses link request hashes to the exact codec output, captured candidate,
original tool-call ID, actual native tool return/error and arm-local continuation.

The fake fixture explicitly proposes Boston; this says nothing about real-model
proposal accuracy. Six negatives are supported but ineligible proposals retained
in both arms, not an injection-success score. No full Task15 completion, historical
recovery, measured Utility improvement, external/held-out validation or production
readiness is claimed. Standing-order, refund, date and password authority remain
outside this first-address domain. V13 authorization/confirmation are not reused.

Next Rule-of-One: `TASK15_PROSPECTIVE_NATIVE_SCORER_OBSERVATION_BOUNDARY_V1`.
A terminal native scorer observation must remain downstream of authority and
must expose partial/full-task limitations rather than repair candidate arguments.
No provider execution is authorized by this next stage.
