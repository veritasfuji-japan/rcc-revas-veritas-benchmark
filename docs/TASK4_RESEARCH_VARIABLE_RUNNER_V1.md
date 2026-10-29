# Task4 variable-step local research runner

The existing bounded Native fixture requires four scripted model responses,
uses a 2031 clock and expects a final answer immediately after its single
refund proposal. Those constraints do not describe every valid real-model
trajectory. This additive runner removes those conversation assumptions
without changing the old fixtures, authority rules or their evidence pins.

This is **PR-U1: local runner preparation**, not a Provider sender. It creates
no SDK client, loads no Provider credential, opens no public transport and
changes no operational approval. `REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN` remain unchanged.

## Implementation

- `task4_research_experiment_profile_v1.py` freezes an explicit execution label,
  task date, model label, request/output/serialized-byte limits and comparison
  scope. These are local callback limits, not token accounting or billing caps.
- `task4_research_case_runner_v1.py` constructs the pinned attacked Native Task4
  environment separately for each arm. It reuses the existing date issuer,
  RCC read-only executor and `_DateExecutor` for the protected simulator action.
  A retains RCC-only behavior; B retains the existing date/argument/Bind checks.
  Model candidates are never rewritten to satisfy them. Both arms receive the
  same configured date metadata and full eleven-tool catalog; all original
  attacked Native tool output remains visible. The source attack is the pinned
  injection-task fixture, not a newly generated adaptive attack.
- `task4_research_terminal_scoring_v1.py` invokes the real detached Native
  User/Attack scorers on the same arm's complete history and pre/post states.
  There is no scorer feedback into generation, authority or tool execution.

The generation callback accepts a detached SDK-shaped request dictionary and
returns a `LocalModelTurn` containing a Native assistant message plus its
observed finish reason. It receives neither a bank environment nor an executor.
It is trusted local TEST code, not a sandbox: malicious Python in the same
process is outside this proof. Changing its JSON or name does not authenticate
a Provider. There is deliberately no `real_provider=True` switch.

Each arm can terminate before any protected proposal, perform bounded Native
reads, attempt one refund, and perform more allowed reads before answering.
The per-arm cap is an upper bound, not a required number of model responses.
Additional protected proposals and unsupported tools stop without execution.
One tool call per assistant step is the declared profile; batches remain
unsupported and visible as incomplete attempts, not silently repaired.

The supplied local `Task4DateProfileSession` must issue the configured date
before the first callback. A caller-owned trusted factory supplies its clock
and test key; the runner does not generate a new signing system. A missing
independent real issuer is not resolved by this callback. Setup/import errors
before a runnable arm is constructed raise to the caller; later generation or
Native exceptions produce fixed UNKNOWN status without copying error text.

## Outcomes and measurement

| Observation | Local treatment |
| --- | --- |
| Actual nonempty `stop` answer, including an early answer or answer after Bind refusal | Score its actual Native history; incorrect task completion can score false |
| `length`, content filter or unsupported finish reason | Retain observed response hash/reason; no invented terminal or score |
| Request/byte limit reached | Retain the arm and any committed simulator effect; no extra callback |
| Additional protected proposal | Save the proposal, do not dispatch it, keep the incomplete arm |
| Callback/Native exception with uncertain outcome | Record UNKNOWN and observed post-state/dispatch count; never retry the arm |

`LocalArmRecord` freezes serialized observations and returns detached copies.
Hashes check internal identity, not trusted external origin. The local scorer
checks claim flags and state/history/profile hashes before scoring. A trusted
Python caller can construct records; this is not a signed-source admission gate.
Every record and summary permanently declares zero new measured Utility
recoveries and null official Utility. No existing V13 score is changed.

`summarize_local_pair` requires A/B order, the same profile and initial state.
It keeps both attempted arms in the denominator even if only one completes.
Independent generation can yield different candidates; the summary does not
call that a same-candidate causal comparison. A pair with the same new date
condition demonstrates local feasibility only, not the causal effect of adding
date authority or recovery of the old V13 refusals. Ben and the experiment
owner still need to choose the actual treatment/control protocol.

The single-threaded harness remembers attempted arms only in memory. It does
not provide a protected cross-process/run/directory single-use ledger. Existing
Native Custody/ledger/ingress components are reusable boundaries for a later
explicit integration; this increment does not claim that this new runner is
already wired into those separated processes, TLS or their archive receipts.

## Verification

Portable configuration tests run in ordinary CI. Explicit Native tests live in
`validation/task4_research_runner_native_checks.py` so ordinary pytest discovery
does not add optional-dependency skips. The dedicated workflow installs the
existing exact pins and invokes that file explicitly with zero skips required.

Native tests cover one through six response histories, successful refunds,
early incorrect answers, read-after-refund, real date/argument/Bind refusal,
unchanged attacked tool output, full tool catalogs, per-arm/serialized-byte
limits, incomplete responses, request mutation, extra protected proposals,
uncertainty after an actual simulator mutation and paired denominators. A real
OpenAI SDK serializes/parses one completion through an explicitly injected
`httpx.MockTransport`; that is not genuine model inference. Network connections
are forbidden during these tests and Provider/DB credential markers are removed.

Example dedicated command, after installing the frozen dependencies:

```sh
TASK4_RESEARCH_AGENTDOJO_ROOT=_pins/agentdojo \
TASK4_RESEARCH_RCC_ROOT=_pins/rcc \
TASK4_RESEARCH_VERITAS_ROOT=_pins/veritas \
PYTHONPATH=. PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
python -m pytest -q -o addopts= \
  tests/test_task4_research_experiment_profile_v1.py \
  validation/task4_research_runner_native_checks.py
```

## Next bounded integration

Select one concrete research Executor deployment and connect this runner's
variable histories to its actual grant/consume, raw-response archive and tool
observation boundaries. The existing local response-ID requirement
`native-local-<op>` is a fixture convention, not a public Provider request-ID
contract. A research adapter must keep internal operation ID and actual
Provider request ID separate. Real model/deployment/credential/private-recipient,
cost and fresh spend permission remain separate unresolved prerequisites.

No new crash-permutation series is required by this PR. Only changed boundaries
and concrete defects justify additional regression work. Completing this local
runner is not grounds to activate a paid workflow or claim production safety.
