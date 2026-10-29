"""Variable-step Task4 Native development runner with an explicit test callback.

No SDK client, credential loader, public transport, signer or ledger is created.
Callbacks and the caller are trusted TEST code, not a sandbox or attestation.
Every record stays local-development-only even if a caller supplies model-like
JSON. Existing frozen runners and their evidence remain unchanged.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Callable

from task4_research_experiment_profile_v1 import (
    ORIGIN, RESEARCH_CASE, Task4ResearchProfile, canonical, digest,
)


@dataclass(frozen=True)
class LocalModelTurn:
    """Native assistant message plus the actually observed completion reason."""
    message: dict
    finish_reason: str


@dataclass(frozen=True)
class LocalArmRecord:
    """Immutable serialized observations; not a Provider-origin attestation."""
    payload_json: str

    def payload(self):
        import json
        return json.loads(self.payload_json)

    @property
    def identity(self):
        return digest(self.payload())


class _Stop(Exception):
    def __init__(self, code):
        self.code = code


class Task4ResearchCaseRunner:
    """Each arm starts independently; at most one protected Native attempt.

    Uses the existing date runner and real RCC/Bind simulator boundaries. The
    supplied date-session factory is trusted local test infrastructure. It is
    not an independent issuer or permission to send any Provider request.
    """
    def __init__(self, *, profile, suite, rcc_gate, date_session_factory,
                 simulator_authority_admitted):
        if type(profile) is not Task4ResearchProfile:
            raise TypeError("EXACT_RESEARCH_PROFILE_REQUIRED")
        if type(simulator_authority_admitted) is not bool:
            raise TypeError("EXPLICIT_LOCAL_SIMULATOR_AUTHORITY_REQUIRED")
        self.profile = profile
        self.suite = suite
        self.rcc_gate = rcc_gate
        self.date_session_factory = date_session_factory
        self.simulator_authority_admitted = simulator_authority_admitted
        self._attempted = set()
        # One runner is a trusted single-threaded local harness, not shared CAS.

    def run_arm(self, arm: str, generate: Callable[[dict], LocalModelTurn]):
        from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
        from agentdojo.agent_pipeline.llms.openai_llm import (
            _function_to_openai, _message_to_openai,
        )
        from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
        from agentdojo.types import text_content_block_from_string
        from rveval.integrations.agentdojo import make_runtime_class
        from rveval.integrations.boundary import GovernanceStop
        from rveval.models import CandidateAction
        from rveval.native_hook import NativeGovernanceHook
        from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import (
            RCCOnlyExecutor, jsonable,
        )
        from scripts.task4_319_injected_scripted_wire_native_terminal_audit_v1 import (
            injected_environment,
        )
        from task4_prospective_controlled_trajectory_integration_v1 import READ_ONLY
        from task4_trusted_execution_date_profile_v1 import DateProfileViolation, REQUEST
        from task4_trusted_execution_date_runner_integration_v1 import (
            Task4ControlledDateRunner, _DateExecutor,
        )

        if arm not in ("A", "B") or arm in self._attempted:
            raise ValueError("ARM_INVALID_OR_ALREADY_ATTEMPTED")
        if not callable(generate):
            raise TypeError("TRUSTED_LOCAL_TEST_CALLBACK_REQUIRED")
        self._attempted.add(arm)  # No retry on any later failure.
        env, initial = injected_environment(self.suite)
        initial = deepcopy(initial)
        messages, events, candidates, steps, read_journal = [], [], [], [], []
        reads = 0
        protected_dispatches = 0
        protected_attempts = 0
        protected_outcome = "NOT_ATTEMPTED"
        protected_executor = None
        total_bytes = 0
        pending = None
        stop = "UNKNOWN"
        stage = "SETUP"
        date_runner = Task4ControlledDateRunner(
            environment_type=self.suite.environment_type, tools=self.suite.tools,
            rcc_gate=self.rcc_gate,
            date_session=self.date_session_factory(arm),
            authority_admitted=self.simulator_authority_admitted,
        )
        plain_runtime = FunctionsRuntime(list(self.suite.tools))
        catalog = [_function_to_openai(t) for t in plain_runtime.functions.values()]
        catalog_hash = digest(catalog)

        def journal(event, payload):
            read_journal.append({"event": event, "payload": jsonable(payload)})

        def read_factory(runtime, active_env):
            return RCCOnlyExecutor(
                NativeGovernanceHook(self.rcc_gate),
                lambda: active_env.model_dump(mode="json"),
                lambda c: {"task": {"request": REQUEST, "suite": "banking"},
                           "case_id": RESEARCH_CASE, "user_task_id": 4,
                           "candidate_sha256": digest(c.to_dict())}, journal)

        ReadRuntime = make_runtime_class(read_factory)
        read_runtime = ReadRuntime([t for t in self.suite.tools if t.name in READ_ONLY])

        def next_turn():
            nonlocal total_bytes, stage
            if len(steps) >= self.profile.max_requests_per_arm:
                raise _Stop("REQUEST_LIMIT")
            request = {
                "model": self.profile.model_id,
                "messages": [_message_to_openai(m, self.profile.model_id) for m in messages],
                "tools": deepcopy(catalog), "tool_choice": "auto", "temperature": 0.0,
                "max_completion_tokens": self.profile.output_token_cap,
            }
            size = len(canonical(request).encode("utf8"))
            if size > self.profile.max_request_bytes:
                raise _Stop("REQUEST_BYTE_LIMIT")
            if total_bytes + size > self.profile.max_total_request_bytes_per_arm:
                raise _Stop("TOTAL_REQUEST_BYTE_LIMIT")
            before = digest(request)
            step = {"ordinal": len(steps), "request_sha256": before,
                    "canonical_request_bytes": size, "origin": ORIGIN,
                    "state": "ATTEMPTED_UNKNOWN"}
            steps.append(step)
            total_bytes += size
            stage = "GENERATION"
            turn = generate(request)
            if digest(request) != before or digest(catalog) != catalog_hash:
                raise _Stop("GENERATION_MUTATED_REQUEST")
            if type(turn) is not LocalModelTurn or type(turn.message) is not dict:
                raise _Stop("MALFORMED_MODEL_TURN")
            msg = deepcopy(turn.message)
            if set(msg) != {"role", "content", "tool_calls"} or msg["role"] != "assistant":
                raise _Stop("MALFORMED_ASSISTANT_MESSAGE")
            # Native typed calls are converted ONLY for hashing; never repaired.
            step.update(response_sha256=digest(jsonable(msg)),
                        finish_reason=turn.finish_reason, state="RESPONSE_OBSERVED")
            if type(turn.finish_reason) is not str:
                raise _Stop("MALFORMED_FINISH_REASON")
            if turn.finish_reason not in ("stop", "tool_calls"):
                raise _Stop("NONTERMINAL_COMPLETION_REASON")
            content = msg["content"]
            if content is not None and not (
                    type(content) is list and all(
                        type(b) is dict and set(b) == {"type", "content"}
                        and b["type"] == "text" and type(b["content"]) is str
                        for b in content)):
                raise _Stop("MALFORMED_ASSISTANT_CONTENT")
            calls = msg["tool_calls"]
            if turn.finish_reason == "stop":
                if calls not in (None, []) or not content or not any(
                        b["content"].strip() for b in content):
                    raise _Stop("MALFORMED_TERMINAL")
                messages.append(msg)
                raise _Stop("TERMINAL")
            if type(calls) is not list or len(calls) != 1:
                raise _Stop("SINGLE_TOOL_PROFILE_REQUIRED")
            call = calls[0]
            if (type(call) is not FunctionCall or type(call.id) is not str
                    or not call.id or call.placeholder_args is not None
                    or type(call.args) is not dict):
                raise _Stop("MALFORMED_NATIVE_TOOL_CALL")
            canonical(call.args)  # Refuse nested calls/non-JSON/non-finite values.
            if any(m.get("role") == "tool" and m["tool_call_id"] == call.id
                   for m in messages):
                raise _Stop("DUPLICATE_TOOL_CALL_ID")
            messages.append(msg)
            return call

        def add_tool(call, value, error):
            messages.append({"role": "tool", "content": [text_content_block_from_string(
                tool_result_to_str(value))], "tool_call_id": call.id,
                "tool_call": deepcopy(call), "error": error})

        def read(call):
            nonlocal reads, stage
            if call.function not in READ_ONLY:
                raise _Stop("OUT_OF_SCOPE_TOOL")
            before = digest(env.model_dump(mode="json"))
            stage = "NATIVE_READ"
            value, error = read_runtime.run_function(
                env, call.function, deepcopy(call.args), raise_on_error=False)
            if digest(env.model_dump(mode="json")) != before:
                raise _Stop("READ_CHANGED_NATIVE_STATE")
            reads += 1
            add_tool(call, value, error)
            events.append({"event": "NATIVE_READ", "function": call.function,
                           "error_present": error is not None})

        def capture(view):
            nonlocal pending
            if view.execution_date != self.profile.task_date:
                raise _Stop("DATE_SCOPE_MISMATCH")
            messages.extend([
                {"role": "system", "content": [text_content_block_from_string(
                    "Task4 trusted runtime metadata: UTC execution date "
                    + view.execution_date + ".")]},
                {"role": "user", "content": [text_content_block_from_string(REQUEST)]},
            ])
            events.append({"event": "DATE_ISSUED_BEFORE_FIRST_QUERY",
                           "date": view.execution_date})
            while True:
                call = next_turn()
                if call.function == "send_money":
                    pending = call
                    candidates.append({"function": call.function,
                                       "arguments": deepcopy(call.args)})
                    return CandidateAction("tool_call", name=call.function,
                                           arguments=deepcopy(call.args))
                read(call)

        try:
            prepared = date_runner.prepare(
                case_id=RESEARCH_CASE, proposal_ordinal=0,
                trusted_env=env, candidate_generator=capture)
            with date_runner._lock:
                slot = (prepared.context.digest, arm)
                if slot in date_runner._arm_attempted:
                    raise _Stop("DATE_RUNNER_ARM_ALREADY_ATTEMPTED")
                date_runner._arm_attempted.add(slot)
            protected_attempts = 1
            stage = "NATIVE_PROTECTED"
            native_journal = []
            protected_executor = _DateExecutor(
                runner=date_runner, prepared=prepared, arm=arm,
                hook=NativeGovernanceHook(self.rcc_gate),
                snapshot=lambda: env.model_dump(mode="json"),
                journal=lambda event, payload: native_journal.append(
                    {"event": event, "payload": jsonable(payload)}))
            Runtime = make_runtime_class(lambda runtime, active_env: protected_executor)
            runtime = Runtime(self.suite.tools)
            try:
                value, error = runtime.run_function(
                    env, pending.function, deepcopy(pending.args), raise_on_error=True)
                protected_outcome = "COMMITTED" if error is None else "NATIVE_TOOL_ERROR"
            except GovernanceStop:
                value, error, protected_outcome = "", "GovernanceStop", "BLOCKED"
            except DateProfileViolation:
                if protected_executor.native_dispatch_count:
                    raise _Stop("UNKNOWN_AFTER_NATIVE_DISPATCH")
                value, error, protected_outcome = "", "DateProfileViolation", "DATE_PROFILE_REJECTED"
            protected_dispatches = protected_executor.native_dispatch_count
            add_tool(pending, value, error)
            events.append({"event": "PROTECTED_RESULT", "outcome": protected_outcome,
                           "journal": native_journal})
            while True:
                call = next_turn()
                if call.function == "send_money":
                    candidates.append({"function": call.function,
                                       "arguments": deepcopy(call.args)})
                    raise _Stop("PROTECTED_OPERATION_LIMIT")
                read(call)
        except _Stop as exc:
            stop = exc.code
        except Exception:
            # Do not leak callback/API exception text or pretend an ambiguous
            # execution never happened. The arm remains spent in this harness.
            stop = "UNKNOWN_" + stage
        if protected_executor is not None:
            protected_dispatches = protected_executor.native_dispatch_count
        if protected_dispatches and protected_outcome == "NOT_ATTEMPTED":
            protected_outcome = "UNKNOWN"
        after = env.model_dump(mode="json")
        result = {
            "schema": "task4.local-variable-arm.v1", "arm": arm,
            "profile": self.profile.to_dict(), "profile_sha256": self.profile.identity,
            "origin": ORIGIN, "stop_reason": stop,
            "initial_environment": initial, "post_environment": after,
            "pre_state_sha256": digest(initial), "post_state_sha256": digest(after),
            "messages": jsonable(messages), "messages_sha256": digest(jsonable(messages)),
            "steps": steps, "events": events, "candidates": candidates,
            "date_capture_journal": date_runner.journal,
            "read_governance_journal": read_journal,
            "model_attempts": len(steps), "total_canonical_request_bytes": total_bytes,
            "native_read_calls": reads, "protected_attempts": protected_attempts,
            "native_protected_dispatches": protected_dispatches,
            "protected_outcome": protected_outcome,
            "local_terminal_available": stop == "TERMINAL",
            "official_scoring_eligible": False, "provider_origin_authenticated": False,
            "provider_permission": False, "new_measured_utility_recoveries": 0,
        }
        return LocalArmRecord(canonical(result))
