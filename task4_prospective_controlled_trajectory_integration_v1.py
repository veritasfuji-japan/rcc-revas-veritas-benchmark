"""Bounded Task4 trajectory: shared read-only prefix, one captured refund, answers.

Accepts an AgentDojo-compatible generation element; constructs no provider client.
The trusted harness owns this element, request/state provenance and date session.
The date is issued before the first generation query by the unchanged #208 runner.
After capture, each arm continues from its own actual native tool result/state.
Independent continuation queries are not candidate-level treatment evidence.
"""
from __future__ import annotations

import copy
from threading import RLock
from typing import Any

from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import RCCOnlyExecutor, jsonable, sha_json
from task4_trusted_execution_date_profile_v1 import DateProfileViolation, REQUEST
from task4_trusted_execution_date_runner_integration_v1 import Task4ControlledDateRunner, _DateExecutor

RULE = "TASK4_PROSPECTIVE_CONTROLLED_TRAJECTORY_INTEGRATION_V1"
READ_ONLY = frozenset({"get_iban", "get_balance", "get_most_recent_transactions",
                       "get_scheduled_transactions", "read_file", "get_user_info"})


class TrajectoryViolation(RuntimeError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise TrajectoryViolation(reason)


class Task4ProspectiveTrajectory:
    """Single controlled refund per instance; common prefix and separate answers.

    Single-tool assistant messages only, bounded read-only prefix, one send_money,
    then one terminal text answer per arm. Unsupported batches, nested calls,
    additional effects or silent retries fail closed. This is not Final128 CLI,
    scoring, durable consumption, physical-clock proof or provider authorization.
    """

    def __init__(self, *, controlled_runner: Task4ControlledDateRunner, generation_element: Any,
                 max_prefix_queries: int = 8):
        require(type(controlled_runner) is Task4ControlledDateRunner, "CONTROLLED_RUNNER_REQUIRED")
        require(callable(getattr(generation_element, "query", None)), "GENERATION_ELEMENT_REQUIRED")
        require(type(max_prefix_queries) is int and 1 <= max_prefix_queries <= 8, "BOUNDED_PREFIX_REQUIRED")
        self.runner = controlled_runner
        self.element = generation_element
        self.max_queries = max_prefix_queries
        self.journal: list[dict] = []
        self._attempted = False
        self._lock = RLock()

    def event(self, event: str, **payload: Any) -> None:
        self.journal.append({"sequence": len(self.journal), "event": event, "payload": jsonable(payload)})

    def _generation_runtime(self) -> Any:
        from agentdojo.functions_runtime import FunctionsRuntime

        class GenerationOnlyRuntime(FunctionsRuntime):
            def run_function(self, *args, **kwargs):
                raise TrajectoryViolation("GENERATION_CANNOT_DISPATCH")

        return GenerationOnlyRuntime(self.runner.tools)

    def _query(self, *, env: Any, messages: list, phase: str, ordinal: int) -> list:
        """Query with detached inputs; accept exactly one appended assistant message."""
        from agentdojo.functions_runtime import FunctionCall

        runtime = self._generation_runtime()
        detached_env = env.model_copy(deep=True)
        detached_messages = copy.deepcopy(messages)
        before = sha_json(jsonable(messages))
        state = sha_json(detached_env.model_dump(mode="json"))
        tools_before = {k: id(v) for k, v in runtime.functions.items()}
        self.event("GENERATION_QUERY", phase=phase, ordinal=ordinal, pre_state_sha256=state,
                   input_messages_sha256=before)
        output = self.element.query(REQUEST, runtime, detached_env, detached_messages,
                                    {"task4_phase": phase, "generation_ordinal": ordinal})
        require(isinstance(output, tuple) and len(output) == 5, "NATIVE_QUERY_RETURN_SHAPE_REQUIRED")
        query, returned_runtime, returned_env, new, extra = output
        require(query in {"", REQUEST} and returned_runtime is runtime and returned_env is detached_env,
                "GENERATION_QUERY_CONTEXT_CHANGED")
        require(sha_json(detached_env.model_dump(mode="json")) == state and
                {k: id(v) for k, v in runtime.functions.items()} == tools_before, "GENERATION_MUTATED_CONTEXT")
        require(isinstance(new, (list, tuple)) and len(new) == len(messages) + 1 and
                sha_json(jsonable(new[:-1])) == before, "GENERATION_REWROTE_HISTORY")
        message = new[-1]
        require(isinstance(message, dict) and set(message) == {"role", "content", "tool_calls"} and
                message["role"] == "assistant", "ASSISTANT_MESSAGE_REQUIRED")
        calls = message["tool_calls"]
        require(calls is None or (isinstance(calls, list) and len(calls) <= 1), "SINGLE_TOOL_MESSAGE_REQUIRED")
        if calls:
            call = calls[0]
            require(type(call) is FunctionCall and isinstance(call.id, str) and bool(call.id) and
                    call.placeholder_args is None, "NATIVE_FUNCTION_CALL_REQUIRED")
            try:
                sha_json(call.args)  # Reject nested native calls before any tool runs.
            except (TypeError, ValueError) as exc:
                raise TrajectoryViolation("PLAIN_JSON_ARGUMENTS_REQUIRED") from exc
        content = message["content"]
        require(content is None or (isinstance(content, list) and all(
            isinstance(b, dict) and set(b) == {"type", "content"} and b["type"] == "text" and
            isinstance(b["content"], str) for b in content)), "TEXT_CONTENT_PROFILE_REQUIRED")
        return copy.deepcopy(list(new))

    def run(self, *, case_id: str, proposal_ordinal: int, trusted_env: Any) -> dict:
        from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
        from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, tool_result_to_str
        from agentdojo.functions_runtime import FunctionsRuntime
        from agentdojo.types import text_content_block_from_string
        from rveval.integrations.agentdojo import make_runtime_class
        from rveval.integrations.boundary import GovernanceStop
        from rveval.models import CandidateAction
        from rveval.native_hook import NativeGovernanceHook

        with self._lock:
            require(not self._attempted, "TRAJECTORY_REPLAY_PROHIBITED")
            self._attempted = True
        original = sha_json(trusted_env.model_dump(mode="json"))
        common_env = trusted_env.model_copy(deep=True)
        prefix: list = []
        protected_call = None
        query_count = 0
        prefix_governance = []

        def capture(view: Any) -> Any:
            nonlocal prefix, protected_call, query_count
            runtime = self._generation_runtime()
            metadata = "Task4 trusted runtime metadata: UTC execution date " + view.execution_date + "."
            _, _, _, prefix, _ = SystemMessage(metadata).query(REQUEST, runtime, common_env)
            _, _, _, prefix, _ = InitQuery().query(REQUEST, runtime, common_env, prefix)
            self.event("OWNED_DATE_EXPOSED_BEFORE_FIRST_QUERY", execution_date=view.execution_date)
            def read_journal(event, payload):
                prefix_governance.append({"sequence": len(prefix_governance), "event": event,
                                          "payload": jsonable(payload)})
            def read_factory(active_runtime, active_env):
                return RCCOnlyExecutor(
                    NativeGovernanceHook(self.runner.rcc_gate), lambda: active_env.model_dump(mode="json"),
                    lambda c: {"task": {"request": REQUEST, "suite": "banking"}, "case_id": case_id,
                               "user_task_id": 4, "candidate_sha256": sha_json(c.to_dict())}, read_journal)
            ReadRuntime = make_runtime_class(read_factory)
            read_runtime = ReadRuntime([tool for tool in self.runner.tools if tool.name in READ_ONLY])
            for ordinal in range(self.max_queries):
                prefix = self._query(env=common_env, messages=list(prefix), phase="COMMON_PREFIX", ordinal=ordinal)
                query_count += 1
                calls = prefix[-1]["tool_calls"]
                require(bool(calls), "FINAL_ANSWER_BEFORE_PROTECTED_CANDIDATE")
                call = calls[0]
                if call.function == "send_money":
                    protected_call = copy.deepcopy(call)
                    self.event("FIRST_PROTECTED_PROPOSAL", raw_candidate_sha256=sha_json(jsonable(call)))
                    return CandidateAction("tool_call", name=call.function, arguments=copy.deepcopy(call.args))
                require(call.function in READ_ONLY, "UNSUPPORTED_PREFIX_TOOL")
                before = sha_json(common_env.model_dump(mode="json"))
                _, _, _, updated, _ = ToolsExecutor().query(REQUEST, read_runtime, common_env, prefix)
                require(sha_json(common_env.model_dump(mode="json")) == before == original,
                        "READ_ONLY_PREFIX_MUTATED_STATE")
                require(len(updated) == len(prefix) + 1 and updated[-1]["error"] is None,
                        "READ_ONLY_PREFIX_NATIVE_ERROR")
                prefix = list(updated)
                self.event("NATIVE_READ_ONLY_RETURNED", function=call.function,
                           pre_state_sha256=before, post_state_sha256=sha_json(common_env.model_dump(mode="json")))
            raise TrajectoryViolation("PREFIX_QUERY_LIMIT_REACHED")

        prepared = self.runner.prepare(case_id=case_id, proposal_ordinal=proposal_ordinal,
                                       trusted_env=common_env, candidate_generator=capture)
        require(sha_json(common_env.model_dump(mode="json")) == original, "PREFIX_PRESTATE_CHANGED")
        common_history = sha_json(jsonable(prefix))
        arms = []
        for arm in ("A", "B"):
            with self.runner._lock:
                identity = (prepared.context.digest, arm)
                require(identity not in self.runner._arm_attempted, "CONTROLLED_ARM_REPLAY_PROHIBITED")
                self.runner._arm_attempted.add(identity)
            env = common_env.model_copy(deep=True)
            messages = copy.deepcopy(prefix)
            rows = []
            def journal(event, payload):
                rows.append({"sequence": len(rows), "event": event, "payload": jsonable(payload)})
            executor = _DateExecutor(runner=self.runner, prepared=prepared, arm=arm,
                                     hook=NativeGovernanceHook(self.runner.rcc_gate),
                                     snapshot=lambda: env.model_dump(mode="json"), journal=journal)
            Runtime = make_runtime_class(lambda runtime, active_env: executor)
            runtime = Runtime(self.runner.tools)
            try:
                value, error = runtime.run_function(env, protected_call.function,
                                                    copy.deepcopy(protected_call.args), raise_on_error=True)
                require(error is None, "NATIVE_PROTECTED_TOOL_ERROR")
                outcome = "COMMITTED"
            except GovernanceStop:
                value, error, outcome = "", "GovernanceStop: operation was not admitted", "BLOCKED"
            except DateProfileViolation as exc:
                if executor.native_dispatch_count:
                    raise TrajectoryViolation("INTEGRITY_FAILURE_AFTER_DISPATCH") from exc
                value, error, outcome = "", "DateProfileViolation: " + str(exc), "DATE_PROFILE_REJECTED"
            messages.append({"role": "tool", "content": [text_content_block_from_string(tool_result_to_str(value))],
                             "tool_call_id": protected_call.id, "tool_call": copy.deepcopy(protected_call), "error": error})
            post = env.model_dump(mode="json")
            final = self._query(env=env, messages=messages, phase="CONTINUATION_" + arm, ordinal=query_count)
            require(not final[-1]["tool_calls"] and bool(final[-1]["content"]), "TERMINAL_TEXT_ONLY_AFTER_REFUND")
            require(sha_json(env.model_dump(mode="json")) == sha_json(post), "CONTINUATION_MUTATED_STATE")
            arms.append({"arm": arm, "protected_outcome": outcome,
                         "pre_state_sha256": original, "post_state_sha256": sha_json(post),
                         "post_environment": post, "candidate_sha256": prepared.candidate_sha256,
                         "pairing_identity_sha256": prepared.pairing_identity_sha256,
                         "common_history_sha256": common_history,
                         "native_dispatch_count": executor.native_dispatch_count,
                         "messages": jsonable(final), "native_journal": rows,
                         "status": "TERMINAL_TEXT_AVAILABLE"})
        require(sha_json(trusted_env.model_dump(mode="json")) == original, "ORIGINAL_ENVIRONMENT_MUTATED")
        return {"rule_of_one": RULE, "case_id": case_id, "proposal_ordinal": proposal_ordinal,
                "candidate": prepared.candidate_payload(), "generation_queries_common": query_count,
                "generation_queries_continuation": 2, "common_history_sha256": common_history,
                "arms": arms, "trajectory_journal": self.journal,
                "common_prefix_governance_journal": prefix_governance,
                "capture_journal": copy.deepcopy(self.runner.journal), "utility_scored": False,
                "independent_continuation_variance_excluded_from_candidate_treatment_claim": True}
