"""Isolated offline A/B first native candidate capture; no governed dispatch.

This replaces no frozen B-sourced paired replay and grants no authority.
One test-injected client per arm receives its own native-format request.
Full three-step A/B independence, canonical enrollment, provider authenticity,
real effects and scoring remain unproven.
"""
from __future__ import annotations

import copy
from threading import RLock

from agentdojo.agent_pipeline.llms.openai_llm import (
    _function_to_openai, _message_to_openai, _openai_to_assistant_message,
)
from agentdojo.functions_runtime import Function
from agentdojo.task_suite.load_suites import get_suite
from scripts.agentdojo_openai_frozen_adapter_v0_1 import (
    MODEL_ID, create_completion_once,
)
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable
from task15_native_model_response_capture_boundary_v1 import (
    SYSTEM_MESSAGE, FUNCTIONS, sha,
)
from task15_frozen_openai_wire_controlled_refund_adapter_v1 import strict_arguments
from rveval.models import CandidateAction

RULE = "TASK15_INDEPENDENT_AB_NATIVE_CANDIDATE_SOURCE_V1"
ARMS = ("A", "B")


class IndependentABSourceViolation(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise IndependentABSourceViolation(reason)


class Task15IndependentABOfflineFirstCandidateV1:
    """Two distinct test-only transports; one first-step proposal per arm.

    The constructor trusts its injected offline clients; no claim is made
    that their model computations or their network origins are independent.
    """

    def __init__(self, *, envelope, case_id, clients,
                 transport_mode="OFFLINE_INJECTED_CLIENT"):
        require(transport_mode == "OFFLINE_INJECTED_CLIENT"
                and type(clients) is dict and list(clients) == list(ARMS)
                and clients["A"] is not clients["B"],
                "TWO_DISTINCT_INJECTED_ARM_CLIENTS_REQUIRED")
        for arm in ARMS:
            client = clients[arm]
            require(callable(getattr(getattr(getattr(
                    client, "chat", None), "completions", None), "create", None)),
                    "EXACT_INJECTED_CHAT_CLIENT_REQUIRED")
        require(type(envelope.instruction) is str
                and bool(envelope.instruction.strip())
                and type(envelope.digest) is str
                and type(case_id) is str
                and case_id == "banking:user_task_15:refund-design-v1",
                "ORIGINAL_NONCANONICAL_LOCAL_SOURCE_REQUIRED")
        self._envelope = envelope
        self._case_id = case_id
        self._clients = clients
        self._lock = RLock()
        self._attempted = False
        self._phase = "READY"
        self._journal = []

    def run(self):
        with self._lock:
            require(not self._attempted and self._phase == "READY",
                    "INDEPENDENT_SOURCE_ONE_ATTEMPT_ONLY")
            self._attempted = True
            self._phase = "RUNNING"
        try:
            suite = get_suite("v1.2.2", "banking")
            selected = [tool for tool in suite.tools if tool.name in FUNCTIONS]
            require(len(selected) == len(FUNCTIONS)
                    and {t.name for t in selected} == set(FUNCTIONS)
                    and all(type(t) is Function for t in selected),
                    "PINNED_NATIVE_TOOL_DEFINITIONS_REQUIRED")
            tools = [_function_to_openai(t) for t in selected]
            tools_sha = sha(tools)
            original = [
                {"role": "system", "content": [
                    {"type": "text", "content": SYSTEM_MESSAGE}]},
                {"role": "user", "content": [
                    {"type": "text", "content": self._envelope.instruction}]},
            ]
            original_sha = sha(jsonable(original))
            baseline = suite.load_and_inject_default_environment({}).model_dump(mode="json")
            baseline_sha = sha(baseline)
            records = {}
            call_ids = set()
            returned_objects = []
            for arm in ARMS:
                messages = [_message_to_openai(x, MODEL_ID)
                            for x in copy.deepcopy(original)]
                exposed = copy.deepcopy(tools)
                request_sha = sha({"messages": messages, "tools": exposed})
                entry = {
                    "arm": arm, "status": "ATTEMPTED", "ordinal": 3,
                    "wire_request_sha256": request_sha,
                    "wire_messages": copy.deepcopy(messages),
                    "wire_tools_sha256": sha(exposed),
                    "baseline_state_sha256": baseline_sha,
                    "original_prefix_sha256": original_sha,
                }
                self._journal.append(entry)
                # No automatic retry; a failure on B leaves A provisional only.
                completion = create_completion_once(
                    client=self._clients[arm], messages=messages, tools=exposed)
                require(not any(completion is prior for prior in returned_objects),
                        "SAME_COMPLETION_OBJECT_REUSED_ACROSS_ARMS")
                returned_objects.append(completion)
                require(self._phase == "RUNNING"
                        and sha({"messages": messages, "tools": exposed}) == request_sha
                        and sha(tools) == tools_sha
                        and sha(jsonable(original)) == original_sha
                        and sha(baseline) == baseline_sha
                        and len(completion.choices) == 1,
                        "ORIGINAL_SOURCE_OR_NATIVE_TRANSPORT_MUTATED")
                raw = completion.choices[0].message
                require(raw.role == "assistant"
                        and not getattr(raw, "refusal", None)
                        and raw.content is None
                        and type(raw.tool_calls) is list
                        and len(raw.tool_calls) == 1,
                        "ONE_NATIVE_PROTECTED_TOOL_PROPOSAL_REQUIRED")
                tool_call = raw.tool_calls[0]
                require(tool_call.type == "function"
                        and tool_call.function.name == FUNCTIONS[0]
                        and type(tool_call.id) is str
                        and 0 < len(tool_call.id) <= 200
                        and tool_call.id.isascii()
                        and tool_call.id.isprintable()
                        and tool_call.id not in call_ids,
                        "NATIVE_FIRST_CALL_ID_MUST_BE_OWNED_AND_UNIQUE")
                call_ids.add(tool_call.id)
                args = strict_arguments(tool_call.function.arguments)
                decoded = _openai_to_assistant_message(raw)
                require(decoded["role"] == "assistant"
                        and len(decoded["tool_calls"]) == 1,
                        "NATIVE_SOURCE_DECODER_REQUIRED")
                call = decoded["tool_calls"][0]
                require(call.function == FUNCTIONS[0]
                        and call.id == tool_call.id
                        and call.placeholder_args is None,
                        "NATIVE_CALL_CODEC_IDENTITY_REQUIRED")
                candidate = CandidateAction(
                    "tool_call", name=call.function,
                    arguments=copy.deepcopy(call.args)).to_dict()
                require(candidate["kind"] == "tool_call"
                        and candidate["name"] == FUNCTIONS[0]
                        and candidate["metadata"] == {}
                        and candidate["content"] is None,
                        "STRICT_UNMODIFIED_FIRST_CANDIDATE_REQUIRED")
                rec = {
                    "arm": arm, "ordinal": 3, "call_id": call.id,
                    "request_sha256": request_sha,
                    "response_sha256": sha(jsonable(decoded)),
                    "candidate_sha256": sha(candidate),
                    "candidate": candidate,
                    "decoded_response": jsonable(decoded),
                    "original_prefix_sha256": original_sha,
                    "baseline_state_sha256": baseline_sha,
                    "provider_authenticated": False,
                }
                entry.update(status="RESPONSE_DECODED",
                             response_sha256=rec["response_sha256"],
                             call_id=call.id,
                             candidate_sha256=rec["candidate_sha256"])
                records[arm] = rec
            require(list(records) == list(ARMS)
                    and len(self._journal) == 2
                    and all(j["status"] == "RESPONSE_DECODED"
                            for j in self._journal)
                    and records["A"]["call_id"] != records["B"]["call_id"],
                    "TWO_DISTINCT_FIRST_CANDIDATE_SOURCES_REQUIRED")
            self._phase = "COMPLETE_OFFLINE_FIRST_PAIR"
            return {
                "rule_of_one": RULE,
                "determination": "TWO_DISTINCT_OFFLINE_NATIVE_FIRST_CANDIDATE_REQUESTS_OBSERVED",
                "source_mode": "OFFLINE_INJECTED_CLIENT",
                "original_local_case_id": self._case_id,
                "original_instruction_sha256": sha(self._envelope.instruction),
                "original_prefix_sha256": original_sha,
                "baseline_state_sha256": baseline_sha,
                "native_model_id": MODEL_ID,
                "native_tools_sha256": tools_sha,
                "arm_sources": copy.deepcopy(records),
                "transport_journal": copy.deepcopy(self._journal),
                "independent_arm_transport_invocations_observed": True,
                "independent_full_three_step_histories_proven": False,
                "canonical_case_enrollment_proven": False,
                "provider_authenticated": False,
                "provider_calls": 0,
                "scorer_calls": 0,
                "new_governed_dispatches": 0,
                "real_external_effects": 0,
                "final128_utility_measured": False,
                "injection_success_measured": False,
            }
        except BaseException:
            self._phase = "TERMINAL_UNKNOWN_OR_FAILED"
            if self._journal and self._journal[-1]["status"] == "ATTEMPTED":
                self._journal[-1]["status"] = "FAILED_OR_CANCELLED"
            raise

    def observation(self):
        with self._lock:
            return {
                "rule_of_one": RULE,
                "phase": self._phase,
                "attempted": self._attempted,
                "transport_journal": copy.deepcopy(self._journal),
                "retry_allowed": False,
                "provider_calls": 0,
                "scorer_calls": 0,
                "new_governed_dispatches": 0,
                "real_external_effects": 0,
            }
