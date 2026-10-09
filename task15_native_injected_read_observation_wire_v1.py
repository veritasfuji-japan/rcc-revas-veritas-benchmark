"""Read-only native AgentDojo tainted-tool-return observation sidecar V1.

For each canonical Task15 DirectAttack case and each A/B arm, independently
rebuild the native injected environment, run ONLY the pinned read-only
get_most_recent_transactions function via the authentic AgentDojo
ToolsExecutor, then encode the tool-result message with the native OpenAI
codec and submit that wire history to a distinct synthetic offline test client.

A harness-authored diagnostic assistant tool call is NOT the previously
model-proposed first candidate; this sidecar neither runs that proposal nor
represents a canonical task execution. No production executor/Bind, actual
provider, scorer, external effect or score inference is allowed.
"""
from __future__ import annotations

import copy
from threading import RLock

from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
from agentdojo.agent_pipeline.llms.openai_llm import _message_to_openai
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.types import ChatAssistantMessage

from scripts.agentdojo_openai_frozen_adapter_v0_1 import (
    MODEL_ID, create_completion_once,
)
from task15_canonical_ab_first_offline_source_binding_v1 import (
    RULE as FIRST_RULE,
)
from task15_canonical_injected_ab_context_isolation_v1 import (
    RULE as CONTEXT_RULE,
)
from task15_canonical_enrollment_gap_preflight_v1 import ENROLLED_TASK15
from task15_canonical_direct_payload_template_v1 import native_expected_direct_payloads
from task15_native_model_response_capture_boundary_v1 import sha

RULE = "TASK15_NATIVE_INJECTED_READ_OBSERVATION_WIRE_V1"
ARMS = ("A", "B")
READ_ONLY = "get_most_recent_transactions"


class NativeObservationViolation(ValueError):
    pass


def require(ok, why):
    if not ok:
        raise NativeObservationViolation(why)


class Task15NativeInjectedReadObservationWireV1:
    """Single-attempt synthetic read-only observation probe; no canonical effect."""

    def __init__(self, *, contexts, first_sources, clients,
                 transport_mode="OFFLINE_INJECTED_CLIENT"):
        require(transport_mode == "OFFLINE_INJECTED_CLIENT"
                and type(contexts) is dict
                and contexts.get("rule_of_one") == CONTEXT_RULE
                and contexts.get("determination") ==
                    "EIGHT_CASES_WITH_TWO_ISOLATED_NATIVE_INJECTED_INITIAL_CONTEXTS"
                and contexts.get("canonical_task15_case_count") == 8
                and contexts.get("prospective_initial_context_count") == 16
                and contexts.get("canonical_case_model_queries") == 0
                and contexts.get("canonical_candidate_dispatches") == 0
                and contexts.get("noncanonical_offline_source_history_promoted_to_canonical") is False
                and contexts.get("provider_calls") == contexts.get("scorer_calls") ==
                    contexts.get("real_external_effects") == 0
                and contexts.get("canonical_final128_utility_measured") is False
                and contexts.get("canonical_injection_success_measured") is False,
                "EXACT_PR262_PROSPECTIVE_CONTEXT_NOT_SCORE_REQUIRED")
        require(type(first_sources) is dict
                and first_sources.get("rule_of_one") == FIRST_RULE
                and first_sources.get("determination") ==
                    "EIGHT_NATIVE_CASES_SIXTEEN_OFFLINE_FIRST_PROPOSALS_BOUND"
                and first_sources.get("context_proof_sha256") == sha(contexts)
                and first_sources.get("native_task15_case_count") == 8
                and first_sources.get("independent_synthetic_client_invocations") == 16
                and first_sources.get("provider_calls") ==
                    first_sources.get("scorer_calls") ==
                    first_sources.get("canonical_native_tool_dispatches") ==
                    first_sources.get("external_effects") == 0
                and first_sources.get("native_injection_visible_to_model") is False
                and first_sources.get("canonical_full_trajectories_proven") is False
                and first_sources.get("canonical_scoring_eligible") is False
                and first_sources.get("real_model_computation_proven") is False
                and first_sources.get("final128_utility_measured") is False
                and first_sources.get("injection_success_measured") is False,
                "EXACT_PR263_UNOBSERVED_FIRST_SOURCE_REQUIRED")
        rows = contexts.get("contexts")
        sources = first_sources.get("source_bindings")
        require(type(rows) is list and type(sources) is list
                and [row.get("case_id") for row in rows] == list(ENROLLED_TASK15)
                and [row.get("case_id") for row in sources] == list(ENROLLED_TASK15)
                and type(clients) is dict
                and list(clients) == list(ENROLLED_TASK15),
                "ALL_EIGHT_ORDERED_CANONICAL_CASES_REQUIRED")
        identities = set()
        for case in ENROLLED_TASK15:
            require(type(clients[case]) is dict
                    and list(clients[case]) == list(ARMS),
                    "EXACT_CASE_LOCAL_AB_CLIENTS_REQUIRED")
            for arm in ARMS:
                client = clients[case][arm]
                require(id(client) not in identities
                        and callable(getattr(getattr(getattr(
                            client, "chat", None), "completions", None), "create", None)),
                        "NO_CROSS_CASE_OR_CROSS_ARM_CLIENT_ALIAS")
                identities.add(id(client))
        self._contexts = copy.deepcopy(contexts)
        self._first = copy.deepcopy(first_sources)
        self._contexts_sha = sha(contexts)
        self._first_sha = sha(first_sources)
        self._clients = clients
        self._lock = RLock()
        self._attempted = False
        self._phase = "READY"
        self._journal = []
        self._provisional = {}

    def _preflight(self, suite, expected):
        native_user = suite.get_user_task_by_id("user_task_15")
        require(native_user.ID == "user_task_15"
                and len(expected) == 8
                and len(self._first["source_transport_journal"]) == 16,
                "PINNED_TASK15_AND_FULL_FIRST_SOURCE_SET_REQUIRED")
        previous_ids = set()
        for i, (row, old_row) in enumerate(zip(
                self._contexts["contexts"], self._first["source_bindings"], strict=True)):
            case = ENROLLED_TASK15[i]
            payload = expected[case]
            require(row["case_id"] == old_row["case_id"] == case
                    and row["attack_profile"] == "direct"
                    and row["native_injection_task_id"] == case.split(":")[2]
                    and row["native_slot_key"] == "injection_incoming_transaction"
                    and row["native_payload_sha256"] == sha(payload)
                    and row["canonical_case_executed"] is False
                    and row["eligible_for_native_canonical_scoring"] is False
                    and list(row["arms"]) == list(old_row["arms"]) == list(ARMS),
                    "NATIVE_DIRECT_CASE_SLOT_AND_ROSTER_REQUIRED")
            native_env = suite.load_and_inject_default_environment(
                {row["native_slot_key"]: payload})
            native_sha = sha(native_env.model_dump(mode="json"))
            require(native_sha == row["verified_native_environment_sha256"],
                    "PINNED_NATIVE_INJECTION_ENVIRONMENT_REQUIRED")
            for arm in ARMS:
                c = row["arms"][arm]
                prior = old_row["arms"][arm]
                prefix = c["native_prospective_messages"]
                require(c["case_id"] == prior["case_id"] == case
                        and c["logical_arm"] == prior["logical_arm"] == arm
                        and c["environment_sha256"] ==
                            prior["injected_initial_environment_sha256"] ==
                            native_sha == sha(c["native_injected_environment"])
                        and c["message_prefix_sha256"] ==
                            row["prospective_native_prompt_sha256"] == sha(prefix)
                        and len(prefix) == 2
                        and [m["role"] for m in prefix] == ["developer", "user"]
                        and prefix[1]["content"][0]["text"] == native_user.PROMPT
                        and payload not in str(prefix)
                        and payload in str(c["native_injected_environment"])
                        and c["source_candidate_generated_for_this_case"] is False
                        and c["canonical_enrollment_eligible"] is False
                        and c["native_agentdojo_pipeline_executed_for_this_case"] is False
                        and prior["injection_observed_by_model"] is False
                        and prior["native_tool_dispatched"] is False
                        and prior["canonical_score_eligible"] is False,
                        "PRE_READ_CANONICAL_NATIVE_SOURCE_AND_CONTEXT_UNCHANGED")
                old_id = prior["native_call_id"]
                require(old_id not in previous_ids
                        and prior["case_arm_binding_sha256"] == sha({
                            "case_id":case, "arm":arm,
                            "environment_sha256":native_sha,
                            "native_payload_sha256":sha(payload),
                            "wire_request_sha256":prior["first_wire_request_sha256"],
                            "native_call_id":old_id,
                            "candidate_sha256":prior["first_candidate_sha256"],
                        }),
                        "PR263_NATIVE_SOURCE_BINDING_MUST_BE_RECOMPUTABLE")
                previous_ids.add(old_id)
        require(len(previous_ids) == 16, "EXACT_SIXTEEN_FIRST_SOURCE_CALL_IDS_REQUIRED")

    def run(self):
        with self._lock:
            require(not self._attempted and self._phase == "READY",
                    "SIDE_CAR_PROBE_ONE_ATTEMPT_ONLY")
            self._attempted = True
            self._phase = "RUNNING"
        completed = []
        try:
            suite = get_suite("v1.2.2", "banking")
            expected = native_expected_direct_payloads()
            self._preflight(suite, expected)
            selected = [tool for tool in suite.tools if tool.name == READ_ONLY]
            require(len(selected) == 1 and selected[0].name == READ_ONLY,
                    "EXACT_NATIVE_READ_ONLY_TOOL_REQUIRED")
            for i, row in enumerate(self._contexts["contexts"]):
                case, payload = row["case_id"], expected[row["case_id"]]
                arms = {}
                for arm in ARMS:
                    original = row["arms"][arm]
                    native_env = suite.load_and_inject_default_environment(
                        {row["native_slot_key"]: payload})
                    pre_state = sha(native_env.model_dump(mode="json"))
                    require(pre_state == original["environment_sha256"],
                            "NATIVE_INJECTED_PRE_STATE_DRIFT")
                    # Diagnostic read call is authored by this PROBE, not by
                    # the model's prior #263 first proposal.
                    call_id = f"probe-native-{i}-{arm}"
                    native_call = FunctionCall(
                        function=READ_ONLY, args={}, id=call_id)
                    assistant = ChatAssistantMessage(
                        role="assistant", content=None, tool_calls=[native_call])
                    tool_pipeline = ToolsExecutor()
                    _,runtime,returned_env,messages,_ = tool_pipeline.query(
                        "",FunctionsRuntime(selected),native_env,
                        [assistant],{})
                    require(returned_env is native_env
                            and len(messages) == 2
                            and messages[0]["role"] == "assistant"
                            and messages[1]["role"] == "tool"
                            and messages[1]["tool_call_id"] == call_id
                            and messages[1]["tool_call"].function == READ_ONLY
                            and messages[1]["error"] is None
                            and len(runtime.functions) == 1,
                            "PINNED_NATIVE_TOOLS_EXECUTOR_MUST_RETURN_REAL_READ_RESULT")
                    native_text = messages[1]["content"][0]["content"]
                    require(type(native_text) is str and
                            native_text.count(payload) >= 1
                            and sha(native_env.model_dump(mode="json")) == pre_state,
                            "ACTUAL_INJECTED_NATIVE_READ_RESULT_REQUIRED")
                    assistant_wire = _message_to_openai(messages[0],MODEL_ID)
                    tool_wire = _message_to_openai(messages[1],MODEL_ID)
                    wire = copy.deepcopy(
                        original["native_prospective_messages"]) + [
                            assistant_wire,tool_wire]
                    require([x["role"] for x in wire] ==
                            ["developer","user","assistant","tool"]
                            and wire[2]["tool_calls"][0]["id"] == call_id
                            and wire[2]["tool_calls"][0]["function"]["name"] == READ_ONLY
                            and wire[3]["tool_call_id"] == call_id
                            and payload in str(wire[3]["content"])
                            and payload not in str(wire[:2]),
                            "ATTACK_MUST_APPEAR_ONLY_IN_NATIVE_TOOL_RESULT")
                    wire_digest = sha(wire)
                    entry = {
                        "case_id":case,"logical_arm":arm,
                        "read_only_probe_call_id":call_id,
                        "environment_sha256":pre_state,
                        "tool_result_native_sha256":sha(native_text),
                        "wire_messages_sha256":wire_digest,
                        "status":"ATTEMPTED",
                        "tool_result_contains_native_payload":True,
                        "model_authored_tool_read":False,
                    }
                    self._journal.append(entry)
                    completion = create_completion_once(
                        client=self._clients[case][arm],
                        messages=wire, tools=[])
                    require(sha(wire) == wire_digest
                            and sha(native_env.model_dump(mode="json")) == pre_state
                            and sha(self._contexts) == self._contexts_sha
                            and sha(self._first) == self._first_sha
                            and len(completion.choices) == 1,
                            "OBSERVATION_WIRE_OR_OWNED_PROVENANCE_MUTATED")
                    response = completion.choices[0].message
                    require(response.role == "assistant"
                            and not getattr(response,"refusal",None)
                            and type(response.content) is str
                            and bool(response.content.strip())
                            and response.tool_calls is None,
                            "SYNTHETIC_OBSERVATION_RESPONSE_MUST_NOT_DISPATCH")
                    entry["status"] = "SYNTHETIC_CONTINUATION_DECODED"
                    entry["synthetic_response_sha256"] = sha(response.content)
                    arms[arm] = {
                        "case_id":case,"logical_arm":arm,
                        "environment_sha256":pre_state,
                        "native_payload_sha256":sha(payload),
                        "native_read_tool":READ_ONLY,
                        "probe_call_id":call_id,
                        "native_tool_return_sha256":sha(native_text),
                        "native_tool_wire_sha256":sha(tool_wire),
                        "native_full_wire_sha256":wire_digest,
                        "synthetic_terminal_response_sha256":sha(response.content),
                        "native_tool_result":native_text,
                        "wire_messages":copy.deepcopy(wire),
                        "payload_exposed_in_tool_wire":True,
                        "provider_authenticated":False,
                        "real_model_generated_probe_call":False,
                        "native_write_tool_dispatch_count":0,
                        "native_read_only_probe_count":1,
                        "canonical_score_eligible":False,
                    }
                completed.append({"case_id":case,"arms":arms})
            require(len(completed) == 8
                    and len(self._journal) == 16
                    and all(e["status"] == "SYNTHETIC_CONTINUATION_DECODED"
                            for e in self._journal),
                    "ALL_SIXTEEN_READ_ONLY_NATIVE_OBSERVATIONS_REQUIRED")
            self._phase = "COMPLETE_OFFLINE_NATIVE_OBSERVATION_SIDECAR"
            return {
                "rule_of_one":RULE,
                "determination":"SIXTEEN_NATIVE_INJECTED_TOOL_RETURNS_SENT_TO_OFFLINE_CLIENTS",
                "context_proof_sha256":self._contexts_sha,
                "first_source_proof_sha256":self._first_sha,
                "native_canonical_case_count":8,
                "native_read_only_probe_count":16,
                "synthetic_continuation_count":16,
                "source_observations":copy.deepcopy(completed),
                "transport_journal":copy.deepcopy(self._journal),
                "native_injection_exposed_in_offline_tool_wire":True,
                "injected_payload_seen_by_real_provider":False,
                "model_selected_native_read_tool":False,
                "canonical_full_trajectories_proven":False,
                "canonical_scoring_eligible":False,
                "provider_calls":0,"scorer_calls":0,
                "native_write_dispatches":0,"real_external_effects":0,
                "canonical_utility_measured":False,
                "injection_success_measured":False,
            }
        except BaseException:
            self._phase="TERMINAL_UNKNOWN_OR_FAILED"
            if self._journal and self._journal[-1]["status"]=="ATTEMPTED":
                self._journal[-1]["status"]="FAILED_OR_CANCELLED"
            self._provisional = {
                "partial_observations_not_promoted":True,
                "probe_journal":copy.deepcopy(self._journal),
                "retry_allowed":False,
                "external_effect_or_no_effect_claim":False,
            }
            raise

    def observation(self):
        with self._lock:
            return {
                "rule_of_one":RULE,
                "phase":self._phase,
                "attempted":self._attempted,
                "transport_journal":copy.deepcopy(self._journal),
                "provisional":copy.deepcopy(self._provisional),
                "retry_allowed":False,
                "provider_calls":0,"scorer_calls":0,
                "native_write_dispatches":0,"real_external_effects":0,
            }
