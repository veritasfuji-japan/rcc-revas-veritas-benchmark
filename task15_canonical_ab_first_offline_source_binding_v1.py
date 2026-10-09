"""Canonical Task15 first-proposal request provenance, synthetic transport only.

The actual eight native DirectAttack case initial environments are isolated by
#262. Here a *new* first native tool-proposal request is issued to each of 16
separate injected test clients and bound to its exact case/environment digest.
The attack payload is NOT yet model-visible in the first request; no native
tool return, governance dispatch, provider, scorer or canonical score occurs.
"""
from __future__ import annotations

import copy
from threading import RLock

from agentdojo.agent_pipeline.llms.openai_llm import (
    _function_to_openai, _openai_to_assistant_message,
)
from agentdojo.functions_runtime import Function
from agentdojo.task_suite.load_suites import get_suite
from rveval.models import CandidateAction

from scripts.agentdojo_openai_frozen_adapter_v0_1 import (
    MODEL_ID, create_completion_once,
)
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable
from task15_frozen_openai_wire_controlled_refund_adapter_v1 import strict_arguments
from task15_canonical_injected_ab_context_isolation_v1 import (
    RULE as CONTEXT_RULE,
)
from task15_canonical_enrollment_gap_preflight_v1 import ENROLLED_TASK15
from task15_canonical_direct_payload_template_v1 import native_expected_direct_payloads
from task15_native_model_response_capture_boundary_v1 import FUNCTIONS, sha

RULE = "TASK15_CANONICAL_AB_FIRST_OFFLINE_SOURCE_BINDING_V1"
ARMS = ("A", "B")


class CanonicalFirstSourceViolation(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise CanonicalFirstSourceViolation(reason)


class Task15CanonicalABFirstOfflineSourceBindingV1:
    """One attempt / no retry / no crossing case environment or source identity."""

    def __init__(self, *, contexts, clients, transport_mode="OFFLINE_INJECTED_CLIENT"):
        require(transport_mode == "OFFLINE_INJECTED_CLIENT"
                and type(contexts) is dict
                and contexts.get("rule_of_one") == CONTEXT_RULE
                and contexts.get("determination") ==
                    "EIGHT_CASES_WITH_TWO_ISOLATED_NATIVE_INJECTED_INITIAL_CONTEXTS"
                and contexts.get("canonical_task15_case_count") == 8
                and contexts.get("prospective_initial_context_count") == 16
                and contexts.get("noncanonical_offline_source_history_promoted_to_canonical") is False
                and contexts.get("canonical_case_model_queries") ==
                    contexts.get("canonical_candidate_dispatches") == 0
                and contexts.get("provider_calls") ==
                    contexts.get("scorer_calls") ==
                    contexts.get("real_external_effects") == 0
                and contexts.get("canonical_final128_utility_measured") is False
                and contexts.get("canonical_injection_success_measured") is False,
                "EXACT_262_INITIAL_CONTEXT_NOT_EXECUTION_REQUIRED")
        require(type(contexts.get("contexts")) is list
                and [r.get("case_id") for r in contexts["contexts"]] ==
                    list(ENROLLED_TASK15),
                "EXACT_EIGHT_ORDERED_NATIVE_CASE_IDS_REQUIRED")
        require(type(clients) is dict and list(clients) == list(ENROLLED_TASK15),
                "EXACT_INDEPENDENT_CANONICAL_CASE_CLIENT_MAP_REQUIRED")
        seen = set()
        for row in contexts["contexts"]:
            case_id = row["case_id"]
            pair = clients[case_id]
            require(type(pair) is dict and list(pair) == list(ARMS)
                    and type(row.get("arms")) is dict
                    and list(row["arms"]) == list(ARMS),
                    "TWO_DISTINCT_OWNED_FIRST_SOURCE_ARMS_REQUIRED")
            for arm in ARMS:
                client = pair[arm]
                require(id(client) not in seen
                        and callable(getattr(getattr(getattr(
                            client, "chat", None), "completions", None), "create", None)),
                        "NO_SOURCE_CLIENT_ALIAS_BETWEEN_ARMS_OR_CASES")
                seen.add(id(client))
        self._contexts = copy.deepcopy(contexts)
        self._source_hash = sha(contexts)
        self._clients = clients
        self._lock = RLock()
        self._attempted = False
        self._phase = "READY"
        self._journal = []
        self._provisional = {}

    def run(self):
        with self._lock:
            require(not self._attempted and self._phase == "READY",
                    "CANONICAL_FIRST_SOURCE_ONE_ATTEMPT_ONLY")
            self._attempted = True
            self._phase = "RUNNING"
        call_ids = set()
        completion_objects = []
        rows = []
        try:
            suite = get_suite("v1.2.2", "banking")
            native_user = suite.get_user_task_by_id("user_task_15")
            expected = native_expected_direct_payloads()
            selected = [t for t in suite.tools if t.name in FUNCTIONS]
            require(len(selected) == len(FUNCTIONS)
                    and {t.name for t in selected} == set(FUNCTIONS)
                    and all(type(t) is Function for t in selected),
                    "EXACT_NATIVE_TOOL_SCHEMA_SET_REQUIRED")
            tools = [_function_to_openai(t) for t in selected]
            tools_sha = sha(tools)
            for row in self._contexts["contexts"]:
                case_id = row["case_id"]
                arm_rows = {}
                payload = expected[case_id]
                require(row["native_payload_sha256"] == sha(payload)
                        and row["native_injection_task_id"] == case_id.split(":")[2]
                        and row["attack_profile"] == "direct"
                        and row["canonical_case_executed"] is False
                        and row["eligible_for_native_canonical_scoring"] is False,
                        "NATIVE_CANONICAL_CASE_OR_PAYLOAD_PROVENANCE_CHANGED")
                for arm in ARMS:
                    context = row["arms"][arm]
                    state = context["native_injected_environment"]
                    wire = copy.deepcopy(context["native_prospective_messages"])
                    require(context["case_id"] == case_id
                            and context["logical_arm"] == arm
                            and context["source_candidate_generated_for_this_case"] is False
                            and context["canonical_enrollment_eligible"] is False
                            and context["native_agentdojo_pipeline_executed_for_this_case"] is False
                            and context["environment_sha256"] == sha(state)
                            and context["environment_sha256"] ==
                                row["verified_native_environment_sha256"]
                            and context["message_prefix_sha256"] ==
                                row["prospective_native_prompt_sha256"] == sha(wire)
                            and len(wire) == 2
                            and [m["role"] for m in wire] == ["developer", "user"]
                            and wire[1]["content"][0]["text"] == native_user.PROMPT
                            and payload in str(state)
                            and payload not in str(wire),
                            "EXACT_UNOBSERVED_INJECTED_NATIVE_CONTEXT_REQUIRED")
                    # Rebuild exact native environment and compare independent data,
                    # not just self-attested digests from upstream JSON.
                    native = suite.load_and_inject_default_environment(
                        {row["native_slot_key"]: payload})
                    require(sha(native.model_dump(mode="json")) == sha(state),
                            "NATIVE_CASE_ENVIRONMENT_NOT_INDEPENDENTLY_RECONSTRUCTED")
                    exposed = copy.deepcopy(tools)
                    request_sha = sha({"messages": wire, "tools": exposed})
                    entry = {
                        "case_id": case_id, "logical_arm": arm, "status": "ATTEMPTED",
                        "ordinal": 0, "environment_sha256": sha(state),
                        "native_payload_sha256": sha(payload),
                        "wire_request_sha256": request_sha,
                        "native_tool_schemas_sha256": tools_sha,
                        "wire_messages": copy.deepcopy(wire),
                        "injection_observed_in_request": False,
                    }
                    self._journal.append(entry)
                    completion = create_completion_once(
                        client=self._clients[case_id][arm],
                        messages=wire, tools=exposed)
                    require(not any(completion is old for old in completion_objects),
                            "REUSED_COMPLETION_OBJECT_ACROSS_CANONICAL_CASES")
                    completion_objects.append(completion)
                    require(self._phase == "RUNNING"
                            and len(completion.choices) == 1
                            and sha({"messages": wire, "tools": exposed}) == request_sha
                            and sha(exposed) == tools_sha
                            and sha(self._contexts) == self._source_hash,
                            "CANONICAL_FIRST_NATIVE_TRANSPORT_OR_CONTEXT_MUTATION")
                    raw = completion.choices[0].message
                    require(raw.role == "assistant"
                            and not getattr(raw, "refusal", None)
                            and raw.content is None
                            and type(raw.tool_calls) is list
                            and len(raw.tool_calls) == 1,
                            "ONE_SYNTHETIC_NATIVE_FIRST_TOOL_PROPOSAL_REQUIRED")
                    native_call = raw.tool_calls[0]
                    require(native_call.type == "function"
                            and native_call.function.name == FUNCTIONS[0]
                            and type(native_call.id) is str
                            and 0 < len(native_call.id) <= 200
                            and native_call.id.isascii()
                            and native_call.id.isprintable()
                            and native_call.id not in call_ids,
                            "CANONICAL_FIRST_CALL_ID_REUSE_OR_BAD_TOOL")
                    call_ids.add(native_call.id)
                    arguments = strict_arguments(native_call.function.arguments)
                    decoded = _openai_to_assistant_message(raw)
                    require(decoded["role"] == "assistant"
                            and len(decoded["tool_calls"]) == 1
                            and decoded["tool_calls"][0].id == native_call.id
                            and decoded["tool_calls"][0].function == FUNCTIONS[0]
                            and decoded["tool_calls"][0].placeholder_args is None,
                            "PINNED_NATIVE_FIRST_RESPONSE_CODEC_REQUIRED")
                    candidate = CandidateAction(
                        "tool_call", name=FUNCTIONS[0],
                        arguments=copy.deepcopy(arguments)).to_dict()
                    require(candidate["kind"] == "tool_call"
                            and candidate["name"] == FUNCTIONS[0]
                            and candidate["content"] is None
                            and candidate["metadata"] == {},
                            "FIRST_NATIVE_PROPOSAL_CANNOT_GRANT_AUTHORITY")
                    binding = sha({
                        "case_id": case_id,
                        "arm": arm,
                        "environment_sha256": sha(state),
                        "native_payload_sha256": sha(payload),
                        "wire_request_sha256": request_sha,
                        "native_call_id": native_call.id,
                        "candidate_sha256": sha(candidate),
                    })
                    rec = {
                        "case_id": case_id, "logical_arm": arm,
                        "injected_initial_environment_sha256": sha(state),
                        "native_payload_sha256": sha(payload),
                        "native_tool_schemas_sha256": tools_sha,
                        "first_wire_request_sha256": request_sha,
                        "first_native_response_sha256": sha(jsonable(decoded)),
                        "first_candidate_sha256": sha(candidate),
                        "first_candidate": candidate,
                        "native_call_id": native_call.id,
                        "case_arm_binding_sha256": binding,
                        "native_first_request_count": 1,
                        "injection_observed_by_model": False,
                        "native_tool_dispatched": False,
                        "governed_execution_proven": False,
                        "provider_authenticated": False,
                        "canonical_score_eligible": False,
                    }
                    entry.update(status="RESPONSE_DECODED",
                                 native_call_id=native_call.id,
                                 candidate_sha256=rec["first_candidate_sha256"],
                                 case_arm_binding_sha256=binding)
                    arm_rows[arm] = rec
                require(arm_rows["A"]["native_call_id"] !=
                        arm_rows["B"]["native_call_id"]
                        and arm_rows["A"]["injected_initial_environment_sha256"] ==
                            arm_rows["B"]["injected_initial_environment_sha256"],
                        "TWO_CASE_LOCAL_SOURCE_IDENTITIES_REQUIRED")
                rows.append({"case_id": case_id, "arms": arm_rows})
            require(len(rows) == 8 and len(call_ids) == 16
                    and len(self._journal) == 16
                    and all(e["status"] == "RESPONSE_DECODED"
                            for e in self._journal),
                    "EXACT_SIXTEEN_CANONICAL_FIRST_SOURCE_INVOCATIONS_REQUIRED")
            self._phase = "COMPLETE_OFFLINE_FIRST_CANONICAL_SOURCE_BINDINGS"
            return {
                "rule_of_one": RULE,
                "determination": "EIGHT_NATIVE_CASES_SIXTEEN_OFFLINE_FIRST_PROPOSALS_BOUND",
                "context_proof_sha256": self._source_hash,
                "native_task15_case_count": 8,
                "independent_synthetic_client_invocations": 16,
                "source_bindings": rows,
                "source_transport_journal": copy.deepcopy(self._journal),
                "provider_calls": 0, "scorer_calls": 0,
                "canonical_native_tool_dispatches": 0,
                "external_effects": 0,
                "native_injection_visible_to_model": False,
                "canonical_full_trajectories_proven": False,
                "canonical_scoring_eligible": False,
                "final128_utility_measured": False,
                "injection_success_measured": False,
                "real_model_computation_proven": False,
            }
        except BaseException:
            self._phase = "TERMINAL_UNKNOWN_OR_FAILED"
            if self._journal and self._journal[-1]["status"] == "ATTEMPTED":
                self._journal[-1]["status"] = "FAILED_OR_CANCELLED"
            self._provisional = {
                "source_transports": copy.deepcopy(self._journal),
                "completed_partial_source_evidence_not_promoted": True,
                "retry_allowed": False,
                "external_effect_or_no_effect_claim": False,
            }
            raise

    def observation(self):
        with self._lock:
            return {
                "rule_of_one": RULE, "phase": self._phase,
                "attempted": self._attempted,
                "source_transports": copy.deepcopy(self._journal),
                "provisional_on_failure": copy.deepcopy(self._provisional),
                "retry_allowed": False,
                "provider_calls": 0, "scorer_calls": 0,
                "canonical_native_tool_dispatches": 0,
                "external_effects": 0,
            }
