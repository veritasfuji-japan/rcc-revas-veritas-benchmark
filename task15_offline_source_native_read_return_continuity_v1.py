"""Native Task15 read call source-to-return continuity, isolated synthetic A/B only.

Unlike #264's harness-authored read probe, each isolated *offline test client*
supplies its own source-captured model-shaped first native READ proposal. The
pinned AgentDojo decoder, real read-only ToolsExecutor, and native wire encoder
then preserve that same call ID through actual injected transaction return and
one synthetic continuation query. This is NOT authenticated model selection,
a canonical trajectory, or an RCC/Bind governed dispatch/score.
"""
from __future__ import annotations

import copy
from threading import RLock

import yaml
from agentdojo.agent_pipeline.llms.openai_llm import (
    _function_to_openai, _message_to_openai, _openai_to_assistant_message,
)
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from rveval.models import CandidateAction

from scripts.agentdojo_openai_frozen_adapter_v0_1 import (
    MODEL_ID, create_completion_once,
)
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable
from task15_native_model_response_capture_boundary_v1 import sha
from task15_canonical_enrollment_gap_preflight_v1 import ENROLLED_TASK15
from task15_canonical_direct_payload_template_v1 import native_expected_direct_payloads
from task15_canonical_ab_first_offline_source_binding_v1 import RULE as FIRST_RULE
from task15_canonical_injected_ab_context_isolation_v1 import RULE as CONTEXT_RULE
from task15_native_injected_read_observation_wire_v1 import RULE as OBSERVATION_RULE

RULE = "TASK15_OFFLINE_SOURCE_NATIVE_READ_RETURN_CONTINUITY_V1"
READ_ONLY = "get_most_recent_transactions"
ARMS = ("A", "B")


class ReadContinuityViolation(ValueError):
    pass


def require(value, reason):
    if not value:
        raise ReadContinuityViolation(reason)


class Task15OfflineNativeReadContinuityV1:
    """One immutable 8x2 source -> read -> continuation proof, no retry."""

    def __init__(self, *, contexts, first_sources, native_observations, clients,
                 transport_mode="OFFLINE_INJECTED_CLIENT"):
        require(transport_mode == "OFFLINE_INJECTED_CLIENT"
                and type(contexts) is dict and type(first_sources) is dict
                and type(native_observations) is dict
                and contexts.get("rule_of_one") == CONTEXT_RULE
                and first_sources.get("rule_of_one") == FIRST_RULE
                and native_observations.get("rule_of_one") == OBSERVATION_RULE
                and contexts.get("determination") ==
                    "EIGHT_CASES_WITH_TWO_ISOLATED_NATIVE_INJECTED_INITIAL_CONTEXTS"
                and first_sources.get("determination") ==
                    "EIGHT_NATIVE_CASES_SIXTEEN_OFFLINE_FIRST_PROPOSALS_BOUND"
                and native_observations.get("determination") ==
                    "SIXTEEN_NATIVE_INJECTED_TOOL_RETURNS_SENT_TO_OFFLINE_CLIENTS"
                and first_sources.get("context_proof_sha256") == sha(contexts)
                and native_observations.get("context_proof_sha256") == sha(contexts)
                and native_observations.get("first_source_proof_sha256") ==
                    sha(first_sources)
                and contexts.get("canonical_task15_case_count") == 8
                and first_sources.get("native_task15_case_count") == 8
                and native_observations.get("native_canonical_case_count") == 8
                and first_sources.get("provider_calls") == first_sources.get("scorer_calls") ==
                    first_sources.get("canonical_native_tool_dispatches") ==
                    first_sources.get("external_effects") == 0
                and native_observations.get("provider_calls") ==
                    native_observations.get("scorer_calls") ==
                    native_observations.get("native_write_dispatches") ==
                    native_observations.get("real_external_effects") == 0
                and native_observations.get("model_selected_native_read_tool") is False
                and native_observations.get("canonical_scoring_eligible") is False
                and contexts.get("canonical_injection_success_measured") is False
                and first_sources.get("injection_success_measured") is False
                and native_observations.get("injection_success_measured") is False,
                "PINNED_PREDECESSOR_PROOFS_AND_STRICT_NONCLAIMS_REQUIRED")
        require(
            all(type(r.get("source_observations")) is list and
                [x.get("case_id") for x in r["source_observations"]] ==
                    list(ENROLLED_TASK15)
                for r in (native_observations,))
            and [r.get("case_id") for r in contexts.get("contexts", [])] ==
                list(ENROLLED_TASK15)
            and [r.get("case_id") for r in first_sources.get("source_bindings", [])] ==
                list(ENROLLED_TASK15)
            and type(clients) is dict
            and list(clients) == list(ENROLLED_TASK15),
            "EXACT_EIGHT_CANONICAL_CASES_AND_OBSERVATIONS_REQUIRED")
        owned_clients = set()
        for case in ENROLLED_TASK15:
            pair = clients[case]
            require(type(pair) is dict and list(pair) == list(ARMS),
                    "EXACT_TWO_CASE_LOCAL_ARMS_REQUIRED")
            for arm in ARMS:
                client = pair[arm]
                require(id(client) not in owned_clients
                        and callable(getattr(getattr(getattr(
                            client, "chat", None), "completions", None),
                            "create", None)),
                        "SOURCE_CLIENT_ALIAS_OR_NOT_INJECTED")
                owned_clients.add(id(client))
        self._contexts = copy.deepcopy(contexts)
        self._first = copy.deepcopy(first_sources)
        self._observation = copy.deepcopy(native_observations)
        self._input_hashes = (sha(contexts), sha(first_sources), sha(native_observations))
        self._clients = clients
        self._attempted = False
        self._phase = "READY"
        self._lock = RLock()
        self._journal = []
        self._provisional = {}

    def _preflight(self, suite, payloads):
        native_user = suite.get_user_task_by_id("user_task_15")
        require(native_user.ID == "user_task_15"
                and len(payloads) == 8
                and self._observation["native_read_only_probe_count"] == 16
                and self._first["independent_synthetic_client_invocations"] == 16,
                "NATIVE_TASK15_FROZEN_ROSTER_REQUIRED")
        for i, case in enumerate(ENROLLED_TASK15):
            row = self._contexts["contexts"][i]
            prior = self._first["source_bindings"][i]
            previous_read = self._observation["source_observations"][i]
            payload = payloads[case]
            require(row["case_id"] == prior["case_id"] ==
                    previous_read["case_id"] == case
                    and row["native_slot_key"] == "injection_incoming_transaction"
                    and row["native_payload_sha256"] == sha(payload)
                    and row["canonical_case_executed"] is False
                    and row["eligible_for_native_canonical_scoring"] is False
                    and list(row["arms"]) == list(prior["arms"]) ==
                        list(previous_read["arms"]) == list(ARMS),
                    "CANONICAL_READ_CASE_OR_PAYLOAD_DRIFT")
            expected_env = suite.load_and_inject_default_environment(
                {row["native_slot_key"]: payload})
            expected_env_sha = sha(expected_env.model_dump(mode="json"))
            require(expected_env_sha == row["verified_native_environment_sha256"],
                    "INDEPENDENT_NATIVE_CASE_STATE_REBUILD_MUST_MATCH")
            for arm in ARMS:
                c = row["arms"][arm]
                p = prior["arms"][arm]
                r = previous_read["arms"][arm]
                prefix = c["native_prospective_messages"]
                require(c["case_id"] == p["case_id"] == r["case_id"] == case
                        and c["logical_arm"] == p["logical_arm"] ==
                            r["logical_arm"] == arm
                        and c["environment_sha256"] ==
                            p["injected_initial_environment_sha256"] ==
                            r["environment_sha256"] == expected_env_sha
                        and sha(c["native_injected_environment"]) == expected_env_sha
                        and c["message_prefix_sha256"] == sha(prefix)
                        and row["prospective_native_prompt_sha256"] == sha(prefix)
                        and [m["role"] for m in prefix] == ["developer", "user"]
                        and prefix[1]["content"][0]["text"] == native_user.PROMPT
                        and payload not in str(prefix)
                        and payload in str(c["native_injected_environment"])
                        and r["native_read_tool"] == READ_ONLY
                        and r["payload_exposed_in_tool_wire"] is True
                        and r["real_model_generated_probe_call"] is False
                        and r["native_write_tool_dispatch_count"] == 0
                        and r["canonical_score_eligible"] is False
                        and r["native_payload_sha256"] == sha(payload),
                        "EXACT_FIRST_SOURCE_AND_INJECTED_OBSERVATION_NOT_ALTERED")

    def run(self):
        with self._lock:
            require(not self._attempted and self._phase == "READY",
                    "ONE_CONTINUOUS_OFFLINE_SOURCE_ATTEMPT_ONLY")
            self._attempted = True
            self._phase = "RUNNING"
        ids = set()
        rows = []
        try:
            suite = get_suite("v1.2.2", "banking")
            payloads = native_expected_direct_payloads()
            self._preflight(suite, payloads)
            native = [t for t in suite.tools if t.name == READ_ONLY]
            require(len(native) == 1 and native[0].name == READ_ONLY
                    and len(native[0].dependencies) > 0,
                    "ONLY_ONE_PINNED_DEPENDENCY_BACKED_READ_TOOL_REQUIRED")
            tools = [_function_to_openai(native[0])]
            tools_sha = sha(tools)
            for i, case in enumerate(ENROLLED_TASK15):
                row = self._contexts["contexts"][i]
                previous = self._observation["source_observations"][i]
                pair = {}
                payload = payloads[case]
                for arm in ARMS:
                    context = row["arms"][arm]
                    prior = previous["arms"][arm]
                    env = suite.load_and_inject_default_environment(
                        {"injection_incoming_transaction":payload})
                    before = sha(env.model_dump(mode="json"))
                    prefix = copy.deepcopy(context["native_prospective_messages"])
                    require(before == prior["environment_sha256"],
                            "NATIVE_PRE_READ_ENVIRONMENT_OR_ARM_DRIFT")
                    wire_tools = copy.deepcopy(tools)
                    request_sha = sha({"messages":prefix,"tools":wire_tools})
                    entry = {
                        "case_id":case,"logical_arm":arm,
                        "status":"FIRST_SYNTHETIC_PROPOSAL_ATTEMPTED",
                        "first_request_sha256":request_sha,
                        "environment_sha256":before,
                    }
                    self._journal.append(entry)
                    first_completion = create_completion_once(
                        client=self._clients[case][arm],
                        messages=prefix, tools=wire_tools)
                    require(len(first_completion.choices) == 1
                            and sha({"messages":prefix,"tools":wire_tools}) == request_sha
                            and sha(wire_tools) == tools_sha,
                            "FIRST_READ_MODEL_SHAPED_REQUEST_MUTATED")
                    raw = first_completion.choices[0].message
                    require(raw.role == "assistant"
                            and not getattr(raw,"refusal",None)
                            and raw.content is None
                            and type(raw.tool_calls) is list
                            and len(raw.tool_calls) == 1,
                            "SINGLE_FIRST_SYNTHETIC_READ_PROPOSAL_REQUIRED")
                    tool = raw.tool_calls[0]
                    require(tool.type == "function"
                            and tool.function.name == READ_ONLY
                            and type(tool.id) is str
                            and 0 < len(tool.id) <= 200
                            and tool.id.isascii() and tool.id.isprintable()
                            and tool.id not in ids,
                            "ONLY_OWNED_DISTINCT_NATIVE_READ_ID_ALLOWED")
                    ids.add(tool.id)
                    decoded = _openai_to_assistant_message(raw)
                    require(decoded["role"] == "assistant"
                            and len(decoded["tool_calls"]) == 1
                            and decoded["tool_calls"][0].function == READ_ONLY
                            and decoded["tool_calls"][0].id == tool.id
                            and decoded["tool_calls"][0].placeholder_args is None
                            and dict(decoded["tool_calls"][0].args) == {},
                            "REAL_NATIVE_CODEC_FIRST_READ_ARGS_REQUIRED")
                    candidate = CandidateAction("tool_call",name=READ_ONLY,
                                                arguments={}).to_dict()
                    require(candidate["kind"] == "tool_call"
                            and candidate["name"] == READ_ONLY
                            and candidate["metadata"] == {},
                            "READ_ONLY_SYNTHETIC_CANDIDATE_WITHOUT_AUTHORITY_REQUIRED")
                    _,runtime,env_after,history,_ = ToolsExecutor().query(
                        "",FunctionsRuntime(native),env,[decoded],{})
                    require(env_after is env and len(runtime.functions) == 1
                            and len(history) == 2
                            and history[0] is decoded
                            and history[1]["role"] == "tool"
                            and history[1]["error"] is None
                            and history[1]["tool_call_id"] == tool.id
                            and history[1]["tool_call"].function == READ_ONLY
                            and sha(env.model_dump(mode="json")) == before,
                            "EXACT_NATIVE_SOURCE_CALL_TO_READ_ONLY_TOOL_RETURN_REQUIRED")
                    result_text = history[1]["content"][0]["content"]
                    parsed = yaml.safe_load(result_text)
                    native_transactions = [
                        t.model_dump(mode="json")
                        for t in env.bank_account.transactions]
                    require(parsed == native_transactions
                            and len([t for t in parsed
                                     if t.get("id") == 5
                                     and t.get("subject") == payload
                                     and t.get("amount") == 10.0
                                     and t.get("recipient") == "me"]) == 1
                            and sha(result_text) ==
                                prior["native_tool_return_sha256"],
                            "FIRST_MODEL_SHAPED_READ_MUST_RETURN_EXACT_PRIOR_NATIVE_INJECTION")
                    assistant_wire = _message_to_openai(decoded,MODEL_ID)
                    tool_wire = _message_to_openai(history[1],MODEL_ID)
                    wire = copy.deepcopy(prefix) + [assistant_wire,tool_wire]
                    require([m["role"] for m in wire] ==
                                ["developer","user","assistant","tool"]
                            and wire[2]["tool_calls"][0]["id"] ==
                                wire[3]["tool_call_id"] == tool.id
                            and wire[2]["tool_calls"][0]["function"]["name"] == READ_ONLY
                            and yaml.safe_load(wire[3]["content"][0]["text"]) ==
                                native_transactions
                            and payload not in str(wire[:2]),
                            "EXACT_SOURCE_CALL_ID_NATIVE_WIRE_CONTINUITY_REQUIRED")
                    wire_sha = sha(wire)
                    entry.update(status="CONTINUATION_ATTEMPTED",
                                 call_id=tool.id, read_result_sha256=sha(result_text),
                                 continuation_wire_sha256=wire_sha)
                    continuation = create_completion_once(
                        client=self._clients[case][arm],messages=wire,tools=[])
                    require(len(continuation.choices) == 1
                            and sha(wire) == wire_sha
                            and sha(env.model_dump(mode="json")) == before
                            and (sha(self._contexts),sha(self._first),
                                 sha(self._observation)) == self._input_hashes,
                            "POST_READ_CONTINUATION_OR_PROVENANCE_MUTATED")
                    final = continuation.choices[0].message
                    require(final.role == "assistant"
                            and not getattr(final,"refusal",None)
                            and type(final.content) is str and bool(final.content.strip())
                            and final.tool_calls is None,
                            "NO_FURTHER_EFFECT_OR_UNTRUSTED_CONTINUATION_ALLOWED")
                    entry["status"] = "SYNTHETIC_SOURCE_READ_RETURN_CONTINUITY_CAPTURED"
                    pair[arm] = {
                        "case_id":case,"logical_arm":arm,
                        "initial_environment_sha256":before,
                        "native_payload_sha256":sha(payload),
                        "native_read_tool_name":READ_ONLY,
                        "source_model_call_id":tool.id,
                        "source_first_request_sha256":request_sha,
                        "source_first_decoded_sha256":sha(jsonable(decoded)),
                        "source_candidate_sha256":sha(candidate),
                        "native_tool_return_sha256":sha(result_text),
                        "native_tool_wire_sha256":sha(tool_wire),
                        "continuation_wire_sha256":wire_sha,
                        "continuation_terminal_sha256":sha(final.content),
                        "wire_messages":copy.deepcopy(wire),
                        "native_tool_result":result_text,
                        "read_tool_selected_by_offline_synthetic_client":True,
                        "read_tool_selected_by_authenticated_model":False,
                        "governed_write_dispatches":0,
                        "native_read_only_dispatches":1,
                        "scoring_eligible":False,
                    }
                rows.append({"case_id":case,"arms":pair})
            require(len(rows) == 8 and len(ids) == 16
                    and len(self._journal) == 16
                    and all(j["status"] ==
                            "SYNTHETIC_SOURCE_READ_RETURN_CONTINUITY_CAPTURED"
                            for j in self._journal),
                    "COMPLETE_SIXTEEN_SAME_SOURCE_READ_RETURN_CHAINS_REQUIRED")
            self._phase = "COMPLETE_OFFLINE_NATIVE_READ_CONTINUITY"
            return {
                "rule_of_one":RULE,
                "determination":
                    "SIXTEEN_SYNTHETIC_SOURCE_TO_NATIVE_READ_RETURNS_CONTINUOUS",
                "context_proof_sha256":self._input_hashes[0],
                "first_source_proof_sha256":self._input_hashes[1],
                "prior_probe_proof_sha256":self._input_hashes[2],
                "canonical_task15_case_count":8,
                "separate_synthetic_source_clients":16,
                "source_proposal_count":16,
                "native_read_only_return_count":16,
                "offline_continuation_count":16,
                "source_returns":copy.deepcopy(rows),
                "source_journal":copy.deepcopy(self._journal),
                "real_model_selected_read_count":0,
                "real_provider_calls":0,"scorer_calls":0,
                "native_write_dispatches":0,"real_external_effects":0,
                "full_canonical_trajectories_proven":False,
                "native_scorer_eligible":False,
                "final128_utility_measured":False,
                "injection_success_measured":False,
            }
        except BaseException:
            self._phase = "TERMINAL_UNKNOWN_OR_FAILED"
            if self._journal and self._journal[-1]["status"] != (
                    "SYNTHETIC_SOURCE_READ_RETURN_CONTINUITY_CAPTURED"):
                self._journal[-1]["status"] = "FAILED_OR_CANCELLED"
            self._provisional = {
                "partial_native_read_chains_not_promoted":True,
                "journal":copy.deepcopy(self._journal),
                "retry_allowed":False,
                "external_effect_or_no_effect_claim":False,
            }
            raise

    def observation(self):
        with self._lock:
            return {
                "rule_of_one":RULE,"phase":self._phase,
                "attempted":self._attempted,
                "journal":copy.deepcopy(self._journal),
                "provisional":copy.deepcopy(self._provisional),
                "retry_allowed":False,
                "real_provider_calls":0,"scorer_calls":0,
                "native_write_dispatches":0,"real_external_effects":0,
            }
