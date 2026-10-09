"""Two isolated offline terminal observations, each from its own governed A/B history.

Only B supplied the original source-candidate history in #253. This additive
successor to #254 tests independent *terminal* A and B requests; it never
retroactively calls the A candidate history independently model-generated.
No rubric invocation, external provider, tool dispatch, new permit or retry.
"""
from __future__ import annotations

import copy

from agentdojo.types import FunctionCall
from agentdojo.agent_pipeline.llms.openai_llm import (
    _message_to_openai, _openai_to_assistant_message,
)
from scripts.agentdojo_openai_frozen_adapter_v0_1 import create_completion_once
from task15_native_model_response_capture_boundary_v1 import (
    require, sha, jsonable, ORDINALS, MODEL_ID,
)
from task15_offline_terminal_native_continuation_v1 import (
    Task15OfflineTerminalNativeContinuationV1,
)

RULE = "TASK15_OFFLINE_PAIRED_TERMINAL_NATIVE_HISTORIES_V1"
ARMS = ("A", "B")


class Task15OfflinePairedTerminalNativeHistoriesV1(
        Task15OfflineTerminalNativeContinuationV1):
    """One A terminal and one B terminal after all six local native commits."""

    def _terminal_query(self, linked):
        require(not self._terminal_attempted
                and self._phase == "COMPLETE_OFFLINE_CAPTURE"
                and self._attempted is True,
                "PAIRED_TERMINAL_REQUIRES_SINGLE_COMPLETED_SOURCE_CAPTURE")
        self._terminal_attempted = True
        state = self._runner.observation()
        require(state["phase"] == "COMPLETE_LOCAL_COMPOSED_RUN"
                and state["native_return_history_fully_composed"] is True
                and len(state["completed_steps"]) == 3
                and len(self._responses) == len(self.journal) == 3
                and len(self._source_query_history_evidence) == 3
                and sha(state) == linked["composed_result_sha256"]
                and linked["source_model_queries_used_prior_tool_results"] is True
                and linked["source_arm_for_continuation"] == "B"
                and linked["model_continuous_conversation_proven"] is False
                and linked["actual_provider_execution"] is False
                and linked["terminal_model_continuations"] == 0
                and set(linked["arm_histories"]) == set(ARMS)
                and len(linked["source_call_id_return_bindings"]) == 3,
                "FROZEN_COMPLETE_PAIRED_NATIVE_EFFECTS_REQUIRED")
        sources = linked["source_call_id_return_bindings"]
        prepared = {}
        # Both complete arm-specific histories must validate BEFORE any final
        # query. Never send A's native return to B's terminal history or vice versa.
        for arm in ARMS:
            saved = linked["arm_histories"][arm]
            require(type(saved) is list and len(saved) == 8
                    and sha(saved[:2]) == self._original_prefix,
                    "EIGHT_NATIVE_MESSAGES_WITH_OWNED_PREFIX_REQUIRED")
            typed = copy.deepcopy(saved)
            for i, row in enumerate(state["completed_steps"]):
                pair = sources[i]
                actual = row["arms"][arm]
                assistant, tool = typed[2+2*i:4+2*i]
                source_assistant, source_tool = saved[2+2*i:4+2*i]
                require(row["step"] == pair["step"] == i
                        and row["actual_generation_ordinal"] == pair["ordinal"] == ORDINALS[i]
                        and row["candidate_sha256"] == self._responses[i]["candidate_sha256"]
                        and pair["source_tool_call_id"] == self._responses[i]["call_id"]
                        and actual["disposition"] == "COMMITTED"
                        and actual["native_dispatch_count"] == 1
                        and actual["candidate_sha256"] == pair["candidate_sha256"]
                        and actual["pre_state_sha256"] == pair["arms"][arm]["pre_state_sha256"]
                        and actual["post_state_sha256"] == pair["arms"][arm]["post_state_sha256"]
                        and sha(actual["native_return"]) == pair["arms"][arm]["native_return_sha256"]
                        and type(actual["native_return"]) is list
                        and len(actual["native_return"]) == 2
                        and actual["native_return"][1] is None
                        and source_tool["role"] == "tool"
                        and source_tool["tool_call_id"] == pair["source_tool_call_id"]
                        and source_tool["tool_call"] == source_assistant["tool_calls"][0]
                        and source_tool["error"] is None
                        and sha(source_tool) == pair["arms"][arm]["native_tool_message_sha256"]
                        and source_assistant["role"] == "assistant"
                        and len(source_assistant["tool_calls"]) == 1,
                        "ARM_NATIVE_EFFECT_AND_SOURCE_TOOL_ID_NOT_GENUINE")
                assistant["tool_calls"] = [
                    FunctionCall(**assistant["tool_calls"][0])]
                tool["tool_call"] = FunctionCall(**tool["tool_call"])
                require(jsonable(assistant) == source_assistant
                        and jsonable(tool) == source_tool,
                        "SERIALIZED_NATIVE_CALL_REHYDRATION_CHANGED")
            wire = [_message_to_openai(x, MODEL_ID) for x in typed]
            require(len(wire) == 8
                    and all(wire[3+2*i]["role"] == "tool"
                            and wire[3+2*i]["tool_call_id"] == sources[i]["source_tool_call_id"]
                            for i in range(3)),
                    "TYPED_NATIVE_TERMINAL_WIRE_NOT_BOUND_TO_SOURCE")
            if arm == "B":
                require(all(wire[:2+2*i] == self.journal[i]["wire_messages"]
                            for i in range(3)),
                        "B_SOURCE_QUERIES_CHANGED_FROM_FROZEN_CONTINUITY")
            else:
                require(wire[:2] == self.journal[0]["wire_messages"]
                        and not linked.get("A_arm_prior_candidate_queries_independent", False),
                        "A_SOURCE_AUTHENTICITY_MISREPRESENTED")
            prepared[arm] = wire
        require(prepared["A"] is not prepared["B"]
                and len(prepared) == 2
                and all(len(prepared[a]) == 8 for a in ARMS),
                "ISOLATED_A_B_TERMINAL_WIRES_REQUIRED")
        results = {}
        for arm in ARMS:
            wire = prepared[arm]
            tools = []
            request_sha = sha({"messages":wire,"tools":tools})
            entry = {"source_arm":arm,
                     "phase":"POST_GOVERNED_NATIVE_PAIRED_TERMINAL",
                     "status":"ATTEMPTED",
                     "wire_messages":copy.deepcopy(wire),
                     "wire_request_sha256":request_sha,
                     "wire_tools":[],
                     "tool_schemas_exposed":0,
                     "native_return_count":3,
                     "composed_native_sha256":sha(state),
                     "provider_authenticated":False}
            self._terminal_journal.append(entry)
            try:
                completion = create_completion_once(
                    client=self._client,messages=wire,tools=tools)
                require(self._phase == "COMPLETE_OFFLINE_CAPTURE"
                        and sha({"messages":wire,"tools":tools}) == request_sha
                        and len(completion.choices) == 1,
                        "PAIRED_TERMINAL_SINGLE_UNMODIFIED_RESPONSE_REQUIRED")
                raw = completion.choices[0].message
                require(raw.role == "assistant"
                        and not getattr(raw,"refusal",None)
                        and raw.tool_calls is None
                        and type(raw.content) is str
                        and bool(raw.content.strip()),
                        "PAIRED_TERMINAL_TEXT_ONLY_NO_TOOL_AUTHORITY")
                decoded = _openai_to_assistant_message(raw)
                require(type(decoded) is dict
                        and decoded["role"] == "assistant"
                        and decoded["tool_calls"] is None
                        and decoded["content"] is not None,
                        "EXACT_NATIVE_TERMINAL_TEXT_DECODER_REQUIRED")
                entry.update(status="RESPONSE_DECODED",
                             response_sha256=sha(jsonable(decoded)),
                             decoded_response=jsonable(decoded))
                results[arm] = {"arm":arm,"terminal_text":raw.content,
                                "response_sha256":sha(jsonable(decoded)),
                                "terminal_request_sha256":request_sha,
                                "native_results_consumed":3,
                                "candidate_source_history_was_B_only":True}
            except BaseException:
                entry["status"] = "FAILED_OR_CANCELLED"
                raise
        require(len(self._terminal_journal)==2
                and [j["source_arm"] for j in self._terminal_journal] == list(ARMS)
                and all(j["status"]=="RESPONSE_DECODED" for j in self._terminal_journal),
                "TWO_INDEPENDENT_TERMINAL_TEXT_COMPLETIONS_REQUIRED")
        observed_state=self._runner.observation()
        require(sha(observed_state)==sha(state),
                "TERMINAL_OBSERVATION_MUTATED_GOVERNED_EXECUTION")
        report={
            "rule_of_one":RULE,
            "determination":"BOUNDED_OFFLINE_PAIRED_TERMINAL_TEXT_OBSERVED",
            "source_mode":"OFFLINE_INJECTED_CLIENT",
            "candidate_source_arm":"B",
            "terminal_arms":list(ARMS),
            "terminal_observations":copy.deepcopy(results),
            "terminal_transport_journal":copy.deepcopy(self._terminal_journal),
            "source_candidate_queries":3,
            "source_queries_used_B_native_results":True,
            "A_candidate_source_history_independently_generated":False,
            "terminal_queries":2,
            "total_offline_queries":5,
            "terminal_wire_message_counts":[8,8],
            "terminal_tool_schemas_exposed":0,
            "native_commits_ab":6,
            "actual_provider_calls":0,
            "actual_provider_execution":False,
            "scorer_calls":0,
            "scorer_input_provenance_ready":True,
            "scored_task15_utility":False,
            "scored_injection_success":False,
            "real_external_effect_authenticated":False,
            "real_provider_full_conversation_proven":False,
            "final128_utility_recovery_proven":False,
            "paired_native_execution":copy.deepcopy(state),
            "captured_source_history":copy.deepcopy(linked),
        }
        self._phase="COMPLETE_OFFLINE_PAIRED_TERMINAL"
        self._terminal_output=copy.deepcopy(report)
        return report

    def observation(self):
        state=super().observation()
        state.update(rule_of_one=RULE,
                     paired_terminal_query_count=len(self._terminal_journal),
                     paired_terminal_complete=self._phase=="COMPLETE_OFFLINE_PAIRED_TERMINAL",
                     scorer_calls=0,
                     actual_provider_calls=0)
        return state
