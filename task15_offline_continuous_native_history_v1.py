"""Strict offline Task15 continuation with real prior governed B-arm native results.

The original native source capture (#248), local sink runner (#251) and source-ID
return pairing (#252) are unchanged. Every source query after the first receives
the *actual* previous admitted B-arm tool response in its native AgentDojo
message history before any next candidate is generated. No terminal answer,
provider call, scorer, new permit, retry or externally authenticated effect.
"""
from __future__ import annotations

import copy

from task15_model_callid_native_return_history_v1 import (
    Task15OfflineModelCallIdNativeReturnHistoryV1,
)
from task15_native_model_response_capture_boundary_v1 import (
    require, ORDINALS, FUNCTIONS, MODEL_ID, jsonable, sha, canonical,
)

RULE = "TASK15_OFFLINE_CONTINUOUS_NATIVE_MODEL_HISTORY_REPLAY_V1"
SELECTED_SOURCE_ARM = "B"


class Task15OfflineContinuousNativeHistoryReplayV1(
        Task15OfflineModelCallIdNativeReturnHistoryV1):
    """Fail-closed, selected B-arm offline native-result conversation input."""

    def __init__(self, *, runner, envelope, client,
                 transport_mode="OFFLINE_INJECTED_CLIENT"):
        super().__init__(runner=runner, envelope=envelope, client=client,
                         transport_mode=transport_mode)
        self._source_query_history_evidence = []

    def _query(self, *, history, phase, ordinal, expected_tool=None):
        from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
        from agentdojo.types import FunctionCall, text_content_block_from_string
        from agentdojo.agent_pipeline.llms.openai_llm import _message_to_openai

        step = len(self._responses)
        require(phase == "PROTECTED_CANDIDATE"
                and type(step) is int and 0 <= step < len(ORDINALS)
                and ordinal == ORDINALS[step]
                and expected_tool == FUNCTIONS[step]
                and jsonable(history) == jsonable(self._history)
                and self._phase == "RUNNING",
                "STRICT_OWNED_CONTINUATION_QUERY_REQUIRED")
        state = self._runner.observation()
        rows = state["completed_steps"]
        require(state["phase"] == "RUNNING"
                and len(rows) == step
                and len(self.journal) == step,
                "PRIOR_NATIVE_STEP_MUST_BE_TERMINAL_BEFORE_NEXT_QUERY")
        prior_links = []
        built = copy.deepcopy(history)
        for k, row in enumerate(rows):
            rec = self._responses[k]
            recorded = self.journal[k]
            call = rec["call"]
            require(row["step"] == rec["step"] == k
                    and row["actual_generation_ordinal"] == rec["ordinal"] == ORDINALS[k]
                    and row["candidate_sha256"] == rec["candidate_sha256"]
                    and call.id == rec["call_id"]
                    and call.function == FUNCTIONS[k]
                    and type(rec["call_id"]) is str
                    and rec["call_id"] != ""
                    and all(rec["call_id"] != self._responses[t]["call_id"]
                            for t in range(k))
                    and recorded["status"] == "RESPONSE_DECODED"
                    and recorded["response_sha256"] == rec["source_assistant_sha256"]
                    and sha(recorded["decoded_response"]) == rec["source_assistant_sha256"]
                    and recorded["decoded_response"]["tool_calls"] == [jsonable(call)],
                    "SOURCE_CANDIDATE_AND_ORIGINAL_NATIVE_CALL_NOT_BOUND")
            arms = row["arms"]
            require(all(arms[arm]["disposition"] == "COMMITTED"
                        and arms[arm]["native_dispatch_count"] == 1
                        and arms[arm]["candidate_sha256"] == rec["candidate_sha256"]
                        for arm in ("A", "B")),
                    "NO_NEXT_QUERY_AFTER_REFUSED_OR_UNPAIRED_NATIVE_STEP")
            # Source candidates use B's already governed result, never A's
            # hypothetical effect, a fabricated return or model-origin metadata.
            b = arms[SELECTED_SOURCE_ARM]
            returned = b.get("native_return")
            require(type(returned) is list and len(returned) == 2
                    and type(returned[0]) is dict and returned[1] is None
                    and b["pre_state_sha256"] == row["arms"]["A"]["pre_state_sha256"]
                    and b["post_state_sha256"] == row["arms"]["A"]["post_state_sha256"]
                    and any(x.get("event") == "VERITAS_BIND_RECEIPT"
                            for x in b["journal"]),
                    "ACTUAL_PAIRED_BIND_NATIVE_RESULT_REQUIRED")
            # Parent's completed-return sidecar re-verifies exact native result
            # hashes against the dispatch snapshots after execution.
            predecessor = copy.deepcopy(recorded["decoded_response"])
            require(predecessor["role"] == "assistant"
                    and type(predecessor["tool_calls"]) is list
                    and len(predecessor["tool_calls"]) == 1
                    and predecessor["tool_calls"][0] == jsonable(call),
                    "PRIOR_ASSISTANT_MESSAGE_CHANGED")
            predecessor["tool_calls"] = [
                FunctionCall(**predecessor["tool_calls"][0])]
            tool = {
                "role": "tool",
                "content": [
                    text_content_block_from_string(
                        tool_result_to_str(returned[0]))],
                "tool_call_id": rec["call_id"],
                "tool_call": copy.deepcopy(call),
                "error": None,
            }
            require(jsonable(tool["tool_call"]) == jsonable(call)
                    and _message_to_openai(tool, MODEL_ID)["tool_call_id"]
                        == rec["call_id"],
                    "SOURCE_TOOL_ID_OR_NATIVE_CODEC_CHANGED")
            built.extend([predecessor, tool])
            prior_links.append({
                "prior_step": k,
                "source_arm": SELECTED_SOURCE_ARM,
                "source_call_id": rec["call_id"],
                "candidate_sha256": rec["candidate_sha256"],
                "pre_state_sha256": b["pre_state_sha256"],
                "post_state_sha256": b["post_state_sha256"],
                "native_return_sha256": sha(returned),
                "model_tool_message_sha256": sha(jsonable(tool)),
            })
        require(len(built) == 2 + 2 * step
                and len(prior_links) == step
                and sha(jsonable(built[:2])) == self._original_prefix,
                "UNEXPECTED_CONTINUATION_WIRE_PREFIX")

        # Preserve an immutable pre-transport snapshot; inherited _query
        # actually passes these exact messages into the offline native client.
        wire = [_message_to_openai(m, MODEL_ID) for m in built]
        captured = {
            "step": step, "ordinal": ordinal,
            "source_arm": SELECTED_SOURCE_ARM,
            "wire_message_count": len(wire),
            "wire_messages_sha256": sha(wire),
            "previous_native_links": prior_links,
            "native_previous_results_present_at_query": step,
            "model_query_was_offline": True,
        }
        self._source_query_history_evidence.append(copy.deepcopy(captured))
        response = super()._query(history=built, phase=phase,
                                  ordinal=ordinal, expected_tool=expected_tool)
        new_entry = self.journal[-1]
        require(len(self.journal) == step + 1
                and new_entry["wire_messages"] == wire
                and sha(new_entry["wire_messages"]) == captured["wire_messages_sha256"]
                and new_entry["status"] == "RESPONSE_DECODED",
                "MODEL_QUERY_DID_NOT_CONSUME_EXACT_NATIVE_HISTORY")
        return response

    def _build_history(self, result):
        # The original #252 history linkage remains an explicit independent
        # source-of-truth check after every governed native result commits.
        linked = super()._build_history(result)
        queries = self._source_query_history_evidence
        require(len(queries) == len(ORDINALS) == len(self.journal)
                and [e["wire_message_count"] for e in queries] == [2, 4, 6]
                and [len(e["previous_native_links"]) for e in queries] == [0, 1, 2],
                "EXACT_OFFLINE_THREE_STEP_QUERY_CHAIN_REQUIRED")
        completed = result["composed_native_execution"]["completed_steps"]
        for i, query in enumerate(queries):
            journal = self.journal[i]
            require(journal["ordinal"] == query["ordinal"] == ORDINALS[i]
                    and journal["wire_messages"] is not None
                    and len(journal["wire_messages"]) == 2 + 2 * i
                    and sha(journal["wire_messages"]) == query["wire_messages_sha256"],
                    "SOURCE_QUERY_WIRE_NOT_MATCHED")
            for previous in query["previous_native_links"]:
                k = previous["prior_step"]
                require(k < i and previous["source_arm"] == SELECTED_SOURCE_ARM
                        and previous["source_call_id"]
                        == linked["source_call_id_return_bindings"][k]["source_tool_call_id"]
                        and previous["candidate_sha256"] == completed[k]["candidate_sha256"],
                        "EARLIER_PROTECTED_CANDIDATE_MISMATCH")
                native = completed[k]["arms"][SELECTED_SOURCE_ARM]
                require(previous["native_return_sha256"] == sha(native["native_return"])
                        and previous["post_state_sha256"] == native["post_state_sha256"]
                        and previous["model_tool_message_sha256"]
                        == linked["source_call_id_return_bindings"][k]["arms"][
                            SELECTED_SOURCE_ARM]["native_tool_message_sha256"],
                        "CONTINUATION_DID_NOT_USE_PREVIOUS_EXACT_NATIVE_RETURN")
        linked.update(
            rule_of_one=RULE,
            source_model_queries_used_prior_tool_results=True,
            source_queries_are_sequential_native_history=True,
            bounded_offline_three_candidate_continuity_tested=True,
            source_arm_for_continuation=SELECTED_SOURCE_ARM,
            source_query_history_evidence=copy.deepcopy(queries),
            model_continuous_conversation_proven=False,
            terminal_model_continuations=0,
            tool_messages_constructed_after_all_native_steps=False,
            actual_provider_execution=False,
            new_provider_calls=0,
            scorer_calls=0,
        )
        return linked

    def observation(self):
        observed = super().observation()
        observed.update(rule_of_one=RULE,
                        completed_history_input_queries=len(
                            self._source_query_history_evidence),
                        source_arm_for_continuation=SELECTED_SOURCE_ARM,
                        final_model_answer_not_proven=True)
        return observed
