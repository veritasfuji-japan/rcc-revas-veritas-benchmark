"""A single offline terminal assistant response after three governed native steps.

Trust boundary: this is a synthetic injected client, *not* an authenticated
external model. The source candidate conversation from PR253 already consumed
the previous B-arm native results, and frozen PR252 captured exact final B
tool-call IDs/returns. Here their fully composed B history is submitted once
to the native OpenAI wire adapter for a text-only final response. No new
execution authority, scorer, provider, A-arm final answer or paid network call.
"""
from __future__ import annotations

import copy

from agentdojo.types import FunctionCall
from agentdojo.agent_pipeline.llms.openai_llm import (
    _message_to_openai, _openai_to_assistant_message,
)
from scripts.agentdojo_openai_frozen_adapter_v0_1 import (
    create_completion_once,
)
from task15_native_model_response_capture_boundary_v1 import (
    require, sha, jsonable, ORDINALS, MODEL_ID,
    Task15NativeCaptureViolation,
)
from task15_offline_continuous_native_history_v1 import (
    Task15OfflineContinuousNativeHistoryReplayV1,
    SELECTED_SOURCE_ARM,
)

RULE = "TASK15_OFFLINE_TERMINAL_NATIVE_CONTINUATION_V1"
TERMINAL_PHASE = "OFFLINE_TERMINAL_AFTER_THREE_NATIVE_COMMITS"


class Task15OfflineTerminalNativeContinuationV1(
        Task15OfflineContinuousNativeHistoryReplayV1):
    """One terminal B-history text-only query after completed A/B native effects."""

    def __init__(self, *, runner, envelope, client,
                 transport_mode="OFFLINE_INJECTED_CLIENT"):
        super().__init__(runner=runner, envelope=envelope, client=client,
                         transport_mode=transport_mode)
        self._terminal_attempted = False
        self._terminal_journal = []
        self._terminal_output = None

    def _terminal_query(self, linked):
        require(not self._terminal_attempted
                and self._phase == "COMPLETE_OFFLINE_CAPTURE"
                and self._attempted is True,
                "TERMINAL_ONCE_ONLY_AFTER_OFFLINE_CAPTURE")
        self._terminal_attempted = True
        state = self._runner.observation()
        require(state["phase"] == "COMPLETE_LOCAL_COMPOSED_RUN"
                and state["native_return_history_fully_composed"] is True
                and len(state["completed_steps"]) == len(ORDINALS) == 3
                and len(self._responses) == len(self.journal) == 3
                and len(self._source_query_history_evidence) == 3
                and sha(state) == linked["composed_result_sha256"]
                and linked["source_model_queries_used_prior_tool_results"] is True
                and linked["source_arm_for_continuation"] == SELECTED_SOURCE_ARM
                and linked["terminal_model_continuations"] == 0
                and linked["model_continuous_conversation_proven"] is False
                and linked["actual_provider_execution"] is False,
                "FROZEN_THREE_STEP_PRETERMINAL_EVIDENCE_REQUIRED")

        arm = SELECTED_SOURCE_ARM
        saved = linked["arm_histories"][arm]
        require(type(saved) is list and len(saved) == 8
                and sha(saved[:2]) == self._original_prefix,
                "EXACT_B_ARM_FINAL_HISTORY_REQUIRED")
        typed = copy.deepcopy(saved)
        for step in range(3):
            row = state["completed_steps"][step]
            pair = linked["source_call_id_return_bindings"][step]
            source = self._responses[step]
            actual = row["arms"][arm]
            assistant, tool = typed[2+2*step:4+2*step]
            stored_assistant = saved[2+2*step]
            stored_tool = saved[3+2*step]
            require(row["step"] == pair["step"] == step
                    and row["actual_generation_ordinal"] == pair["ordinal"] == ORDINALS[step]
                    and row["candidate_sha256"] == source["candidate_sha256"]
                    and pair["source_tool_call_id"] == source["call_id"]
                    and actual["disposition"] == "COMMITTED"
                    and actual["native_dispatch_count"] == 1
                    and pair["arms"][arm]["native_return_sha256"] == sha(actual["native_return"])
                    and pair["arms"][arm]["candidate_sha256"] == actual["candidate_sha256"]
                    and pair["arms"][arm]["post_state_sha256"] == actual["post_state_sha256"]
                    and stored_tool["tool_call_id"] == source["call_id"]
                    and stored_tool["tool_call"] == stored_assistant["tool_calls"][0]
                    and stored_tool["error"] is None
                    and sha(stored_tool) == pair["arms"][arm]["native_tool_message_sha256"],
                    "NO_TERMINAL_BEFORE_EXACT_GOVERNED_NATIVE_HISTORY")
            require(type(assistant["tool_calls"]) is list and
                    len(assistant["tool_calls"]) == 1
                    and type(tool["tool_call"]) is dict,
                    "NATIVE_JSON_HISTORY_SHAPE_REQUIRED")
            assistant["tool_calls"] = [FunctionCall(**assistant["tool_calls"][0])]
            tool["tool_call"] = FunctionCall(**tool["tool_call"])
            require(jsonable(assistant) == stored_assistant
                    and jsonable(tool) == stored_tool,
                    "TYPED_NATIVE_HISTORY_NOT_JSON_LOSSLESS")

        wire = [_message_to_openai(message, MODEL_ID) for message in typed]
        require(len(wire) == 8
                and all(self.journal[step]["wire_messages"] ==
                        wire[:2+2*step] for step in range(3))
                and all(len(self.journal[step]["wire_messages"]) == 2+2*step
                        for step in range(3)),
                "TERMINAL_WIRE_DIVERGED_FROM_PREVIOUS_REAL_SOURCE_QUERIES")
        for step in range(3):
            require(wire[3+2*step]["role"] == "tool"
                    and wire[3+2*step]["tool_call_id"]
                    == linked["source_call_id_return_bindings"][step]["source_tool_call_id"],
                    "TERMINAL_NATIVE_RESULT_CALL_ID_MISMATCH")
        tools = []
        request_hash = sha({"messages": wire, "tools": tools})
        entry = {
            "phase": TERMINAL_PHASE,
            "source_arm": arm,
            "status": "ATTEMPTED",
            "model": MODEL_ID,
            "wire_request_sha256": request_hash,
            "wire_messages": copy.deepcopy(wire),
            "wire_tools": [],
            "tool_schemas_exposed": 0,
            "prior_native_tool_results": 3,
            "source_candidate_queries_before_terminal": len(self.journal),
            "composed_native_sha256": sha(state),
            "provider_authenticity_proven": False,
        }
        self._terminal_journal.append(entry)
        try:
            completion = create_completion_once(
                client=self._client, messages=wire, tools=tools)
            require(self._phase == "COMPLETE_OFFLINE_CAPTURE"
                    and sha({"messages": wire, "tools": tools}) == request_hash
                    and len(completion.choices) == 1,
                    "SINGLE_UNMUTATED_TERMINAL_RESPONSE_REQUIRED")
            raw = completion.choices[0].message
            require(raw.role == "assistant"
                    and not getattr(raw, "refusal", None)
                    and raw.tool_calls is None
                    and type(raw.content) is str
                    and bool(raw.content.strip()),
                    "TEXT_ONLY_TERMINAL_NO_MORE_TOOLS_REQUIRED")
            decoded = _openai_to_assistant_message(raw)
            require(type(decoded) is dict
                    and decoded["role"] == "assistant"
                    and decoded["tool_calls"] is None
                    and decoded["content"] is not None
                    and sha(jsonable(decoded)) == sha(jsonable(
                        _openai_to_assistant_message(raw))),
                    "NATIVE_TERMINAL_DECODE_REQUIRED")
            entry.update(status="RESPONSE_DECODED",
                         decoded_response=jsonable(decoded),
                         response_sha256=sha(jsonable(decoded)))
            result = {
                "rule_of_one": RULE,
                "determination": "BOUNDED_OFFLINE_B_ARM_TERMINAL_TEXT_TESTED",
                "source_mode": "OFFLINE_INJECTED_CLIENT",
                "source_arm_for_continuation": arm,
                "original_request_digest": self._envelope.digest,
                "source_model_candidate_queries": 3,
                "terminal_model_queries": 1,
                "total_offline_queries": 4,
                "source_candidate_ordinal_sequence": list(ORDINALS),
                "terminal_wire_message_count": len(wire),
                "terminal_tool_schemas_exposed": 0,
                "terminal_wire_request_sha256": request_hash,
                "terminal_text": raw.content,
                "terminal_response_sha256": sha(jsonable(decoded)),
                "terminal_history_uses_all_three_actual_B_native_returns": True,
                "native_return_bindings": 6,
                "post_terminal_native_dispatches": 0,
                "provider_calls": 0,
                "scorer_calls": 0,
                "automatic_retries": 0,
                "model_provider_authenticated": False,
                "external_effect_authenticated": False,
                "A_arm_terminal_answer_tested": False,
                "real_provider_full_conversation_proven": False,
                "Final128_utility_recovery_proven": False,
                "candidate_history_proof": copy.deepcopy(linked),
                "terminal_transport_journal": copy.deepcopy(self._terminal_journal),
                "composed_native_execution": copy.deepcopy(state),
            }
            self._terminal_output = copy.deepcopy(result)
            self._phase = "COMPLETE_OFFLINE_TERMINAL"
            return result
        except BaseException:
            entry["status"] = "FAILED_OR_CANCELLED"
            raise

    def run(self):
        # No replay after a completed or failed capture, and no second final call.
        if self._attempted or self._terminal_attempted:
            raise Task15NativeCaptureViolation("OFFLINE_CAPTURE_ONE_ATTEMPT_ONLY")
        try:
            linked = super().run()
            return self._terminal_query(linked)
        except BaseException:
            self._phase = "TERMINAL_UNKNOWN_OR_FAILED"
            self._terminal_output = None
            self._provisional = {
                "native_execution": self._runner.observation(),
                "source_transport_journal": copy.deepcopy(self.journal),
                "terminal_transport_journal": copy.deepcopy(self._terminal_journal),
                "completed_terminal_output": False,
                "retry_allowed": False,
                "no_effect_or_rollback_claim": False,
            }
            raise

    def observation(self):
        observed = super().observation()
        observed.update(rule_of_one=RULE,
                        terminal_query_attempted=self._terminal_attempted,
                        terminal_model_queries=len(self._terminal_journal),
                        terminal_journal=copy.deepcopy(self._terminal_journal),
                        complete_terminal_output=self._terminal_output is not None,
                        model_provider_authenticated=False,
                        scorer_calls=0)
        return observed
