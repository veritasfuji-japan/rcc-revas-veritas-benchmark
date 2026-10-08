"""Bounded offline captured assistant call ID -> governed native tool return.

No new authority or provider transport. Both the source native codec from PR248
and the native composed return receipts from PR251 retain their exact pinned
implementation. Messages are constructed *after* all three local steps, NOT fed
back into the original offline candidate queries. Continuity is NOT proven.
"""
from __future__ import annotations
import copy
from threading import RLock
from task15_native_model_response_capture_boundary_v1 import (
    Task15OfflineNativeModelCapture,
    Task15NativeCaptureViolation, require, ORDINALS, FUNCTIONS,
    SYSTEM_MESSAGE, MODEL_ID, jsonable, canonical, sha,
)
from task15_composed_native_return_binding_v1 import (
    Task15ComposedNativeReturnBindingRunnerV1,
)

RULE="TASK15_MODEL_CALL_ID_TO_NATIVE_TOOL_RETURN_HISTORY_V1"

class Task15OfflineModelCallIdNativeReturnHistoryV1(Task15OfflineNativeModelCapture):
    """V1 exact-call-ID to actual native JSON result association, no model replay."""
    def __init__(self, *, runner, envelope, client, transport_mode="OFFLINE_INJECTED_CLIENT"):
        require(type(runner) is Task15ComposedNativeReturnBindingRunnerV1 and
                runner.observation()["phase"]=="READY" and
                transport_mode=="OFFLINE_INJECTED_CLIENT",
                "EXACT_FRESH_OFFLINE_COMPOSED_RETURN_RUNNER_REQUIRED")
        require(type(envelope.instruction) is str and envelope.digest==runner._envelope_digest,
                "ORIGINAL_REQUEST_AUTHORITY_REQUIRED")
        require(callable(getattr(getattr(getattr(client,"chat",None),"completions",None),"create",None)),
                "INJECTED_NATIVE_COMPLETION_CLIENT_REQUIRED")
        self._runner,self._client,self._envelope=runner,client,envelope
        self._attempted=False
        self._lock=RLock()
        self.journal=[]
        self._history=[
            {"role":"system","content":[{"type":"text","content":SYSTEM_MESSAGE}]},
            {"role":"user","content":[{"type":"text","content":envelope.instruction}]},
        ]
        self._responses=[]
        self._call_ids=set()
        self._original_prefix=sha(jsonable(self._history))
        self._native_tools=None
        self._native_tool_identity=None
        self._phase="READY"
        self._source_model_id=MODEL_ID
        self._provisional=None

    def _build_history(self, result):
        from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
        from agentdojo.types import text_content_block_from_string
        from agentdojo.agent_pipeline.llms.openai_llm import _message_to_openai
        require(result["composed_native_execution"]["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN"
                and result["native_tool_returns_exposed"] is False
                and result["native_conversation_captured"] is False
                and result["model_queries_independent_by_step"] is True
                and len(result["source_candidate_events"])==len(ORDINALS)==3,
                "FROZEN_OFFLINE_SOURCE_SCOPE_REQUIRED")
        composed=result["composed_native_execution"]
        rows=composed["completed_steps"]
        local=composed["local_native_return_history"]
        require(composed["native_return_history_fully_composed"] is True
                and len(rows)==len(local)==3
                and len(self.journal)==len(self._responses)==3,
                "EXACT_COMPOSED_RETURN_HISTORY_REQUIRED")
        # These histories are held per arm; no reuse of B tool output in A.
        histories={arm:copy.deepcopy(self._history) for arm in ("A","B")}
        bindings=[]
        seen=set()
        for i,(rec,row,native) in enumerate(zip(self._responses,rows,local)):
            displayed=result["source_candidate_events"][i]
            require(type(displayed) is dict
                    and displayed["step"]==rec["step"]
                    and displayed["ordinal"]==rec["ordinal"]
                    and displayed["call_id"]==rec["call_id"]
                    and displayed["candidate_sha256"]==rec["candidate_sha256"]
                    and displayed["source_assistant_sha256"]==rec["source_assistant_sha256"],
                    "FROZEN_SOURCE_EVENT_PROVENANCE_CHANGED")
            require(type(rec["call_id"]) is str and rec["call_id"] not in seen
                    and 0<len(rec["call_id"])<=200
                    and rec["call_id"].isascii() and rec["call_id"].isprintable(),
                    "SOURCE_CALL_ID_UNIQUE_AND_VALID_REQUIRED")
            seen.add(rec["call_id"])
            origin=self.journal[i]
            message=origin.get("decoded_response")
            require(origin["status"]=="RESPONSE_DECODED"
                    and origin["phase"]=="PROTECTED_CANDIDATE"
                    and origin["ordinal"]==ORDINALS[i]
                    and origin["response_sha256"]==rec["source_assistant_sha256"]
                    and sha(message)==rec["source_assistant_sha256"],
                    "SOURCE_CAPTURED_ASSISTANT_CHANGED")
            require(type(message) is dict and message["role"]=="assistant"
                    and type(message["tool_calls"]) is list
                    and len(message["tool_calls"])==1
                    and jsonable(rec["call"])==message["tool_calls"][0],
                    "CAPTURED_CALL_OBJECT_CHANGED")
            require(row["step"]==native["step"]==rec["step"]==i
                    and row["actual_generation_ordinal"]==native["actual_generation_ordinal"]==rec["ordinal"]
                    and row["candidate_sha256"]==native["candidate_sha256"]==rec["candidate_sha256"]
                    and native["function"]==rec["call"].function==FUNCTIONS[i]
                    and rec["call"].id==rec["call_id"],
                    "MODEL_CALL_TO_EFFECT_CANDIDATE_NOT_PINNED")
            pair={"step":i,"ordinal":ORDINALS[i],
                  "source_tool_call_id":rec["call_id"],
                  "source_assistant_sha256":rec["source_assistant_sha256"],
                  "candidate_sha256":rec["candidate_sha256"],
                  "actual_pairing_identity_sha256":row["actual_pairing_identity_sha256"],
                  "arms":{}}
            for arm in ("A","B"):
                arm_result=row["arms"][arm]
                bound=native["arms"][arm]
                returned=arm_result.get("native_return")
                require(arm_result["disposition"]=="COMMITTED"
                        and arm_result["native_dispatch_count"]==1
                        and type(returned) is list and len(returned)==2
                        and returned[1] is None
                        and type(returned[0]) is dict
                        and bound["native_return"]==returned
                        and canonical(returned)==bound["native_return_canonical_json"]
                        and sha(returned)==bound["native_return_sha256"]
                        and arm_result["candidate_sha256"]==bound["candidate_sha256"]==rec["candidate_sha256"]
                        and arm_result["pre_state_sha256"]==bound["pre_state_sha256"]
                        and arm_result["post_state_sha256"]==bound["post_state_sha256"],
                        "NATIVE_TOOL_RETURN_NOT_FROM_EXACT_GOVERNED_SINK")
                tool={
                    "role":"tool",
                    "content":[text_content_block_from_string(tool_result_to_str(returned[0]))],
                    "tool_call_id":rec["call_id"],
                    "tool_call":copy.deepcopy(rec["call"]),
                    "error":None,
                }
                # Roundtrip through the actual pinned native wire codec.
                prefix=histories[arm]
                require(sha(prefix[:2])==self._original_prefix,
                        "OWNED_REQUEST_PREFIX_CHANGED")
                prior=copy.deepcopy(prefix)
                prefix.append(copy.deepcopy(message))
                prefix.append(tool)
                converted=_message_to_openai(tool,MODEL_ID)
                require(converted["role"]=="tool"
                        and converted["tool_call_id"]==rec["call_id"],
                        "ACTUAL_NATIVE_TOOL_MESSAGE_CODEC_DIVERGENCE")
                pair["arms"][arm]={
                    "pre_history_sha256":sha(prior),
                    "post_history_sha256":sha(jsonable(prefix)),
                    "source_call_id":rec["call_id"],
                    "native_return_sha256":sha(returned),
                    "native_tool_message_sha256":sha(jsonable(tool)),
                    "pre_state_sha256":bound["pre_state_sha256"],
                    "post_state_sha256":bound["post_state_sha256"],
                    "candidate_sha256":rec["candidate_sha256"],
                    "native_dispatch_count":arm_result["native_dispatch_count"],
                }
            bindings.append(pair)
        require(len(bindings)==3 and all(len(histories[arm])==8 for arm in ("A","B")),
                "THREE_COMPLETE_OFFLINE_TOOL_RESULT_LINKS_REQUIRED")
        return {"rule_of_one":RULE,"source_mode":"OFFLINE_INJECTED_CLIENT",
                "source_provider_authenticated":False,
                "source_model_queries_used_prior_tool_results":False,
                "tool_messages_constructed_after_all_native_steps":True,
                "model_continuous_conversation_proven":False,
                "actual_provider_execution":False,
                "terminal_model_continuations":0,
                "scorer_calls":0,"new_provider_calls":0,
                "source_call_id_return_bindings":bindings,
                "arm_histories":{arm:jsonable(history) for arm,history in histories.items()},
                "source_query_transport_journal":copy.deepcopy(self.journal),
                "composed_result_sha256":sha(composed),
                "execution_effect_authenticated":False}

    def run(self):
        # Parent closes the capture token before the first source query.
        # Linkage failures are terminal even after all local native effects.
        try:
            result=super().run()
            history=self._build_history(result)
            return history
        except BaseException:
            self._phase="TERMINAL_UNKNOWN_OR_FAILED"
            self._provisional={
                "native_execution":self._runner.observation(),
                "transport_journal":copy.deepcopy(self.journal),
                "completed_model_history":False}
            raise
