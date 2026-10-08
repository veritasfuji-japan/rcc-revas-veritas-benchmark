"""Bounded source-at-capture native assistant messages for governed Task15 A/B.

A trust-owned injected client supplies native chat-completion response objects.
The model may propose a CandidateAction but cannot obtain/issue authorizations,
edit request authority, dispatch a native tool or grant a retry. Every effect
still runs solely through the exact, unchanged #246 RCC/Bind/native runner.

This V1 test harness ALLOWS ONLY OFFLINE INJECTED CLIENTS. It proves wire
preservation and linkage, NOT real provider execution, utility, or authenticity.
Actual model/provider transport is a separate future authorization boundary.
"""
from __future__ import annotations

import copy
from threading import RLock
from typing import Any

from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable
from scripts.agentdojo_openai_frozen_adapter_v0_1 import create_completion_once, MODEL_ID
from task15_frozen_openai_wire_controlled_refund_adapter_v1 import strict_arguments
from task15_native_address_request_profile_issuance_v1 import canonical, sha
from task15_controlled_multi_effect_composed_admission_runner_v1 import (
    Task15ControlledMultiEffectComposedRunner, FUNCTIONS, ORDINALS,
)
from task15_prospective_controlled_refund_trajectory_v1 import SYSTEM_MESSAGE

RULE = "TASK15_NATIVE_MODEL_RESPONSE_CAPTURE_BOUNDARY_V1"
ALLOWED_TOOLS = frozenset(FUNCTIONS)

class Task15NativeCaptureViolation(ValueError):
    pass

def require(value,reason):
    if not value:
        raise Task15NativeCaptureViolation(reason)

class Task15OfflineNativeModelCapture:
    """One local run, three source-captured proposed native calls and two texts.

    External effects, actual authenticated response provenance, final benchmark
    scoring and access to fresh production credentials are excluded in V1.
    Constructor is trusted; the owned client is a test-only injection seam.
    """
    def __init__(self, *, runner, envelope, client, transport_mode="OFFLINE_INJECTED_CLIENT"):
        require(type(runner) is Task15ControlledMultiEffectComposedRunner and
                runner.observation()["phase"]=="READY" and
                transport_mode=="OFFLINE_INJECTED_CLIENT",
                "EXACT_FRESH_OFFLINE_COMPOSED_RUNNER_REQUIRED")
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

    def _verify_tools(self):
        # Only the actual version-pinned native functions' schemas are exposed.
        from agentdojo.task_suite.load_suites import get_suite
        from agentdojo.agent_pipeline.llms.openai_llm import _function_to_openai
        from agentdojo.functions_runtime import Function
        suite=get_suite("v1.2.2","banking")
        tools=[tool for tool in suite.tools if tool.name in ALLOWED_TOOLS]
        require(len(tools)==len(ALLOWED_TOOLS) and
                {tool.name for tool in tools}==set(ALLOWED_TOOLS) and
                all(type(tool) is Function for tool in tools),
                "EXACT_NATIVE_THREE_TOOL_DEFINITIONS_REQUIRED")
        native=[_function_to_openai(t) for t in tools]
        digest=sha(native)
        require(self._native_tool_identity is None or
                self._native_tool_identity==digest, "NATIVE_SCHEMAS_CHANGED")
        self._native_tools,self._native_tool_identity=copy.deepcopy(native),digest
        return copy.deepcopy(native)

    def _query(self, *, history, phase, ordinal, expected_tool=None):
        from agentdojo.agent_pipeline.llms.openai_llm import (
            _message_to_openai, _openai_to_assistant_message,
        )
        require(self._phase=="RUNNING" and
                sha(jsonable(history[:2]))==self._original_prefix and
                sha(jsonable(self._history[:2]))==self._original_prefix and
                type(ordinal) is int and ordinal>=0,
                "OWNED_QUERY_CONTEXT_REQUIRED")
        tools=self._verify_tools() if expected_tool else []
        wire=[_message_to_openai(m,self._source_model_id) for m in history]
        request_hash=sha({"messages":wire,"tools":tools})
        entry={"sequence":len(self.journal),"phase":phase,"ordinal":ordinal,
               "model":self._source_model_id,"wire_request_sha256":request_hash,
               "native_tools_sha256":sha(tools),"wire_messages":copy.deepcopy(wire),
               "wire_tools":copy.deepcopy(tools),"status":"ATTEMPTED"}
        self.journal.append(entry)
        try:
            completion=create_completion_once(client=self._client,messages=wire,tools=tools)
            require(self._phase=="RUNNING" and
                    sha({"messages":wire,"tools":tools})==request_hash,
                    "TRANSPORT_MUTATED_OWNED_REQUEST")
            require(len(completion.choices)==1, "EXACT_ONE_NATIVE_RESPONSE_CHOICE_REQUIRED")
            raw=completion.choices[0].message
            require(raw.role=="assistant" and not getattr(raw,"refusal",None),
                    "SOURCE_ASSISTANT_OR_REFUSAL_INVALID")
            calls=raw.tool_calls
            if expected_tool:
                require(type(calls) is list and len(calls)==1 and
                        raw.content is None, "ONE_CAPTURED_PROTECTED_NATIVE_CALL_REQUIRED")
                call=calls[0]
                require(call.type=="function" and
                        call.function.name==expected_tool and
                        type(call.id) is str and 0<len(call.id)<=200 and
                        call.id.isascii() and call.id.isprintable() and
                        call.id not in self._call_ids,
                        "EXPECTED_UNIQUE_NATIVE_CALL_ID_REQUIRED")
                args=strict_arguments(call.function.arguments)
                self._call_ids.add(call.id)
            else:
                require(calls is None and type(raw.content) is str and
                        bool(raw.content.strip()),"TERMINAL_TEXT_NO_MORE_EFFECT_REQUIRED")
                args=None
            message=_openai_to_assistant_message(raw)
            require(type(message) is dict and message["role"]=="assistant" and
                    (message["tool_calls"] is None if expected_tool is None
                    else len(message["tool_calls"])==1),
                    "NATIVE_DECODED_MESSAGE_REQUIRED")
            if expected_tool:
                call=message["tool_calls"][0]
                require(call.function==expected_tool and
                        call.id==raw.tool_calls[0].id and
                        canonical(call.args)==canonical(args) and
                        call.placeholder_args is None,
                        "SOURCE_NATIVE_CODEC_DIVERGENCE")
            entry.update(status="RESPONSE_DECODED",
                         response_sha256=sha(jsonable(message)),
                         decoded_response=jsonable(message))
            return message
        except BaseException:
            entry["status"]="FAILED_OR_CANCELLED"
            raise

    @staticmethod
    def _native_result_message(row, captured_call):
        from agentdojo.types import text_content_block_from_string
        from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
        require(row["arms"]["A"]["disposition"]=="COMMITTED" and
                row["arms"]["B"]["disposition"]=="COMMITTED" and
                row["arms"]["A"]["native_dispatch_count"]==1 and
                row["arms"]["B"]["native_dispatch_count"]==1 and
                row["arms"]["A"]["candidate_sha256"]==
                    row["arms"]["B"]["candidate_sha256"]==
                    row["candidate_sha256"] and
                row["arms"]["A"]["pre_state_sha256"]==
                    row["arms"]["B"]["pre_state_sha256"] and
                row["arms"]["A"]["post_state_sha256"]==
                    row["arms"]["B"]["post_state_sha256"],
                "GOVERNED_NATIVE_PAIR_DIVERGED")
        a,b=row["arms"]["A"],row["arms"]["B"]
        require(type(a["native_return"]) is list and len(a["native_return"])==2 and
                a["native_return"][1] is None and
                canonical(a["native_return"])==canonical(b["native_return"]),
                "ACTUAL_ARM_RETURN_NOT_SHARED")
        return {"role":"tool","content":[text_content_block_from_string(
                   tool_result_to_str(a["native_return"][0]))],
                "tool_call_id":captured_call.id,
                "tool_call":copy.deepcopy(captured_call),"error":None}

    def run(self):
        from rveval.models import CandidateAction
        with self._lock:
            require(not self._attempted and self._phase=="READY",
                    "OFFLINE_CAPTURE_ONE_ATTEMPT_ONLY")
            self._attempted=True
            self._phase="RUNNING"
        try:
            def generator(view):
                step=view["component_proof_slot"]
                require(step==len(self._responses) and
                        view["actual_generation_ordinal"]==ORDINALS[step] and
                        view["function"]==FUNCTIONS[step] and
                        view["original_request_digest"]==self._envelope.digest,
                        "CAPTURE_ORDER_OR_OWNED_REQUEST_CHANGED")
                if step:
                    observation=self._runner.observation()
                    require(observation["phase"]=="RUNNING" and
                            len(observation["completed_steps"])==step,
                            "MISSING_PRIOR_ACTUAL_EFFECT")
                    row=observation["completed_steps"][-1]
                    previous=self._responses[-1]
                    require(row["step"]==step-1 and
                            row["candidate_sha256"]==previous["candidate_sha256"],
                            "PRIOR_SOURCE_CAPTURE_NOT_EXECUTED")
                    # Convert real completed native A/B return into a shared
                    # history, never predict the tool output from candidate.
                    self._history.append(
                        self._native_result_message(row,previous["call"]))
                history=copy.deepcopy(self._history)
                native=self._query(history=history,phase="PROTECTED_CANDIDATE",
                                   ordinal=ORDINALS[step],expected_tool=FUNCTIONS[step])
                call=native["tool_calls"][0]
                candidate=CandidateAction("tool_call",name=call.function,
                                           arguments=copy.deepcopy(call.args))
                payload=candidate.to_dict()
                require(payload["kind"]=="tool_call" and
                        payload["name"]==FUNCTIONS[step] and
                        payload["metadata"]=={} and payload["content"] is None,
                        "NATIVE_CANDIDATE_UNMODIFIED_REQUIRED")
                rec={"step":step,"ordinal":ORDINALS[step],
                     "call_id":call.id,"candidate_sha256":sha(payload),
                     "source_assistant_sha256":sha(jsonable(native)),
                     "call":copy.deepcopy(call)}
                self._responses.append(rec)
                self._history.append(copy.deepcopy(native))
                return candidate

            result=self._runner.run(generator)
            require(result["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN" and
                    len(result["completed_steps"])==3 and len(self._responses)==3,
                    "ONLY_FULL_NATIVE_COMPOSED_COMPLETION_CONTINUES")
            rows=result["completed_steps"]
            for i,(rec,row) in enumerate(zip(self._responses,rows)):
                require(i==row["step"] and
                        row["candidate_sha256"]==rec["candidate_sha256"] and
                        row["actual_generation_ordinal"]==rec["ordinal"],
                        "SOURCE_RESPONSE_NOT_BOUND_TO_NATIVE_EFFECT")
            common=copy.deepcopy(self._history)
            final_tool=self._native_result_message(rows[-1],self._responses[-1]["call"])
            common.append(final_tool)
            common_hash=sha(jsonable(common))
            arms=[]
            for arm in ("A","B"):
                # Only after all native effects are terminal. Tool exposure is
                # empty and all additional proposed effects fail closed.
                response=self._query(history=copy.deepcopy(common),
                                     phase="TERMINAL_"+arm,ordinal=ORDINALS[-1]+1)
                arms.append({"arm":arm,"messages":jsonable([*common,response]),
                             "native_final_state_sha256":result[
                                 "latest_local_state_sha256"][arm],
                             "terminal_assistant_sha256":sha(jsonable(response)),
                             "status":"TERMINAL_TEXT_AVAILABLE"})
            self._phase="COMPLETE_OFFLINE_CAPTURE"
            return {"rule_of_one":RULE,
                    "source_mode":"OFFLINE_INJECTED_CLIENT",
                    "provider_execution":False,
                    "provider_response_authenticity_proven":False,
                    "actual_provider_utility_measured":False,
                    "new_injection_attack_measured":False,
                    "production_readiness":False,
                    "utility_scored":False,
                    "original_request_digest":self._envelope.digest,
                    "source_model_id_configured":self._source_model_id,
                    "source_candidate_events":[{
                        k:v for k,v in rec.items() if k!="call"
                    } for rec in self._responses],
                    "common_history_sha256":common_hash,
                    "arms":arms,
                    "composed_native_execution":copy.deepcopy(result),
                    "transport_journal":copy.deepcopy(self.journal),
                    "new_provider_calls":0,
                    "new_external_effects":0,
                    "new_authority_issued_by_wire":0,
                    "scorer_calls":0,
                    "automatic_retries":0}
        except BaseException:
            self._phase="TERMINAL_UNKNOWN_OR_FAILED"
            # A committed native effect might precede a late model/codec
            # exception; the original runner observation remains available.
            self._provisional={"native_execution":self._runner.observation(),
                               "transport_journal":copy.deepcopy(self.journal)}
            raise

    def observation(self):
        with self._lock:
            return {"rule_of_one":RULE,"phase":self._phase,
                    "candidate_capture_count":len(self._responses),
                    "source_mode":"OFFLINE_INJECTED_CLIENT",
                    "transport_journal":copy.deepcopy(self.journal),
                    "unreconciled_on_failure":copy.deepcopy(self._provisional),
                    "provider_execution":False,
                    "new_authority_issued_by_wire":0,
                    "retry_allowed":False}
