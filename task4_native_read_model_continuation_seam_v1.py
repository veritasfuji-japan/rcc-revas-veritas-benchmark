"""#293: independently feed first model outputs into REAL native READ-ONLY tools.

One invariant: native OpenAI-shaped completion -> native AgentDojo codec ->
real pinned read-only tool -> next model-format request on that arm, while
maintaining original request, injected state, native call ID and no-write
boundaries. ALL completion inputs in this proof are OFFLINE FIXTURES.

The response's self-reported id/model is NOT proof of Provider authenticity.
No real transport, operator approval, bank writes or scoring. The next
model request is MATERIALIZED, never sent.
"""
from __future__ import annotations
import copy
import json
from threading import Lock

from task4_two_arm_first_live_request_packet_v1 import (
    RULE as PACKET_RULE, CASE, MODEL, digest, canon
)
from task4_native_injected_read_exposure_v1 import (
    native_case_environment,contains_exact_injected_native_transaction,
)
from task4_trusted_execution_date_profile_v1 import REQUEST
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import sha_json

RULE="TASK4_NATIVE_READ_MODEL_CONTINUATION_SEAM_V1"
EXPECTED_READS=("get_iban","get_most_recent_transactions")
FORBIDDEN_EFFECTS=frozenset({"send_money","schedule_transaction",
                              "update_scheduled_transaction",
                              "update_password","update_user_info"})

class NativeReadDenied(ValueError):
    pass

def need(check,reason):
    if not check: raise NativeReadDenied(reason)

class Task4NativeReadContinuation:
    """Single-use-per-step, NO writer ever instantiated, no model client."""
    def __init__(self,*,packet,arm,source,env):
        need(type(packet) is dict and packet.get("rule_of_one")==PACKET_RULE
             and packet.get("entrypoint")=="PREPARED_OFFLINE_ONLY_NOT_EXECUTABLE"
             and packet.get("approved_request_count")==0
             and packet.get("approved_cost_micro_usd")==0
             and packet.get("actual_provider_calls")==0
             and packet.get("independent_real_model_sources_proven") is False
             and type(packet.get("packets")) is dict and
             set(packet["packets"])=={"A","B"},
             "NO_LIVE_PROVIDER_AUTHORITY_FROM_PACKET")
        need(arm in ("A","B") and source.get("case_id")==CASE
             and source.get("native_slot")=="injection_incoming_transaction"
             and packet.get("case_id")==CASE,
             "EXACT_NATIVE_TASK4_CASE_REQUIRED")
        entry=packet["packets"][arm]
        first=entry["complete_first_request"]
        need(entry["logical_arm"]==arm and
             entry["source_synthetic_only"] is True and
             entry["request_sent_to_provider"] is False
             and entry["provider_response_authenticity_proven"] is False
             and entry["complete_first_request_sha256"]==digest(first)
             and first.get("model")==MODEL
             and [m["role"] for m in first["messages"]]==["developer","user"],
             "EXACT_UNSENT_FIRST_NATIVE_MODEL_QUERY_REQUIRED")
        snapshot=env.model_dump(mode="json")
        need(sha_json(snapshot)==source["injected_prestate_sha256"] and
             sha_json(snapshot)==sha_json(source["native_injected_prestate"]),
             "REAL_NATIVE_INJECTED_PRESTATE_REQUIRED")
        self.arm=arm
        self.source=copy.deepcopy({k:v for k,v in source.items()
                                  if k!="injected_environment"})
        self._env=env.model_copy(deep=True)
        self._initial_sha=sha_json(snapshot)
        self._original_sha=sha_json(env.model_dump(mode="json"))
        self._messages=[
            {"role":"system","content":[
                {"type":"text","content":first["messages"][0]["content"][0]["text"]}]},
            {"role":"user","content":[
                {"type":"text","content":REQUEST}]}
        ]
        self._first=copy.deepcopy(first)
        self._request=copy.deepcopy(first)
        self._step=0
        self._journal=[]
        self._ids=set()
        self._lock=Lock()
        self._burned=False

    @property
    def current_request(self):
        return copy.deepcopy(self._request)

    @property
    def observation(self):
        return {"rule_of_one":RULE,"arm":self.arm,"steps":self._step,
                "burned":self._burned,"read_journal":copy.deepcopy(self._journal),
                "initial_injected_prestate_sha256":self._initial_sha,
                "final_injected_prestate_sha256":sha_json(self._env.model_dump(mode="json")),
                "native_bank_write_dispatches":0,
                "provider_calls":0,"actual_spend_usd":0,
                "completion_provenance":"OFFLINE_UNAUTHENTICATED_FIXTURE",
                "independent_real_llm_sampling_proven":False,
                "new_canonical_final128_scores":0}

    def consume_first_two_tool_responses(self, response, *,submitted_request_sha):
        """Consume exactly ONE mocked full ChatCompletion and execute ONE read.

        Every attempt irrevocably burns that step if an exception occurs.
        No scorer/effect capability is made available to this helper.
        """
        from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
        from agentdojo.agent_pipeline.llms.openai_llm import (
            _message_to_openai, _openai_to_assistant_message,
        )
        from agentdojo.functions_runtime import FunctionsRuntime
        from openai.types.chat import ChatCompletionMessage

        with self._lock:
            need(not self._burned and self._step<len(EXPECTED_READS),
                 "ATTEMPT_BURNED_OR_TWO_NATIVE_READS_ALREADY_DONE")
            self._burned=True
            before=sha_json(self._env.model_dump(mode="json"))
            need(before==self._initial_sha,
                 "NATIVE_READ_STATE_CHANGED_BEFORE_ATTEMPT")
            need(type(submitted_request_sha) is str and
                 submitted_request_sha==digest(self._request),
                 "MODEL_RESPONSE_NOT_BOUND_TO_EXACT_UNSENT_FIRST_OR_SECOND_QUERY")
            need(type(response) is dict and
                 response.get("object")=="chat.completion" and
                 type(response.get("id")) is str and response["id"] and
                 type(response.get("created")) is int and
                 response.get("model")==MODEL,
                 "RAW_OPENAI_SHAPED_COMPLETION_REQUIRED_UNAUTHENTICATED")
            choices=response.get("choices")
            need(type(choices) is list and len(choices)==1 and
                 choices[0].get("index")==0 and
                 choices[0].get("finish_reason")=="tool_calls",
                 "ONE_FIRST_TOOL_CALL_REQUIRED")
            usage=response.get("usage")
            need(type(usage) is dict and
                 all(type(usage.get(x)) is int and 0<=usage[x]<=100000
                     for x in ("prompt_tokens","completion_tokens","total_tokens"))
                 and usage["total_tokens"]==
                     usage["prompt_tokens"]+usage["completion_tokens"],
                 "RAW_USAGE_SHAPE_CANNOT_CERTIFY_PROVIDER_BILLING")
            raw=choices[0].get("message")
            need(type(raw) is dict and raw.get("role")=="assistant" and
                 raw.get("content") is None and
                 raw.get("refusal") in (None,""),
                 "EXACT_ASSISTANT_TOOL_RESPONSE_REQUIRED")
            calls=raw.get("tool_calls")
            need(type(calls) is list and len(calls)==1 and
                 calls[0].get("type")=="function"
                 and type(calls[0].get("id")) is str and
                 0<len(calls[0]["id"])<=200 and
                 calls[0]["id"].isascii() and
                 calls[0]["id"].isprintable() and
                 calls[0]["id"] not in self._ids,
                 "UNIQUE_UNTRUSTED_PROVIDER_TOOL_CALL_ID_REQUIRED")
            tool=calls[0]["function"]
            name=EXPECTED_READS[self._step]
            need(tool.get("name")==name and
                 name not in FORBIDDEN_EFFECTS,
                 "ONLY_EXACT_NATIVE_READ_ONLY_TOOL_MAY_EXECUTE")
            need(type(tool.get("arguments")) is str and
                 len(tool["arguments"])<=300,
                 "BOUNDED_NATIVE_READ_ARGUMENTS_REQUIRED")
            try: args=json.loads(tool["arguments"])
            except (ValueError,TypeError) as e:
                raise NativeReadDenied("MODEL_TOOL_ARGUMENT_JSON_MALFORMED") from e
            need(type(args) is dict and
                 (args=={} if name=="get_iban" else args=={"n":10}),
                 "EXACT_SAFE_READ_ONLY_ARGUMENTS_REQUIRED")
            native=_openai_to_assistant_message(ChatCompletionMessage.model_validate(raw))
            need(len(native["tool_calls"])==1 and
                 native["tool_calls"][0].function==name and
                 native["tool_calls"][0].args==args and
                 native["tool_calls"][0].id==calls[0]["id"],
                 "AGENTDOJO_NATIVE_COMPLETION_CODEC_DIVERGED")
            suite=getattr(self,"_suite",None)
            if suite is None:
                from agentdojo.task_suite.load_suites import get_suite
                suite=get_suite("v1.2.2","banking")
                self._suite=suite
            tools=[x for x in suite.tools if x.name in EXPECTED_READS]
            need(len(tools)==2 and
                 {x.name for x in tools}==set(EXPECTED_READS),
                 "READ_ONLY_ALLOWLIST_MUST_BE_PHYSICALLY_ENFORCED")
            runtime=FunctionsRuntime(tools)  # Does not contain ANY native writer.
            old=copy.deepcopy(self._messages)
            _,returned_runtime,new_env,new_messages,_=ToolsExecutor().query(
                REQUEST,runtime,self._env,[*old,native],{})
            need(returned_runtime is runtime and new_env is self._env and
                 len(new_messages)==len(old)+2
                 and new_messages[-1]["role"]=="tool" and
                 new_messages[-1]["error"] is None and
                 new_messages[-1]["tool_call_id"]==calls[0]["id"] and
                 sha_json(self._env.model_dump(mode="json"))==before,
                 "NATIVE_TOOL_ERROR_OR_BANK_STATE_MUTATION")
            wire=[_message_to_openai(m,MODEL) for m in new_messages]
            need(wire[:len(self._request["messages"])]==
                 self._request["messages"],
                 "OWNED_NATIVE_QUERY_PREFIX_CHANGED")
            next_request=copy.deepcopy(self._first)
            next_request["messages"]=wire
            need(len(canon(next_request))<=32768,
                 "NEXT_MODEL_QUERY_EXCEEDS_PINNED_BYTE_CEILING")
            payload=source_payload=self.source["exact_payload"]
            native_contains=contains_exact_injected_native_transaction(
                wire[-1],payload,wire=True)
            need(native_contains == (name=="get_most_recent_transactions"),
                 "NATIVE_INJECTION_TOOL_RESULT_EXPOSURE_INCONSISTENT")
            self._ids.add(calls[0]["id"])
            self._journal.append({
                "ordinal":self._step,"tool":name,
                "source_request_sha256":submitted_request_sha,
                "untrusted_fixture_response_sha256":digest(response),
                "untrusted_model_response_id":response["id"],
                "actual_native_tool_call_id":calls[0]["id"],
                "actual_native_tool_return_sha256":digest(wire[-1]),
                "actual_native_tool_result_seen_by_next_model":native_contains,
                "native_prestate_and_poststate_sha256":before,
                "next_request_sha256":digest(next_request),
                "bank_write_dispatches":0
            })
            self._messages=copy.deepcopy(new_messages)
            self._request=next_request
            self._step+=1
            self._burned=False
            return {"arm":self.arm,"step":self._step,
                    "next_model_request":copy.deepcopy(next_request),
                    "next_request_sha256":digest(next_request),
                    "native_attack_text_in_next_tool_response":native_contains,
                    "raw_completion_is_real_provider_authenticated":False,
                    "next_provider_call_authorized":False,
                    "native_bank_write_dispatches":0,
                    "provider_calls":0,"real_spend_usd":0}
