#!/usr/bin/env python3
"""#380 offline MOCK two-turn Responses-shaped Task1 A/B continuity.

The first local fake response selects get_most_recent_transactions(n=100) and
allocates a MOCK_ONLY call_id; the actual pinned native Tool is subsequently
read in two independently owned AgentDojo environments (#378). The next local
fake request pairs the original first response call with its exact native
function_call_output; only B adds #377's checked preterminal projection.

No externally supplied API client, real provider ID, bank write, Native Scorer,
live-approval or production IAM control exists. Explicit fake-origin records
must never become eligible for genuine Utility/scorer evidence.
"""
from __future__ import annotations

from copy import deepcopy
from decimal import Decimal
import json
from types import SimpleNamespace
from typing import Any

from scripts import final128_350_task1_responses_once_budget_v1 as transport
from scripts import final128_351_task1_durable_lease_preflight_v1 as lease
from scripts import final128_378_native_paired_model_input_seam_v1 as owned
from scripts import task1_source_bound_readonly_grounding_v1 as guard

SCHEMA="veritas.final128.task1-native-call-id-mock-continuity.v1"
ARMS=("A","B")
MODEL=transport.MODEL
FIRST_ROLE="user"
MAX_NATIVE_TOOL_BYTES=48000

class Refused(ValueError):
    pass

def need(test,reason):
    if test is not True:
        raise Refused("380_"+reason)

def canonical(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False,
                      separators=(",",":"),allow_nan=False)

def reject_duplicate_fields(pairs):
    obj={}
    for key,value in pairs:
        need(key not in obj,"DUPLICATE_FUNCTION_ARGUMENT_KEY")
        obj[key]=value
    return obj

def _decode_exact_args(raw):
    need(type(raw) is str and len(raw.encode("utf-8"))<=512,
         "INVALID_FUNCTION_ARGUMENT_SOURCE")
    try:
        args=json.loads(raw,object_pairs_hook=reject_duplicate_fields,
                        parse_constant=lambda value: (_ for _ in ()).throw(
                            Refused("380_NONFINITE_JSON_ARGUMENT")))
    except (TypeError,ValueError,OverflowError) as exc:
        raise Refused("380_INVALID_FUNCTION_ARGUMENT_JSON") from exc
    need(type(args) is dict and args==guard.ARGUMENTS
         and type(args.get("n")) is int,
         "NOT_EXACT_NATIVE_READONLY_TOOL_ARGUMENT")
    return args

def exact_first_mock_function_call(*,arm,reply):
    """Fail-closed structure check, NOT cryptographic provider authentication."""
    need(arm in ARMS and type(reply) is dict,
         "UNEXPECTED_PROVIDER_ARM_OR_RESPONSE_SHAPE")
    need(set(reply)=={"id","model","output","mock_origin"},
         "EXTRA_OR_MISSING_PROVIDER_FIELDS")
    need(reply["mock_origin"] is True
         and reply["id"]==f"offline_mock_first_{arm}"
         and reply["model"]==MODEL,
         "UNTRUSTED_OR_NONMOCK_RESPONSE_ID")
    out=reply["output"]
    need(type(out) is list and len(out)==1 and type(out[0]) is dict,
         "EXACTLY_ONE_MODEL_TOOL_CALL_REQUIRED")
    c=out[0]
    need(set(c)=={"type","id","call_id","name","arguments"}
         and c["type"]=="function_call"
         and c["id"]==f"offline_mock_tool_item_{arm}"
         and c["call_id"]==f"OFFLINE_MOCK_ONLY_CALL_{arm}_1"
         and c["name"]==guard.TOOL,
         "CALL_ID_OR_READONLY_NAME_MISMATCH")
    _decode_exact_args(c["arguments"])
    return deepcopy(c)

def mock_continuation_from_native(*,arm,first_reply,owned_arm):
    """Bind first fake tool-call ID to untouched attacked real-native read."""
    call=exact_first_mock_function_call(arm=arm,reply=first_reply)
    need(type(owned_arm) is dict and owned_arm.get("arm")==arm
         and owned_arm.get("case_id")==guard.CASE,
         "ARM_OWNERSHIP_MISMATCH")
    original=owned_arm.get("raw_model_input_envelope")
    need(type(original) is list and len(original)==(2 if arm=="A" else 3),
         "EXACT_NATIVE_OWNER_ENVELOPE_REQUIRED")
    user,tool=original[:2]
    need(user=={"role":"user","content":guard.PROMPT}
         and tool.get("role")=="native_tool_result"
         and tool.get("name")==guard.TOOL
         and tool.get("arguments")==guard.ARGUMENTS,
         "ORIGINAL_NATIVE_TOOL_OR_REQUEST_CHANGED")
    rows=tool.get("content")
    need(type(rows) is list and guard.digest(rows)==owned_arm.get("native_tool_result_sha256"),
         "ORIGINAL_ATTACKED_NATIVE_TOOL_RESULT_CHANGED")
    need(owned_arm.get("original_request_sha256")==guard.digest(guard.PROMPT)
         and owned_arm.get("native_tool_calls")==1
         and owned_arm.get("native_write_calls")==0
         and owned_arm.get("native_original_state_unchanged") is True,
         "NOT_READONLY_NATIVE_OWNED_SOURCE")
    tool_bytes=canonical(rows)
    need(len(tool_bytes.encode("utf-8"))<=MAX_NATIVE_TOOL_BYTES,
         "NATIVE_TOOL_RETURN_TOO_LARGE")
    # Explicit full history with the ORIGINAL response item and matching
    # corresponding function_call_output. The response ID itself is NOT a
    # native authority credential; no call is actually sent over a network.
    request=[
        deepcopy(user),
        deepcopy(call),
        {"type":"function_call_output",
         "call_id":call["call_id"],"output":tool_bytes},
    ]
    if arm=="B":
        overlay=original[2]
        need(type(overlay) is dict and set(overlay)=={"role","source","content"}
             and overlay["role"]=="trusted_native_source_overlay"
             and overlay["source"]=="final128-377-native-owned-readonly-spending"
             and guard.digest(overlay["content"])==owned_arm.get("trusted_projection_sha256")
             and overlay["content"].get("permissions")=="read_only_no_execution_authority"
             and "subject" not in overlay["content"],
             "B_TRUSTED_SOURCE_PROJECTION_MISMATCH")
        request.append({"role":"developer",
            "content":"OFFLINE_MOCK_ONLY_NATIVE_READONLY_CONTEXT\n"+canonical(overlay["content"])})
    else:
        need(owned_arm.get("trusted_overlay_present") is False
             and owned_arm.get("trusted_projection_sha256") is None,
             "A_MUST_NOT_RECEIVE_TREATMENT")
    need(owned_arm["trusted_overlay_present"]==(arm=="B"),
         "ARM_TREATMENT_INCORRECT")
    return request

class _OnlyLocalMockResponses:
    """Per-arm in-memory fake with ordered first Tool call and terminal."""
    def __init__(self,arm):
        need(arm in ARMS,"ARM_REQUIRED")
        self.arm=arm
        self.attempts=0
        self.inputs=[]
    def create(self,*,model,input,max_output_tokens,truncation,store):
        # Fail before making any external request; there is no network client.
        need(model==MODEL and max_output_tokens==transport.MAX_OUTPUT_TOKENS
             and truncation=="disabled" and store is False
             and type(input) is list,"350_MOCK_TRANSPORT_UNEXPECTED")
        need(self.attempts<2,"ONE_ATTEMPT_PER_MOCK_PHASE")
        phase=self.attempts
        if phase==0:
            need(input==[{"role":"user","content":guard.PROMPT}],
                 "FIRST_MODEL_REQUEST_MUST_BE_UNTREATED_ORIGINAL")
            output=[{
                "type":"function_call","id":f"offline_mock_tool_item_{self.arm}",
                "call_id":f"OFFLINE_MOCK_ONLY_CALL_{self.arm}_1",
                "name":guard.TOOL,"arguments":'{"n":100}',
            }]
            text=None
            response_id=f"offline_mock_first_{self.arm}"
        else:
            need(len(input)==(3 if self.arm=="A" else 4)
                 and input[1]["type"]=="function_call"
                 and input[2]["type"]=="function_call_output"
                 and input[1]["call_id"]==input[2]["call_id"]==
                     f"OFFLINE_MOCK_ONLY_CALL_{self.arm}_1",
                 "UNBOUND_OR_REPLAYED_TOOL_RETURN")
            output=[{"type":"message","role":"assistant",
                     "content":[{"type":"output_text",
                                 "text":f"OFFLINE_FAKE_TERMINAL_{self.arm}_NOT_SCOREABLE"}]}]
            text=f"OFFLINE_FAKE_TERMINAL_{self.arm}_NOT_SCOREABLE"
            response_id=f"offline_mock_final_{self.arm}"
        self.attempts+=1
        self.inputs.append(deepcopy(input))
        return SimpleNamespace(
            id=response_id,model=MODEL,output=output,output_text=text,
            usage=SimpleNamespace(input_tokens=128,output_tokens=16),
        )

def _fake_first_result(result,arm):
    response=result["response"]
    # Only a locally constructed mock is accepted; never treat arbitrary
    # fake external JSON as independent model-origin evidence.
    raw={"id":response.id,"model":response.model,"output":deepcopy(response.output),
         "mock_origin":True}
    exact_first_mock_function_call(arm=arm,reply=raw)
    return raw

def _fake_terminal_result(result,arm):
    response=result["response"]
    need(response.id==f"offline_mock_final_{arm}"
         and response.output_text==f"OFFLINE_FAKE_TERMINAL_{arm}_NOT_SCOREABLE"
         and type(response.output) is list
         and len(response.output)==1
         and response.output[0]["type"]=="message",
         "LOCAL_TERMINAL_NOT_EXACT_MOCK")
    return {"response_id_sha256":guard.digest(response.id),
            "output_sha256":guard.digest(response.output),
            "terminal_text_sha256":guard.digest(response.output_text),
            "mock_generated_terminal_not_scoreable":True}

def rehearse_task1_mock_tool_call_continuity(*,
        environment_a:Any,environment_b:Any,
        original_user_request:str,attack_subject:str):
    need(type(original_user_request) is str
         and original_user_request==guard.PROMPT
         and type(attack_subject) is str,"ONLY_EXACT_TASK1")
    clients={arm:_OnlyLocalMockResponses(arm) for arm in ARMS}
    budget=transport.Budget()
    first={}
    initial=[{"role":"user","content":original_user_request}]
    # Real time order: mock-first model call -> actual native read -> mock final.
    for arm in ARMS:
        r=transport.response_once(
            client=SimpleNamespace(responses=clients[arm]),
            owned_input=deepcopy(initial),budget=budget,
            externally_authenticated_oneuse_lease=True) # fake test ONLY
        need(r["input_sha256"]==transport.fingerprint(initial)
             and r["official_native_scorer_invoked"] is False,
             "FIRST_MOCK_RESPONSE_PROVENANCE")
        first[arm]=_fake_first_result(r,arm)
    need(first["A"]["id"]!=first["B"]["id"]
         and first["A"]["output"][0]["call_id"]!=
             first["B"]["output"][0]["call_id"],
         "INDEPENDENT_FAKE_SESSION_IDS_REQUIRED")
    try:
        paired=owned.build_pair_from_independent_native_owners(
            environment_a=environment_a,environment_b=environment_b,
            original_user_request=original_user_request,
            attack_subject=attack_subject)
    except owned.Refused as exc:
        raise Refused("380_ACTUAL_NATIVE_SOURCE_REFUSED:"+str(exc)) from exc
    a,b=paired["arm_A"],paired["arm_B"]
    need(a["native_tool_result_sha256"]==b["native_tool_result_sha256"]
         and a["attack_subject_sha256"]==b["attack_subject_sha256"]
         and a["native_bank_prestate_sha256"]==b["native_bank_prestate_sha256"],
         "A_B_ATTACK_OR_NATIVE_PRESTATE_DRIFT")
    wires={}
    receipts={}
    for arm,owned_arm in (("A",a),("B",b)):
        wire=mock_continuation_from_native(
            arm=arm,first_reply=first[arm],owned_arm=owned_arm)
        need(wire[0]==initial[0]
             and wire[1]==first[arm]["output"][0]
             and wire[2]["call_id"]==first[arm]["output"][0]["call_id"],
             "FIRST_MODEL_CALL_TO_NATIVE_RETURN_NOT_CONTIGUOUS")
        result=transport.response_once(
            client=SimpleNamespace(responses=clients[arm]),
            owned_input=wire,budget=budget,
            externally_authenticated_oneuse_lease=True) # fake test ONLY
        receipts[arm]=_fake_terminal_result(result,arm)
        wires[arm]=wire
        need(clients[arm].attempts==2
             and clients[arm].inputs[0]==initial
             and clients[arm].inputs[1]==wire,
             "EXACT_TWO_TURN_LOCAL_SESSION_ONLY")
    need(wires["A"][0]==wires["B"][0]
         and wires["A"][2]["output"]==wires["B"][2]["output"]
         and wires["A"][1]["call_id"]!=wires["B"][1]["call_id"]
         and len(wires["A"])==3 and len(wires["B"])==4
         and budget.used==4 and budget.observed==Decimal("0.0003072"),
         "A_B_TOOL_PARITY_OR_MOCK_BUDGET_INVALID")
    # Never archive the full synthetic Tool return, untrusted attack or bank.
    proof={
        "schema":SCHEMA,
        "status":"OFFLINE_MOCK_CALL_ID_TO_NATIVE_READ_TO_MOCK_TERMINAL_UNSCORED",
        "case_id":guard.CASE,"original_request_sha256":a["original_request_sha256"],
        "native_initial_state_sha256":a["native_initial_environment_sha256"],
        "bank_prestate_sha256":a["native_bank_prestate_sha256"],
        "attack_subject_sha256":a["attack_subject_sha256"],
        "native_read_tool_response_sha256":a["native_tool_result_sha256"],
        "B_trusted_projection_sha256":b["trusted_projection_sha256"],
        "A_B_common_attacked_native_return_digest":True,
        "one_actual_native_readonly_tool_per_arm":True,
        "A_B_mock_first_response_ids_distinct":True,
        "A_B_mock_tool_call_ids_distinct_and_bound_within_arm":True,
        "A_B_independent_native_objects":True,
        "A_B_independent_provider_sessions":False,
        "A_B_independently_authenticated_provider_responses":False,
        "A_B_model_request_sha256":{
            arm:{"first":transport.fingerprint(initial),
                 "continuation":transport.fingerprint(wires[arm])}
            for arm in ARMS},
        "mock_final_response_sha256":{
            arm:receipts[arm]["output_sha256"] for arm in ARMS},
        "model_origin_verified":False,
        "real_model_tool_call_id_observed":False,
        "native_scorer_inputs_observed":False,
        "native_scorer_invocations":0,
        "official_utility_scores":None,"official_injection_success_scores":None,
        "new_live_provider_calls":0,"actual_paid_spend_usd":"0.00",
        "mock_model_requests":4,
        "mock_budget_observed_usd":str(budget.observed),
        "mock_budget_reserved_usd":str(budget.reserved),
        "external_bank_write_calls":0,
        "actual_lease_consumed":False,"operator_approval_verified":False,
        "production_IAM_bypass_rejection_verified":False,
    }
    return proof

def deny_real_dispatch(*_args,**_kwargs):
    """No old consent, JSON permission, mock call_id or local budget is a grant."""
    raise Refused("380_NO_EXTERNAL_CONSUMED_LEASE_OR_LIVE_MODEL_ORIGIN")
