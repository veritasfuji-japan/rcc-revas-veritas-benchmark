#!/usr/bin/env python3
"""Task4 two first genuine Provider-response captures, never a benchmark result.

The sole live entry is workflow_dispatch AFTER a new operator action, with a
dedicated Actions environment key and an atomically CREATED consumed Git ref.
No model/tool followups, banking tool execution, retries, or authority grants.
If a request's outcome is unknown, stop; retry is explicitly forbidden.
"""
from __future__ import annotations
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import ssl
import sys
import time

RULE="TASK4_LIVE_FIRST_TWO_CALL_CAPTURE_ONEUSE_V1"
CASE="banking:user_task_4:injection_task_0:direct"
MODEL="gpt-4.1-mini-2025-04-14"
FIRST_REQUEST_SHA="c83bca26d25f6a6332cc1b7266c84ee5974f1f7904d0d77d4f6a913100233dc7"
COMPLETE_REQUEST_SHA="3c9ef1c4fa4d58f8969df723b40b99298fc08a9d44acfc6609f086fc0d7c5b13"
SOURCE_RUN="38060638006"
SOURCE_ARTIFACT="11672698922"
APPROVAL_TEXT="APPROVE_TASK4_ONE_CASE_A_B_FIRST_2_CALLS_MAX_USD_0.50"
CONSUME_REF="refs/tags/task4-first-two-real-provider-v1-consumed"
ARMS=("A","B")
OUTPUT_LIMIT=256
BYTE_LIMIT=32768
PER_FIRST_USD=0.25
TOTAL_USD=0.50
# Official model per-million text-token rates (October 2026).
INPUT_RATE_PER_MILLION=0.40
OUTPUT_RATE_PER_MILLION=1.60

class Blocked(Exception): pass

def check(condition,reason):
    if not condition:raise Blocked(reason)

def canonical(obj):
    return json.dumps(obj,sort_keys=True,ensure_ascii=False,
                      separators=(",",":"),allow_nan=False).encode("utf8")

def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()

def read_verified_packets(path:Path):
    raw=json.loads(path.read_text("utf8"))
    check(raw.get("rule_of_one")=="TASK4_TWO_ARM_FIRST_LIVE_REQUEST_PACKET_V1"
          and raw.get("case_id")==CASE
          and raw.get("entrypoint")=="PREPARED_OFFLINE_ONLY_NOT_EXECUTABLE"
          and raw.get("approved_request_count")==0
          and raw.get("approved_cost_micro_usd")==0
          and raw.get("actual_provider_calls")==0
          and raw.get("fresh_human_approval_present") is False
          and raw.get("independent_real_model_sources_proven") is False
          and raw.get("packets") is not None,
          "PINNED_292_SOURCE_IS_SYNTHETIC_AND_NEVER_PREVIOUSLY_AUTHORIZED")
    packets=raw["packets"]
    check(type(packets) is dict and set(packets)==set(ARMS),
          "EXACT_TWO_SOURCE_ARMS")
    roots=set()
    requests={}
    for arm in ARMS:
        entry=packets[arm]
        request=entry["complete_first_request"]
        check(entry["logical_arm"]==arm and
              entry["source_synthetic_only"] is True and
              entry["request_sent_to_provider"] is False and
              entry["provider_response_id"] is None and
              entry["provider_use_authorized"] is False and
              entry["first_request_sha256"]==FIRST_REQUEST_SHA and
              entry["complete_first_request_sha256"]==
              COMPLETE_REQUEST_SHA==digest(request) and
              entry["complete_first_request_bytes"]==len(canonical(request)),
              "ORIGINAL_292_FIRST_PAYLOAD_SHA_CHANGED")
        roots.add(entry["synthetic_source_sha256"])
        check(set(request)=={"model","messages","tools","tool_choice",
                            "temperature","max_completion_tokens",
                            "n","stream","store"} and
              request["model"]==MODEL and
              request["temperature"]==0.0 and
              request["tool_choice"]=="auto" and
              request["max_completion_tokens"]==OUTPUT_LIMIT and
              request["n"]==1 and request["stream"] is False and
              request["store"] is False and
              [x["role"] for x in request["messages"]]==["developer","user"] and
              len(request["tools"])==11 and
              all(t.get("type")=="function" for t in request["tools"]) and
              len(canonical(request))<=BYTE_LIMIT,
              "ONLY_BOUNDED_NO_HISTORY_FIRST_CHAT_REQUESTS")
        # The proposals are byte-equal, but source labels are separate.
        requests[arm]=request
    check(len(roots)==2 and canonical(requests["A"])==canonical(requests["B"]),
          "EXACT_TWO_DISTINCT_SOURCE_OWNERS_IDENTICAL_FIRST_BYTES")
    # Conservative input ceiling: no more tokens than UTF8 bytes plus
    # 10k overhead per call; not a provider-side billing guarantee.
    worst_input_tokens=BYTE_LIMIT+10000
    estimated_bound=(worst_input_tokens*INPUT_RATE_PER_MILLION+
                     OUTPUT_LIMIT*OUTPUT_RATE_PER_MILLION)/1000000
    check(estimated_bound < PER_FIRST_USD and
          estimated_bound*2 < TOTAL_USD,
          "PROPOSED_COST_ESTIMATE_OVER_APPROVED_CEILING")
    return requests,{"rule_of_one":RULE,
                     "source_run":SOURCE_RUN,"source_artifact":SOURCE_ARTIFACT,
                     "case_id":CASE,"model":MODEL,
                     "first_payload_sha256":COMPLETE_REQUEST_SHA,
                     "first_payload_bytes":len(canonical(requests["A"])),
                     "expected_provider_calls":2,
                     "model_max_completion_tokens":OUTPUT_LIMIT,
                     "approved_proposed_max_usd":TOTAL_USD,
                     "estimated_upper_usd_per_call_not_billing_guarantee":estimated_bound,
                     "provider_project_hard_cap_verified":False,
                     "first_call_contains_malicious_native_tool_data":False,
                     "raw_model_responses_are_not_canonical_scores":True}

def durable_log(path:Path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("a",encoding="utf8") as f:
        f.write(json.dumps(obj,sort_keys=True,ensure_ascii=False)+"\n")
        f.flush()
        os.fsync(f.fileno())

def send_exactly_once(*,request,key,arm,request_id,transport=None):
    """One HTTPS POST attempt. No SDK and NO implicit retry."""
    check(arm in ARMS and request_id.startswith("task4-v1-"+arm+"-"),
          "BOUND_PROVIDER_SOURCE_CALL_ID")
    data=canonical(request)
    check(len(data)<=BYTE_LIMIT and digest(request)==COMPLETE_REQUEST_SHA,
          "PRE_DISPATCH_FIRST_BODY_DRIFT")
    headers={
       "Authorization":"Bearer "+key,
       "Content-Type":"application/json",
       "X-Client-Request-Id":request_id,
       "User-Agent":"veritas-task4-two-first-requests-v1",
    }
    factory=transport or (lambda: http.client.HTTPSConnection(
        "api.openai.com",443,timeout=25,context=ssl.create_default_context()))
    conn=factory()
    try:
        conn.request("POST","/v1/chat/completions",body=data,headers=headers)
        response=conn.getresponse()
        status=response.status
        provider_request_id=response.getheader("x-request-id")
        body=response.read(262145)
        check(len(body)<=262144,"RESPONSE_BODY_SIZE_UNTRUSTED")
        obj=json.loads(body)
        check(status==200,"HTTP_NON_SUCCESS_REQUEST_OUTCOME_UNKNOWN_NO_RETRY_"+str(status))
        check(type(provider_request_id) is str and bool(provider_request_id),
              "PROVIDER_REQUEST_ID_MISSING_NO_RETRY")
        check(type(obj) is dict and obj.get("object")=="chat.completion"
              and obj.get("model")==MODEL and
              type(obj.get("id")) is str and bool(obj["id"]) and
              type(obj.get("choices")) is list and len(obj["choices"])==1
              and type(obj.get("usage")) is dict and
              all(type(obj["usage"].get(t)) is int and
                  0<=obj["usage"][t]<100000
                  for t in ("prompt_tokens","completion_tokens","total_tokens")),
              "UNAUTHENTICATED_OR_INCOMPLETE_PROVIDER_RESPONSE_STOP")
        usage=obj["usage"]
        check(usage["total_tokens"]==usage["prompt_tokens"]+
              usage["completion_tokens"] and
              usage["completion_tokens"]<=OUTPUT_LIMIT,
              "BAD_USAGE_OR_COMPLETION_LIMIT_STOP")
        cost=(usage["prompt_tokens"]*INPUT_RATE_PER_MILLION+
              usage["completion_tokens"]*OUTPUT_RATE_PER_MILLION)/1000000
        check(cost<=PER_FIRST_USD,
              "PROVIDER_COST_EXCEEDED_PROPOSED_PER_CALL_STOP_NO_RETRY")
        return {"arm":arm,"request_sha256":digest(request),
                "client_request_id":request_id,
                "server_request_id":provider_request_id,
                "provider_response_id":obj["id"],
                "reported_model":obj.get("model"),
                "usage":usage,
                "estimated_cost_usd":cost,
                "real_provider_response":obj,
                "provider_response_sha256":digest(obj),
                "model_output_not_yet_accepted_as_execution_authority":True,
                "native_tools_dispatched":0,
                "canonical_case_utility_scored":False,
                "canonical_injection_success_measured":False}
    finally:
        conn.close()

def execute(args):
    path=Path(args.source)
    requests,manifest=read_verified_packets(path)
    output=Path(args.output)
    if args.mode=="preflight":
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n")
        return
    check(args.mode=="send","EXACT_MODE_REQUIRED")
    check(os.getenv("GITHUB_ACTIONS")=="true" and
          os.getenv("GITHUB_EVENT_NAME")=="workflow_dispatch" and
          os.getenv("GITHUB_REF")=="refs/heads/main" and
          os.getenv("GITHUB_RUN_ATTEMPT")=="1" and
          os.getenv("TASK4_CONSUMED_REF_CREATED")=="1" and
          os.getenv("TASK4_APPROVAL_PHRASE")==APPROVAL_TEXT,
          "NO_MANUAL_OPERATOR_CONSUMED_ONE_SHOT_WORKFLOW_AUTHORIZATION")
    key=os.getenv("TASK4_OPENAI_API_KEY","")
    check(len(key)>20 and not any(c.isspace() for c in key),
          "DEDICATED_TASK4_OPENAI_SECRET_REQUIRED")
    check(not output.exists(),"LOCAL_EXISTING_EVIDENCE_CANNOT_BE_OVERWRITTEN")
    durable_log(output,{"event":"AUTHORIZATION_ALREADY_CONSUMED",
         "source":SOURCE_ARTIFACT,"max_calls":2,"max_usd":0.50,
         "run_id":os.getenv("GITHUB_RUN_ID"),"sha":os.getenv("GITHUB_SHA"),
         "request_sha256":COMPLETE_REQUEST_SHA,
         "no_retry_allowed":True})
    accumulated=0.0
    for arm in ARMS:
        request_id="task4-v1-"+arm+"-"+str(os.getenv("GITHUB_RUN_ID"))
        durable_log(output,{"event":"BEFORE_PROVIDER_POST_CONSUMED",
                      "arm":arm,"request_id":request_id,"retry_allowed":False})
        try:
            outcome=send_exactly_once(request=requests[arm],key=key,
                   arm=arm,request_id=request_id)
            accumulated+=outcome["estimated_cost_usd"]
            durable_log(output,{"event":"PROVIDER_RESPONSE_CAPTURED",
                       **outcome})
        except BaseException as error:
            durable_log(output,{"event":"UNKNOWN_OR_FAILED_STOP",
                           "arm":arm,"exception_type":type(error).__name__,
                           "no_retry_authorized":True,
                           "note":"The request may have been sent or billed. Do not dispatch again."})
            raise
    check(accumulated<=TOTAL_USD,
          "TWO_RESPONSE_USAGE_ESTIMATE_EXCEEDED_CONSENT_STOP")
    durable_log(output,{"event":"TWO_FIRST_RESPONSES_COMPLETE",
        "successful_post_attempts":2,"estimated_total_cost_usd":accumulated,
        "new_canonical_final128_scores":0,
        "new_task4_injection_utility_measurements":0,
        "provider_response_ids_are_not_native_tool_effect_authority":True})
    print("TWO_PROVIDER_FIRST_REQUESTS_CAPTURED_NO_NATIVE_EXECUTION")
    print("NO_CANONICAL_UTILITY_OR_INJECTION_RESULT_FROM_FIRST_RESPONSES")

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("preflight","send"),required=True)
    p.add_argument("--source",required=True)
    p.add_argument("--output",required=True)
    try: execute(p.parse_args())
    except BaseException as err:
        print(type(err).__name__+": "+str(err),file=sys.stderr)
        sys.exit(1)
