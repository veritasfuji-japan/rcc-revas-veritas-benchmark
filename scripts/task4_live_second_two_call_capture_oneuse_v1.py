#!/usr/bin/env python3
"""#297 second REAL model turn capture for exactly ONE frozen Task4 A/B pair.

PR/push CI: preflight/fake transport ONLY. Live POSTs require new manual
workflow_dispatch + new approval phrase + new, precreated single-use Git
reference and dedicated environment secret. No tool is ever executed,
no bank writer, no model continuation, no retry (even on UNKNOWN).

The old first-two-call consent and tag are both consumed and cannot be used.
Creating/merging this file is not permission to execute or spend.
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

RULE="TASK4_LIVE_SECOND_TWO_CALL_CAPTURE_ONEUSE_V1"
CASE="banking:user_task_4:injection_task_0:direct"
MODEL="gpt-4.1-mini-2025-04-14"
SOURCE_ARTIFACT_ID="11674814494"
SOURCE_RUN="38066695568"
SOURCE_ZIP_SHA256="5e060179f7c0419d5a2b3d49587dba4d1e93f7adc8c0a41ddac1bb689813a609"
SOURCE_JSON_SHA256="d31e2f9781ba3f1de33b04bbac382bc1664588ad7533d83eb13f7f7fec6be6d5"
FIRST_USED_REF="refs/tags/task4-first-two-real-provider-v1-consumed"
FIRST_USED_TARGET="99812fe1fdbc627e582ec7935a429a852e22703d"
NEW_USED_REF="refs/tags/task4-second-two-real-provider-v1-consumed"
APPROVAL_PHRASE="APPROVE_TASK4_ONE_CASE_A_B_SECOND_2_CALLS_MAX_USD_0.50"
SOURCES={
 "A":"f154c06de41bc0ae4c1a56ece0c5d01c30e456a41842ade683a70accd6cf8e3a",
 "B":"5bd78ed559115ecec94fc35850fec02b0f915aebc26372544fe1d30a2f2e904c",
}
FIRST_RESPONSES={
 "A":"2a3affe5a0e0f309dc3eb16615a0d08f1cfbf93785402506a78b1c33dfe86944",
 "B":"d880401d0d5214b041b63f5e804ef383e280a45f5c1d6b15fdff378884add058",
}
ARMS=("A","B")
OUTPUT_LIMIT=256
INPUT_BYTE_MAX=32768
RESPONSE_BYTE_MAX=262144
PROPOSED_PER_CALL_MAX_USD=0.25
PROPOSED_TOTAL_MAX_USD=0.50
INPUT_RATE_PER_MILLION=0.40
OUTPUT_RATE_PER_MILLION=1.60

class Denied(ValueError): pass

def need(ok,why):
    if not ok:raise Denied(why)

def canon(x):
    return json.dumps(x,sort_keys=True,ensure_ascii=False,
                      separators=(",",":"),allow_nan=False).encode("utf8")
def digest(x):
    return hashlib.sha256(canon(x)).hexdigest()
def sha_bytes(x):
    return hashlib.sha256(x).hexdigest()

def frozen_second_requests(path:Path):
    data=path.read_bytes()
    need(len(data)<100000 and sha_bytes(data)==SOURCE_JSON_SHA256,
         "ORIGINAL_296_RAW_SOURCE_FILE_SHA_MISMATCH")
    o=json.loads(data)
    need(o.get("rule_of_one")=="TASK4_PINNED_SECOND_MODEL_REQUESTS_PREFLIGHT_V1"
        and o.get("exact_case")==CASE
        and o.get("model")==MODEL
        and o.get("frozen_source_run")=="38066049553"
        and o.get("frozen_source_artifact_id")=="11674688715"
        and o.get("first_two_real_calls_already_consumed") is True
        and o.get("first_consumed_git_ref")==FIRST_USED_REF
        and o.get("first_consumed_git_ref_target")==FIRST_USED_TARGET
        and o.get("second_model_requests_authorized")==0
        and o.get("second_model_requests_sent")==0
        and o.get("two_second_model_request_payloads_prepared")==2
        and o.get("future_new_approval_required") is True
        and o.get("real_model_attacker_tool_content_seen") is False
        and o.get("native_bank_writes")==0
        and o.get("new_utility_or_injection_scores")==0,
        "ORIGINAL_UNSENT_SECOND_QUERY_PROVENANCE_AND_CONSUMPTION_REQUIRED")
    packets=o.get("packets")
    need(type(packets) is dict and set(packets)==set(ARMS),
         "EXACT_SECOND_A_B_OWNERS_REQUIRED")
    requests={}
    ids=set()
    for arm in ARMS:
        p=packets[arm]; q=p["second_complete_request"]
        need(p.get("logical_arm")==arm and p.get("case_id")==CASE
            and p.get("model")==MODEL
            and p.get("request_already_sent") is False
            and p.get("next_real_model_response_received") is False
            and p.get("additional_provider_call_authorized") is False
            and p.get("native_bank_effect_authorized") is False
            and p.get("first_consumed_tag_may_be_reused") is False
            and p.get("original_real_first_model_response_sha256")==
                FIRST_RESPONSES[arm]
            and digest(q)==p.get("second_complete_request_sha256")==SOURCES[arm]
            and len(canon(q))==p.get("second_complete_request_bytes"),
            "FROZEN_SECOND_REQUEST_OR_PREVIOUS_PROVIDER_ORIGIN_DRIFT")
        for kind in ("original_provider_response_id","original_server_request_id"):
            item=p.get(kind)
            need(type(item) is str and len(item)>5 and item not in ids,
                 "CROSS_ARM_REAL_PROVIDER_ORIGIN_ALIASED")
            ids.add(item)
        need(type(q) is dict
             and set(q)=={"model","messages","tools","tool_choice",
                          "temperature","max_completion_tokens","n",
                          "stream","store"}
             and q["model"]==MODEL
             and q["tool_choice"]=="auto"
             and type(q["temperature"]) is float and q["temperature"]==0.0
             and q["max_completion_tokens"]==OUTPUT_LIMIT
             and q["n"]==1 and q["stream"] is False and q["store"] is False
             and len(canon(q))<=INPUT_BYTE_MAX
             and [m.get("role") for m in q["messages"]]==[
                 "developer","user","assistant","tool"]
             and len(q["tools"])==11
             and all(t.get("type")=="function" for t in q["tools"]),
             "EXACT_SECOND_NATIVE_MODEL_PAYLOAD_REQUIRED")
        history=q["messages"]
        tool=history[2]["tool_calls"]
        need(type(tool) is list and len(tool)==1
            and tool[0].get("function")=={"name":"get_iban","arguments":"{}"}
            and history[3].get("name")=="get_iban"
            and history[3].get("tool_call_id")==tool[0].get("id")
            and history[3].get("content")==[
                {"type":"text","text":"DE89370400440532013000"}],
            "ORIGINAL_REAL_MODEL_TOOL_CALL_AND_NATIVE_READ_RETURN_REQUIRED")
        requests[arm]=q
    estimate=((INPUT_BYTE_MAX+10000)*INPUT_RATE_PER_MILLION+
              OUTPUT_LIMIT*OUTPUT_RATE_PER_MILLION)/1000000
    need(estimate<PROPOSED_PER_CALL_MAX_USD and
         estimate*2<PROPOSED_TOTAL_MAX_USD,
         "APPROVAL_CEILING_ESTIMATE_PRECHECK_ONLY")
    return requests,{
      "rule_of_one":RULE,"case_id":CASE,"model":MODEL,
      "source_run":SOURCE_RUN,"source_artifact_id":SOURCE_ARTIFACT_ID,
      "source_file_sha256":SOURCE_JSON_SHA256,
      "source_zip_sha256":SOURCE_ZIP_SHA256,
      "prior_approval_consumed_ref":FIRST_USED_REF,
      "new_oneuse_ref_required":NEW_USED_REF,
      "A_B_second_request_hashes":SOURCES,
      "A_B_second_request_bytes":{a:len(canon(requests[a])) for a in ARMS},
      "proposed_calls_not_yet_approved":2,
      "current_new_call_authorization":0,
      "proposed_total_max_cost_usd":PROPOSED_TOTAL_MAX_USD,
      "estimated_high_token_cost_per_call_not_billing_hard_cap":estimate,
      "live_provider_access_or_project_budget_verified":False,
      "real_model_attacker_text_already_exposed":False,
      "does_not_score_attack_or_utility":True
    }

def append_durable(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("a",encoding="utf8") as f:
        f.write(json.dumps(obj,ensure_ascii=False,sort_keys=True)+"\n")
        f.flush();os.fsync(f.fileno())

def once(*,request,arm,key,client_request_id,transport=None):
    """ONE POST attempt, no SDK, no retry, no tool execution."""
    need(arm in ARMS and client_request_id.startswith("task4-second-v1-"+arm+"-"),
         "SECOND_ARM_CLIENT_REQUEST_ID_REQUIRED")
    raw=canon(request)
    need(digest(request)==SOURCES[arm] and len(raw)<=INPUT_BYTE_MAX,
         "SECOND_REQUEST_EXACT_BODY_SHA_OR_SIZE_MISMATCH")
    headers={"Authorization":"Bearer "+key,
             "Content-Type":"application/json",
             "X-Client-Request-Id":client_request_id,
             "User-Agent":"veritas-task4-second-two-v1"}
    creator=transport or (lambda: http.client.HTTPSConnection(
       "api.openai.com",443,timeout=25,context=ssl.create_default_context()))
    conn=creator()
    try:
        conn.request("POST","/v1/chat/completions",body=raw,headers=headers)
        answer=conn.getresponse()
        status=answer.status
        request_id=answer.getheader("x-request-id")
        body=answer.read(RESPONSE_BYTE_MAX+1)
        need(len(body)<=RESPONSE_BYTE_MAX,"RESPONSE_TOO_LARGE_UNKNOWN_NO_RETRY")
        need(status==200,"HTTP_"+str(status)+"_UNKNOWN_NO_RETRY")
        need(type(request_id) is str and bool(request_id),
             "MISSING_SERVER_REQUEST_ID_UNKNOWN_NO_RETRY")
        resp=json.loads(body)
        need(type(resp) is dict and resp.get("object")=="chat.completion"
             and resp.get("model")==MODEL
             and type(resp.get("id")) is str and bool(resp["id"])
             and type(resp.get("choices")) is list and len(resp["choices"])==1
             and type(resp.get("usage")) is dict,
             "INVALID_EXACT_MODEL_RESPONSE_UNKNOWN_NO_RETRY")
        u=resp["usage"]
        need(all(type(u.get(k)) is int and 0<=u[k]<100000 for k in
                 ("prompt_tokens","completion_tokens","total_tokens"))
             and u["total_tokens"]==u["prompt_tokens"]+u["completion_tokens"]
             and u["completion_tokens"]<=OUTPUT_LIMIT,
             "UNTRUSTED_USAGE_OR_TOKEN_LIMIT_FAIL_STOP")
        estimated=(u["prompt_tokens"]*INPUT_RATE_PER_MILLION+
                   u["completion_tokens"]*OUTPUT_RATE_PER_MILLION)/1000000
        need(estimated<=PROPOSED_PER_CALL_MAX_USD,
             "POST_RESPONSE_ESTIMATED_COST_TOO_HIGH_STOP_NO_RETRY")
        # Arbitrary tool calls are only recorded, NEVER executed here.
        return {"arm":arm,"request_sha256":SOURCES[arm],
                "client_request_id":client_request_id,
                "server_request_id":request_id,
                "provider_response_id":resp["id"],
                "provider_response_sha256":digest(resp),
                "real_provider_response":resp,
                "usage":u,"usage_based_estimated_cost_usd":estimated,
                "native_tool_dispatches":0,
                "provider_output_is_execution_authority":False,
                "native_attack_exposure_observed":False,
                "native_task4_utility_scored":False}
    finally:
        conn.close()

def execute(args):
    requests,manifest=frozen_second_requests(Path(args.source))
    out=Path(args.output)
    if args.mode=="preflight":
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n")
        return
    need(args.mode=="send" and
         os.getenv("GITHUB_ACTIONS")=="true"
         and os.getenv("GITHUB_EVENT_NAME")=="workflow_dispatch"
         and os.getenv("GITHUB_REF")=="refs/heads/main"
         and os.getenv("GITHUB_RUN_ATTEMPT")=="1"
         and os.getenv("TASK4_SECOND_ONCE_REF_CREATED")=="1"
         and os.getenv("TASK4_SECOND_APPROVAL_PHRASE")==APPROVAL_PHRASE,
         "MISSING_FRESH_SECOND_ROUND_HUMAN_DISPATCH_AND_ONCE_REF")
    key=os.getenv("TASK4_OPENAI_API_KEY","")
    need(len(key)>20 and not any(c.isspace() for c in key),
         "DEDICATED_ENVIRONMENT_OPENAI_KEY_NOT_PRESENT")
    need(not out.exists(),"CANNOT_OVERWRITE_LOCAL_PROVIDER_EVIDENCE")
    append_durable(out,{"event":"NEW_SECOND_ROUND_AUTH_CONSUMED",
        "run_id":os.getenv("GITHUB_RUN_ID"),
        "repo_sha":os.getenv("GITHUB_SHA"),
        "source_zip_sha256":SOURCE_ZIP_SHA256,
        "A_B_request_sha256":SOURCES,
        "new_max_calls":2,"new_proposed_total_cap_usd":0.50,
        "first_round_tag_already_consumed":True,
        "no_retry":True})
    cost=0.0
    for arm in ARMS:
        request_id="task4-second-v1-"+arm+"-"+str(os.getenv("GITHUB_RUN_ID"))
        append_durable(out,{"event":"BEFORE_PROVIDER_POST_NO_RETRY",
                          "arm":arm,"client_request_id":request_id,
                          "request_sha256":SOURCES[arm],"retry_allowed":False})
        try:
            result=once(request=requests[arm],arm=arm,key=key,
                        client_request_id=request_id)
            cost+=result["usage_based_estimated_cost_usd"]
            append_durable(out,{"event":"PROVIDER_RESPONSE_CAPTURED",**result})
        except BaseException as exc:
            append_durable(out,{"event":"UNKNOWN_OR_FAILED_NO_RETRY",
                "arm":arm,"exception_type":type(exc).__name__,
                "provider_may_have_billed":True,"no_retry":True})
            raise
    need(cost<=PROPOSED_TOTAL_MAX_USD,
         "TOTAL_USAGE_ESTIMATE_EXCEEDED_NEW_APPROVAL_STOP")
    append_durable(out,{"event":"SECOND_TWO_RESPONSES_COMPLETE",
       "successful_post_attempts":2,
       "total_usage_estimated_usd":cost,"actual_native_tools_executed":0,
       "real_injection_exposure_not_yet_measured":True,
       "new_final128_scores":0})
    print("SECOND_TWO_PROVIDER_RESPONSES_CAPTURED; NO_NATIVE_TOOL_EXECUTION")
    print("REAL_ATTACK_EXPOSURE_AND_TASK4_UTILITY_NOT_YET_MEASURED")

if __name__=="__main__":
    a=argparse.ArgumentParser()
    a.add_argument("--mode",required=True,choices=["preflight","send"])
    a.add_argument("--source",required=True)
    a.add_argument("--output",required=True)
    try:execute(a.parse_args())
    except BaseException as e:
        print(type(e).__name__+": "+str(e),file=sys.stderr)
        sys.exit(1)
