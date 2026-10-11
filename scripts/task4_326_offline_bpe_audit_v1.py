#!/usr/bin/env python3
"""#326 read-only audit of actual SDK bytes under local UTF8 and pinned BPE cap.

Not a server-side token-meter or an authorization gate. The mock-only policy
can establish that a locally defined threshold rejects before fake response,
but cannot certify unknown OpenAI tool framing or provider billing limits.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from scripts import task4_326_offline_bpe_wire_gate_v1 as source
from scripts import task4_325_sdk_wire_audit_v1 as parent
from scripts import task4_320_local_sdk_complete_native_v1 as base
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import sha_json

CONTRACT=ROOT/"contracts/TASK4_326_LOCAL_BPE_WIRE_GATE_OFFLINE_V1.json"
class Rejected(ValueError):pass
def need(v,why):
    if not v:raise Rejected(why)

def frozen():
    return json.loads(CONTRACT.read_text())

def check_contract(x):
    need(type(x) is dict and x=={
      "schema":"veritas.task4.offline-bpe-json-and-utf8-byte-gate.v1",
      "rule_of_one":source.RULE,
      "exact_merged_main_parent_sha":source.PARENT_MAIN,
      "source_case":source.CASE if hasattr(source,"CASE") else base.SOURCE_CASE,
      "model":source.MODEL,
      "tiktoken_package_version":source.EXPECTED_TIKTOKEN_VERSION,
      "tiktoken_model_encoding":source.ENCODING_NAME,
      "sdk_exact_version":"1.109.1","httpx_exact_version":"0.28.1",
      "request_json_utf8_max_bytes":source.MAX_JSON_UTF8_BYTES,
      "request_local_json_bpe_max_tokens":source.MAX_LOCAL_BPE_TOKENS,
      "whole_trial_local_bpe_max_tokens":source.MAX_LOCAL_BPE_SUM,
      "max_requests_per_arm":source.MAX_PER_ARM,
      "max_requests_both_arms":source.MAX_BOTH_ARMS,
      "output_cap":source.CAP_OUTPUT,
      "local_json_bpe_equals_provider_chat_prompt_usage":False,
      "server_side_prompt_tokens_upper_bound_proven":False,
      "true_prompt_token_cost_hard_cap_proven":False,
      "live_provider_sender_exists":False,
      "cross_run_atomic_consumption_proven":False,
      "new_human_spend_authorization":False,
      "real_provider_posts":0,"genuine_model_outputs":0,
      "real_bank_effects":0,"new_final128_scores":0,
      "status":"OFFLINE_LOCAL_BPE_AND_SDK_WIRE_BYTES_ONLY_REAL_PROVIDER_DENY",
    },"FROZEN_LOCAL_ONLY_SCOPE_VIOLATION")
    return True

def check_row(row, encoder):
    need(type(row) is dict and set(row)=={
        "arm","original_325_native_wire_row","early_local_budget_receipts",
        "no_network_provider_calls","authoritative_provider_token_count",
        "real_send_allowed"
    },"STRICT_ROW_SHAPE")
    arm=row["arm"];native=row["original_325_native_wire_row"]
    need(arm in ("A","B") and native["arm"]==arm
         and row["no_network_provider_calls"]==0
         and row["authoritative_provider_token_count"] is False
         and row["real_send_allowed"] is False,"ONLY_OFFLINE_SINGLE_MODEL_ROOT")
    parent_res=parent.check_row(native)
    need(parent_res["arm"]==arm and
         parent_res["native_effect_count"]==parent_res["native_scorer_calls"]==1 and
         parent_res["real_model_responses"]==0,
         "SCORER_AND_SDK_ROOT_NOT_FROZEN")
    source_wires=native["wire_proof"]
    receipts=row["early_local_budget_receipts"]
    need(type(receipts) is list and len(receipts)==len(source_wires)==4,
         "ALL_SDK_WIRE_INTERCEPTS_MUST_HAVE_EARLY_RECEIPT")
    old="0"*64;total=0
    for idx,(rec,wire) in enumerate(zip(receipts,source_wires)):
        need(type(rec) is dict and set(rec)=={
          "arm","ordinal","raw_sdk_http_body_sha256","raw_sdk_json_utf8_bytes",
          "local_json_bpe_tokens_not_provider_usage","whole_arm_local_bpe_after",
          "output_cap_on_sdk_request","encoding","tiktoken_version",
          "raw_body_utf8","previous_receipt_sha256",
          "true_provider_input_tokens_bound_proven",
          "real_provider_post_allowed","receipt_sha256"
        },"EXACT_EARLY_GATE_RECEIPT_FIELDS")
        signed=rec["receipt_sha256"]
        need(rec["arm"]==arm and type(rec["ordinal"]) is int and rec["ordinal"]==idx
             and rec["previous_receipt_sha256"]==old
             and rec["encoding"]==source.ENCODING_NAME
             and rec["tiktoken_version"]==source.EXPECTED_TIKTOKEN_VERSION
             and rec["output_cap_on_sdk_request"]==source.CAP_OUTPUT
             and rec["true_provider_input_tokens_bound_proven"] is False
             and rec["real_provider_post_allowed"] is False
             and source.parent.hash_bytes(source.parent.canonical({
               k:v for k,v in rec.items() if k!="receipt_sha256"}))==signed,
             "PRE_FAKE_RESPONSE_RECEIPT_HASH_OR_NO_LIVE_CLAIM_CHANGED")
        payload=rec["raw_body_utf8"]
        need(type(payload) is str and
             payload==wire["raw_wire_body_utf8"] and
             source.parent.hash_bytes(payload.encode("utf-8"))==
                 rec["raw_sdk_http_body_sha256"]==
                 wire["actual_sdk_post_body_sha256"] and
             len(payload.encode("utf-8"))==
                 rec["raw_sdk_json_utf8_bytes"]==
                 wire["actual_sdk_wire_bytes"] and
             rec["raw_sdk_json_utf8_bytes"]<=source.MAX_JSON_UTF8_BYTES,
             "ORIGINAL_WIRE_BYTES_MUST_MATCH_BOTH_GATES")
        local_count=len(encoder.encode(payload,disallowed_special=()))
        total+=local_count
        need(type(rec["local_json_bpe_tokens_not_provider_usage"]) is int
             and local_count==rec["local_json_bpe_tokens_not_provider_usage"]
             and 0<local_count<=source.MAX_LOCAL_BPE_TOKENS
             and rec["whole_arm_local_bpe_after"]==total
             and total<=source.MAX_LOCAL_BPE_SUM,
             "PINNED_LOCAL_BPE_ACCOUNTING_OR_AGGREGATE_DRIFT")
        old=signed
    return {
      "arm":arm,"local_sdk_intercepts":len(receipts),
      "full_local_http_body_bytes":sum(x["raw_sdk_json_utf8_bytes"] for x in receipts),
      "local_json_bpe_total_not_provider_usage":total,
      "native_dispatches":parent_res["native_effect_count"],
      "native_postonly_scorer_calls":parent_res["native_scorer_calls"],
      "first_response_id":native["source_response_ids"][0],
      "native_selected_terminal_sha256":native["native_selected_terminal_sha256"],
      "early_budget_receipt_chain_tip":old,
      "true_provider_prompt_usage_attested":False
    }

def audit(rows):
    base.reject_live_context()
    check_contract(frozen())
    need(type(rows) is list and len(rows)==2,"EXACT_TWO_INDEPENDENT_SOURCE_ROWS")
    encoding=source.tiktoken_encoder()
    results={}
    for entry in rows:
        result=check_row(entry,encoding)
        need(result["arm"] not in results,"DUPLICATE_LOCAL_ARM")
        results[result["arm"]]=result
    need(set(results)=={"A","B"},"BOTH_LOCAL_ROOTS_REQUIRED")
    a,b=results["A"],results["B"]
    need(a["first_response_id"]!=b["first_response_id"] and
         a["native_selected_terminal_sha256"]!=b["native_selected_terminal_sha256"]
         and a["native_dispatches"]==b["native_dispatches"]==1 and
         a["native_postonly_scorer_calls"]==b["native_postonly_scorer_calls"]==1,
         "TRUE_SEPARATE_LOCAL_SDK_NATIVE_A_B")
    total=sum(x["local_json_bpe_total_not_provider_usage"] for x in results.values())
    need(total<=source.MAX_LOCAL_BPE_SUM,"WHOLE_TRIAL_LOCAL_BPE_LIMIT")
    report={
      "rule_of_one":source.RULE,
      "exact_parent_main_sha":source.PARENT_MAIN,
      "independent_scripted_sources":2,
      "actual_sdk_wire_intercepts":8,
      "native_dispatches":2,"native_postonly_scorer_calls":2,
      "all_early_local_byte_bpe_receipts_verified":True,
      "strict_sdk_wire_json_byte_ceiling_enforced_locally":source.MAX_JSON_UTF8_BYTES,
      "local_bpe_threshold_enforced_per_request":source.MAX_LOCAL_BPE_TOKENS,
      "local_json_bpe_total_not_provider_usage":total,
      "output_cap_per_actual_sdk_json":source.CAP_OUTPUT,
      "model_prompt_tokens_true_hard_upper_bound":False,
      "provider_spend_hard_cap_enforced":False,
      "cross_workflow_oneuse_ledger_proven":False,
      "api_model_availability_attested":False,
      "real_provider_posts":0,"new_final128_scores":0,"real_bank_effects":0,
      "api_dispatch":"DENY",
      "arms":results,
      "classification":"LOCAL_JSON_BPE_AND_BYTE_POLICY_PROVEN_NOT_PROVIDER_BILLING_TOKENS"
    }
    report["report_sha256"]=sha_json(report)
    return report

def main():
    arg=argparse.ArgumentParser()
    arg.add_argument("--input",required=True)
    arg.add_argument("--output",required=True)
    x=arg.parse_args()
    i=(ROOT/x.input).resolve();o=(ROOT/x.output).resolve()
    need(i.is_relative_to(ROOT/"results") and o.is_relative_to(ROOT/"results")
         and i!=o and not o.exists(),"LOCAL_REPORT_PATHS_NO_OVERWRITE")
    rows=[json.loads(z) for z in i.read_text().splitlines() if z.strip()]
    result=audit(rows)
    o.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("TASK4_326_STRICT_LOCAL_UTF8_BPE_BUDGET_REAL_PROVIDER_DENY")

if __name__=="__main__":main()
