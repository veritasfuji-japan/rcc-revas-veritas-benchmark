#!/usr/bin/env python3
"""#318: re-adjudicate the exact genuine A/B third proposals and audit native
scorer eligibility. NO terminal evidence is invented, no provider or bank I/O.

Scope: authoritative previously frozen third model tool-call responses,
native bank prestate and actual pinned VERITAS Bind no-effect refusal only.
The *official* AgentDojo scorer requires a complete observed terminal
trajectory. Here only the third proposal exists: calling it would turn
missing model/tool history into a fabricated post-execution result.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
if str(ROOT/"scripts") not in sys.path: sys.path.insert(0,str(ROOT/"scripts"))
import task4_third_actual_veritas_bind_predispatch_refusal_v1 as bind301
import task4_317_cross_origin_utility_nonpromotion_v1 as proof317

RULE="TASK4_318_REAL_THIRD_PROPOSAL_NATIVE_BIND_REFUSAL_IS_NOT_COMPLETE_TERMINAL_SCORING_V1"
PARENT="f6fc6361f56dda8d0b5c1afae2b1955dd914a6e0"
CONTRACT="contracts/TASK4_318_REAL_THIRD_TERMINAL_SCORER_ELIGIBILITY_V1.json"
PINS={
"scripts/task4_third_actual_veritas_bind_predispatch_refusal_v1.py":"8e009ec9bfabef807a1cad485523495fee25f857",
"scripts/task4_317_cross_origin_utility_nonpromotion_v1.py":"01d7d505fa93280c98a81625a18a5932c57458fb",
"scripts/agentdojo_native_scorer_invocation_v0_1.py":"e7e431a87a14af135e0bdc3dbf74e68e6e802dfd",
"task4_prospective_native_scorer_observation_boundary_v1.py":"9673b73fcdd10433c9df66e6c92ab17204bc8304",
"contracts/TASK4_THIRD_ACTUAL_VERITAS_BIND_PREDISPATCH_REFUSAL_V1.json":"206375331fd594159a50bf4ad8c0ad0b056f05d5",
"contracts/TASK4_317_CROSS_ORIGIN_UTILITY_NONPROMOTION_V1.json":"620820c07a476b0e79fbd7716b19a20d723558b0"
}
REAL_SHA="6d9842caa8c017ae2bd4426ee7d4b0f1c02f79252d82c96767c048c88f176ab2"
NATIVE_SHA="bbc7ba1a16aaac67aed75bdbb7a5abc71bfa978599e1cfc42700779377e838f4"
CONSUMED="95ff6be8c5875ed3827a00fe71fb54bd9de48130"
REQUIRED_CREDENTIALS=("OPENAI_API_KEY","TASK4_OPENAI_API_KEY","ANTHROPIC_API_KEY",
 "OPENAI_BASE_URL","VERITAS_DATABASE_URL","TASK4_318_APPROVAL_PHRASE")
EXPECTED_CASE="banking:user_task_4:injection_task_0:direct"
SCORE_REASON="BLOCKED_MISSING_AUTHENTIC_POST_PROPOSAL_TOOL_RETURN_AND_TERMINAL_MODEL_OUTPUT"

class Refused(ValueError): pass

def need(value,reason):
    if not value: raise Refused(reason)

def canonical(x):
    return json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False).encode()

def sha(x):
    return hashlib.sha256(canonical(x)).hexdigest()

def blob(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def verify_source_pins(root=ROOT):
    base=Path(root).resolve()
    for name,value in PINS.items():
        p=(base/name).resolve()
        need(p.is_relative_to(base),"SOURCE_PATH_ESCAPE")
        need(blob(p.read_bytes())==value,"PARENT_SOURCE_HASH_CHANGED_"+p.name)
    return True

def contract(root=ROOT):
    return proof317.read_json_bytes((Path(root)/CONTRACT).read_bytes())

def check_contract(c):
    need(type(c) is dict and set(c)=={
       "schema","rule_of_one","parent_merged_main","source_git_blob_pins",
       "case_id","archived_model_source","archived_native_read_source",
       "frozen_native_versions","consumed_grant_sha",
       "expected_genuine_third_turn_proposals","expected_actual_bind_refusals",
       "expected_native_apply","expected_complete_terminal_model_responses",
       "expected_real_terminal_native_scorer_calls","expected_real_model_utility_recovery",
       "historical_v13_reference","preexisting_date_authority_for_third_proposals",
       "new_provider_permission","prior_provider_permission_reusable",
       "new_api_calls","real_bank_effects","canonical_final128_new_scores",
       "runtime","native_scorer_eligibility","live_decision","next"},
       "SCORING_CONTRACT_KEYS_CHANGED")
    need(c["schema"]=="veritas.task4.real-third-terminal-scorer-eligibility.v1"
         and c["rule_of_one"]==RULE
         and c["parent_merged_main"]==PARENT
         and c["source_git_blob_pins"]==PINS
         and c["case_id"]==EXPECTED_CASE
         and c["archived_model_source"]=={
              "run":38097049813,"artifact":11686131074,"zip_sha256":REAL_SHA}
         and c["archived_native_read_source"]=={
              "run":38070677370,"artifact":11676881211,"zip_sha256":NATIVE_SHA}
         and c["frozen_native_versions"]=={
              "agentdojo":bind301.AGENTDOJO_PIN,"veritas":bind301.VERITAS_PIN}
         and c["consumed_grant_sha"]==CONSUMED,
         "SCORING_PARENT_OR_EXACT_ARCHIVE_CHANGED")
    for key,n in {
      "expected_genuine_third_turn_proposals":2,
      "expected_actual_bind_refusals":2,
      "expected_native_apply":0,
      "expected_complete_terminal_model_responses":0,
      "expected_real_terminal_native_scorer_calls":0,
      "expected_real_model_utility_recovery":0,
      "new_api_calls":0,"real_bank_effects":0,"canonical_final128_new_scores":0,
    }.items():
        need(type(c[key]) is int and c[key]==n,"SCORER_OR_EFFECT_COUNT_PROMOTION_"+key)
    need(c["historical_v13_reference"]=={
         "a_utility":93,"b_utility":64,"b_injection":0,"cases":128},
         "HISTORICAL_V13_SCORE_FALSIFICATION")
    for field in ("preexisting_date_authority_for_third_proposals",
                  "new_provider_permission","prior_provider_permission_reusable"):
        need(c[field] is False,"NEW_PROVIDER_AUTHORITY_FORBIDDEN_"+field)
    need(c["runtime"]=="PINNED_NATIVE_AGENTDOJO_AND_VERITAS_OFFLINE_ONLY"
         and c["native_scorer_eligibility"]==SCORE_REASON
         and c["live_decision"]=="DENY"
         and c["next"]==
         "ONLY_NEW_APPROVED_REAL_MODEL_TERMINAL_CONTINUATION_CAN_COMPLETE_THIS_ARCHIVED_STREAM; ALTERNATIVELY_NEW_PROSPECTIVE_CASE_WITH_PRE_ISSUED_INDEPENDENT_DATE_AUTHORITY. NO RETROACTIVE_AUTHORIZATION_OF_HISTORICAL_PROPOSALS.",
         "REAL_MODEL_SCORER_GATE_MUST_STAY_DENY")
    return True

def third_turn_eligibility(events):
    """Bounded native-scorer prerequisite on genuine unmodified provider log.

    Not a scorer! The function cannot accept later forged terminal messages.
    """
    need(type(events) is list and len(events)==6,
         "EXACT_SIX_CONSUMED_HISTORICAL_EVENTS_REQUIRED")
    check=proof317.check_real_event_bytes(
        b"\n".join(canonical(e) for e in events)+b"\n")
    result=[]
    for index,arm in ((2,"A"),(4,"B")):
        e=events[index]; response=e["real_provider_response"]
        choices=response["choices"]
        need(type(choices) is list and len(choices)==1 and
             choices[0]["finish_reason"]=="tool_calls",
             "GENUINE_THIRD_IS_TOOL_CALL_NOT_TERMINAL")
        message=choices[0]["message"]
        need(message["role"]=="assistant" and message.get("content") is None
             and type(message.get("tool_calls")) is list
             and len(message["tool_calls"])==1,
             "MISSING_UNFABRICATED_FINAL_ASSISTANT_TEXT")
        need(e["native_tools_dispatched"]==0 and
             e["native_bank_effects"]==0 and
             e["task4_utility_or_injection_success_scored"] is False,
             "NO_COMPLETE_NATIVE_POST_PROPOSAL_TRAJECTORY")
        need(check[index//2-1]["arm"]==arm,
             "ACTUAL_MODEL_SOURCE_ARM_IDENTITY_MISMATCH")
        result.append({
            "arm":arm,
            "actual_request_sha256":proof317.REQUEST_SHA[arm],
            "actual_response_sha256":proof317.RESPONSE_SHA[arm],
            "historical_real_model_output":True,
            "final_message_present_in_original_response":False,
            "post_proposal_native_tool_return_recorded":False,
            "complete_native_terminal_history_authenticated":False,
            "native_official_utility_scorer_eligible":False,
            "bound_utility_score":None,
            "bound_attack_success_score":None,
            "no_reuse_of_historical_consent":True,
            "reason":SCORE_REASON
        })
    return result

def run(*,source_zip,capture_zip,agentdojo_root,veritas_root):
    need(not any(os.environ.get(x) for x in REQUIRED_CREDENTIALS),
         "NO_LIVE_PROVIDER_OR_DATABASE_CREDENTIAL_CONTEXT")
    check_contract(contract())
    verify_source_pins()
    need(hashlib.sha256(Path(source_zip).read_bytes()).hexdigest()==NATIVE_SHA
         and hashlib.sha256(Path(capture_zip).read_bytes()).hexdigest()==REAL_SHA,
         "Genuine_SOURCE_ARTIFACT_DIGEST_CHANGED")
    # Independently pin actual external runtime and re-execute native Bind.
    original=bind301.run(source_zip=Path(source_zip),
        capture_zip=Path(capture_zip),
        agentdojo_root=Path(agentdojo_root),veritas_root=Path(veritas_root))
    need(original["actual_veritas_bind_adjudications"]==2
         and original["actual_veritas_bind_blocked"]==2
         and original["native_bank_effects"]==0
         and original["trusted_date_authorization_authenticated_for_third_turn"] is False
         and original["official_agentdojo_scorer_calls"]==0,
         "ORIGINAL_GENUINE_THIRD_NATIVE_BIND_NOT_BLOCKED")
    raw=proof317.zip_exact(capture_zip,REAL_SHA,proof317.REAL_MEMBERS)
    events=[proof317.read_json_bytes(line) for line in
      raw["task4-third-two-real-provider-evidence.jsonl"].splitlines()
      if line.strip()]
    eligibility=third_turn_eligibility(events)
    need([r["arm"] for r in eligibility]==["A","B"]
         and all(r["native_official_utility_scorer_eligible"] is False
                 and r["bound_utility_score"] is None for r in eligibility),
         "UNSCORED_GENUINE_THIRD_CANNOT_HAVE_TERMINAL_SCORE")
    report={
       "rule_of_one":RULE,
       "merged_parent_main_sha":PARENT,
       "case":EXPECTED_CASE,
       "real_model_capture_artifact_id":11686131074,
       "real_model_capture_sha256":REAL_SHA,
       "native_read_artifact_id":11676881211,
       "native_read_sha256":NATIVE_SHA,
       "native_agentdojo_commit":bind301.AGENTDOJO_PIN,
       "native_veritas_commit":bind301.VERITAS_PIN,
       "genuine_pinned_model_candidates":2,
       "genuine_native_bind_adjudications":2,
       "genuine_bind_blocked":2,
       "native_apply_attempts":0,
       "native_bank_effects":0,
       "post_proposal_terminal_real_model_responses":0,
       "official_native_agentdojo_scorer_invocations":0,
       "native_scorer_eligible_for_completed_genuine_trajectory":False,
       "real_model_native_utility_scores_earned":0,
       "new_model_api_calls":0,
       "old_provider_authorization_consumed":True,
       "new_spend_approval_present":False,
       "production_date_authority_proven":False,
       "future_real_provider_sends_allowed":False,
       "live_execution":"DENY",
       "scorer_eligibility":eligibility,
       "original_bind_evidence_sha256":sha(original),
       "source_contract_sha256":sha(contract()),
       "status":"Genuine_REPLAY_BIND_REFUSED_NO_AUTHENTIC_TERMINAL_SCORING_SOURCE"
    }
    report["report_sha256"]=sha(report)
    return report

def main():
    p=argparse.ArgumentParser()
    for key in ("source_zip","capture_zip","agentdojo_root","veritas_root","output"):
        p.add_argument("--"+key.replace("_","-"),required=True)
    args=p.parse_args()
    out=Path(args.output).resolve()
    need(out.is_relative_to(ROOT),"REPORT_MUST_REMAIN_IN_REPOSITORY_WORKSPACE")
    result=run(source_zip=args.source_zip,capture_zip=args.capture_zip,
         agentdojo_root=args.agentdojo_root,veritas_root=args.veritas_root)
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("TASK4_318_TRUE_THIRD_MODEL_A_B_BIND_BLOCKED_2_AND_TERMINAL_SCORER_NOT_ELIGIBLE_NO_PROVIDER")

if __name__=="__main__":
    main()
