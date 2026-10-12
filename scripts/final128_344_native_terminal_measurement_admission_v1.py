#!/usr/bin/env python3
"""#344 honest Utility optimization: source-bound same-run native scorer admission.

No live model, scorer, SDK, Bind, grant, bank effect or change to old evidence.
Structural transcript manifests are NOT a substitute for independent provenance;
even fully filled user-provided manifests remain AUTHENTICITY_UNVERIFIED.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re

from scripts import final128_335_optimization_ledger_v1 as r335
from scripts import final128_336_authority_safe_case_triage_v1 as r336

ROOT=Path(__file__).resolve().parents[1]
CONTRACT=ROOT/"contracts/FINAL128_344_NATIVE_TERMINAL_MEASUREMENT_ADMISSION_V1.json"
OUTPUT=ROOT/"results/final128-344-native-terminal-measurement-admission.json"
SCHEMA="veritas.final128.native-terminal-measurement-admission.v1"
RULE="NO_UTILITY_PROMOTION_WITHOUT_AUTHENTIC_SAME_RUN_NATIVE_TERMINAL_AND_SCORER_EVIDENCE"
BASE="4dfffea3717f5077cd8fc5fd248f6d88a49dea25"
HEX64=re.compile(r"^[0-9a-f]{64}$")
COHORTS={
 "MODEL_OR_TRAJECTORY_VARIANCE":("REPLAY_DIAGNOSTIC_ONLY_NOT_AUTOMATICALLY_AUTHORIZED",3),
 "AUTHORITY_PROTECTIVE_BLOCK":("DENY_UNLESS_PREEXISTING_NATIVE_AUTHORITY",10),
 "SEND_MONEY_PARAMETER_AUTHORITY_UNRESOLVED":("DENY_UNLESS_EXACT_ORIGINAL_PARAMETER_GRANTS",10),
 "CONDITIONAL_PREDICATE_NOT_PREREGISTERED":("DENY_UNLESS_PREREGISTERED_TRUSTED_PREDICATE",7)
}
SOURCE={
 "contracts/FINAL128_335_OPTIMIZATION_LEDGER_AND_TASK4_GAP_V1.json":"9cce521891f3faf4513062a09f99df58ab2f349a",
 "scripts/final128_335_optimization_ledger_v1.py":"d9ed932e0ede63fe23a080cae053315af332e4be",
 "contracts/FINAL128_336_AUTHORITY_SAFE_CASE_TRIAGE_V1.json":"d7f76c9a66dd457d55e69fb82521eacc6ec8445f",
 "scripts/final128_336_authority_safe_case_triage_v1.py":"d413e417d755ad4e9f44b38adc3060eefc2b658d",
 "contracts/TASK4_318_REAL_THIRD_TERMINAL_SCORER_ELIGIBILITY_V1.json":"0ea1b8c4de7e8fbc70c9f7bb11ba8367d62e6147",
}
FIELDS=[
 "original_request_sha256","initial_native_prestate_sha256","provider_model_request_sha256",
 "provider_response_receipt_sha256","native_candidate_sha256",
 "native_tool_result_or_denial_sha256","native_terminal_model_response_sha256",
 "native_user_scorer_input_sha256","native_user_scorer_output_sha256",
 "native_attack_scorer_input_sha256","native_attack_scorer_output_sha256",
 "native_wrapper_continuity_sha256","native_authority_source_sha256",
 "native_policy_source_sha256"
]
CLAIMS={
 "new_real_provider_calls":0,"new_native_bank_effects":0,
 "new_native_utility_scorer_calls":0,"new_native_attack_scorer_calls":0,
 "new_final128_scored_runs":0,"new_utility_recoveries":0,
 "new_verified_terminals":0,"paid_provider_dispatch":"DENY",
 "existing_provider_consent_reusable":False,
 "old_task4_authority_retroactively_granted":False,
 "official_score_from_self_declared_hashes":False,
 "independent_external_validation":False,
}
FROZEN={"run_id":37585673492,"arm_a_utility":93,"arm_b_utility":64,
        "arm_b_injection_success":0,"regressions":30,
        "arm_b_only_success":1,"net_gap":29,"total_cases":128}
THIRD={"genuine_model_tool_proposals":2,"actual_native_bind_denials":2,
       "authorized_native_applies":0,"authentic_post_proposal_tool_returns":0,
       "genuine_terminal_model_responses":0,"genuine_native_terminal_scorer_calls":0,
       "status":"UNSCORED"}

class Refused(ValueError):pass
def require(value,why):
    if not value:raise Refused(why)
def canonical(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,
                      separators=(",",":"),allow_nan=False).encode("utf-8")
def sha(value):return hashlib.sha256(canonical(value)).hexdigest()
def git_blob(path):
    b=(ROOT/path).read_bytes()
    return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\x00"+b).hexdigest()
def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def check_contract(c):
    require(type(c) is dict and set(c)=={
      "schema","rule_of_one","parent_main_sha","source_git_blobs",
      "frozen_v13","historical_task4_third","ranked_offline_measurement_cohorts",
      "structural_evidence_fields","required_pair_arms","nonclaims","allowed_outcomes"},
      "344_CONTRACT_KEYS_CHANGED")
    require(c["schema"]==SCHEMA and c["rule_of_one"]==RULE
      and c["parent_main_sha"]==BASE and c["source_git_blobs"]==SOURCE
      and c["frozen_v13"]==FROZEN and c["historical_task4_third"]==THIRD
      and c["structural_evidence_fields"]==FIELDS
      and c["required_pair_arms"]==["A","B"]
      and c["nonclaims"]==CLAIMS
      and c["allowed_outcomes"]==[
          "INCOMPLETE_UNSCORED","STRUCTURE_PRESENT_AUTHENTICITY_UNVERIFIED"]
      and len(c["ranked_offline_measurement_cohorts"])==4
      and [(row["rank"],row["lane"],row["count"],row["status"]) for row in
           c["ranked_offline_measurement_cohorts"]]==[
         (i,lane,COHORTS[lane][1],COHORTS[lane][0]) for i,lane in enumerate(
             ("MODEL_OR_TRAJECTORY_VARIANCE","AUTHORITY_PROTECTIVE_BLOCK",
              "SEND_MONEY_PARAMETER_AUTHORITY_UNRESOLVED",
              "CONDITIONAL_PREDICATE_NOT_PREREGISTERED"),1)],
      "344_PIN_OBJECTIVE_OR_AUTHORITY_DRIFT")
    for path,expected in SOURCE.items():
        require(git_blob(path)==expected,"344_SOURCE_GIT_BLOB_CHANGED:"+path)
    r336.check_contract(r336.read("contracts/FINAL128_336_AUTHORITY_SAFE_CASE_TRIAGE_V1.json"))
    r335.validate_contract(r335.load_json(r335.CONTRACT))
    return c

def case_score_admission(record, c):
    """Inspect only shape of a *hypothetical future* A/B manifest.

    DO NOT accept self-declared hashes as authentic provider receipts/scorer results.
    No output from this function represents a measured official score.
    """
    check_contract(c)
    require(type(record) is dict and set(record)=={
        "case_id","run_id","model_id","arm_records"},
        "344_FUTURE_RECORD_SHAPE_INVALID")
    require(type(record["case_id"]) is str and record["case_id"].startswith("banking:")
       and type(record["run_id"]) is int and record["run_id"]>0
       and type(record["model_id"]) is str and len(record["model_id"])>0,
       "344_FUTURE_RECORD_METADATA_INVALID")
    arms=record["arm_records"]
    require(type(arms) is dict and set(arms)=={"A","B"},
            "344_SAME_RUN_A_B_REQUIRED")
    for arm in ("A","B"):
        row=arms[arm]
        require(type(row) is dict and set(row)==set(FIELDS),
                "344_NATIVE_SCORER_EVIDENCE_FIELDS_REQUIRED")
        for name in FIELDS:
            value=row[name]
            require(value is None or
                    (type(value) is str and HEX64.fullmatch(value) is not None),
                    "344_MISSING_OR_INVALID_DIGEST:"+name)
    require(arms["A"]["original_request_sha256"] ==
            arms["B"]["original_request_sha256"]
            and arms["A"]["initial_native_prestate_sha256"] ==
                arms["B"]["initial_native_prestate_sha256"],
            "344_PAIRED_INPUT_OR_PRESTATE_MISMATCH")
    present=all(type(arms[a][field]) is str and
                HEX64.fullmatch(arms[a][field]) for a in ("A","B") for field in FIELDS)
    require(not (present and
       arms["A"]["provider_response_receipt_sha256"] ==
       arms["B"]["provider_response_receipt_sha256"]),
       "344_COPIED_A_B_PROVIDER_RECEIPT")
    return {
        "case_id":record["case_id"],"run_id":record["run_id"],
        "paired_arm_count":2,
        "status":("STRUCTURE_PRESENT_AUTHENTICITY_UNVERIFIED" if present
                   else "INCOMPLETE_UNSCORED"),
        "native_user_utility_score":None,"native_attack_success_score":None,
        "authentic_provider_origins_verified":False,
        "authentic_terminal_native_scorer_verified":False,
        "eligible_for_official_utility_claim":False,
        "missing_fields":sorted({
          name for arm in ("A","B") for name in FIELDS
          if arms[arm][name] is None}),
        "next_step":"VERIFY_ORIGINAL_PROVIDER_TOOL_TERMINAL_AND_NATIVE_SCORER_ARTIFACTS_INDEPENDENTLY",
    }

def build_report():
    c=check_contract(read(CONTRACT))
    prior=r335.audit()
    t=r336.triage()
    require(t["exact_case_count"]==30 and t["verified_authority_safe_historical_recoveries"]==0
       and t["official_utility_improvement"]==0 and t["new_paid_provider_calls"]==0
       and t["new_final128_scored_runs"]==0 and t["historical_scored_reference"]=={
           "run":37585673492,"arm_a":93,"arm_b":64,
           "arm_b_injection":0,"net_gap":29},
       "344_V13_HISTORIC_TRIAGE_CHANGED")
    third=prior["task4_genuine_model_native_score_gap"]
    require(third["actual_veritas_bind_refusals"]==2
       and third["genuine_native_user_task_score"]=="UNSCORED"
       and prior["new_real_utility_recoveries"]==0,
       "344_NO_LEGITIMATE_ARCHIVED_TASK4_RECOVERY")
    rows=t["case_triage"]
    require(len(rows)==30 and len({row["case_id"] for row in rows})==30,
           "344_V13_CASE_ROSTER_DRIFT")
    counts=Counter(r["v13_failure_lane"] for r in rows)
    require(dict(counts)=={k:v[1] for k,v in COHORTS.items()},
            "344_CLUSTER_COUNTS_DRIFT")
    cases=[]
    for row in rows:
        lane=row["v13_failure_lane"]
        require(row["new_native_utility_scored"] is False
            and row["recoverable_from_existing_335_evidence"] is False
            and row["independently_authorized_as_historical"] is False,
            "344_UNMEASURED_CASE_PROMOTED")
        case=row["case_id"]
        require(case.startswith("banking:user_task_"),"344_INVALID_CASE_ID")
        cases.append({
          "case_id":case,
          "lane":lane,
          "cohort_rank":next(x["rank"] for x in
                      c["ranked_offline_measurement_cohorts"] if x["lane"]==lane),
          "status":"UNSCORED_NEW_TREATMENT",
          "native_authority_must_remain_unmodified":True,
          "safe_next_action":row["requires_before_future_measurement"],
          "historical_disposition":row["observed_disposition"],
          "observed_recovery":False,
        })
    cases.sort(key=lambda z:(z["cohort_rank"],z["case_id"]))
    # A replay of existing third-turn proposal without a terminal reply remains
    # definitively inadmissible. No fabricated terminal message is manufactured.
    incomplete={name:None for name in FIELDS}
    placeholder={
      "case_id":r335.load_json(r335.CONTRACT)["task4_exact"]["case_id"],
      "run_id":38097049813,
      "model_id":r335.load_json(r335.CONTRACT)["task4_exact"]["model"],
      "arm_records":{"A":deepcopy(incomplete),"B":deepcopy(incomplete)}
    }
    admission=case_score_admission(placeholder,c)
    require(admission["status"]=="INCOMPLETE_UNSCORED"
       and admission["eligible_for_official_utility_claim"] is False,
       "344_PARTIAL_REAL_MODEL_HISTORY_MUST_REMAIN_UNSCORED")
    report={
      "schema":SCHEMA,"rule_of_one":RULE,"parent_main_sha":BASE,
      "historical_v13":FROZEN,"case_count":len(cases),
      "priority_cohorts":c["ranked_offline_measurement_cohorts"],
      "source_bound_case_queue":cases,
      "archived_task4_third_status":THIRD,
      "historical_task4_terminal_admission":admission,
      "first_bounded_offline_measurement_cohort":[
        x["case_id"] for x in cases if x["lane"]=="MODEL_OR_TRAJECTORY_VARIANCE"],
      "measurement_chain_required":[
        "FREEZE_REQUEST_AND_SAME_PRESTATE_FOR_BOTH_ARMS",
        "ACTUAL_INDEPENDENT_MODEL_CALL_OR_VERIFIED_ARCHIVED_ORIGIN",
        "ACTUAL_NATIVE_TOOL_EFFECT_OR_AUTHENTIC_DENIAL",
        "ACTUAL_POST_TOOL_NATIVE_RETURN_AND_MODEL_TERMINAL",
        "ACTUAL_NATIVE_USER_AND_ATTACK_SCORER",
        "CASE_LEVEL_PAIRED_DELTA_WITH_INJECTION_ZERO_CHECK",
        "CANONICAL_WRAPPER_AND_CREDENTIAL_AUTHORITY_CONTINUITY",
      ],
      "new_measured_native_terminal_utility":None,
      "new_measured_native_attack_success":None,
      "claims":CLAIMS,
      "next_action":"DO_NOT_RUN_SPENT_TASK4_THIRD_AGAIN_SELECT_SOURCE_AUTHORIZED_COHORT_OR_GET_FRESH_APPROVAL",
      "treatment_freeze":False,"external_validation":False,
    }
    verify_report(report)
    report["report_sha256"]=sha(report)
    return report

def verify_report(r):
    c=check_contract(read(CONTRACT))
    require(r["schema"]==SCHEMA and r["rule_of_one"]==RULE
       and r["parent_main_sha"]==BASE and r["historical_v13"]==FROZEN
       and r["case_count"]==30
       and r["priority_cohorts"]==c["ranked_offline_measurement_cohorts"]
       and len(r["source_bound_case_queue"])==30
       and len({x["case_id"] for x in r["source_bound_case_queue"]})==30
       and Counter(x["lane"] for x in r["source_bound_case_queue"])==
          Counter({k:v[1] for k,v in COHORTS.items()})
       and all(x["status"]=="UNSCORED_NEW_TREATMENT"
             and x["native_authority_must_remain_unmodified"] is True
             and x["observed_recovery"] is False
             for x in r["source_bound_case_queue"])
       and len(r["first_bounded_offline_measurement_cohort"])==3
       and set(r["first_bounded_offline_measurement_cohort"])=={
           x["case_id"] for x in r["source_bound_case_queue"]
           if x["lane"]=="MODEL_OR_TRAJECTORY_VARIANCE"}
       and r["archived_task4_third_status"]==THIRD
       and r["historical_task4_terminal_admission"]["status"]=="INCOMPLETE_UNSCORED"
       and r["historical_task4_terminal_admission"]["eligible_for_official_utility_claim"] is False
       and r["new_measured_native_terminal_utility"] is None
       and r["new_measured_native_attack_success"] is None
       and r["claims"]==CLAIMS
       and r["treatment_freeze"] is False
       and r["external_validation"] is False
       and r["next_action"]=="DO_NOT_RUN_SPENT_TASK4_THIRD_AGAIN_SELECT_SOURCE_AUTHORIZED_COHORT_OR_GET_FRESH_APPROVAL",
       "344_UTILITY_OR_SCORER_EVIDENCE_PROMOTION_REFUSED")
    return True

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    require(not any(os.environ.get(k) for k in (
      "OPENAI_API_KEY","TASK4_OPENAI_API_KEY","ANTHROPIC_API_KEY",
      "VERITAS_DATABASE_URL","GITHUB_TOKEN","GH_TOKEN")),
      "344_LIVE_API_OR_BANK_CREDENTIALS_FORBIDDEN")
    path=args.output.resolve()
    require(path==OUTPUT.resolve() and not path.exists(),
            "344_ONLY_FRESH_FIXED_REPORT_CAN_BE_CREATED")
    result=build_report()
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(result,sort_keys=True,indent=2,ensure_ascii=False)+"\n",
                    encoding="utf-8")
    print("FINAL128_344_SAFE_COHORT_3_OF_30_WITH_GENUINE_TASK4_UNSCORED_NO_FAKE_NATIVE_SCORER")
    print(json.dumps({"case_count":30,
      "first_diagnostic_cohort":result["first_bounded_offline_measurement_cohort"],
      "historical_task4_terminal":"UNSCORED",
      "new_utility_improvement":0,
      "report_sha256":result["report_sha256"]},sort_keys=True))
if __name__=="__main__":main()
