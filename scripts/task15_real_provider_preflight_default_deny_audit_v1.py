#!/usr/bin/env python3
"""Replay #268 then audit Task15 provider preflight: no permission, no API call."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
NAME="task15-real-provider-preflight-default-deny-v1"
RULE="TASK15_REAL_PROVIDER_PREFLIGHT_DEFAULT_DENY_V1"

def require(x,reason):
    if not x: raise ValueError(reason)

def sha(x):
    return hashlib.sha256(json.dumps(x,ensure_ascii=False,sort_keys=True,
        separators=(",",":"),allow_nan=False).encode()).hexdigest()

def blob(path):
    raw=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def main():
    p=argparse.ArgumentParser()
    for k in ("agentdojo","rcc","veritas"):
        p.add_argument("--"+k+"-root",type=Path,required=True)
    for k in ("replay-artifact","v13-artifact","output-dir"):
        p.add_argument("--"+k,type=Path,required=True)
    a=p.parse_args()
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE
            and contract["predecessor_main_sha"]==
                "f96051f7afd0395b8f4d4707b544023c06ba28ec"
            and contract["status"]=="IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI",
            "PINNED_PR268_MAIN_REQUIRED")
    for path,digest in contract["source_blobs"].items():
        require(blob(ROOT/path)==digest,"NEW_SOURCE_BLOB_DRIFT:"+path)
    for path,digest in contract["agentdojo_native_blobs"].items():
        require(blob(a.agentdojo_root.resolve()/path)==digest,
                "NATIVE_SOURCE_BLOB_DRIFT:"+path)
    config_file=ROOT/"contracts/AGENTDOJO_EXACT_MODEL_CONFIGURATION_v0.1.json"
    require(blob(config_file)==contract["model_configuration_blob"],
            "EXACT_FROZEN_MODEL_CONFIGURATION_DRIFT")
    # A nonempty credential or DB connection in the CI environment is an
    # unconditional stop even though this proof contains no transport adapter.
    require(not os.environ.get("OPENAI_API_KEY")
            and not os.environ.get("VERITAS_DATABASE_URL"),
            "LIVE_API_KEY_OR_DATABASE_CANNOT_ENTER_OFFLINE_PROOF")
    out=a.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    predecessor=subprocess.run([
        sys.executable,"scripts/task15_postread_a_bind_commit_b_refusal_pair_audit_v1.py",
        "--agentdojo-root",str(a.agentdojo_root.resolve()),
        "--rcc-root",str(a.rcc_root.resolve()),
        "--veritas-root",str(a.veritas_root.resolve()),
        "--replay-artifact",str(a.replay_artifact.resolve()),
        "--v13-artifact",str(a.v13_artifact.resolve()),
        "--output-dir",str(out),
    ],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(
        predecessor.stdout+predecessor.stderr)
    require(predecessor.returncode==0,
            "PR268_FROZEN_PREDECESSOR_CHAIN_FAILED:"+
            (predecessor.stdout+predecessor.stderr)[-24000:])
    old=json.loads((out/"task15-postread-a-bind-commit-b-refusal-pair-v1.json").read_text())
    require(old["determination"]==
                "EIGHT_LOCAL_A_BIND_COMMITS_JOINED_TO_EIGHT_B_BIND_BLOCKS"
            and old["predecessor_tests"]==2502
            and old["new_tests"]==15
            and old["refusals"]==14
            and old["native_task15_cases"]==8
            and old["actual_bind_a_committed"]==
                old["actual_bind_b_blocked_from_prior_round"]==
                old["local_native_user_info_effects"]==8
            and old["real_bank_or_network_effects"]==
                old["real_provider_calls"]==old["scorer_calls"]==0
            and old["same_candidate_paired_scoring"] is False
            and old["canonical_final128_utility_measured"] is False,
            "NO_LIVE_MODEL_PROOF_PROMOTION_FROM_PR268")
    names={
        "previous_pair":"task15-postread-a-bind-commit-b-refusal-pair-v1",
        "previous_ab":"task15-offline-postread-rcc-quarantine-v1",
        "previous_b":"task15-postread-actual-bind-refusal-v1"}
    def load(n):
        file=out/(n+".evidence.jsonl")
        require(file.is_file(),"PINNED_PROOF_RECORD_MISSING:"+n)
        rows=[json.loads(x) for x in file.read_text().splitlines()]
        require(len(rows)==1,"ONE_PREDECESSOR_PROOF_REQUIRED:"+n)
        return rows[0]["proof"]
    old_p={k:load(v) for k,v in names.items()}
    paths=[out/(NAME+"."+s) for s in
           ("evidence.jsonl","refusals.jsonl","junit.xml")]
    for p in paths:p.unlink(missing_ok=True)
    evidence,refusals,junit=paths
    env["TASK15_REAL_PROVIDER_PREFLIGHT_PROOF"]="1"
    env["TASK15_REAL_PROVIDER_PREFLIGHT_PREDECESSOR_DIR"]=str(out)
    env["TASK15_REAL_PROVIDER_PREFLIGHT_EVIDENCE"]=str(evidence)
    env["TASK15_REAL_PROVIDER_PREFLIGHT_REFUSALS"]=str(refusals)
    run=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task15_real_provider_preflight_default_deny_v1.py",
        "--junitxml",str(junit),
    ],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".tests.log")).write_text(run.stdout+run.stderr)
    print(run.stdout,end="")
    require(run.returncode==0,"NEW_OFFLINE_PROVIDER_PREFLIGHT_TESTS_FAILED:"+
            (run.stdout+run.stderr)[-28000:])
    testcases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(testcases)==15 and not any(
        t.find(k) is not None for t in testcases
        for k in ("failure","error","skipped")),
        "EXACT_FIFTEEN_JUNIT_TESTS_PASS_REQUIRED")
    good=[json.loads(x) for x in evidence.read_text().splitlines()]
    bad=[json.loads(x) for x in refusals.read_text().splitlines()]
    require(len(good)==1 and len(bad)==14
            and len({x["fault"] for x in bad})==14
            and all(x["result"]=="NO_PROVIDER_AUTHORITY_PROMOTION"
                    for x in bad)
            and len([x for x in bad if x["stage"]==
                "LIVE_PROVIDER_DISPATCH_IMPOSSIBLE"])==1,
            "FOURTEEN_DISTINCT_PROVENANCE_AND_PERMISSION_REFUSALS_REQUIRED")
    proof=good[0]["proof"]
    require(proof["rule_of_one"]==RULE
            and proof["determination"]==
                "SIXTEEN_TASK15_OFFLINE_REQUESTS_PINNED_REAL_PROVIDER_GATE_CLOSED"
            and proof["predecessor_proof_sha256"]==sha(old_p["previous_pair"])
            and proof["prior_ab_proof_sha256"]==sha(old_p["previous_ab"])
            and proof["prior_b_proof_sha256"]==sha(old_p["previous_b"])
            and proof["model_configuration_sha256"]==
                sha(json.loads(config_file.read_text()))
            and proof["case_count"]==8
            and proof["case_arm_request_count"]==16
            and proof["model_id"]=="gpt-4.1-mini-2025-04-14"
            and proof["budget_ceiling_usd"]==5.0
            and proof["budget_ceiling_is_expenditure_authority"] is False
            and proof["operator_approval_issued"] is False
            and proof["single_use_provider_authority_issued"] is False
            and proof["permission_to_call_provider"] is False
            and proof["response_authenticity_proven"] is False
            and proof["model_candidate_observed"] is False
            and proof["transport_adapter_enabled"] is False
            and proof["real_provider_calls"]==
                proof["real_provider_charges_usd"]==
                proof["scorer_calls"]==
                proof["native_write_dispatches"]==
                proof["external_effects"]==0
            and proof["full_canonical_trajectory_proven"] is False
            and proof["final128_utility_measured"] is False
            and proof["injection_success_measured"] is False,
            "NO_PROVIDER_TRANSPORT_OR_AUTHENTICITY_PERMISSION_PROMOTED")
    ids=set()
    require(len(proof["requests"])==16,"EXACT_SIXTEEN_FROZEN_REQUESTS_REQUIRED")
    for i in range(8):
        old_a=old_p["previous_ab"]["proposals"][i]
        require(old_a["case_id"]==
                    f"banking:user_task_15:injection_task_{(0,1,2,3,4,5,6,8)[i]}:direct",
                "EIGHT_CANONICAL_TASK15_INJECTION_CASES_REQUIRED")
        for j,arm in enumerate(("A","B")):
            r=proof["requests"][2*i+j]
            old_r=old_a["arms"][arm]
            require(r["case_id"]==old_a["case_id"] and r["arm"]==arm
                and r["prior_native_read_call_id"]==
                    old_r["prior_native_read_call_id"]
                and r["prior_native_read_result_sha256"]==
                    old_r["prior_native_tool_return_sha256"]
                and r["native_postread_request_sha256"]==
                    old_r["postread_request_sha256"]
                and r["native_tool_schemas_sha256"]==
                    sha(old_r["postread_request_tools"])
                and r["original_user_message_sha256"]==
                    sha(old_r["postread_request_messages"][1])
                and r["prior_offline_candidate_sha256"]==
                    old_r["candidate_sha256"]
                and r["prior_offline_rcc_review_sha256"]==
                    old_r["rcc_review_sha256"]
                and r["offline_source_only"] is True
                and r["provider_response_authenticated"] is False
                and r["provider_request_issued"] is False
                and r["provider_response_received"] is False
                and r["provider_response_id"] is None
                and r["provider_usage"] is None
                and r["provider_charge_usd"] is None
                and r["provider_executable_authority"] is False
                and r["bind_permit_from_future_model"] is False
                and r["native_effect_dispatch_authorized"] is False,
                "SOURCE_RECORD_NOT_A_LIVE_PROVIDER_RESPONSE")
            req=r["prior_native_read_call_id"]
            require(req not in ids,"DUPLICATE_FROZEN_SOURCE_CALL_ID")
            ids.add(req)
    require(len(ids)==16,"EXACT_SIXTEEN_INDEPENDENT_PREVIOUS_TOOL_CALLS")
    result={
        "rule_of_one":RULE,
        "determination":proof["determination"],
        "predecessor_tests":2517,
        "new_tests":len(testcases),"refusals":len(bad),
        "frozen_source_requests":16,
        "provider_calls":0,"provider_charges_usd":0,
        "provider_permission_issued":False,
        "authenticated_model_response_proven":False,
        "native_bank_writes":0,"scorer_calls":0,
        "canonical_final128_utility_measured":False,
    }
    (out/(NAME+".json")).write_text(
        json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("PASS_"+RULE)
    print("new_tests=15 refusals=14 source_requests=16 permission=0 "
          "provider_calls=0 scorer_calls=0 native_writes=0")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
