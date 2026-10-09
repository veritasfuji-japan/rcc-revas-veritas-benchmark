#!/usr/bin/env python3
"""Replay pinned #269 and independently audit one-shot offline grant rehearsal.

Never creates a live API client, never accepts a real provider key, and never
treats a local rehearsal nonce as verified human spending authorization.
"""
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
RULE="TASK15_PROVIDER_SINGLE_USE_REHEARSAL_DEFAULT_DENY_V1"
NAME="task15-provider-single-use-rehearsal-default-deny-v1"

def require(ok,reason):
    if not ok:raise ValueError(reason)

def sha(x):
    return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(", ",":"),
        ensure_ascii=False,allow_nan=False).encode()).hexdigest()

def canonical_sha(x):
    return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(",",":"),
        ensure_ascii=False,allow_nan=False).encode()).hexdigest()

def blob(path):
    data=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()

def main():
    ap=argparse.ArgumentParser()
    for k in ("agentdojo","rcc","veritas"):
        ap.add_argument("--"+k+"-root",type=Path,required=True)
    for k in ("replay-artifact","v13-artifact","output-dir"):
        ap.add_argument("--"+k,type=Path,required=True)
    args=ap.parse_args()
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE
            and contract["status"]=="IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI"
            and contract["predecessor_main_sha"]==
                "5206a8e032362f0c362dba444a99ce38dd146a87",
            "FROZEN_PR269_MERGED_MAIN_REQUIRED")
    for path,digest in contract["source_blobs"].items():
        require(blob(ROOT/path)==digest,"NEW_SOURCE_BLOB_MISMATCH:"+path)
    for path,digest in contract["agentdojo_native_blobs"].items():
        require(blob(args.agentdojo_root.resolve()/path)==digest,
                "NATIVE_AGENTDOJO_BLOB_MISMATCH:"+path)
    require(blob(ROOT/"contracts/AGENTDOJO_EXACT_MODEL_CONFIGURATION_v0.1.json")==
                contract["model_configuration_blob"],
            "FROZEN_MODEL_SNAPSHOT_CONFIGURATION_CHANGED")
    require(not os.environ.get("OPENAI_API_KEY")
            and not os.environ.get("VERITAS_DATABASE_URL"),
            "LIVE_API_CREDENTIAL_OR_DB_CANNOT_ENTER_OFFLINE_PROOF")
    out=args.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    previous=subprocess.run([
        sys.executable,
        "scripts/task15_real_provider_preflight_default_deny_audit_v1.py",
        "--agentdojo-root",str(args.agentdojo_root.resolve()),
        "--rcc-root",str(args.rcc_root.resolve()),
        "--veritas-root",str(args.veritas_root.resolve()),
        "--replay-artifact",str(args.replay_artifact.resolve()),
        "--v13-artifact",str(args.v13_artifact.resolve()),
        "--output-dir",str(out),
    ],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(
        previous.stdout+previous.stderr)
    require(previous.returncode==0,
            "FROZEN_PR269_EVIDENCE_REPLAY_FAILED:"+
            (previous.stdout+previous.stderr)[-24000:])
    summary=json.loads((out/"task15-real-provider-preflight-default-deny-v1.json").read_text())
    require(summary["determination"]==
                "SIXTEEN_TASK15_OFFLINE_REQUESTS_PINNED_REAL_PROVIDER_GATE_CLOSED"
            and summary["predecessor_tests"]==2517
            and summary["new_tests"]==15
            and summary["refusals"]==14
            and summary["frozen_source_requests"]==16
            and summary["provider_calls"]==
                summary["provider_charges_usd"]==
                summary["native_bank_writes"]==
                summary["scorer_calls"]==0
            and summary["provider_permission_issued"] is False
            and summary["authenticated_model_response_proven"] is False
            and summary["canonical_final128_utility_measured"] is False,
            "FROZEN_PR269_PROVENANCE_AND_DEFAULT_DENY_REQUIRED")
    pre_file=out/"task15-real-provider-preflight-default-deny-v1.evidence.jsonl"
    prior=[json.loads(x) for x in pre_file.read_text().splitlines()]
    require(len(prior)==1,"ONE_DURABLE_PR269_PROOF_REQUIRED")
    prior=prior[0]["proof"]
    require(prior["case_arm_request_count"]==16
            and len(prior["requests"])==16
            and prior["permission_to_call_provider"] is False,
            "PR269_EVIDENCE_CANNOT_PROMOTE_PAID_MODEL_TRANSPORT")
    good=out/(NAME+".evidence.jsonl")
    bad=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for f in (good,bad,junit):f.unlink(missing_ok=True)
    env["TASK15_SINGLE_USE_REHEARSAL_PROOF"]="1"
    env["TASK15_SINGLE_USE_REHEARSAL_PREDECESSOR_DIR"]=str(out)
    env["TASK15_SINGLE_USE_REHEARSAL_EVIDENCE"]=str(good)
    env["TASK15_SINGLE_USE_REHEARSAL_REFUSALS"]=str(bad)
    run=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task15_provider_single_use_rehearsal_default_deny_v1.py",
        "--junitxml",str(junit)
    ],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".tests.log")).write_text(run.stdout+run.stderr)
    print(run.stdout,end="")
    require(run.returncode==0,
            "FROZEN_SINGLE_USE_REHEARSAL_TESTS_FAILED:"+
            (run.stdout+run.stderr)[-24000:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==15 and not any(
        c.find(key) is not None for c in cases
        for key in ("failure","error","skipped")),
        "EXACT_FIFTEEN_PASS_ZERO_SKIPS_REQUIRED")
    proofs=[json.loads(x) for x in good.read_text().splitlines()]
    refusals=[json.loads(x) for x in bad.read_text().splitlines()]
    require(len(proofs)==1 and len(refusals)==14
            and len({x["fault"] for x in refusals})==14
            and all(x["result"]=="NO_LIVE_PROVIDER_CAPABILITY" for x in refusals),
            "FOURTEEN_DISTINCT_NON_EXECUTABLE_REFUSALS_REQUIRED")
    expected={
        "PREDECESSOR_NOT_ELIGIBLE":2,
        "DRAFT_REJECTED":6,
        "CONSUME_BURNED_NO_RETRY":5,
        "LIVE_DISPATCH_FORBIDDEN":1,
    }
    require({k:sum(1 for r in refusals if r["stage"]==k)
             for k in expected}==expected,
            "EXACT_REFUSAL_STAGE_DISTRIBUTION_REQUIRED")
    evidence=proofs[0]
    result=evidence["proof"]
    plan=evidence["plan"]
    req=prior["requests"][0]
    require(result["rule_of_one"]==plan["rule_of_one"]==RULE
            and result["determination"]==
                "ONE_LOCAL_REHEARSAL_CONSUMED_PROVIDER_AUTHORITY_ABSENT"
            and result["plan_sha256"]==canonical_sha(plan)
            and result["predecessor_proof_sha256"]==canonical_sha(prior)
            and plan["predecessor_proof_sha256"]==canonical_sha(prior)
            and plan["predecessor_merged_main_sha"]==
                "5206a8e032362f0c362dba444a99ce38dd146a87"
            and plan["schema"]=="task15.future-model-capture-request-plan.v1"
            and plan["kind"]=="NON_EXECUTABLE_OFFLINE_REHEARSAL_PROPOSAL"
            and plan["case_id"]==result["case_id"]==req["case_id"]
            and plan["arm"]==result["arm"]==req["arm"]=="A"
            and plan["frozen_model_snapshot"]==
                result["model_snapshot"]==
                req["frozen_model_snapshot"]=="gpt-4.1-mini-2025-04-14"
            and plan["source_request_sha256"]==
                req["native_postread_request_sha256"]
            and plan["source_tool_schemas_sha256"]==
                req["native_tool_schemas_sha256"]
            and plan["source_user_message_sha256"]==
                req["original_user_message_sha256"]
            and plan["source_read_call_id"]==
                req["prior_native_read_call_id"]
            and plan["max_cost_micro_usd"]==result["max_cost_micro_usd"]==5000000
            and plan["historical_ceiling_is_not_spend_permission"] is True
            and plan["issued_at"]=="2026-10-09T12:24:00+00:00"
            and plan["expires_at"]=="2026-10-09T12:29:00+00:00"
            and plan["offline_public_nonce"]==
                "OFFLINE-REHEARSAL-NOT-A-SECRET-OR-PROVIDER-TOKEN"
            and plan["transport_adapter_present"] is False
            and plan["trusted_human_approval_attested"] is False
            and plan["trusted_issuer_present"] is False
            and plan["live_provider_authority_issued"] is False
            and plan["native_bank_execution_authority_issued"] is False
            and plan["provider_response_authenticated"] is False
            and plan["provider_response_id"] is None
            and result["local_rehearsal_consumed"] is True
            and result["in_memory_single_use_only"] is True
            and result["durable_replay_protection_proven"] is False
            and result["human_approval_verified"] is False
            and result["live_provider_capability_issued"] is False
            and result["permission_to_call_provider"] is False
            and result["provider_request_sent"] is False
            and result["provider_response_authenticated"] is False
            and result["provider_calls"]==result["provider_charges_usd"]==
                result["native_write_dispatch_count"]==
                result["scorer_calls"]==result["external_effects"]==0
            and result["canonical_final128_measured"] is False
            and evidence["concurrent_attempts"]==16
            and evidence["concurrency_barrier_parties"]==16
            and evidence["rehearsals_consumed"]==1
            and evidence["replay_refusals"]==15,
            "ONLY_SINGLE_IN_MEMORY_REHEARSAL_NO_LIVE_EFFECT_CLAIM_ALLOWED")
    summary={
        "rule_of_one":RULE,
        "determination":result["determination"],
        "predecessor_tests":2532,
        "new_tests":len(cases),"refusals":len(refusals),
        "offline_prior_request_records":len(prior["requests"]),
        "concurrent_attempts":16,"consumed_local_rehearsals":1,
        "concurrent_replay_refusals":15,
        "provider_permission_issued":False,
        "durable_replay_protection_proven":False,
        "real_provider_calls":0,"real_provider_charges_usd":0,
        "native_writes":0,"scorer_calls":0,"external_effects":0,
    }
    (out/(NAME+".json")).write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
    print("PASS_"+RULE)
    print("tests=15 refusals=14 concurrent_attempts=16 "
          "local_rehearsals=1 provider_permission=0 provider_calls=0 native_writes=0")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
