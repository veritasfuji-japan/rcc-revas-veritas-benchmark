#!/usr/bin/env python3
"""Replay exact #274 chain, verify frozen Task15 first model-call preflight.

Never instantiates an API client, sends provider requests, or uses credentials.
Approval and any live transport must be a SEPARATE, explicitly authorized round.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
RULE="TASK15_REAL_PROVIDER_FIRST_CALL_PREFLIGHT_DEFAULT_DENY_V1"
NAME="task15-real-provider-first-call-preflight-default-deny-v1"
SOURCE="task15-authoritative-mock-signed-sink-v1"

def require(ok,reason):
    if not ok:raise ValueError(reason)

def canonical(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False)

def sha(x):
    return hashlib.sha256(canonical(x).encode()).hexdigest()

def blob(path):
    data=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()

def main():
    p=argparse.ArgumentParser()
    for k in ("agentdojo","rcc","veritas"):
        p.add_argument("--"+k+"-root",type=Path,required=True)
    for k in ("replay-artifact","v13-artifact","output-dir"):
        p.add_argument("--"+k,type=Path,required=True)
    a=p.parse_args()
    c=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(c["rule_of_one"]==RULE
            and c["predecessor_main_sha"]==
                "7fdfed5cf4d8b1302fc376d36d97b67089dcfa12"
            and c["status"]=="IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI",
            "FROZEN_PR274_MERGED_MAIN_REQUIRED")
    for path,d in c["source_blobs"].items():
        found=blob(ROOT/path)
        require(found==d,
                "SOURCE_GIT_BLOB_DRIFT:"+path+":expected="+d+":actual="+found)
    for path,d in c["agentdojo_native_blobs"].items():
        require(blob(a.agentdojo_root.resolve()/path)==d,
                "AGENTDOJO_NATIVE_SOURCE_DRIFT:"+path)
    require(blob(ROOT/"contracts/AGENTDOJO_EXACT_MODEL_CONFIGURATION_v0.1.json")==
            c["model_configuration_blob"],
            "MODEL_CONFIG_DRIFT")
    require(not os.environ.get("OPENAI_API_KEY")
            and not os.environ.get("VERITAS_DATABASE_URL")
            and not os.environ.get("OPENAI_BASE_URL"),
            "REAL_PROVIDER_CREDENTIAL_OR_CUSTOM_TRANSPORT_ENV_FORBIDDEN")
    out=a.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             OPENAI_BASE_URL="",PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
             PYTEST_ADDOPTS="")
    prior=subprocess.run([
        sys.executable,"scripts/task15_authoritative_mock_signed_sink_audit_v1.py",
        "--agentdojo-root",str(a.agentdojo_root.resolve()),
        "--rcc-root",str(a.rcc_root.resolve()),
        "--veritas-root",str(a.veritas_root.resolve()),
        "--replay-artifact",str(a.replay_artifact.resolve()),
        "--v13-artifact",str(a.v13_artifact.resolve()),
        "--output-dir",str(out)
    ],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(prior.stdout+prior.stderr)
    require(prior.returncode==0,
            "PR274_PREDECESSOR_REPLAY_FAILED:"+
            (prior.stdout+prior.stderr)[-24000:])
    summ=json.loads((out/(SOURCE+".json")).read_text())
    require(summ["rule_of_one"]==
                "TASK15_AUTHORITATIVE_MOCK_SIGNED_SINK_V1"
            and summ["new_tests"]==15
            and summ["unique_refusals"]==14
            and summ["scenarios"]==4
            and summ["raw_sqlite_independently_verified"]==16
            and summ["authoritative_signed_confirmed"]==1
            and summ["legacy_generic_unsigned_confirmed_but_sink_unknown"]==1
            and summ["unsigned_or_absent_mock_effect_sink_unknown"]==2
            and summ["real_provider_calls"]==
                summ["real_provider_charges_usd"]==
                summ["real_bank_writes"]==
                summ["external_effects"]==0
            and summ["system_wide_bypass_resistance_proven"] is False,
            "ONLY_BOUNDED_PR274_RESULT_PERMITTED")
    old=json.loads((out/(SOURCE+".evidence.jsonl")).read_text().splitlines()[0])
    durable=json.loads((out/"task15-sqlite-durable-offline-consume-v1.evidence.jsonl").read_text().splitlines()[0])
    require(old["source_prior_sha256"]==sha(durable),
            "EXACT_FROZEN_PRIOR_SOURCE_HASH_REQUIRED")
    evidence=out/(NAME+".evidence.jsonl")
    negative=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    ledger=out/(NAME+".sqlite3")
    for file in (evidence,negative,junit,ledger):file.unlink(missing_ok=True)
    env["TASK15_FIRST_CALL_PREFLIGHT_OFFLINE_PROOF"]="1"
    env["TASK15_FIRST_CALL_PREDECESSOR_DIR"]=str(out)
    env["TASK15_FIRST_CALL_EVIDENCE"]=str(evidence)
    env["TASK15_FIRST_CALL_REFUSALS"]=str(negative)
    env["TASK15_FIRST_CALL_DB_ARTIFACT"]=str(ledger)
    run=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task15_real_provider_first_call_preflight_default_deny_v1.py",
        "--junitxml",str(junit)
    ],cwd=ROOT,env=env,capture_output=True,text=True,timeout=180)
    (out/(NAME+".tests.log")).write_text(run.stdout+run.stderr)
    print(run.stdout,end="")
    require(run.returncode==0,"FIRST_REAL_PROVIDER_OFFLINE_PREFLIGHT_TESTS_FAILED:"+
            (run.stdout+run.stderr)[-26000:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==15 and not any(
        t.find(k) is not None for t in cases
        for k in ("failure","error","skipped")),
        "FIFTEEN_NEW_TESTS_MUST_PASS_WITH_NO_SKIP")
    good=[json.loads(x) for x in evidence.read_text().splitlines()]
    bad=[json.loads(x) for x in negative.read_text().splitlines()]
    require(len(good)==1 and len(bad)==14
            and len({r["fault"] for r in bad})==14
            and all(r["result"]==
                    "NO_REAL_PROVIDER_CAPABILITY_AND_NO_PAID_REQUEST"
                    for r in bad),
            "FOURTEEN_DISTINCT_FAIL_CLOSED_NEGATIVES_REQUIRED")
    g=good[0];m=g["manifest"]
    require(g["rule_of_one"]==RULE
            and g["determination"]==
                "EXACT_ONE_SOURCE_SEALED_NO_LIVE_PROVIDER_AUTHORITY"
            and g["predecessor_pr274_sha256"]==sha(old)
            and g["predecessor_pr271_sha256"]==sha(durable)
            and g["source_plan_sha256"]==sha(durable["plan"])
            and m["rule_of_one"]==RULE
            and m["kind"]=="NON_EXECUTABLE_ONE_CALL_SOURCE_PREFLIGHT"
            and m["source_pr274_evidence_sha256"]==sha(old)
            and m["source_pr271_evidence_sha256"]==sha(durable)
            and m["source_plan_sha256"]==sha(durable["plan"])
            and m["first_case_id"]==
                "banking:user_task_15:injection_task_0:direct"
            and m["first_arm"]=="A"
            and m["provider_name"]=="openai"
            and m["exact_model_snapshot"]=="gpt-4.1-mini-2025-04-14"
            and m["requested_model_call_limit"]==1
            and m["proposed_max_output_tokens"]==256
            and m["proposed_cost_ceiling_micro_usd"]==250000
            and m["cost_ceiling_authorizes_spend"] is False
            and m["historical_five_dollars_authorizes_spend"] is False
            and m["operator_approval_attested"] is False
            and m["provider_api_credential_present"] is False
            and m["provider_transport_present"] is False
            and m["live_provider_execution_authority_issued"] is False
            and m["bank_write_capability_present"] is False
            and m["native_effect_dispatch_allowed"] is False
            and m["network_connectivity_permitted"] is False
            and m["provider_response_id"] is None
            and m["provider_response_authenticated"] is False
            and m["actual_provider_spend_usd"]==0
            and g["actual_real_provider_calls"]==
                g["actual_real_provider_spend_usd"]==
                g["actual_bank_effects"]==
                g["approved_spend_budget_usd"]==0
            and g["fresh_operator_approval_issued"] is False,
            "OFFLINE_MANIFEST_NOT_AN_EXECUTION_CAPABILITY")
    require(ledger.is_file()
            and g["artifact_db_name"]==ledger.name
            and hashlib.sha256(ledger.read_bytes()).hexdigest()==
                g["artifact_db_sha256"],
            "RAW_SQLITE_PLAN_SNAPSHOT_SHA_MISMATCH")
    conn=sqlite3.connect("file:"+str(ledger.resolve())+"?mode=ro",uri=True)
    try:
        integrity=conn.execute("PRAGMA integrity_check").fetchone()[0]
        rows=conn.execute("SELECT request_id,manifest_sha256,manifest_json,"
            "state,actual_call_count,actual_spend_usd,bank_effect_count"
            " FROM preflight").fetchall()
        events=conn.execute("SELECT event FROM audit ORDER BY seq").fetchall()
    finally:conn.close()
    o=g["observation"]
    require(integrity=="ok"
            and len(rows)==len(events)==1
            and rows[0]==(
                sha(m),sha(m),canonical(m),"PREPARED_NO_EXECUTION",0,0,0)
            and events[0][0]=="EXACT_SOURCE_MANIFEST_SEALED_NO_AUTHORITY"
            and o["manifest_sha256"]==sha(m)
            and o["state"]=="PREPARED_NO_EXECUTION"
            and o["real_provider_calls"]==
                o["real_provider_charges_usd"]==
                o["real_bank_writes"]==
                o["external_effects"]==0
            and o["operator_approval_issued"] is False
            and o["real_provider_transport_present"] is False
            and o["model_response_authenticated"] is False
            and o["executable"] is False,
            "RAW_SQLITE_PREPARED_NO_EXECUTION_PROOF_MISMATCH")
    summary={
        "rule_of_one":RULE,
        "determination":"EXACT_ONE_SOURCE_SEALED_NO_LIVE_PROVIDER_AUTHORITY",
        "new_tests":15,"distinct_refusals":14,
        "sealed_source_manifest_records":1,
        "raw_sqlite_verified":True,
        "proposed_model":m["exact_model_snapshot"],
        "proposed_cost_cap_usd":0.25,
        "cost_cap_is_not_permission":True,
        "new_human_approval_present":False,
        "real_provider_transport_present":False,
        "live_provider_calls":0,"live_provider_charges_usd":0,
        "real_bank_effects":0,"live_effect_reconciliation_proven":False,
        "real_model_response_authenticated":False,
    }
    (out/(NAME+".json")).write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
    print("PASS_"+RULE)
    print("new_tests=15 refusals=14 immutable_sqlite_plans=1 "
          "real_provider_calls=0 spend_usd=0 operator_approval=0 bank_effects=0")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
