#!/usr/bin/env python3
"""Re-run #275 offline proof and independently audit Task15 one-shot mock evidence.

No network, no OpenAI SDK transport invocation, no actual approval or charges.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import xml.etree.ElementTree as ET

# Script entrypoints start with scripts/ on sys.path, not repository root.
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from task15_one_shot_openai_model_capture_gate_v1 import (
    RULE,CASE,ARM,MODEL,SOURCE_SHA,
    canonical,digest,input_from_exact_archived_evidence,
    validate_fresh_approval,
)

ROOT=Path(__file__).resolve().parents[1]
NAME="task15-one-shot-openai-model-capture-gate-v1"
NOW=datetime(2026,10,10,3,40,tzinfo=timezone.utc)

def require(check,reason):
    if not check:raise ValueError(reason)

def blob(path):
    raw=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def main():
    p=argparse.ArgumentParser()
    for x in ("agentdojo","rcc","veritas"):
        p.add_argument("--"+x+"-root",type=Path,required=True)
    for x in ("replay-artifact","v13-artifact","output-dir"):
        p.add_argument("--"+x,type=Path,required=True)
    a=p.parse_args()
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE
            and contract["predecessor_main_sha"]==
               "aee25a92d105183aafd07fecc63f1c614b5ab8f4"
            and contract["status"]==
               "IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI",
            "EXACT_PR275_MERGED_MAIN_REQUIRED")
    for path,expected in contract["source_blobs"].items():
        found=blob(ROOT/path)
        require(found==expected,
                "SOURCE_BLOB_DRIFT:"+path+":expected="+expected+":actual="+found)
    for path,expected in contract["agentdojo_native_blobs"].items():
        require(blob(a.agentdojo_root.resolve()/path)==expected,
                "AGENTDOJO_NATIVE_SOURCE_DRIFT:"+path)
    require(blob(ROOT/"contracts/AGENTDOJO_EXACT_MODEL_CONFIGURATION_v0.1.json")==
                contract["model_configuration_blob"],
            "EXACT_MODEL_PROFILE_DRIFT")
    require(not os.environ.get("OPENAI_API_KEY")
            and not os.environ.get("VERITAS_DATABASE_URL")
            and not os.environ.get("OPENAI_BASE_URL"),
            "ACTUAL_PROVIDER_KEYS_FORBIDDEN_IN_PROOF_CI")
    out=a.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             OPENAI_BASE_URL="",PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    prev=subprocess.run([
        sys.executable,
        "scripts/task15_real_provider_first_call_preflight_default_deny_audit_v1.py",
        "--agentdojo-root",str(a.agentdojo_root.resolve()),
        "--rcc-root",str(a.rcc_root.resolve()),
        "--veritas-root",str(a.veritas_root.resolve()),
        "--replay-artifact",str(a.replay_artifact.resolve()),
        "--v13-artifact",str(a.v13_artifact.resolve()),
        "--output-dir",str(out),
    ],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(prev.stdout+prev.stderr)
    require(prev.returncode==0,
            "EXACT_PR275_PREDECESSOR_CHAIN_NOT_VERIFIED:"+
            (prev.stdout+prev.stderr)[-25000:])
    ps=json.loads((out/"task15-real-provider-first-call-preflight-default-deny-v1.json").read_text())
    require(ps["rule_of_one"]==
                "TASK15_REAL_PROVIDER_FIRST_CALL_PREFLIGHT_DEFAULT_DENY_V1"
            and ps["determination"]=="EXACT_ONE_SOURCE_SEALED_NO_LIVE_PROVIDER_AUTHORITY"
            and ps["new_tests"]==15 and ps["distinct_refusals"]==14
            and ps["sealed_source_manifest_records"]==1
            and ps["raw_sqlite_verified"] is True
            and ps["new_human_approval_present"] is False
            and ps["real_provider_transport_present"] is False
            and ps["live_provider_calls"]==
                ps["live_provider_charges_usd"]==
                ps["real_bank_effects"]==0,
            "ONLY_FROZEN_NONEXECUTABLE_PR275_CAN_BE_USED")
    def one(filename):
        rows=[json.loads(x) for x in (out/filename).read_text().splitlines()]
        require(len(rows)==1,"EXACT_ONE_EVIDENCE_ROW:"+filename)
        return rows[0]
    pf=one("task15-real-provider-first-call-preflight-default-deny-v1.evidence.jsonl")
    q=one("task15-offline-postread-rcc-quarantine-v1.evidence.jsonl")
    positive=out/(NAME+".evidence.jsonl")
    negative=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for f in (positive,negative,junit):f.unlink(missing_ok=True)
    env["TASK15_ONE_SHOT_OPENAI_GATE_OFFLINE_PROOF"]="1"
    env["TASK15_ONE_SHOT_PREDECESSOR_DIR"]=str(out)
    env["TASK15_ONE_SHOT_EVIDENCE"]=str(positive)
    env["TASK15_ONE_SHOT_REFUSALS"]=str(negative)
    env["TASK15_ONE_SHOT_SQLITE_DIR"]=str(out)
    result=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task15_one_shot_openai_model_capture_gate_v1.py",
        "--junitxml",str(junit)
    ],cwd=ROOT,env=env,capture_output=True,text=True,timeout=180)
    (out/(NAME+".tests.log")).write_text(result.stdout+result.stderr)
    print(result.stdout,end="")
    require(result.returncode==0,"ONE_SHOT_GATE_TESTS_FAILED:"+
            (result.stdout+result.stderr)[-28000:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==15 and not any(
        c.find(k) is not None for c in cases
        for k in ("error","failure","skipped")),
        "FIFTEEN_TESTS_ALL_PASS_REQUIRED")
    rows=[json.loads(s) for s in positive.read_text().splitlines()]
    bad=[json.loads(s) for s in negative.read_text().splitlines()]
    require(len(rows)==1 and len(bad)==14
            and len({v["fault"] for v in bad})==14
            and all(v["result"]==
                    "NO_UNAUTHORIZED_OR_REPLAYED_REAL_PROVIDER_CALL"
                    for v in bad),
            "FOURTEEN_UNIQUE_DEFAULT_DENY_REFUSALS_REQUIRED")
    v=rows[0]
    request=input_from_exact_archived_evidence(pf["manifest"],q)
    require(v["rule_of_one"]==RULE and v["pr275_evidence_sha256"]==digest(pf)
            and v["determination"]==
                "EXACT_FROZEN_NATIVE_SOURCE_ONE_LOCAL_MODEL_ATTEMPT_MOCK_ONLY"
            and v["source_request_sha256"]==SOURCE_SHA
            and v["exact_http_request_sha256"]==digest(request)
            and v["exact_http_request"]==request
            and v["preapproved_test_root_only"] is True
            and v["actual_operator_approval_present"] is False
            and v["actual_provider_requests"]==
                v["actual_spend_usd"]==
                v["bank_tool_execution_count"]==0
            and v["mock_attempts"]==v["mock_one_winner"]==1
            and v["mock_replay_refusals"]==15
            and v["ambiguous_timeout_state"]=="DISPATCH_UNKNOWN",
            "MOCK_PROOF_MUST_NOT_CLAIM_REAL_MODEL_CONNECTION")
    pub=bytes.fromhex(v["offline_test_public_key_hex"])
    approval=v["offline_signed_approval"]
    approval_digest=validate_fresh_approval(approval,pub,request,now_utc=NOW)
    snapshots=v["snapshots"]
    require(set(snapshots)=={"mock","timeout_unknown"},
            "EXACT_MOCK_AND_TIMEOUT_SQLITE_FILES_REQUIRED")
    expected={"mock":("MOCK_RECORDED",3),"timeout_unknown":("DISPATCH_UNKNOWN",2)}
    for name,entry in snapshots.items():
        path=out/entry["name"]
        require(path.name=="task15-one-shot-"+name+".sqlite3"
                and path.is_file()
                and hashlib.sha256(path.read_bytes()).hexdigest()==entry["sha256"],
                "REAL_ARCHIVED_SQLITE_FILE_HASH_MISMATCH:"+name)
        db=sqlite3.connect("file:"+str(path.resolve())+"?mode=ro",uri=True)
        try:
            require(db.execute("PRAGMA integrity_check").fetchone()[0]=="ok",
                    "RAW_SQLITE_CORRUPTION")
            raw=db.execute("SELECT request_sha,manifest_sha,approval_sha,"
                           "state,claim_count,response_sha,raw_response_json"
                           " FROM capture").fetchall()
            journal=[r[0] for r in db.execute(
                "SELECT event FROM audit ORDER BY seq")]
        finally:db.close()
        state,events=expected[name]
        require(len(raw)==1
                and raw[0][0]==digest(request)
                and raw[0][1]==digest(pf["manifest"])
                and raw[0][2]==approval_digest
                and raw[0][3]==state and raw[0][4]==1
                and len(journal)==events
                and journal==entry["status"]["journal"]
                and state==entry["status"]["state"]
                and entry["status"]["claims"]==1,
                "ATOMIC_SINGLE_ATTEMPT_SOURCE_OR_EVENT_DRIFT")
        if name=="mock":
            r=json.loads(raw[0][6])
            require(raw[0][5]==digest(r)
                    and r["id"]=="chatcmpl_OFFLINE_NOT_REAL_PROVIDER"
                    and r["model"]==MODEL
                    and r["choices"][0]["message"]["tool_calls"][0]["function"]["name"]==
                       "send_money"
                    and journal[-1]=="MOCK_RESPONSE_SAVED_NEVER_TOOL_EXECUTED",
                    "MOCK_TOOL_RETURN_MUST_NOT_BECOME_BANK_EFFECT")
        else:
            require(raw[0][5] is None and raw[0][6] is None
                    and journal[-1]=="CLAIMED_BEFORE_ANY_POSSIBLE_MODEL_SEND",
                    "TIMEOUT_IS_UNKNOWN_AND_NEVER_RETRY")
    summary={
        "rule_of_one":RULE,
        "determination":"BOUNDED_OFFLINE_ONE_SHOT_MODEL_GATE_AND_UNKNOWN_PROVEN",
        "frozen_model":MODEL,"frozen_case":CASE,"arm":ARM,
        "source_sha256":SOURCE_SHA,
        "archived_native_payload_bytes":len(canonical(
             {"messages":request["messages"],"tools":request["tools"]}).encode()),
        "new_tests":15,"distinct_denials":14,
        "raw_sqlite_directly_verified":2,
        "parallel_contenders":16,"successful_mock_calls":1,
        "denied_mock_duplicates":15,"timeout_unknown":1,
        "actual_operator_grants":0,"real_provider_calls":0,
        "real_provider_charges_usd":0,"native_bank_effects":0,
        "production_human_approval_or_clock_proven":False,
        "real_provider_response_authenticated":False,
        "real_external_effect_reconciliation_proven":False,
    }
    (out/(NAME+".json")).write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
    print("PASS_"+RULE)
    print("tests=15 refusals=14 raw_sqlite=2 contenders=16 "
          "mock_winners=1 replay_denied=15 timeout_UNKNOWN=1 "
          "real_provider_calls=0 bank_writes=0")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
