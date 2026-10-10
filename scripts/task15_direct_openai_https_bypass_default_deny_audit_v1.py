#!/usr/bin/env python3
"""Prove both public #276 live HTTP entrypoints now fail closed, OFFLINE only.

The old immutable #276 merge proof remains an archived historical reference.
We independently rerun its full prior proof chain with source blobs repinned
to the current remediation, then inspect two real raw SQLite databases here.
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
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from task15_one_shot_openai_model_capture_gate_v1 import (
    CASE,MODEL,ARM,SOURCE_SHA,DirectOpenAIHTTPSOnce,OneShotDenied,
    input_from_exact_archived_evidence,validate_fresh_approval,
    canonical,digest,
)

ROOT=Path(__file__).resolve().parents[1]
NAME="task15-direct-openai-https-bypass-default-deny-v1"
RULE="TASK15_DIRECT_OPENAI_HTTPS_BYPASS_DEFAULT_DENY_V1"
NOW=datetime(2026,10,10,6,30,tzinfo=timezone.utc)

def require(good,reason):
    if not good:raise ValueError(reason)

def blob(path):
    data=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()

def one_file(out,name):
    rows=[json.loads(s) for s in (out/name).read_text().splitlines()]
    require(len(rows)==1,"EXACT_ONE_EVIDENCE_ROW:"+name)
    return rows[0]

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
                "677a65721fb44d11618a0f906b71eb1931166b44"
            and c["status"]=="IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI",
            "EXACT_POST_276_DIRECT_HTTP_REMEDIATION_REQUIRED")
    for pth,expected in c["source_blobs"].items():
        actual=blob(ROOT/pth)
        require(actual==expected,
                "EXACT_SOURCE_SHA_DRIFT:"+pth+":expected="+expected+":actual="+actual)
    for pth,expected in c["agentdojo_native_blobs"].items():
        require(blob(a.agentdojo_root.resolve()/pth)==expected,
                "AGENTDOJO_EXACT_NATIVE_SOURCE_DRIFT:"+pth)
    require(blob(ROOT/"contracts/AGENTDOJO_EXACT_MODEL_CONFIGURATION_v0.1.json")==
                c["model_configuration_blob"],
            "FROZEN_MODEL_CONFIG_DRIFT")
    require(not os.environ.get("OPENAI_API_KEY")
            and not os.environ.get("OPENAI_BASE_URL")
            and not os.environ.get("VERITAS_DATABASE_URL"),
            "NO_REAL_PROVIDER_KEY_OR_CUSTOM_ENDPOINT_IN_PROOF")
    # Assert current code itself blocks BOTH original helper entrypoints.
    with _expect_one_shot("DIRECT_HTTPS_HELPER_WITH_KEY_DEFAULT_DENIED"):
        DirectOpenAIHTTPSOnce("sk-untrusted-offline-test-only-123456")
    with _expect_one_shot("DIRECT_HTTPS_DISPATCH_NOT_AN_AUTHORIZED_EFFECT_SINK"):
        object.__new__(DirectOpenAIHTTPSOnce).send({"model":MODEL})
    out=a.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",OPENAI_BASE_URL="",
             VERITAS_DATABASE_URL="",PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
             PYTEST_ADDOPTS="")
    predecessor=subprocess.run([
        sys.executable,"scripts/task15_one_shot_openai_model_capture_gate_audit_v1.py",
        "--agentdojo-root",str(a.agentdojo_root.resolve()),
        "--rcc-root",str(a.rcc_root.resolve()),
        "--veritas-root",str(a.veritas_root.resolve()),
        "--replay-artifact",str(a.replay_artifact.resolve()),
        "--v13-artifact",str(a.v13_artifact.resolve()),
        "--output-dir",str(out)
    ],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(
        predecessor.stdout+predecessor.stderr)
    require(predecessor.returncode==0,
            "PR276_REGRESSION_CHAIN_FAILED:"+
            (predecessor.stdout+predecessor.stderr)[-30000:])
    prior=json.loads((out/"task15-one-shot-openai-model-capture-gate-v1.json").read_text())
    require(prior["determination"]==
                "BOUNDED_OFFLINE_ONE_SHOT_MODEL_GATE_AND_UNKNOWN_PROVEN"
            and prior["new_tests"]==15
            and prior["distinct_denials"]==14
            and prior["raw_sqlite_directly_verified"]==2
            and prior["successful_mock_calls"]==1
            and prior["denied_mock_duplicates"]==15
            and prior["timeout_unknown"]==1
            and prior["real_provider_calls"]==
                prior["real_provider_charges_usd"]==
                prior["native_bank_effects"]==0,
            "PR276_REPLAY_MUST_REMAIN_BOUNDED_OFFLINE_ONLY")
    pf=one_file(out,"task15-real-provider-first-call-preflight-default-deny-v1.evidence.jsonl")
    q=one_file(out,"task15-offline-postread-rcc-quarantine-v1.evidence.jsonl")
    old=one_file(out,"task15-one-shot-openai-model-capture-gate-v1.evidence.jsonl")
    require(old["actual_provider_requests"]==0
            and old["bank_tool_execution_count"]==0,
            "PR276_NOT_A_LIVE_PROVIDER_PROOF")
    ev=out/(NAME+".evidence.jsonl")
    no=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for target in (ev,no,junit):target.unlink(missing_ok=True)
    env.update({
        "TASK15_DIRECT_HTTPS_BYPASS_PROOF":"1",
        "TASK15_DIRECT_HTTPS_PREDECESSOR_DIR":str(out),
        "TASK15_DIRECT_HTTPS_EVIDENCE":str(ev),
        "TASK15_DIRECT_HTTPS_REFUSALS":str(no),
        "TASK15_DIRECT_HTTPS_SNAPSHOT_DIR":str(out)
    })
    result=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task15_direct_openai_https_bypass_default_deny_v1.py",
        "--junitxml",str(junit)
    ],cwd=ROOT,env=env,capture_output=True,text=True,timeout=180)
    (out/(NAME+".tests.log")).write_text(result.stdout+result.stderr)
    print(result.stdout,end="")
    require(result.returncode==0,
            "DIRECT_HTTP_BYPASS_REFUSAL_TESTS_FAILED:"+
            (result.stdout+result.stderr)[-28000:])
    tests=ET.parse(junit).getroot().findall(".//testcase")
    require(len(tests)==15 and not any(t.find(k) is not None
            for t in tests for k in ("failure","error","skipped")),
            "EXACT_15_JUNIT_PASS_NO_SKIP")
    good=[json.loads(s) for s in ev.read_text().splitlines()]
    bad=[json.loads(s) for s in no.read_text().splitlines()]
    require(len(good)==1 and len(bad)==14
            and len({x["fault"] for x in bad})==14
            and all(x["result"]==
                    "NO_DIRECT_HTTP_OR_UNAUTHORIZED_LIVE_PROVIDER_DISPATCH"
                    for x in bad),
            "FOURTEEN_REAL_DIRECT_BYPASS_REFUSALS_REQUIRED")
    obs=good[0]
    req=input_from_exact_archived_evidence(pf["manifest"],q)
    require(obs["rule_of_one"]==RULE
            and obs["determination"]==
               "ARCHIVED_DIRECT_OPENAI_HELPER_DEFAULT_DENIED_NO_LIVE_DISPATCH"
            and obs["source_pr276_evidence_sha256"]==digest(old)
            and obs["source_pr275_evidence_sha256"]==digest(pf)
            and obs["exact_source_request_sha256"]==SOURCE_SHA
            and obs["request_sha256"]==digest(req)
            and obs["direct_helper_constructor_blocked"] is True
            and obs["direct_helper_send_blocked"] is True
            and obs["live_gate_refused_before_claim"] is True
            and obs["test_only_operator_signature"] is True
            and obs["mock_call_count"]==1
            and obs["bank_effects_executed"]==
                obs["provider_http_requests"]==
                obs["provider_spend_usd"]==0,
            "CURRENT_PATH_MUST_PROVE_NO_LIVE_OPENAI_EFFECT")
    approval=obs["signed_fixture_approval"]
    public=bytes.fromhex(obs["public_fixture_root_hex"])
    approval_sha=validate_fresh_approval(approval,public,req,now_utc=NOW)
    paths=obs["snapshots"]
    require(set(paths)=={"mock","direct_live_denied"},"TWO_RAW_REMEDIATION_DATABASES")
    exp={"mock":("MOCK_RECORDED",1,3),
         "direct_live_denied":("PREPARED",0,1)}
    for name,row in paths.items():
        path=out/row["name"]
        require(path.is_file()
                and path.name=="task15-direct-bypass-"+(
                    "direct-live-denied" if name=="direct_live_denied" else "mock"
                )+".sqlite3"
                and hashlib.sha256(path.read_bytes()).hexdigest()==row["sha256"],
                "RAW_REMEDIATION_SQLITE_SHA_MISMATCH:"+name)
        db=sqlite3.connect("file:"+str(path.resolve())+"?mode=ro",uri=True)
        try:
            integrity=db.execute("PRAGMA integrity_check").fetchone()[0]
            values=db.execute("SELECT request_sha,manifest_sha,approval_sha,"
                "state,claim_count,response_sha,raw_response_json"
                " FROM capture").fetchall()
            events=[x[0] for x in db.execute(
                "SELECT event FROM audit ORDER BY seq").fetchall()]
        finally:db.close()
        state,claims,journal_count=exp[name]
        require(integrity=="ok"
                and len(values)==1 and len(events)==journal_count,
                "RAW_SQLITE_INTEGRITY_ONE_ROW_EXACT_JOURNAL")
        r=values[0]
        require(r[0]==digest(req)
                and r[1]==digest(pf["manifest"])
                and r[2]==approval_sha
                and r[3]==state and r[4]==claims
                and row["state"]["state"]==state
                and row["state"]["claims"]==claims
                and row["state"]["journal"]==events,
                "ATOMIC_DENIED_LIVE_STATE_MUST_BE_PREPARED")
        if name=="mock":
            require(r[5]==digest(json.loads(r[6]))
                    and json.loads(r[6])["choices"][0]["message"]["tool_calls"][0]["function"]["name"]=="send_money"
                    and events[-1]=="MOCK_RESPONSE_SAVED_NEVER_TOOL_EXECUTED",
                    "MOCK_TOOL_PROPOSAL_NOT_AN_EXECUTED_BANK_EFFECT")
        else:
            require(r[5] is None and r[6] is None
                    and events==["SIGNED_OPERATOR_APPROVAL_PINNED_NO_PROVIDER_SEND"],
                    "DENIED_LIVE_MUST_NOT_EVEN_CLAIM_ON_DISK")
    output={
        "rule_of_one":RULE,
        "determination":"BOUND_DIRECT_HELPER_AND_LIVE_GATE_DEFAULT_DENY_OFFLINE_PROVEN",
        "tests":15,"distinct_refusals":14,"raw_sqlite_direct_inspections":2,
        "direct_https_constructor_denied":True,
        "direct_https_send_denied":True,
        "live_gate_denied_before_durable_claim":True,
        "offline_mock_still_usable":True,
        "real_operator_approval_present":False,
        "real_provider_calls":0,"provider_charges_usd":0,
        "bank_effects":0,
        "system_wide_credential_and_network_isolation_proven":False,
        "independent_trust_root_proven":False,
    }
    (out/(NAME+".json")).write_text(json.dumps(output,indent=2,sort_keys=True)+"\n")
    print("PASS_"+RULE)
    print("new_tests=15 refusals=14 sqlite=2 direct_https=DENIED "
          "live_gate=DENIED offline_mock=PASS real_provider_calls=0 bank_writes=0")
    return 0

class _expect_one_shot:
    def __init__(self,message):self.message=message
    def __enter__(self):return self
    def __exit__(self,kind,val,tb):
        if kind is None:raise ValueError("BYPASS_HELPER_UNEXPECTEDLY_ALLOWED")
        if not issubclass(kind,OneShotDenied) or self.message not in str(val):
            return False
        return True

if __name__=="__main__":
    raise SystemExit(main())
