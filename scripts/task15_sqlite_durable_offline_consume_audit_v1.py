#!/usr/bin/env python3
"""Exact #270 replay, single-host multi-process SQLite offline ticket audit."""
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
RULE="TASK15_SQLITE_DURABLE_OFFLINE_CONSUME_V1"
NAME="task15-sqlite-durable-offline-consume-v1"

def require(ok,reason):
    if not ok:raise ValueError(reason)

def canonical_sha(x):
    return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(",",":"),
        ensure_ascii=False,allow_nan=False).encode()).hexdigest()

def blob(path):
    raw=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def main():
    cli=argparse.ArgumentParser()
    for k in ("agentdojo","rcc","veritas"):
        cli.add_argument("--"+k+"-root",type=Path,required=True)
    for k in ("replay-artifact","v13-artifact","output-dir"):
        cli.add_argument("--"+k,type=Path,required=True)
    a=cli.parse_args()
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE
            and contract["predecessor_main_sha"]==
                "ec648458d79ef80f6b508b6a489bcda705426920"
            and contract["status"]=="IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI",
            "PR270_EXACT_MERGED_MAIN_REQUIRED")
    for path,digest in contract["source_blobs"].items():
        require(blob(ROOT/path)==digest,"REHEARSAL_SOURCE_BLOB_MISMATCH:"+path)
    for path,digest in contract["agentdojo_native_blobs"].items():
        require(blob(a.agentdojo_root.resolve()/path)==digest,
                "AGENTDOJO_NATIVE_RUNTIME_DRIFT:"+path)
    require(blob(ROOT/"contracts/AGENTDOJO_EXACT_MODEL_CONFIGURATION_v0.1.json")==
                contract["model_configuration_blob"],
            "FROZEN_MODEL_COST_PROFILE_DRIFT")
    require(not os.environ.get("OPENAI_API_KEY")
            and not os.environ.get("VERITAS_DATABASE_URL"),
            "API_KEY_OR_PRODUCTION_DATABASE_ENV_FORBIDDEN")
    out=a.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    prior=subprocess.run([
        sys.executable,
        "scripts/task15_provider_single_use_rehearsal_default_deny_audit_v1.py",
        "--agentdojo-root",str(a.agentdojo_root.resolve()),
        "--rcc-root",str(a.rcc_root.resolve()),
        "--veritas-root",str(a.veritas_root.resolve()),
        "--replay-artifact",str(a.replay_artifact.resolve()),
        "--v13-artifact",str(a.v13_artifact.resolve()),
        "--output-dir",str(out)
    ],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(prior.stdout+prior.stderr)
    require(prior.returncode==0,"PR270_SOURCE_PROOF_REPLAY_FAILED:"+
            (prior.stdout+prior.stderr)[-20000:])
    previous=json.loads((out/"task15-provider-single-use-rehearsal-default-deny-v1.json").read_text())
    require(previous["determination"]==
                "ONE_LOCAL_REHEARSAL_CONSUMED_PROVIDER_AUTHORITY_ABSENT"
            and previous["predecessor_tests"]==2532
            and previous["new_tests"]==15
            and previous["refusals"]==14
            and previous["offline_prior_request_records"]==16
            and previous["concurrent_attempts"]==16
            and previous["consumed_local_rehearsals"]==1
            and previous["concurrent_replay_refusals"]==15
            and previous["provider_permission_issued"] is False
            and previous["durable_replay_protection_proven"] is False
            and previous["real_provider_calls"]==
                previous["real_provider_charges_usd"]==
                previous["native_writes"]==
                previous["scorer_calls"]==
                previous["external_effects"]==0,
            "PR270_NOT_A_DURABLE_OR_LIVE_CAPABILITY")
    evidence_path=out/"task15-provider-single-use-rehearsal-default-deny-v1.evidence.jsonl"
    prior_evidence=[json.loads(x) for x in evidence_path.read_text().splitlines()]
    require(len(prior_evidence)==1,"ONE_EXACT_PR270_EVIDENCE_ROW_REQUIRED")
    previous=prior_evidence[0]
    require(previous["proof"]["plan_sha256"]==canonical_sha(previous["plan"])
            and previous["concurrent_attempts"]==16
            and previous["concurrency_barrier_parties"]==16
            and previous["rehearsals_consumed"]==1,
            "ACTUAL_PR270_REHEARSAL_SOURCE_REQUIRED")
    evidence=out/(NAME+".evidence.jsonl")
    refusals=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for f in (evidence,refusals,junit):f.unlink(missing_ok=True)
    env["TASK15_SQLITE_DURABLE_OFFLINE_CONSUME_PROOF"]="1"
    env["TASK15_SQLITE_DURABLE_PREDECESSOR_DIR"]=str(out)
    env["TASK15_SQLITE_DURABLE_EVIDENCE"]=str(evidence)
    env["TASK15_SQLITE_DURABLE_REFUSALS"]=str(refusals)
    test=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task15_sqlite_durable_offline_consume_v1.py",
        "--junitxml",str(junit)
    ],cwd=ROOT,env=env,capture_output=True,text=True,timeout=180)
    (out/(NAME+".tests.log")).write_text(test.stdout+test.stderr)
    print(test.stdout,end="")
    require(test.returncode==0,"NEW_SQLITE_CROSS_PROCESS_TESTS_FAILED:"+
            (test.stdout+test.stderr)[-20000:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==15 and not any(
        t.find(k) is not None
        for t in cases for k in ("failure","error","skipped")),
        "FIFTEEN_PASS_NO_SKIP_JUNIT_REQUIRED")
    good=[json.loads(s) for s in evidence.read_text().splitlines()]
    bad=[json.loads(s) for s in refusals.read_text().splitlines()]
    require(len(good)==1 and len(bad)==14
            and len({r["fault"] for r in bad})==14
            and all(r["result"]==
                    "NO_LIVE_PROVIDER_AUTHORITY_OR_REPLAY_PROMOTION"
                    for r in bad),
            "FOURTEEN_DISTINCT_FAIL_CLOSED_SQLITE_NEGATIVE_CASES_REQUIRED")
    categories={
        "UNTRUSTED_PREDECESSOR_REJECTED":2,
        "REISSUE_FORBIDDEN":1,
        "WRONG_TICKET_REFUSED":1,
        "LIVE_TRANSPORT_FORBIDDEN":1,
        "OWNER_MISMATCH_UNRESOLVED":1,
        "PROCESS_CRASH_PERSISTS_UNRESOLVED":1,
        "INVALID_AT_CONSUME_BURNED_DURABLY":7,
    }
    require({k:sum(1 for b in bad if b["stage"]==k)
             for k in categories}==categories,
            "WRONG_NEGATIVE_STAGE_BREAKDOWN")
    record=good[0]
    ticket=record["ticket_id"]
    p=record["proof"]
    state=record["durable_state"]
    require(record["predecessor_proof_sha256"]==canonical_sha(previous)
            and record["plan"]==previous["plan"]
            and record["processes_started"]==
                record["barrier_arrivals"]==16
            and record["successful_process_consumptions"]==1
            and record["refused_process_consumptions"]==15
            and len(record["refusal_reasons"])==15
            and all(s=="DURABLE_TICKET_ALREADY_CLAIMED_OR_ABSENT"
                    for s in record["refusal_reasons"])
            and p["rule_of_one"]==RULE
            and p["determination"]==
                "ONE_SQLITE_CROSS_PROCESS_LOCAL_CONSUME_NO_PROVIDER_AUTHORITY"
            and p["ticket_id"]==ticket
            and p["local_sqlite_single_host_replay_resistance"] is True
            and p["cross_machine_replay_protection_proven"] is False
            and p["crash_effect_reconciliation_proven"] is False
            and p["trusted_clock_proven"] is False
            and p["provider_authority_issued"] is False
            and p["provider_calls"]==
                p["charges_usd"]==
                p["native_writes"]==
                p["scorer_calls"]==
                p["external_effects"]==0,
            "ONLY_SINGLE_HOST_OFFLINE_ATOMIC_CONSUMPTION_ALLOWED")
    rows=state["records"]
    require(len(rows)==1 and state["arrivals"]==16
            and rows[0]["ticket_id"]==ticket
            and rows[0]["plan_sha256"]==canonical_sha(record["plan"])
            and rows[0]["predecessor_sha256"]==canonical_sha(previous)
            and rows[0]["state"]=="CONSUMED_OFFLINE"
            and rows[0]["owner"]==p["owner"]
            and rows[0]["claims"]==1
            and [e["event"] for e in state["events"]]==[
                "OFFLINE_NONEXECUTABLE_TICKET_CREATED",
                "ATOMIC_SINGLE_CLAIM_COMMITTED",
                "ONE_LOCAL_DURABLE_REHEARSAL_FINISHED"]
            and state["live_provider_authority_issued"] is False
            and state["trusted_human_approval_verified"] is False
            and state["live_provider_calls"]==
                state["provider_charges_usd"]==
                state["native_bank_writes"]==
                state["scorer_calls"]==
                state["external_effects"]==0,
            "DURABLE_ON_DISK_SINGLE_CLAIM_JOURNAL_INVALID")
    summary={
        "rule_of_one":RULE,
        "determination":p["determination"],
        "predecessor_tests":2547,
        "new_tests":15,"refusals":14,
        "separate_python_processes":16,
        "synchronized_sqlite_arrivals":16,
        "atomic_claim_winners":1,
        "replay_or_already_claimed_refusals":15,
        "crash_leave_unresolved_without_retry":True,
        "cross_machine_proof":False,
        "provider_issuance":False,
        "provider_calls":0,"provider_charges_usd":0,
        "native_bank_writes":0,"external_effects":0,"scorer_calls":0,
    }
    (out/(NAME+".json")).write_text(json.dumps(summary,sort_keys=True,indent=2)+"\n")
    print("PASS_"+RULE)
    print("new_tests=15 refusals=14 processes=16 durable_single_winner=1 "
          "replay_refused=15 live_provider_authority=0 provider_calls=0 native_writes=0")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
