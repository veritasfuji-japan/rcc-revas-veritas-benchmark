#!/usr/bin/env python3
"""Exact #271 replay + independent raw SQLite mock consequence/UNKNOWN audit."""
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
NAME="task15-mock-effect-unknown-reconcile-v1"
RULE="TASK15_MOCK_EFFECT_UNKNOWN_RECONCILE_V1"

def require(ok,reason):
    if not ok:raise ValueError(reason)

def sha(x):
    return hashlib.sha256(json.dumps(x,ensure_ascii=False,sort_keys=True,
        separators=(",",":"),allow_nan=False).encode()).hexdigest()

def blob(path):
    b=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()

def inspect_db(path,role):
    db=sqlite3.connect("file:"+str(path.resolve())+"?mode=ro",uri=True)
    try:
        require(db.execute("PRAGMA integrity_check").fetchone()[0]=="ok",
                "RAW_"+role+"_SQLITE_INTEGRITY_FAILED")
        if role=="controller":
            record=db.execute("SELECT operation_id,plan_sha256,prior_sha256,"
                "state,claims,dispatch_fences,receipt_sha256 FROM dispatch").fetchall()
            events=db.execute("SELECT event FROM journal ORDER BY seq").fetchall()
            require(len(record)==1,"CONTROLLER_MUST_HAVE_ONE_TICKET")
            values=record[0]
            return {
                "row":dict(zip(("operation_id","plan_sha256","prior_sha256",
                                "state","claims","dispatch_fences","receipt_sha256"),
                               values)),
                "events":[x[0] for x in events]}
        effects=db.execute("SELECT operation_id,plan_sha256,receipt_sha256,receipt_json"
                           " FROM mock_effects").fetchall()
        attempts=db.execute("SELECT operation_id,request_sha256"
                            " FROM mock_attempts").fetchall()
        require(len(effects)<=1 and len(attempts)<=1,
                "NO_MULTIPLE_MOCK_PROVIDER_EFFECTS")
        if effects:
            a=effects[0]
            rec=json.loads(a[3])
            require(a[2]==sha(rec) and a[3]==json.dumps(rec,sort_keys=True,
                    separators=(",",":"),ensure_ascii=False,allow_nan=False)
                    and a[0]==rec["operation_id"]
                    and a[1]==rec["plan_sha256"]
                    and rec["issuer"]=="LOCAL_SQLITE_SIMULATOR_NOT_A_REAL_PROVIDER"
                    and rec["receipt_kind"]=="MOCK_EFFECT_COMMITTED",
                    "RAW_MOCK_PROVIDER_RECEIPT_NOT_AUTHENTIC_TO_SIMULATOR_DATA")
        return {
            "effect_rows":len(effects),"attempt_rows":len(attempts),
            "receipt":json.loads(effects[0][3]) if effects else None,
            "attempt":attempts[0] if attempts else None}
    finally:db.close()

def main():
    cli=argparse.ArgumentParser()
    for k in ("agentdojo","rcc","veritas"):
        cli.add_argument("--"+k+"-root",type=Path,required=True)
    for k in ("replay-artifact","v13-artifact","output-dir"):
        cli.add_argument("--"+k,type=Path,required=True)
    a=cli.parse_args()
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE
            and contract["status"]=="IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI"
            and contract["predecessor_main_sha"]==
                "c32de2526ee5e2fd454fd1359ef985d582caf2c8",
            "EXACT_PR271_MERGED_MAIN_REQUIRED")
    for path,digest in contract["source_blobs"].items():
        require(blob(ROOT/path)==digest,"SOURCE_GIT_BLOB_MISMATCH:"+path)
    for path,digest in contract["agentdojo_native_blobs"].items():
        require(blob(a.agentdojo_root.resolve()/path)==digest,
                "AGENTDOJO_EXACT_SOURCE_BLOB_DRIFT:"+path)
    require(blob(ROOT/"contracts/AGENTDOJO_EXACT_MODEL_CONFIGURATION_v0.1.json")==
                contract["model_configuration_blob"],
            "EXACT_CLOSED_MODEL_CONFIGURATION_REQUIRED")
    require(not os.environ.get("OPENAI_API_KEY")
            and not os.environ.get("VERITAS_DATABASE_URL"),
            "LIVE_CREDENTIALS_NOT_PERMITTED_IN_OFFLINE_CI")
    out=a.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    predecessor=subprocess.run([
        sys.executable,"scripts/task15_sqlite_durable_offline_consume_audit_v1.py",
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
            "PR271_FROZEN_EVIDENCE_REPLAY_FAILED:"+
            (predecessor.stdout+predecessor.stderr)[-20000:])
    old=json.loads((out/"task15-sqlite-durable-offline-consume-v1.json").read_text())
    require(old["determination"]==
                "ONE_SQLITE_CROSS_PROCESS_LOCAL_CONSUME_NO_PROVIDER_AUTHORITY"
            and old["predecessor_tests"]==2547
            and old["new_tests"]==15
            and old["refusals"]==14
            and old["separate_python_processes"]==16
            and old["synchronized_sqlite_arrivals"]==16
            and old["atomic_claim_winners"]==1
            and old["replay_or_already_claimed_refusals"]==15
            and old["crash_leave_unresolved_without_retry"] is True
            and old["cross_machine_proof"] is False
            and old["provider_issuance"] is False
            and old["provider_calls"]==
                old["provider_charges_usd"]==
                old["native_bank_writes"]==
                old["scorer_calls"]==old["external_effects"]==0,
            "PR271_PRESERVED_DURABLE_BOUNDED_PROOF_REQUIRED")
    predecessor_file=out/"task15-sqlite-durable-offline-consume-v1.evidence.jsonl"
    rows=[json.loads(x) for x in predecessor_file.read_text().splitlines()]
    require(len(rows)==1,"ONE_PR271_DURABLE_EVIDENCE_REQUIRED")
    prior=rows[0]
    positive=out/(NAME+".evidence.jsonl")
    negative=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for p in (positive,negative,junit):p.unlink(missing_ok=True)
    env["TASK15_MOCK_EFFECT_UNKNOWN_PROOF"]="1"
    env["TASK15_MOCK_EFFECT_PREDECESSOR_DIR"]=str(out)
    env["TASK15_MOCK_EFFECT_EVIDENCE"]=str(positive)
    env["TASK15_MOCK_EFFECT_REFUSALS"]=str(negative)
    env["TASK15_MOCK_EFFECT_SNAPSHOT_DIR"]=str(out)
    test=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task15_mock_effect_unknown_reconcile_v1.py",
        "--junitxml",str(junit)
    ],cwd=ROOT,env=env,capture_output=True,text=True,timeout=180)
    (out/(NAME+".tests.log")).write_text(test.stdout+test.stderr)
    print(test.stdout,end="")
    require(test.returncode==0,"MOCK_UNKNOWN_NATIVE_TESTS_FAILED:"+
            (test.stdout+test.stderr)[-24000:])
    testcase=ET.parse(junit).getroot().findall(".//testcase")
    require(len(testcase)==15 and not any(
        item.find(k) is not None
        for item in testcase for k in ("failure","error","skipped")),
        "FIFTEEN_NEW_JUNIT_PASS_NO_SKIPS_REQUIRED")
    yes=[json.loads(s) for s in positive.read_text().splitlines()]
    no=[json.loads(s) for s in negative.read_text().splitlines()]
    require(len(yes)==1 and len(no)==14
            and len({item["fault"] for item in no})==14
            and all(item["result"]==
                    "NO_UNVERIFIED_EFFECT_PROMOTION_OR_LIVE_PROVIDER"
                    for item in no),
            "FOURTEEN_INDEPENDENT_MOCK_REFUSALS_REQUIRED")
    proof=yes[0]
    require(proof["rule_of_one"]==RULE
            and proof["source_prior_sha256"]==sha(prior)
            and proof["case_count"]==1
            and proof["actual_live_provider_calls"]==proof["actual_bank_effects"]==0
            and proof["production_authenticity_proven"] is False
            and proof["no_retries_after_unknown"] is True,
            "ACTUAL_LIVE_EFFECTS_MUST_REMAIN_UNCLAIMED")
    scenarios=proof["mock_scenarios"]
    require(type(scenarios) is list and len(scenarios)==6
            and len({s["scenario"] for s in scenarios})==6,
            "EXACT_SIX_MOCK_CONSEQUENCE_OUTCOMES_REQUIRED")
    outcomes={
        "delivered":("CONFIRMED_MOCK_EFFECT",1,1),
        "response_lost":("CONFIRMED_MOCK_EFFECT",1,1),
        "fenced_no_row":("DISPATCH_UNKNOWN",0,0),
        "predispatch_abort":("PRE_DISPATCH_NO_EFFECT",0,0),
        "crash_after_effect":("CONFIRMED_MOCK_EFFECT",1,1),
        "crash_after_fence":("DISPATCH_UNKNOWN",0,0),
    }
    raw_artifacts=0
    for scenario in scenarios:
        name=scenario["scenario"]
        require(name in outcomes,"UNKNOWN_OR_DUPLICATED_MOCK_CASE")
        expected,attempts,effects=outcomes[name]
        state=scenario["state"]
        ctrl=state["controller"]
        require(state["rule_of_one"]==RULE
                and state["source_proof_sha256"]==sha(prior)
                and state["source_plan_sha256"]==sha(prior["plan"])
                and ctrl["operation_id"]==state["operation_id"]
                and ctrl["plan_sha256"]==sha(prior["plan"])
                and ctrl["prior_sha256"]==sha(prior)
                and ctrl["claims"]==1
                and ctrl["state"]==expected
                and ctrl["dispatch_fences"]==(0 if name=="predispatch_abort" else 1)
                and state["mock_dispatch_attempts"]==attempts
                and state["mock_effect_rows"]==effects
                and state["mock_provider_only"] is True
                and state["real_provider_calls"]==
                    state["real_provider_charges_usd"]==
                    state["real_bank_writes"]==
                    state["real_native_effects"]==
                    state["scorer_calls"]==0
                and state["production_effect_reconciliation_proven"] is False
                and state["trusted_real_provider_receipt"] is False,
                "MOCK_SCENARIO_SCOPE_OR_NO_EFFECT_RULE_VIOLATED")
        snapshots=[scenario["snapshots"]]
        if name=="crash_after_effect":
            snapshots.append(scenario["before_recovery_snapshots"])
        for files in snapshots:
            cpath=out/files["controller"]["name"]
            ppath=out/files["provider"]["name"]
            for role,path in (("controller",cpath),("provider",ppath)):
                require(path.is_file() and path.name.startswith(
                    "task15-mock-effect-unknown-") and
                    hashlib.sha256(path.read_bytes()).hexdigest()==
                        files[role]["sha256"],
                    "MISSING_OR_TAMPERED_RAW_SQLITE_ARTIFACT")
                raw_artifacts+=1
            raw_ctrl=inspect_db(cpath,"controller")
            raw_mock=inspect_db(ppath,"provider")
            require(raw_ctrl["row"]["operation_id"]==state["operation_id"]
                    and raw_ctrl["row"]["plan_sha256"]==sha(prior["plan"])
                    and raw_ctrl["row"]["prior_sha256"]==sha(prior)
                    and raw_ctrl["row"]["claims"]==1,
                    "INDEPENDENT_CONTROLLER_DB_SOURCE_LINK_FAILED")
            require(raw_mock["effect_rows"]==effects
                    and raw_mock["attempt_rows"]==attempts,
                    "INDEPENDENT_EXTERNAL_MOCK_DB_EFFECT_COUNT_MISMATCH")
            if effects:
                receipt=raw_mock["receipt"]
                require(receipt["operation_id"]==state["operation_id"]
                        and receipt["plan_sha256"]==sha(prior["plan"])
                        and receipt["result"]=="LOCAL_SIMULATED_EFFECT_ONLY",
                        "SIMULATOR_RECEIPT_SCOPE_HASH_FAILED")
            else:
                require(raw_mock["receipt"] is None,
                        "NO_MOCK_ROW_REQUIRES_ABSENT_RECEIPT")
            if name=="crash_after_effect" and files is snapshots[1]:
                require(raw_ctrl["row"]["state"]=="DISPATCH_UNKNOWN"
                        and raw_ctrl["row"]["receipt_sha256"] is None,
                        "CRASHED_EFFECT_MUST_BE_UNKNOWN_BEFORE_READ_ONLY_RECOVERY")
            else:
                require(raw_ctrl["row"]==ctrl
                        and raw_ctrl["events"]==state["controller_events"],
                        "RAW_SQLITE_CONTROLLER_ROW_JOURNAL_INCONSISTENT")
    require(raw_artifacts==14,"FOURTEEN_INDEPENDENT_RAW_SQLITE_FILES_REQUIRED")
    # Critically, no post-fence attempt with absent evidence can be NO_EFFECT.
    for s in scenarios:
        c=s["state"]["controller"]
        if c["dispatch_fences"]==1 and s["state"]["mock_effect_rows"]==0:
            require(c["state"]=="DISPATCH_UNKNOWN",
                    "POST_FENCE_ABSENCE_CANNOT_PROMOTE_NO_EFFECT")
    summary={
        "rule_of_one":RULE,
        "determination":"SIX_BOUNDED_OFFLINE_MOCK_OUTCOMES_WITH_UNKNOWN_PRESERVED",
        "predecessor_tests":2562,"new_tests":15,
        "refusals":14,"simulated_consequence_scenarios":6,
        "raw_sqlite_artifacts_independently_inspected":raw_artifacts,
        "mock_effect_cases":3,
        "pre_dispatch_no_effect_cases":1,
        "post_dispatch_unknown_without_receipt_cases":2,
        "read_only_receipt_reconciliations":3,
        "external_real_provider_calls":0,"real_provider_charges_usd":0,
        "real_bank_writes":0,"native_writes":0,"scorer_calls":0,
        "production_effect_reconciliation_proven":False,
    }
    (out/(NAME+".json")).write_text(json.dumps(summary,sort_keys=True,indent=2)+"\n")
    print("PASS_"+RULE)
    print("tests=15 refusals=14 mock_scenarios=6 raw_sqlite=14 "
          "post_fence_UNKNOWN=2 mock_confirmed=3 pre_dispatch_NO_EFFECT=1 "
          "live_provider_calls=0 bank_writes=0")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
