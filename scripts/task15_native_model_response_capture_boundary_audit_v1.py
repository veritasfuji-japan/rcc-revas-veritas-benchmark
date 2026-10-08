#!/usr/bin/env python3
"""Offline source-captured native chat messages around unchanged Task15 sinks."""
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
RULE="TASK15_NATIVE_MODEL_RESPONSE_CAPTURE_BOUNDARY_V1"
NAME="task15-native-model-response-capture-boundary-v1"

def require(ok,reason):
    if not ok:
        raise ValueError(reason)

def blob(path):
    data=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()

def main():
    parser=argparse.ArgumentParser()
    for k in ("agentdojo","rcc","veritas"):
        parser.add_argument("--"+k+"-root",type=Path,required=True)
    for k in ("replay-artifact","v13-artifact","output-dir"):
        parser.add_argument("--"+k,type=Path,required=True)
    p=parser.parse_args()
    require(not os.getenv("OPENAI_API_KEY") and
            not os.getenv("VERITAS_DATABASE_URL"),
            "PROVIDER_AND_DATABASE_CREDENTIALS_FORBIDDEN")
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE and
            contract["proof_status"]=="IMPLEMENTED_PENDING_EXACT_HEAD_AUDIT",
            "EXACT_NATIVE_SOURCE_CONTRACT_REQUIRED")
    for path,expected in contract["source_blobs"].items():
        require(blob(ROOT/path)==expected,"NATIVE_SOURCE_PIN_CHANGED:"+path)
    out=p.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    predecessor=[
        sys.executable,
        "scripts/task15_composed_native_state_scorer_diagnostic_audit_v1.py",
        "--agentdojo-root",str(p.agentdojo_root.resolve()),
        "--rcc-root",str(p.rcc_root.resolve()),
        "--veritas-root",str(p.veritas_root.resolve()),
        "--replay-artifact",str(p.replay_artifact.resolve()),
        "--v13-artifact",str(p.v13_artifact.resolve()),
        "--output-dir",str(out),
    ]
    process=subprocess.run(predecessor,cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(process.stdout+process.stderr)
    require(process.returncode==0,"PREDECESSOR_NATIVE_SCORER_PROOF_NOT_CLOSED:"+
            (process.stdout+process.stderr)[-4500:])
    report=json.loads((out/"task15-composed-native-state-scorer-diagnostic-v1.json").read_text())
    require(report["new_tests"]==18 and report["predecessor_tests"]==2224 and
            report["native_rubric_calls"]==2 and
            report["provider_calls"]==0 and
            report["determination"]=="BOUNDED_LOCAL_NATIVE_STATE_SCORER_DIAGNOSTIC_PASS",
            "PREDECESSOR_CLAIM_OR_SOURCE_CHANGED")
    evidence=out/(NAME+".evidence.jsonl")
    refusals=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for f in (evidence,refusals,junit):
        f.unlink(missing_ok=True)
    env.update({v:"1" for v in (
        "TASK15_REFUND_DESIGN_PROOF","TASK15_REFUND_METADATA_PROOF",
        "TASK15_REFUND_CORRELATION_PROOF","TASK15_RENT_DESIGN_PROOF",
        "TASK15_CONTROLLED_RENT_PROOF","TASK15_SCOPE_LINEAGE_PROOF",
        "TASK15_COMPOSED_BOUNDARY_PROOF","TASK15_COMPOSED_RUNNER_PROOF",
        "TASK15_COMPOSED_NATIVE_SCORER_PROOF","TASK15_NATIVE_MODEL_CAPTURE_PROOF",
    )})
    env.update(TASK15_RCC_ROOT=str(p.rcc_root.resolve()),
               TASK15_NATIVE_MODEL_CAPTURE_EVIDENCE=str(evidence),
               TASK15_NATIVE_MODEL_CAPTURE_REFUSALS=str(refusals))
    cmd=[sys.executable,"-m","pytest","-q","-o","addopts=",
         "tests/test_task15_native_model_response_capture_boundary_v1.py",
         "--junitxml",str(junit)]
    test=subprocess.run(cmd,cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".test.log")).write_text(test.stdout+test.stderr)
    print(test.stdout,end="")
    require(test.returncode==0,"NATIVE_CAPTURE_TEST_FAILURE:"+
            (test.stdout+test.stderr)[-5000:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==contract["expected_dedicated_tests"] and
            all(all(x.find(failure) is None for failure in ("skipped","failure","error"))
                for x in cases),"MISSING_OR_SKIPPED_NATIVE_CAPTURE_CASES")
    result=[json.loads(x) for x in evidence.read_text().splitlines()]
    rejected=[json.loads(x) for x in refusals.read_text().splitlines()]
    require(len(result)==1 and len(rejected)==14 and
            len({x["fault"] for x in rejected})==14 and
            all(x["retry_allowed"] is False for x in rejected),
            "OFFLINE_CAPTURE_FAULT_POPULATION_CHANGED")
    good=result[0]
    require(good["rule_of_one"]==RULE and
            good["source_mode"]=="OFFLINE_INJECTED_CLIENT" and
            good["provider_execution"] is False and
            good["provider_response_authenticity_proven"] is False and
            good["actual_provider_utility_measured"] is False and
            good["new_injection_attack_measured"] is False and
            good["utility_scored"] is False and
            good["new_provider_calls"]==0 and good["scorer_calls"]==0 and
            good["new_authority_issued_by_wire"]==0 and
            len(good["source_candidate_events"])==3 and
            [x["ordinal"] for x in good["source_candidate_events"]]==[3,9,14] and
            len(good["arms"])==2 and
            all(x["status"]=="TERMINAL_TEXT_AVAILABLE" for x in good["arms"]) and
            [x["phase"] for x in good["transport_journal"]]==contract["expected_candidate_phases"] and
            all(x["status"]=="RESPONSE_DECODED" for x in good["transport_journal"]) and
            good["composed_native_execution"]["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN" and
            len(good["composed_native_execution"]["completed_steps"])==3,
            "UNSUPPORTED_PROVIDER_OR_TRAJECTORY_PROOF_PROMOTED")
    output={
        "rule_of_one":RULE,
        "determination":"BOUNDED_OFFLINE_SOURCE_AT_CAPTURE_LINKAGE_TESTED",
        "predecessor_tests":contract["expected_predecessor_tests"],
        "new_tests":len(cases),
        "failures":0,
        "rejected_faults":len(rejected),
        "owned_native_steps":3,
        "owned_a_b_local_dispatches":6,
        "offline_injected_client_calls":5,
        "provider_calls":0,
        "new_scoring_calls":0,
        "model_response_authenticity_proven":False,
        "real_provider_conversation_scored":False,
        "final128_utility_recovery_proven":False,
        "external_effect_authenticated":False,
        "independent_external_validation":False,
    }
    (out/(NAME+".json")).write_text(json.dumps(output,indent=2,sort_keys=True)+"\n")
    print("PASS_"+RULE)
    print("new_tests="+str(len(cases)))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
