#!/usr/bin/env python3
"""Exact predecessor-chain replay plus read-only Task15 state scorer tests."""
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
RULE="TASK15_COMPOSED_NATIVE_STATE_SCORER_DIAGNOSTIC_V1"
NAME="task15-composed-native-state-scorer-diagnostic-v1"

def require(ok,message):
    if not ok: raise ValueError(message)

def blob(path):
    payload=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(payload)).encode()+b"\0"+payload).hexdigest()

def main():
    parser=argparse.ArgumentParser()
    for name in ("agentdojo","rcc","veritas"):
        parser.add_argument("--"+name+"-root",type=Path,required=True)
    for name in ("replay-artifact","v13-artifact","output-dir"):
        parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args()
    require(not os.environ.get("OPENAI_API_KEY") and
            not os.environ.get("VERITAS_DATABASE_URL"),
            "PROVIDER_OR_DATABASE_CREDENTIAL_FORBIDDEN")
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE and
            contract["state"]=="IMPLEMENTED_PENDING_EXACT_MAIN_AND_INDEPENDENT_AUDIT",
            "FROZEN_DIAGNOSTIC_CONTRACT_REQUIRED")
    for filename,pin in contract["source_blobs"].items():
        require(blob(ROOT/filename)==pin,"FROZEN_SOURCE_BLOB_MISMATCH:"+filename)
    out=args.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    prior=[sys.executable,
           "scripts/task15_controlled_multi_effect_composed_admission_runner_audit_v1.py",
           "--agentdojo-root",str(args.agentdojo_root.resolve()),
           "--rcc-root",str(args.rcc_root.resolve()),
           "--veritas-root",str(args.veritas_root.resolve()),
           "--replay-artifact",str(args.replay_artifact.resolve()),
           "--v13-artifact",str(args.v13_artifact.resolve()),
           "--output-dir",str(out)]
    finished=subprocess.run(prior,cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(finished.stdout+finished.stderr)
    require(finished.returncode==0,"FROZEN_COMPOSED_NATIVE_PROOF_FAILED:"+
            (finished.stdout+finished.stderr)[-3000:])
    report=json.loads((out/"task15-controlled-multi-effect-composed-admission-runner-v1.json").read_text())
    require(report["new_tests"]==15 and report["predecessor_tests"]==2209 and
            report["governed_steps"]==3 and
            report["terminal_phase"]=="COMPLETE_LOCAL_COMPOSED_RUN" and
            report["provider_calls"]==0,
            "FROZEN_PREDECESSOR_PROOF_OR_CLAIM_BOUNDARY_CHANGED")
    evidence=out/(NAME+".evidence.jsonl")
    refusals=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for path in (evidence,refusals,junit):path.unlink(missing_ok=True)
    env.update({k:"1" for k in (
        "TASK15_REFUND_DESIGN_PROOF","TASK15_REFUND_METADATA_PROOF",
        "TASK15_REFUND_CORRELATION_PROOF","TASK15_RENT_DESIGN_PROOF",
        "TASK15_CONTROLLED_RENT_PROOF","TASK15_SCOPE_LINEAGE_PROOF",
        "TASK15_COMPOSED_BOUNDARY_PROOF","TASK15_COMPOSED_RUNNER_PROOF",
        "TASK15_COMPOSED_NATIVE_SCORER_PROOF")})
    env["TASK15_RCC_ROOT"]=str(args.rcc_root.resolve())
    env["TASK15_COMPOSED_NATIVE_SCORER_EVIDENCE"]=str(evidence)
    env["TASK15_COMPOSED_NATIVE_SCORER_REFUSALS"]=str(refusals)
    cmd=[sys.executable,"-m","pytest","-q","-o","addopts=",
         "tests/test_task15_composed_native_state_scorer_diagnostic_v1.py",
         "--junitxml",str(junit)]
    test=subprocess.run(cmd,cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".test.log")).write_text(test.stdout+test.stderr)
    print(test.stdout,end="")
    require(test.returncode==0,"NATIVE_SCORER_DIAGNOSTIC_TEST_FAILED:"+
            (test.stdout+test.stderr)[-4500:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==contract["expected_dedicated_tests"] and
            not any(row.find(k) is not None for row in cases
                    for k in ("skipped","failure","error")),
            "STRICT_DIAGNOSTIC_TEST_POPULATION_REQUIRED")
    positive=[json.loads(x) for x in evidence.read_text().splitlines()]
    negative=[json.loads(x) for x in refusals.read_text().splitlines()]
    require(len(positive)==1 and len(negative)==15 and
            all(row["rubric_calls"]==0 and row["accepted"] is False
                for row in negative),"DIAGNOSTIC_REFUSAL_POPULATION_CHANGED")
    scored=positive[0]["observation"]
    require(scored["rule_of_one"]==RULE and
            scored["scorer_calls"]==2 and
            scored["scorer_timing"]=="AFTER_ALL_THREE_PAIRED_NATIVE_STEPS" and
            len(scored["scores"])==2 and
            len(scored["native_step_evidence"])==3 and
            [x["actual_generation_ordinal"] for x in
             scored["native_step_evidence"]]==[3,9,14] and
            all(x["native_dispatch_count_A"]==1 and
                x["native_dispatch_count_B"]==1 for x in
                scored["native_step_evidence"]),"COMPLETE_NATIVE_DIAGNOSTIC_ABSENT")
    for k in ("native_conversation_captured","full_conversation_utility_measured",
              "final128_utility_recovery_proven","new_injection_success_measured",
              "external_effect_authenticated","refusal_reopened"):
        require(scored[k] is False,"MODEL_OR_AUTHORITY_CLAIM_PROMOTED:"+k)
    require(scored["model_output_source"]=="EMPTY_NOT_CAPTURED" and
            scored["functions_stack_trace_source"]=="EMPTY_NOT_CAPTURED" and
            scored["provider_calls"]==0 and scored["new_native_dispatch_count"]==0,
            "MODEL_EVIDENCE_SYNTHESIZED_OR_NEW_DISPATCH_OCCURRED")
    result=dict(rule_of_one=RULE,
                determination="BOUNDED_LOCAL_NATIVE_STATE_SCORER_DIAGNOSTIC_PASS",
                source_pr_merge_sha=contract["base_main_sha"],
                predecessor_tests=2224,new_tests=len(cases),
                test_failures=0,refusals_without_rubric=len(negative),
                local_governed_steps=3,native_rubric_calls=2,
                model_conversation_captured=False,full_trajectory_utility_measured=False,
                final128_utility_recovery_proven=False,injection_success_remeasured=False,
                provider_calls=0,new_native_dispatches=0,
                independent_external_validation=False,external_effect_authenticated=False)
    (out/(NAME+".json")).write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("PASS_"+RULE)
    print("new_tests="+str(len(cases))+" predecessor_tests=2224")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
