#!/usr/bin/env python3
"""Exact-pinned predecessor replay and bounded provider-free composition audit."""
import argparse, hashlib, json, os, subprocess, sys
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
RULE="TASK15_CONTROLLED_MULTI_EFFECT_COMPOSED_ADMISSION_RUNNER_V1"
NAME="task15-controlled-multi-effect-composed-admission-runner-v1"
def require(ok,why):
    if not ok: raise ValueError(why)
def blob(path):
    b=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
def main():
    p=argparse.ArgumentParser()
    for x in ("agentdojo","rcc","veritas"):p.add_argument("--"+x+"-root",type=Path,required=True)
    for x in ("replay-artifact","v13-artifact","output-dir"):p.add_argument("--"+x,type=Path,required=True)
    a=p.parse_args()
    require(not os.environ.get("OPENAI_API_KEY") and not os.environ.get("VERITAS_DATABASE_URL"),"CREDENTIALS_FORBIDDEN")
    c=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(c["rule_of_one"]==RULE and c["status"]=="IMPLEMENTED_PENDING_CI_AND_INDEPENDENT_AUDIT","BOUNDED_CONTRACT_REQUIRED")
    for path,pin in c["source_blobs"].items():require(blob(ROOT/path)==pin,"SOURCE_CHANGED:"+path)
    out=a.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    flags=["--agentdojo-root",str(a.agentdojo_root.resolve()),"--rcc-root",str(a.rcc_root.resolve()),"--veritas-root",str(a.veritas_root.resolve()),"--replay-artifact",str(a.replay_artifact.resolve()),"--v13-artifact",str(a.v13_artifact.resolve()),"--output-dir",str(out)]
    prev=subprocess.run([sys.executable,"scripts/task15_controlled_multi_effect_composed_admission_boundary_audit_v1.py"]+flags,cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".prior.log")).write_text(prev.stdout+prev.stderr)
    require(prev.returncode==0,"FROZEN_PREDECESSOR_FAILED:"+(prev.stdout+prev.stderr)[-3000:])
    before=json.loads((out/"task15-controlled-multi-effect-composed-admission-boundary-v1.json").read_text())
    require(before["boundary_tests"]==110 and before["prior_dedicated_tests"]==2099 and before["actual_RCC_review_proven"] is False and before["actual_Bind_adjudication_proven"] is False,"FROZEN_CLAIMS_CHANGED")
    env.update({key:"1" for key in ("TASK15_REFUND_DESIGN_PROOF","TASK15_REFUND_METADATA_PROOF","TASK15_REFUND_CORRELATION_PROOF","TASK15_RENT_DESIGN_PROOF","TASK15_CONTROLLED_RENT_PROOF","TASK15_SCOPE_LINEAGE_PROOF","TASK15_COMPOSED_BOUNDARY_PROOF","TASK15_COMPOSED_RUNNER_PROOF")})
    env["TASK15_RCC_ROOT"]=str(a.rcc_root.resolve())
    evidence=out/(NAME+".evidence.jsonl");refusals=out/(NAME+".refusals.jsonl");junit=out/(NAME+".junit.xml")
    for path in (evidence,refusals,junit):path.unlink(missing_ok=True)
    env["TASK15_COMPOSED_RUNNER_EVIDENCE"]=str(evidence)
    env["TASK15_COMPOSED_RUNNER_REFUSALS"]=str(refusals)
    partial=out/(NAME+".partial.jsonl");partial.unlink(missing_ok=True)
    env["TASK15_COMPOSED_RUNNER_PARTIAL"]=str(partial)
    run=subprocess.run([sys.executable,"-m","pytest","-q","-o","addopts=","tests/test_task15_controlled_multi_effect_composed_admission_runner_v1.py","--junitxml",str(junit)],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".test.log")).write_text(run.stdout+run.stderr)
    print(run.stdout,end="")
    require(run.returncode==0,"COMPOSED_TESTS_FAILED:"+(run.stdout+run.stderr)[-3000:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==15 and not any(t.find(k)is not None for t in cases for k in ("skipped","error","failure")),"TEST_POPULATION_CHANGED")
    rows=[json.loads(x) for x in evidence.read_text().splitlines()]
    rejected=[json.loads(x) for x in refusals.read_text().splitlines()]
    require(len(rows)==1 and len(rejected)==6,"AUDIT_EVIDENCE_POPULATION_CHANGED")
    incomplete=[json.loads(x) for x in partial.read_text().splitlines()]
    require(len(incomplete)==2 and {x["fault"] for x in incomplete}=={"B_INTERRUPTED_AFTER_A_EFFECT","REFUND_B_INTERRUPTED"},"PARTIAL_EFFECT_PROBE_POPULATION_CHANGED")
    for x in incomplete:
        o=x["observation"];attempt=o["unresolved_native_attempt"]
        require(o["phase"]=="TERMINAL_UNKNOWN_OR_FAILED" and attempt["executing_arm"]=="B" and "B" not in attempt["captured_arm_results"],"INTERRUPTED_PAIR_MISCLASSIFIED")
        a=attempt["captured_arm_results"]["A"]
        require(a["integrity_verified"] is True and a["result"]["disposition"]=="COMMITTED" and a["result"]["native_dispatch_count"]==1,"FIRST_ARM_LOCAL_EFFECT_DISCARDED")
        if x["fault"]=="REFUND_B_INTERRUPTED":
            store=attempt["terminal_owned_refund_store"]
            require(len(o["completed_steps"])==2 and store["state"]=="CLOSED_BEFORE_CONSUMPTION" and store["consumptions"]==0 and store["slot_retry_allowed"] is False,"EARLIER_EFFECT_OR_RESERVATION_NOT_PRESERVED")
        else:require(not o["completed_steps"],"INTERRUPTED_ADDRESS_COMPOSITION_NOT_TERMINAL")
    result=rows[0]
    require(result["phase"] in ("COMPLETE_LOCAL_COMPOSED_RUN","TERMINAL_PAIR_DIVERGENCE") and 1<=len(result["completed_steps"])<=3,"COMPOSITION_TERMINAL_RESULT_REQUIRED")
    for i,step in enumerate(result["completed_steps"]):
        require(step["step"]==step["proof_slot"]==i and step["actual_generation_ordinal"]==(3,9,14)[i],"ORDINAL_SCOPE_MISMATCH")
        a,b=step["arms"]["A"],step["arms"]["B"]
        require(a["candidate_sha256"]==b["candidate_sha256"] and a["pre_state_sha256"]==b["pre_state_sha256"],"PAIR_MISMATCH")
        for arm in (a,b):require(any(row["event"]=="RCC_REVIEW" for row in arm["journal"]) and arm["native_dispatch_count"] in (0,1),"NATIVE_RCC_MISSING")
        if b["disposition"]=="COMMITTED":require(any(x["event"]=="VERITAS_BIND_RECEIPT" for x in b["journal"]),"BIND_MISSING")
    require(result["provider_execution"] is False and result["utility_recovery_proven"] is False and result["externally_authenticated_effect"] is False,"INVALID_CLAIM_UPGRADE")
    report=dict(rule_of_one=RULE,determination="BOUNDED_LOCAL_COMPOSED_RUNTIME_TESTED",predecessor_tests=2209,new_tests=15,partial_effect_probes=2,failures=0,terminal_phase=result["phase"],governed_steps=len(result["completed_steps"]),provider_calls=0,external_effect_authenticated=False,utility_recovery_proven=False,independent_external_validation=False)
    (out/(NAME+".json")).write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print("PASS_"+RULE)
if __name__=="__main__":raise SystemExit(main())
