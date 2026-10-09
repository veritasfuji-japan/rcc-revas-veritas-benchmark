#!/usr/bin/env python3
"""Read-only exact Task15 canonical roster and local evidence non-promotion proof."""
from __future__ import annotations
import argparse,hashlib,json,os,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
RULE="TASK15_CANONICAL_ENROLLMENT_GAP_PREFLIGHT_V1"
NAME="task15-canonical-enrollment-gap-preflight-v1"

def require(v,why):
    if not v:raise ValueError(why)

def blob(path):
    raw=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def main():
    ap=argparse.ArgumentParser()
    for n in ("agentdojo","rcc","veritas"):
        ap.add_argument("--"+n+"-root",type=Path,required=True)
    for n in ("replay-artifact","v13-artifact","output-dir"):
        ap.add_argument("--"+n,type=Path,required=True)
    a=ap.parse_args()
    require(not os.environ.get("OPENAI_API_KEY")
            and not os.environ.get("VERITAS_DATABASE_URL"),
            "NO_CREDENTIALS_OR_PRODUCTION_DATABASE")
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE
            and contract["status"]=="IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI",
            "EXACT_NO_PROMOTION_CONTRACT_REQUIRED")
    for p,pin in contract["source_blobs"].items():
        require(blob(ROOT/p)==pin,"PINNED_SOURCE_DRIFT:"+p)
    dest=a.output_dir.resolve()
    dest.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    previous=subprocess.run([
        sys.executable,
        "scripts/task15_offline_paired_scorer_input_provenance_audit_v1.py",
        "--agentdojo-root",str(a.agentdojo_root.resolve()),
        "--rcc-root",str(a.rcc_root.resolve()),
        "--veritas-root",str(a.veritas_root.resolve()),
        "--replay-artifact",str(a.replay_artifact.resolve()),
        "--v13-artifact",str(a.v13_artifact.resolve()),
        "--output-dir",str(dest)],cwd=ROOT,env=env,capture_output=True,text=True)
    (dest/(NAME+".predecessor.log")).write_text(previous.stdout+previous.stderr)
    require(previous.returncode==0,"PR256_PREDECESSOR_REPLAY_FAILED:"+
            (previous.stdout+previous.stderr)[-12000:])
    baseline=json.loads((dest/"task15-offline-paired-scorer-input-provenance-v1.json").read_text())
    require(baseline["determination"] ==
            "OFFLINE_NATIVE_MODEL_OUTPUT_AND_FUNCTION_TRACE_PROJECTED"
            and baseline["predecessor_tests"]==2322
            and baseline["new_tests"]==15
            and baseline["negative_cases"]==13
            and baseline["native_scorer_input_arms"]==2
            and baseline["native_trace_items"]==6
            and baseline["real_provider_calls"]==baseline["scorer_calls"]==0
            and baseline["native_task15_utility_measured"] is False
            and baseline["canonical_final128_enrollment_proven"] is False,
            "PR256_FROZEN_CLAIMS_CHANGED")
    positive=dest/(NAME+".evidence.jsonl")
    denied=dest/(NAME+".refusals.jsonl")
    junit=dest/(NAME+".junit.xml")
    for p in (positive,denied,junit):p.unlink(missing_ok=True)
    env.update({k:"1" for k in (
        "TASK15_CANONICAL_ENROLLMENT_GAP_PROOF",
        "TASK15_PAIRED_SCORER_INPUT_PROOF",
        "TASK15_OFFLINE_PAIRED_TERMINAL_PROOF",
        "TASK15_OFFLINE_TERMINAL_NATIVE_PROOF",
        "TASK15_OFFLINE_CONTINUOUS_NATIVE_PROOF",
        "TASK15_MODEL_CALLID_RETURN_HISTORY_PROOF",
        "TASK15_NATIVE_MODEL_CAPTURE_PROOF",
        "TASK15_COMPOSED_NATIVE_RETURN_PROOF",
        "TASK15_COMPOSED_RUNNER_PROOF",
        "TASK15_NATIVE_ADDRESS_PROOF",
        "TASK15_EXACT_NATIVE_RETURN_PROOF",
        "TASK15_CONTROLLED_RENT_PROOF",
        "TASK15_RENT_DESIGN_PROOF",
        "TASK15_SCOPE_LINEAGE_PROOF",
        "TASK15_REFUND_DESIGN_PROOF",
        "TASK15_REFUND_METADATA_PROOF",
        "TASK15_REFUND_CORRELATION_PROOF",
    )})
    env["TASK15_RCC_ROOT"]=str(a.rcc_root.resolve())
    env["TASK15_CANONICAL_ENROLLMENT_EVIDENCE"]=str(positive)
    env["TASK15_CANONICAL_ENROLLMENT_REFUSALS"]=str(denied)
    run=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task15_canonical_enrollment_gap_preflight_v1.py",
        "--junitxml",str(junit)],cwd=ROOT,env=env,capture_output=True,text=True)
    (dest/(NAME+".tests.log")).write_text(run.stdout+run.stderr)
    print(run.stdout,end="")
    require(run.returncode==0,"CANONICAL_ENROLLMENT_GAP_TESTS_FAILED:"+
            (run.stdout+run.stderr)[-14000:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==contract["expected_new_tests"]
            and all(not any(t.find(n) is not None
                            for n in ("failure","error","skipped")) for t in cases),
            "EXACT_CANONICAL_GAP_NEW_TESTS_REQUIRED")
    success=[json.loads(x) for x in positive.read_text().splitlines()]
    refused=[json.loads(x) for x in denied.read_text().splitlines()]
    require(len(success)==1
            and len(refused)==contract["expected_denied_cases"],
            "PRECISE_LOCAL_NONPROMOTION_EVIDENCE_CARDINALITY_REQUIRED")
    result=success[0]["roster_preflight"]
    projection=success[0]["source_projection"]
    enrollment=json.loads((ROOT/"contracts"/"AGENTDOJO_INJECTION_ENROLLMENT_FREEZE_v0.1.json").read_text())
    scorer=json.loads((ROOT/"contracts"/"AGENTDOJO_NATIVE_SCORER_FREEZE_v0.1.json").read_text())
    from task15_native_address_request_profile_issuance_v1 import sha
    from task15_canonical_enrollment_gap_preflight_v1 import ENROLLED_TASK15,LOCAL_DESIGN_CASE
    require(result["rule_of_one"]==RULE
            and result["determination"]==
            "CANONICAL_TASK15_ROSTER_RESOLVED_LOCAL_EVIDENCE_INELIGIBLE"
            and result["frozen_enrollment_sha256"]==sha(enrollment)
            and result["frozen_scorer_sha256"]==sha(scorer)
            and result["source_local_projection_sha256"]==sha(projection)
            and result["source_local_case_id"]==LOCAL_DESIGN_CASE
            and result["frozen_task15_case_count"]==8
            and result["frozen_all_case_count"]==128
            and [x["case_id"] for x in result["frozen_task15_cases"]]==list(ENROLLED_TASK15)
            and all(x["frozen_roster_member"] is True
                    and x["native_injection_task_resolved"] is True
                    and x["score_eligible"] is False
                    and x["provider_response_authenticated"] is False
                    and x["actual_candidate_trajectory_enrolled"] is False
                    for x in result["frozen_task15_cases"])
            and result["canonical_case_executed"] is False
            and result["canonical_case_score_eligible"] is False
            and result["local_projection_is_canonical_score_input"] is False
            and result["scorer_called"] is False
            and result["scorer_calls"]==result["real_provider_calls"]==result["new_native_effects"]==0
            and result["final128_utility_recovered"] is False,
            "FROZEN_8_128_LOCAL_NO_PROMOTION_NOT_PROVEN")
    require(len({x["fault"] for x in refused})==contract["expected_denied_cases"]
            and all(x["result"]=="NO_CANONICAL_PROMOTION" for x in refused),
            "NEGATIVE_RESULTS_NOT_COMPLETE")
    report={"rule_of_one":RULE,
            "determination":"CANONICAL_TASK15_ROSTER_RESOLVED_LOCAL_EVIDENCE_INELIGIBLE",
            "predecessor_tests":contract["expected_predecessor_tests"],
            "new_tests":len(cases),
            "denied_cases":len(refused),
            "canonical_roster_cases":128,
            "canonical_task15_subset":8,
            "source_local_case_id":LOCAL_DESIGN_CASE,
            "canonical_score_eligible":False,
            "native_scorer_called":False,
            "provider_calls":0,"scorer_calls":0,"new_effects":0,
            "final128_utility_recovery_proven":False}
    (dest/(NAME+".json")).write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print("PASS_"+RULE)
    print("tests="+str(len(cases))+" denied="+str(len(refused))+
          " task15_roster=8 total=128 canonical_scores=0")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
