#!/usr/bin/env python3
"""Exact-native Task15 DirectAttack slot+environment proof; no external effects."""
from __future__ import annotations
import argparse,hashlib,json,os,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
RULE="TASK15_NATIVE_DIRECT_ATTACK_SLOT_APPLICATION_V1"
NAME="task15-native-direct-attack-slot-application-v1"

def require(cond,why):
    if not cond:raise ValueError(why)

def git_blob(path):
    raw=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def main():
    p=argparse.ArgumentParser()
    for arg in ("agentdojo","rcc","veritas"):
        p.add_argument("--"+arg+"-root",type=Path,required=True)
    for arg in ("replay-artifact","v13-artifact","output-dir"):
        p.add_argument("--"+arg,type=Path,required=True)
    a=p.parse_args()
    require(not os.environ.get("OPENAI_API_KEY")
            and not os.environ.get("VERITAS_DATABASE_URL"),
            "PROVIDER_OR_PRODUCTION_DB_FORBIDDEN")
    c=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(c["rule_of_one"]==RULE
            and c["status"]=="IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI",
            "FROZEN_PROOF_CONTRACT_REQUIRED")
    for path,pin in c["source_blobs"].items():
        require(git_blob(ROOT/path)==pin,"LOCAL_SOURCE_BLOB_DRIFT:"+path)
    for path,pin in c["agentdojo_native_blobs"].items():
        require(git_blob(a.agentdojo_root.resolve()/path)==pin,
                "NATIVE_AGENTDOJO_SOURCE_CHANGED:"+path)
    out=a.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="",
             OPENAI_API_KEY="",VERITAS_DATABASE_URL="")
    previous=subprocess.run([
        sys.executable,"scripts/task15_canonical_direct_payload_template_audit_v1.py",
        "--agentdojo-root",str(a.agentdojo_root.resolve()),
        "--rcc-root",str(a.rcc_root.resolve()),
        "--veritas-root",str(a.veritas_root.resolve()),
        "--replay-artifact",str(a.replay_artifact.resolve()),
        "--v13-artifact",str(a.v13_artifact.resolve()),
        "--output-dir",str(out)],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(previous.stdout+previous.stderr)
    require(previous.returncode==0,
            "PR258_PREDECESSOR_CHAIN_MUST_PASS:"+
            (previous.stdout+previous.stderr)[-15000:])
    old=json.loads((out/"task15-canonical-direct-payload-template-v1.json").read_text())
    require(old["determination"]==
            "EIGHT_NATIVE_DIRECT_TEMPLATE_PAYLOADS_EXACT_NOT_APPLIED"
            and old["predecessor_tests"]==2352
            and old["new_tests"]==15
            and old["denied_cases"]==14
            and old["canonical_task15_payloads"]==8
            and old["native_injection_slot_discovery_proven"] is False
            and old["native_attack_payloads_applied"] is False
            and old["provider_calls"]==old["scorer_calls"]==0,
            "FROZEN_PR258_TEMPLATE_REPORT_CHANGED")
    evidence=out/(NAME+".evidence.jsonl")
    refusals=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for f in (evidence,refusals,junit):f.unlink(missing_ok=True)
    env.update({k:"1" for k in (
        "TASK15_NATIVE_DIRECT_SLOT_PROOF",
        "TASK15_CANONICAL_DIRECT_PAYLOAD_PROOF",
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
    env["TASK15_NATIVE_DIRECT_SLOT_EVIDENCE"]=str(evidence)
    env["TASK15_NATIVE_DIRECT_SLOT_REFUSALS"]=str(refusals)
    tests=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task15_native_direct_attack_slot_application_v1.py",
        "--junitxml",str(junit)],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".tests.log")).write_text(tests.stdout+tests.stderr)
    print(tests.stdout,end="")
    require(tests.returncode==0,
            "NATIVE_DIRECT_SLOT_NEW_TESTS_FAILED:"+
            (tests.stdout+tests.stderr)[-20000:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==c["expected_new_tests"]
            and all(not any(z.find(t) is not None
                        for t in ("failure","error","skipped")) for z in cases),
            "ALL_FIFTEEN_NATIVE_SLOT_TESTS_REQUIRED")
    good=[json.loads(x) for x in evidence.read_text().splitlines()]
    bad=[json.loads(x) for x in refusals.read_text().splitlines()]
    require(len(good)==1
            and len(bad)==c["expected_refusals"]
            and len({r["fault"] for r in bad})==14
            and all(r["result"]=="NO_NATIVE_SLOT_PROOF_PROMOTION" for r in bad),
            "ALL_FOURTEEN_NATIVE_SLOT_REFUSALS_REQUIRED")
    report=good[0]["slot_application_proof"]
    actual=good[0]["observed_native_direct_slot_maps"]
    from task15_native_address_request_profile_issuance_v1 import sha
    from task15_native_direct_attack_slot_application_v1 import ENROLLED_TASK15
    from agentdojo.task_suite.load_suites import get_suite
    suite=get_suite("v1.2.2","banking")
    original=suite.load_and_inject_default_environment({}).model_dump(mode="json")
    require(report["rule_of_one"]==RULE
            and report["determination"]==
                "NATIVE_DIRECT_SLOTS_DISCOVERED_AND_LOCAL_ENVIRONMENTS_INJECTED"
            and report["canonical_roster_case_count"]==128
            and report["canonical_task15_case_count"]==8
            and report["native_ground_truth_local_simulation_executed"] is True
            and report["original_ground_truth_function_calls_simulated_locally"] is True
            and report["native_templated_environment_injection_proven"] is True
            and report["provider_calls"]==report["scorer_calls"]==0
            and report["new_RCC_BIND_governed_dispatches"]==report["real_external_effects"]==0
            and report["independent_A_model_candidate_source_proven"] is False
            and report["canonical_task15_utility_measured"] is False
            and report["final128_utility_recovery_proven"] is False
            and list(actual)==list(ENROLLED_TASK15)
            and len(report["native_direct_case_injection_rows"])==8,
            "DIRECT_SLOT_PROOF_CLAIMS_OUTSIDE_BOUNDED_LOCAL_DOMAIN")
    rows=report["native_direct_case_injection_rows"]
    checked=0
    for case_id,row in zip(ENROLLED_TASK15,rows,strict=True):
        slots=actual[case_id]
        assert set(slots).issubset(suite.get_injection_vector_defaults())
        assert slots
        injected=suite.load_and_inject_default_environment(slots)
        require(row["case_id"]==case_id
                and row["native_injection_slot_keys"]==list(slots)
                and row["native_injection_slot_count"]==len(slots)
                and row["native_direct_payload_sha256"]==sha(next(iter(slots.values())))
                and row["injected_environment_sha256"]==
                    sha(injected.model_dump(mode="json"))
                and row["baseline_environment_sha256"]==sha(original)
                and row["injection_value_present_in_environment"] is True
                and row["local_ground_truth_slot_discovery"] is True
                and row["local_templated_environment_injection"] is True
                and row["provider_authenticated"] is False
                and row["canonical_utility_scored"] is False,
                "INDEPENDENT_NATIVE_INJECTED_ENVIRONMENT_MISMATCH")
        checked+=1
    require(checked==8 and len(bad)==14,"ALL_EIGHT_NATIVE_ENVIRONMENTS_REQUIRED")
    result={"rule_of_one":RULE,
        "determination":"NATIVE_DIRECT_SLOTS_DISCOVERED_AND_LOCAL_ENVIRONMENTS_INJECTED",
        "predecessor_tests":c["expected_predecessor_tests"],
        "new_tests":len(cases),"refusals":len(bad),
        "canonical_task15_cases":checked,"canonical_roster_cases":128,
        "native_local_ground_truth_simulation":True,
        "native_disposable_environment_injected":True,
        "provider_calls":0,"scorer_calls":0,"real_external_effects":0,
        "new_governed_effects":0,
        "independent_A_candidate_source_proven":False,
        "final128_utility_recovery_proven":False}
    (out/(NAME+".json")).write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("PASS_"+RULE)
    print("new_tests="+str(len(cases))+" refusals="+str(len(bad))+
          " native_injected_cases=8 provider_calls=0 scorer_calls=0")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
