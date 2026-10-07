#!/usr/bin/env python3
"""Reproduce #221 then independently recompute pure rent design and native probes."""
from __future__ import annotations
import argparse,copy,hashlib,json,os,subprocess,sys
from pathlib import Path
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from scripts.task15_prospective_controlled_address_trajectory_audit_v1 import blob,require
from task15_native_address_request_profile_issuance_v1 import sha
from original_request_authority_lineage_v1 import OriginalRequestEnvelope
from task15_standing_order_original_request_authority_design_v1 import derive_rent_update_design,assess_rent_update_design
NAME="task15-standing-order-original-request-authority-design-v1"
CONTRACT=ROOT/"contracts/TASK15_STANDING_ORDER_ORIGINAL_REQUEST_AUTHORITY_DESIGN_V1.json"
EXPECTED_CONTRACT="40b466c5067ca2b0405f302d0d0834e157d6266e"

def audit_design(evidence,probes):
    owned=copy.deepcopy(evidence["owned_input"]);owned["envelope"]=OriginalRequestEnvelope(**owned["envelope"])
    projection=derive_rent_update_design(**owned)
    require(projection.payload()==evidence["projection"],"INDEPENDENT_DESIGN_PROJECTION_MISMATCH")
    assessment=assess_rent_update_design(projection=projection,candidate=evidence["candidate"],**owned).observation()
    require(assessment==evidence["assessment"] and assessment["design_matches"],"INDEPENDENT_ASSESSMENT_MISMATCH")
    for k in ("execution_permission","runtime_admission_activated","full_action_admissible","issuer_present","mandate_authenticated"):
        require(assessment[k] is False,"DESIGN_BECAME_EXECUTION_AUTHORITY:"+k)
    import agentdojo.task_suite.load_suites
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.functions_runtime import make_function,FunctionsRuntime
    from agentdojo.default_suites.v1.tools.banking_client import update_scheduled_transaction
    fn=make_function(update_scheduled_transaction)
    require(fn.parameters.model_json_schema()==evidence["native_schema"],"NATIVE_SCHEMA_CHANGED")
    require(fn.parameters.model_validate(evidence["candidate"]["arguments"]).model_dump(mode="json")==evidence["candidate"]["arguments"],"CANDIDATE_NOT_NATIVE_NORMALIZED")
    require(len(probes)==2 and [x["flag"] for x in probes]==[False,True],"DETACHED_NATIVE_PROBES_INCOMPLETE")
    suite=get_suite("v1.2.2","banking")
    for row in probes:
        require(row["governed_dispatch_authorized"] is False and row["before"]==owned["trusted_prestate"],"PROBE_BECAME_GOVERNED_DISPATCH")
        require(type(row["flag"]) is bool and row["candidate"]["arguments"]["recurring"] is row["flag"],"PROBE_FLAG_BINDING_CHANGED")
        env=suite.environment_type.model_validate(copy.deepcopy(row["before"]))
        value,error=FunctionsRuntime([fn]).run_function(env,"update_scheduled_transaction",copy.deepcopy(row["candidate"]["arguments"]),raise_on_error=True)
        require(error is None and value==row["return"] and env.model_dump(mode="json")==row["after"],"DETACHED_NATIVE_PROBE_RECOMPUTATION_MISMATCH")
        expected=copy.deepcopy(row["before"])
        target=next(x for x in expected["bank_account"]["scheduled_transactions"] if x["id"]==projection.payload()["target_record"]["id"])
        target.update(recipient=projection.payload()["explicit_request_fields"]["recipient"],amount=projection.payload()["explicit_request_fields"]["native_amount"])
        if row["flag"]:target["recurring"]=True
        require(row["after"]==expected and row["assessment"]["design_matches"] is (not row["flag"]),"PROBE_EXPECTED_EFFECT_SCOPE_CHANGED")
        require(assess_rent_update_design(projection=projection,candidate=row["candidate"],**owned).observation()==row["assessment"],"PROBE_ASSESSMENT_MISMATCH")
    return {"projection_sha256":projection.digest,"candidate_sha256":assessment["candidate_sha256"],
            "immediate_pre_state_sha256":projection.payload()["immediate_pre_state_sha256"],"target_id":projection.payload()["target_record"]["id"],
            "native_schema_sha256":sha(evidence["native_schema"]),"explicit_request_fields":projection.payload()["explicit_request_fields"]}

def main():
    p=argparse.ArgumentParser()
    for n in ("agentdojo","rcc","veritas"):p.add_argument("--"+n+"-root",type=Path,required=True)
    for n in ("replay-artifact","v13-artifact","output-dir"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args()
    for key in ("OPENAI_API_KEY","VERITAS_DATABASE_URL"):require(not os.environ.get(key),key+"_MUST_BE_EMPTY")
    require(blob(CONTRACT)==EXPECTED_CONTRACT,"CONTRACT_PIN_MISMATCH");c=json.loads(CONTRACT.read_text())
    for path,pin in c["source_blobs"].items():require(blob(ROOT/path)==pin,"SOURCE_PIN_MISMATCH:"+path)
    for path,pin in c["agentdojo_design_source_blobs"].items():require(blob(a.agentdojo_root/path)==pin,"DESIGN_NATIVE_SOURCE_MISMATCH:"+path)
    out=a.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ);env.update(OPENAI_API_KEY="",VERITAS_DATABASE_URL="",PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    command=[sys.executable,"scripts/task15_prospective_native_scorer_observation_boundary_audit_v1.py"]
    for n in ("agentdojo","rcc","veritas","replay-artifact","v13-artifact"):
        attr=n.replace("-","_")+("_root" if n in ("agentdojo","rcc","veritas") else "")
        command.extend(["--"+n+("-root" if n in ("agentdojo","rcc","veritas") else ""),str(getattr(a,attr).resolve())])
    command.extend(["--output-dir",str(out)])
    prior=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True)
    require(prior.returncode==0,"PRIOR_OBSERVER_FAILED:"+prior.stderr+prior.stdout[-2000:])
    print(prior.stdout,end="");(out/"task15-prospective-native-scorer-observation-boundary-v1.log").write_text(prior.stdout)
    raw=(out/"task15-prospective-native-scorer-observation-boundary-v1.json").read_bytes()
    require(hashlib.sha256(raw).hexdigest()==c["prior_observer_report_sha256"],"PRIOR_OBSERVER_REPORT_CHANGED")
    evidence,refusals,probes,junit=[out/(NAME+s) for s in (".projection.json",".refusals.jsonl",".native-probes.jsonl",".junit.xml")]
    for path in (evidence,refusals,probes,junit,out/(NAME+".json")):path.unlink(missing_ok=True)
    env.update(TASK15_RENT_DESIGN_PROOF="1",TASK15_RENT_DESIGN_EVIDENCE=str(evidence),TASK15_RENT_DESIGN_REFUSALS=str(refusals),TASK15_RENT_DESIGN_NATIVE_PROBES=str(probes))
    run=subprocess.run([sys.executable,"-m","pytest","-q","-o","addopts=","tests/test_task15_standing_order_original_request_authority_design_v1.py","--junitxml",str(junit)],cwd=ROOT,env=env,capture_output=True,text=True)
    print(run.stdout,end="");require(run.returncode==0,"RENT_DESIGN_TESTS_FAILED:"+run.stderr)
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==73 and not any(x.find(t)is not None for x in cases for t in ("failure","error","skipped")),"DESIGN_TESTS_INCOMPLETE")
    positive=json.loads(evidence.read_text());native=[json.loads(x) for x in probes.read_text().splitlines()]
    identity=audit_design(positive,native)
    negative=[json.loads(x) for x in refusals.read_text().splitlines()]
    require(len(negative)==17 and all(not x["observation"]["design_matches"] and not x["observation"]["full_action_admissible"] for x in negative),"DESIGN_REJECTED_POPULATION_CHANGED")
    report={"rule_of_one":c["rule_of_one"],"determination":"BOUNDED_ORIGINAL_REQUEST_RENT_UPDATE_DESIGN_PASS_NOT_AUTHORITY",
        "design_tests":73,"failures":0,"skipped":0,"prior_observer_tests":28,"prior_wire_tests":32,"prior_trajectory_tests":40,
        "prior_native_runner_tests":65,"prior_profile_tests":101,"prior_mapping_tests":91,"identity":identity,
        "candidate_independent_design_projection":True,"positive_design_matches":True,"ineligible_design_candidates":17,
        "detached_native_semantics_probes":2,"live_or_governed_dispatches":0,"issuer_present":False,"execution_permission":False,
        "runtime_admission_activated":False,"full_action_admissible":False,"mandate_authenticated":False,
        "provider_execution":0,"provider_client_constructed":0,"database_access_in_new_design_proof":0,"scorer_or_gold_derived_authority":0,
        "candidate_repair":0,"v13_authorization_reuse":0,"v13_human_confirmation_reuse":0,"historical_candidates_recovered":0,
        "safe_to_relax_existing_runner_now":0,"real_model_utility_recovery_proven":False,"injection_success_remeasured":False,
        "full_task15_execution_supported":False,"independent_external_validation":False,"held_out_validation":False,"production_readiness":False,
        "prior_observer_report_sha256":hashlib.sha256(raw).hexdigest(),"next_rule_of_one":c["next_rule_of_one"]}
    (out/(NAME+".json")).write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print("PASS_TASK15_STANDING_ORDER_ORIGINAL_REQUEST_AUTHORITY_DESIGN_V1")
    print("design_tests=73 ineligible_design_candidates=17 detached_native_probes=2 failures=0 skipped=0")
    print("execution_permission=false runtime_admission_activated=false live_or_governed_dispatches=0 safe_to_relax_now=0")
    print("provider_execution=0 candidate_repair=0 scorer_or_gold_authority=0 v13_reuse=0 injection_success_remeasured=false")
    print("next_rule_of_one="+c["next_rule_of_one"])
    return 0
if __name__=="__main__":raise SystemExit(main())
