#!/usr/bin/env python3
"""Reproduce #222 and independently reissue/capture local rent evidence."""
from __future__ import annotations
import argparse,copy,hashlib,json,os,re,secrets,subprocess,sys
from pathlib import Path
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from scripts.task15_prospective_controlled_address_trajectory_audit_v1 import blob,require
from original_request_authority_lineage_v1 import OriginalRequestEnvelope
from task15_native_address_request_profile_issuance_v1 import canonical,sha
from scripts.pairwise_protected_candidate_control_v1_1 import ProtectedCandidateControlV11,fork_exact_candidate
from task15_standing_order_request_profile_issuance_v1 import (
    Task15RentRequestContext,Task15RentRequestProfileSession,native_definition,native_definition_digest,
)
NAME="task15-standing-order-request-profile-issuance-v1"
CONTRACT=ROOT/"contracts/TASK15_STANDING_ORDER_REQUEST_PROFILE_ISSUANCE_V1.json"
EXPECTED_CONTRACT="e9bbef735c828017061dded371c78ae2571657d9"

def audit_profile(evidence):
    scope=copy.deepcopy(evidence["owned_input"]);scope["envelope"]=OriginalRequestEnvelope(**scope["envelope"])
    ctx=Task15RentRequestContext(**evidence["context"]);payload=ctx.payload();expected=Task15RentRequestProfileSession._scope(**scope)
    require(set(payload)==set(expected)|{"source_id","session_id"} and
            canonical({k:payload[k] for k in expected})==canonical(expected),"INDEPENDENT_PROFILE_SCOPE_MISMATCH")
    require(type(ctx.signature) is str and re.fullmatch(r"[0-9a-f]{64}",ctx.signature) is not None,"EXPORTED_LOCAL_MAC_SHAPE_INVALID")
    candidate=copy.deepcopy(evidence["candidate"])
    raw=Task15RentRequestProfileSession._candidate_json(candidate,**scope)
    control=ProtectedCandidateControlV11.build(case_id=scope["case_id"],proposal_ordinal=scope["proposal_ordinal"],
        immediate_pre_state_sha256=payload["projection"]["immediate_pre_state_sha256"],function="update_scheduled_transaction",
        normalized_arguments=candidate["arguments"])
    b=evidence["binding"]
    expected_binding={"context_digest":ctx.digest,"candidate_json":raw,"candidate_sha256":control.candidate_sha256,
        "pairing_identity_sha256":control.pairing_identity_sha256(),"request_candidate_binding_sha256":sha({
        "context_digest":ctx.digest,"candidate_sha256":control.candidate_sha256,"pairing_identity_sha256":control.pairing_identity_sha256(),
        "native_definition_digest":native_definition_digest()})}
    require(b==expected_binding,"RECORDED_CONTEXT_BINDING_LINKAGE_MISMATCH")
    require(evidence["events"]==["ISSUED","GENERATED_NATIVE_NORMALIZED","CAPTURED"],"RECORDED_PROGRAM_ORDER_CHANGED")
    import agentdojo.task_suite.load_suites
    from agentdojo.functions_runtime import make_function
    from agentdojo.default_suites.v1.tools.banking_client import update_scheduled_transaction
    fn=make_function(update_scheduled_transaction)
    require(fn.parameters.model_json_schema()==evidence["native_schema"] and
        sha(evidence["native_schema"])==native_definition()["native_schema_sha256"],"ACTUAL_NATIVE_SCHEMA_CHANGED")
    require(fn.parameters.model_validate(candidate["arguments"]).model_dump(mode="json")==candidate["arguments"],"NATIVE_NORMALIZED_CANDIDATE_CHANGED")
    fresh=Task15RentRequestProfileSession(source_id="independent-local-reissue",signing_key=secrets.token_bytes(32));events=[]
    original_issue=fresh.issue_before_candidate
    def issue(**kw):
        result=original_issue(**kw);events.append("ISSUED");return result
    fresh.issue_before_candidate=issue
    def generate():
        require(events==["ISSUED"],"INDEPENDENT_GENERATION_PRECEDED_ISSUANCE")
        events.append("GENERATED_NATIVE_NORMALIZED");return copy.deepcopy(candidate)
    freshctx,freshbinding=fresh.capture_from_generator(generate_candidate=generate,**scope);events.append("CAPTURED")
    require(events==evidence["events"],"INDEPENDENT_PROGRAM_ORDER_MISMATCH")
    a,b=fork_exact_candidate(control)
    observations=[fresh.verify_captured_candidate(context=freshctx,binding=freshbinding,candidate=c,**scope) for c in (a,b)]
    require(observations[0]==observations[1],"INDEPENDENT_PAIRED_VERIFICATION_DIVERGED")
    stable=("local_issuance_verified","rent_design_fields_verified","native_definition_digest","projection_sha256","request_digest",
            "candidate_sha256","pairing_identity_sha256","execution_permission","native_dispatch_authorized",
            "runtime_admission_activated","full_action_admissible","mandate_authenticated")
    for key in ("verification_a","verification_b"):
        require({k:evidence[key][k] for k in stable}=={k:observations[0][k] for k in stable},"RECORDED_PAIRED_EVIDENCE_MISMATCH")
        require(evidence[key]["request_candidate_binding_sha256"]==expected_binding["request_candidate_binding_sha256"],"RECORDED_VERIFICATION_BINDING_MISMATCH")
    for key in ("execution_permission","native_dispatch_authorized","runtime_admission_activated","full_action_admissible","mandate_authenticated"):
        require(observations[0][key] is False,"PROFILE_BECAME_EXECUTION_AUTHORITY:"+key)
    return {"native_definition_digest":native_definition_digest(),"projection_sha256":payload["projection_sha256"],
            "candidate_sha256":control.candidate_sha256,"pairing_identity_sha256":control.pairing_identity_sha256(),
            "immediate_pre_state_sha256":payload["projection"]["immediate_pre_state_sha256"],"target_id":payload["projection"]["target_record"]["id"]}

def main():
    p=argparse.ArgumentParser()
    for n in ("agentdojo","rcc","veritas"):p.add_argument("--"+n+"-root",type=Path,required=True)
    for n in ("replay-artifact","v13-artifact","output-dir"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args()
    for key in ("OPENAI_API_KEY","VERITAS_DATABASE_URL"):require(not os.environ.get(key),key+"_MUST_BE_EMPTY")
    require(blob(CONTRACT)==EXPECTED_CONTRACT,"CONTRACT_PIN_MISMATCH");c=json.loads(CONTRACT.read_text())
    for path,pin in c["source_blobs"].items():require(blob(ROOT/path)==pin,"SOURCE_PIN_MISMATCH:"+path)
    for path,pin in c["agentdojo_profile_source_blobs"].items():require(blob(a.agentdojo_root/path)==pin,"PROFILE_NATIVE_SOURCE_MISMATCH:"+path)
    out=a.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ);env.update(OPENAI_API_KEY="",VERITAS_DATABASE_URL="",PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    command=[sys.executable,"scripts/task15_standing_order_original_request_authority_design_audit_v1.py"]
    for n in ("agentdojo","rcc","veritas","replay-artifact","v13-artifact"):
        attr=n.replace("-","_")+("_root" if n in ("agentdojo","rcc","veritas") else "")
        command.extend(["--"+n+("-root" if n in ("agentdojo","rcc","veritas") else ""),str(getattr(a,attr).resolve())])
    command.extend(["--output-dir",str(out)])
    prior=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True)
    require(prior.returncode==0,"PRIOR_RENT_DESIGN_FAILED:"+prior.stderr+prior.stdout[-2000:])
    print(prior.stdout,end="");(out/"task15-standing-order-original-request-authority-design-v1.log").write_text(prior.stdout)
    raw=(out/"task15-standing-order-original-request-authority-design-v1.json").read_bytes()
    require(hashlib.sha256(raw).hexdigest()==c["prior_design_report_sha256"],"PRIOR_RENT_DESIGN_REPORT_CHANGED")
    evidence,refusals,junit=[out/(NAME+s) for s in (".evidence.json",".refusals.jsonl",".junit.xml")]
    for path in (evidence,refusals,junit,out/(NAME+".json")):path.unlink(missing_ok=True)
    env.update(TASK15_RENT_PROFILE_PROOF="1",TASK15_RENT_PROFILE_EVIDENCE=str(evidence),TASK15_RENT_PROFILE_REFUSALS=str(refusals))
    run=subprocess.run([sys.executable,"-m","pytest","-q","-o","addopts=","tests/test_task15_standing_order_request_profile_issuance_v1.py","--junitxml",str(junit)],cwd=ROOT,env=env,capture_output=True,text=True)
    print(run.stdout,end="");require(run.returncode==0,"RENT_PROFILE_TESTS_FAILED:"+run.stderr)
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==101 and not any(x.find(t)is not None for x in cases for t in ("failure","error","skipped")),"PROFILE_TESTS_INCOMPLETE")
    identity=audit_profile(json.loads(evidence.read_text()))
    negative=[json.loads(x) for x in refusals.read_text().splitlines()]
    require(len(negative)==18 and all(x["slot_closed"] and x["candidate_repair"]==0 and x["native_dispatch_authorized"] is False for x in negative),"CLOSED_CAPTURE_SLOT_POPULATION_CHANGED")
    report={"rule_of_one":c["rule_of_one"],"determination":"PROSPECTIVE_LOCAL_RENT_PROFILE_AND_EXACT_CAPTURE_PASS_NOT_EXECUTION_AUTHORITY",
        "profile_tests":101,"failures":0,"skipped":0,"prior_design_tests":73,"prior_observer_tests":28,"prior_wire_tests":32,
        "prior_trajectory_tests":40,"prior_native_runner_tests":65,"prior_address_profile_tests":101,"prior_mapping_tests":91,
        "identity":identity,"program_order":["ISSUED","GENERATED_NATIVE_NORMALIZED","CAPTURED"],"scripted_generation_calls":1,
        "same_candidate_and_prestate_a_b":True,"paired_readonly_verifications":2,"invalid_candidates_terminal_slots":18,
        "parallel_attempts_per_operation":32,"parallel_issuance_winners":1,"parallel_capture_winners":1,"parallel_generation_winners":1,
        "generation_exception_or_cancellation_scenarios":3,"local_issuance_evidence":True,"exported_original_mac_independently_authenticated":False,
        "mandate_authenticated":False,"execution_permission":False,"native_dispatch_authorized":False,"runtime_admission_activated":False,"full_action_admissible":False,
        "native_dispatches_in_new_profile_proof":0,"provider_execution":0,"provider_client_constructed":0,"database_access_in_new_profile_proof":0,
        "scorer_or_gold_derived_authority":0,"candidate_repair":0,"v13_authorization_reuse":0,"v13_human_confirmation_reuse":0,
        "historical_profiles_issued":0,"historical_candidates_recovered":0,"safe_to_relax_existing_runner_now":0,
        "real_model_utility_recovery_proven":False,"injection_success_remeasured":False,"full_task15_execution_supported":False,
        "independent_external_validation":False,"held_out_validation":False,"production_readiness":False,
        "prior_design_report_sha256":hashlib.sha256(raw).hexdigest(),"next_rule_of_one":c["next_rule_of_one"]}
    (out/(NAME+".json")).write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print("PASS_TASK15_STANDING_ORDER_REQUEST_PROFILE_ISSUANCE_V1")
    print("profile_tests=101 failures=0 skipped=0 invalid_candidates_terminal_slots=18")
    print("program_order=ISSUED,GENERATED_NATIVE_NORMALIZED,CAPTURED scripted_generation_calls=1 paired_readonly_verifications=2")
    print("parallel_attempts=32 issuance_winners=1 capture_winners=1 generation_winners=1")
    print("execution_permission=false native_dispatch_authorized=false native_dispatches=0 safe_to_relax_now=0")
    print("provider_execution=0 candidate_repair=0 scorer_or_gold_authority=0 v13_reuse=0 injection_success_remeasured=false")
    print("next_rule_of_one="+c["next_rule_of_one"])
    return 0
if __name__=="__main__":raise SystemExit(main())
