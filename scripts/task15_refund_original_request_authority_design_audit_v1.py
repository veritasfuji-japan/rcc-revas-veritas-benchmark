#!/usr/bin/env python3
"""Reproduce #227 then independently recompute partial refund design and detached native probes."""
from __future__ import annotations
import argparse,copy,hashlib,json,os,subprocess,sys
from pathlib import Path
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from scripts.task15_prospective_controlled_address_trajectory_audit_v1 import blob,require
from task15_native_address_request_profile_issuance_v1 import sha
from original_request_authority_lineage_v1 import OriginalRequestEnvelope
from task15_refund_original_request_authority_design_v1 import derive_refund_design,assess_refund_design
NAME="task15-refund-original-request-authority-design-v1"
CONTRACT=ROOT/"contracts/TASK15_REFUND_ORIGINAL_REQUEST_AUTHORITY_DESIGN_V1.json"
EXPECTED_CONTRACT="bb411994bf7b1debfa8535be76451ee94631661e"

def audit_design(evidence,probes):
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.functions_runtime import make_function,FunctionsRuntime
    from agentdojo.default_suites.v1.tools.banking_client import send_money
    from scripts.pairwise_protected_candidate_control_v1_1 import ProtectedCandidateControlV11
    owned=copy.deepcopy(evidence['owned_input']);owned['envelope']=OriginalRequestEnvelope(**owned['envelope'])
    p=derive_refund_design(**owned);require(p.payload()==evidence['projection'],'REFUND_PROJECTION_CHANGED')
    assessment=assess_refund_design(projection=p,candidate=evidence['candidate'],**owned).observation()
    require(assessment==evidence['assessment'] and assessment['refund_core_matches'],'REFUND_COMPONENT_ASSESSMENT_CHANGED')
    for k in ('execution_permission','runtime_admission_activated','full_action_admissible','issuer_present','mandate_authenticated','principal_mapping_authenticated','friend_relationship_authenticated','date_authority_present','subject_authority_present','duplicate_refund_excluded'):
        require(assessment[k] is False,'DRAFT_BECAME_AUTHORITY:'+k)
    fn=make_function(send_money);require(fn.parameters.model_json_schema()==evidence['native_schema'],'NATIVE_SEND_SCHEMA_CHANGED')
    require(fn.parameters.model_validate(evidence['candidate']['arguments']).model_dump(mode='json')==evidence['candidate']['arguments'],'NATIVE_NORMALIZATION_CHANGED')
    control=ProtectedCandidateControlV11.build(case_id=owned['case_id'],proposal_ordinal=owned['proposal_ordinal'],immediate_pre_state_sha256=sha(owned['trusted_prestate']),function='send_money',normalized_arguments=evidence['candidate']['arguments'])
    require(control.candidate_sha256==assessment['candidate_sha256'],'RCC_CANDIDATE_HASH_CHANGED')
    require(len(probes)==2,'DETACHED_REFUND_PROBES_INCOMPLETE')
    require([r['candidate']['arguments']['date'] for r in probes]==['2030-01-02','2099-01-01'],'PROBE_DATE_POPULATION_CHANGED')
    for row in probes:
        require(row['governed_dispatch_authorized'] is False and row['before']==owned['trusted_prestate'],'PROBE_BECAME_GOVERNED_AUTHORITY')
        env=get_suite('v1.2.2','banking').environment_type.model_validate(copy.deepcopy(row['before']))
        value,error=FunctionsRuntime([fn]).run_function(env,'send_money',copy.deepcopy(row['candidate']['arguments']),raise_on_error=True)
        require(error is None and value==row['return'] and env.model_dump(mode='json')==row['after'],'ACTUAL_SEND_MONEY_SEMANTICS_CHANGED')
        expected=copy.deepcopy(row['before']);bank=expected['bank_account'];args=row['candidate']['arguments']
        nextid=max(x['id'] for x in bank['transactions']+bank['scheduled_transactions'])+1
        bank['transactions'].append({'id':nextid,'sender':bank['iban'],'recipient':args['recipient'],'amount':args['amount'],'subject':args['subject'],'date':args['date'],'recurring':False})
        require(expected==row['after'] and row['after']['bank_account']['balance']==row['before']['bank_account']['balance'],'NATIVE_APPEND_ONLY_SCOPE_CHANGED')
        require(assess_refund_design(projection=p,candidate=row['candidate'],**owned).observation()==row['assessment'] and row['assessment']['refund_core_matches'],'PROBE_COMPONENT_ASSESSMENT_CHANGED')
        require(row['assessment']['date_authority_present'] is False and row['assessment']['subject_authority_present'] is False and row['assessment']['execution_permission'] is False,'PROBE_METADATA_BECAME_AUTHORITY')
    return {'projection_sha256':p.digest,'candidate_sha256':assessment['candidate_sha256'],'control_identity_sha256':control.pairing_identity_sha256(),
      'immediate_pre_state_sha256':p.payload()['immediate_pre_state_sha256'],'receipt_id':p.payload()['target_receipt']['id'],
      'refund_recipient':p.payload()['refund_recipient'],'explicit_request_amount':p.payload()['explicit_request_amount'],'native_schema_sha256':sha(evidence['native_schema'])}

def main():
    p=argparse.ArgumentParser()
    for n in ("agentdojo","rcc","veritas"):p.add_argument("--"+n+"-root",type=Path,required=True)
    for n in ("replay-artifact","v13-artifact","output-dir"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args()
    sys.path.insert(0,str(a.rcc_root.resolve()/"external-eval/v0.3.9/src"))
    for key in ("OPENAI_API_KEY","VERITAS_DATABASE_URL"):require(not os.environ.get(key),key+"_MUST_BE_EMPTY")
    require(blob(CONTRACT)==EXPECTED_CONTRACT,"CONTRACT_PIN_MISMATCH");c=json.loads(CONTRACT.read_text())
    for path,pin in c["source_blobs"].items():require(blob(ROOT/path)==pin,"SOURCE_PIN_MISMATCH:"+path)
    for path,pin in c["agentdojo_design_source_blobs"].items():require(blob(a.agentdojo_root/path)==pin,"DESIGN_NATIVE_SOURCE_MISMATCH:"+path)
    out=a.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ);env.update(OPENAI_API_KEY="",VERITAS_DATABASE_URL="",PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    command=[sys.executable,"scripts/task15_standing_order_native_scorer_observation_boundary_audit_v1.py"]
    for n in ("agentdojo","rcc","veritas","replay-artifact","v13-artifact"):
        attr=n.replace("-","_")+("_root" if n in ("agentdojo","rcc","veritas") else "")
        command.extend(["--"+n+("-root" if n in ("agentdojo","rcc","veritas") else ""),str(getattr(a,attr).resolve())])
    command.extend(["--output-dir",str(out)])
    prior=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True)
    require(prior.returncode==0,"PRIOR_OBSERVER_FAILED:"+prior.stderr+prior.stdout[-2000:])
    print(prior.stdout,end="");(out/"task15-standing-order-native-scorer-observation-boundary-v1.log").write_text(prior.stdout)
    raw=(out/"task15-standing-order-native-scorer-observation-boundary-v1.json").read_bytes()
    require(hashlib.sha256(raw).hexdigest()==c["prior_observer_report_sha256"],"PRIOR_OBSERVER_REPORT_CHANGED")
    evidence,refusals,probes,junit=[out/(NAME+s) for s in (".projection.json",".refusals.jsonl",".native-probes.jsonl",".junit.xml")]
    for path in (evidence,refusals,probes,junit,out/(NAME+".json")):path.unlink(missing_ok=True)
    env.update(TASK15_RENT_DESIGN_PROOF="1",TASK15_CONTROLLED_RENT_PROOF="1",TASK15_RCC_ROOT=str(a.rcc_root.resolve()),TASK15_REFUND_DESIGN_PROOF="1",TASK15_REFUND_DESIGN_EVIDENCE=str(evidence),TASK15_REFUND_DESIGN_REFUSALS=str(refusals),TASK15_REFUND_DESIGN_NATIVE_PROBES=str(probes))
    run=subprocess.run([sys.executable,"-m","pytest","-q","-o","addopts=","tests/test_task15_refund_original_request_authority_design_v1.py","--junitxml",str(junit)],cwd=ROOT,env=env,capture_output=True,text=True)
    print(run.stdout,end="");require(run.returncode==0,"REFUND_DESIGN_TESTS_FAILED:"+run.stderr)
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==63 and not any(x.find(t)is not None for x in cases for t in ("failure","error","skipped")),"DESIGN_TESTS_INCOMPLETE")
    positive=json.loads(evidence.read_text());native=[json.loads(x) for x in probes.read_text().splitlines()]
    identity=audit_design(positive,native)
    negatives=[json.loads(x) for x in refusals.read_text().splitlines()]
    require(len(negatives)==11 and all(not x['observation']['refund_core_matches'] and not x['observation']['full_action_admissible'] for x in negatives),'REFUSAL_COMPONENT_POPULATION_CHANGED')
    report={'rule_of_one':c['rule_of_one'],'determination':'BOUNDED_REFUND_COMPONENT_DESIGN_PASS_NOT_AUTHORITY',
      'design_tests':63,'prior_dedicated_tests':822,'failures':0,'skipped':0,'identity':identity,'candidate_independent_projection':True,
      'positive_refund_core_matches':True,'ineligible_design_candidates':11,'detached_native_semantics_probes':2,'native_append_only_balance_unchanged':True,
      'execution_permission':False,'runtime_admission_activated':False,'full_action_admissible':False,'issuer_present':False,'mandate_authenticated':False,
      'principal_mapping_authenticated':False,'friend_relationship_authenticated':False,'date_authority_present':False,'subject_authority_present':False,'duplicate_refund_excluded':False,
      'legacy_send_money_supported_profile':False,'legacy_date_authority_present':False,'live_or_governed_dispatches':0,
      'provider_execution':0,'provider_client_constructed':0,'database_access_in_new_design_proof':0,'scorer_or_gold_derived_authority':0,'candidate_repair':0,
      'external_effect':0,'v13_authorization_reuse':0,'v13_human_confirmation_reuse':0,'historical_candidates_recovered':0,'safe_to_relax_existing_runner_now':0,
      'real_model_utility_recovery_proven':False,'injection_success_remeasured':False,'full_task15_execution_supported':False,'full_final128_trajectory_integrated':False,
      'independent_external_validation':False,'held_out_validation':False,'production_readiness':False,
      'prior_observer_report_sha256':hashlib.sha256(raw).hexdigest(),'next_rule_of_one':c['next_rule_of_one']}
    (out/(NAME+'.json')).write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print('PASS_TASK15_REFUND_ORIGINAL_REQUEST_AUTHORITY_DESIGN_V1')
    print('design_tests=63 prior_dedicated_tests=822 failures=0 skipped=0 ineligible_design_candidates=11 detached_native_probes=2')
    print('execution_permission=false principal_mapping_authenticated=false date_authority=false subject_authority=false duplicate_refund_excluded=false')
    print('native_semantics=append_only balance_unchanged=true governed_dispatches=0 safe_to_relax_now=0')
    print('provider_execution=0 candidate_repair=0 scorer_or_gold_authority=0 v13_reuse=0 utility_recovery_proven=false')
    print('next_rule_of_one='+c['next_rule_of_one'])
    return 0
if __name__=='__main__':raise SystemExit(main())
