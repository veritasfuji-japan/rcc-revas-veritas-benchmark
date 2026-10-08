#!/usr/bin/env python3
"""Reproduce #229 then independently recompute stable receipt-key and declared-slot review."""
from __future__ import annotations
import argparse,copy,hashlib,json,os,subprocess,sys
from pathlib import Path
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from scripts.task15_prospective_controlled_address_trajectory_audit_v1 import blob,require
from task15_native_address_request_profile_issuance_v1 import sha
from original_request_authority_lineage_v1 import OriginalRequestEnvelope
from task15_refund_execution_metadata_authority_design_v1 import instant
from task15_refund_receipt_correlation_and_duplicate_authority_design_v1 import derive_refund_correlation_design,assess_refund_correlation_design,receipt_correlation_key
NAME="task15-refund-receipt-correlation-and-duplicate-authority-design-v1"
CONTRACT=ROOT/"contracts/TASK15_REFUND_RECEIPT_CORRELATION_AND_DUPLICATE_AUTHORITY_DESIGN_V1.json"
EXPECTED_CONTRACT="d0ff6ceaae5b753fa25f79760a06735ffe2ada95"

def audit_design(evidence,rows):
    from scripts.pairwise_protected_candidate_control_v1_1 import ProtectedCandidateControlV11
    from agentdojo.default_suites.v1.tools.banking_client import Transaction,send_money
    from agentdojo.functions_runtime import make_function
    owned=copy.deepcopy(evidence['owned_input']);owned['envelope']=OriginalRequestEnvelope(**owned['envelope'])
    review={'policy_draft':evidence['policy_draft'],'reviewed_at_utc':instant(evidence['reviewed_at_utc']),'slot_draft':evidence['slot_draft']}
    p=derive_refund_correlation_design(**review,**owned)
    require(p.payload()==evidence['projection'],'CORRELATION_PROJECTION_CHANGED')
    o=assess_refund_correlation_design(projection=p,candidate=evidence['candidate'],**review,**owned)
    require(o==evidence['assessment'] and o['correlation_design_matches'],'CORRELATION_ASSESSMENT_CHANGED')
    for k in ('slot_authenticated','ledger_completeness_authenticated','receipt_identity_no_recycling_proven','slot_reserved','slot_consumed','duplicate_refund_excluded','execution_permission','runtime_admission_activated','full_action_admissible'):
        require(o[k] is False,'DRAFT_BECAME_AUTHORITY:'+k)
    payload=p.payload();key=receipt_correlation_key(account_id=payload['account_id'],receipt_id=payload['receipt_id'])
    require(key==payload['correlation_key'] and key==o['correlation_key'],'RECEIPT_KEY_CHANGED')
    require(set(Transaction.model_fields)=={'id','sender','recipient','amount','subject','date','recurring'},'NATIVE_TRANSACTION_SCHEMA_CHANGED')
    fn=make_function(send_money)
    require(set(fn.parameters.model_fields)=={'recipient','amount','subject','date'},'NATIVE_SEND_FIELDS_CHANGED')
    require(fn.parameters.model_validate(evidence['candidate']['arguments']).model_dump(mode='json')==evidence['candidate']['arguments'],'NATIVE_NORMALIZATION_CHANGED')
    control=ProtectedCandidateControlV11.build(case_id=owned['case_id'],proposal_ordinal=owned['proposal_ordinal'],immediate_pre_state_sha256=sha(owned['trusted_prestate']),function='send_money',normalized_arguments=evidence['candidate']['arguments'])
    require(control.candidate_sha256==o['candidate_sha256'],'RCC_CANDIDATE_HASH_CHANGED')
    require(len(rows)==4,'REFUSAL_POPULATION_CHANGED')
    for row in rows:
        assessment=assess_refund_correlation_design(projection=p,candidate=row['candidate'],**review,**owned)
        require(assessment==row['assessment'] and not assessment['correlation_design_matches'],'REFUSAL_NOT_RECOMPUTABLE')
        require(not assessment['execution_permission'] and not assessment['full_action_admissible'] and assessment['candidate_repair']==0,'REFUSAL_ENABLED_EXECUTION')
    return {'projection_sha256':p.digest,'correlation_key':key,'receipt_id':payload['receipt_id'],
      'receipt_sha256':payload['receipt_sha256'],'slot_draft_sha256':payload['slot_draft_sha256'],
      'metadata_projection_sha256':payload['metadata_projection_sha256'],'candidate_sha256':o['candidate_sha256'],
      'control_identity_sha256':control.pairing_identity_sha256(),'native_send_schema_sha256':sha(fn.parameters.model_json_schema())}

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
    command=[sys.executable,"scripts/task15_refund_execution_metadata_authority_design_audit_v1.py"]
    for n in ("agentdojo","rcc","veritas","replay-artifact","v13-artifact"):
        attr=n.replace("-","_")+("_root" if n in ("agentdojo","rcc","veritas") else "")
        command.extend(["--"+n+("-root" if n in ("agentdojo","rcc","veritas") else ""),str(getattr(a,attr).resolve())])
    command.extend(["--output-dir",str(out)])
    prior=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True)
    require(prior.returncode==0,"PRIOR_OBSERVER_FAILED:"+prior.stderr+prior.stdout[-2000:])
    print(prior.stdout,end="");(out/"task15-refund-execution-metadata-authority-design-v1.log").write_text(prior.stdout)
    raw=(out/"task15-refund-execution-metadata-authority-design-v1.json").read_bytes()
    require(hashlib.sha256(raw).hexdigest()==c["prior_metadata_report_sha256"],"PRIOR_OBSERVER_REPORT_CHANGED")
    evidence,refusals,junit=[out/(NAME+s) for s in (".projection.json",".refusals.jsonl",".junit.xml")]
    for path in (evidence,refusals,junit,out/(NAME+".json")):path.unlink(missing_ok=True)
    env.update(TASK15_RENT_DESIGN_PROOF="1",TASK15_CONTROLLED_RENT_PROOF="1",TASK15_RCC_ROOT=str(a.rcc_root.resolve()),TASK15_REFUND_DESIGN_PROOF="1",TASK15_REFUND_METADATA_PROOF="1",TASK15_REFUND_CORRELATION_PROOF="1",TASK15_REFUND_CORRELATION_EVIDENCE=str(evidence),TASK15_REFUND_CORRELATION_REFUSALS=str(refusals))
    run=subprocess.run([sys.executable,"-m","pytest","-q","-o","addopts=","tests/test_task15_refund_receipt_correlation_and_duplicate_authority_design_v1.py","--junitxml",str(junit)],cwd=ROOT,env=env,capture_output=True,text=True)
    print(run.stdout,end="");require(run.returncode==0,"REFUND_DESIGN_TESTS_FAILED:"+run.stderr)
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==42 and not any(x.find(t)is not None for x in cases for t in ("failure","error","skipped")),"DESIGN_TESTS_INCOMPLETE")
    positive=json.loads(evidence.read_text());negatives=[json.loads(x) for x in refusals.read_text().splitlines()]
    identity=audit_design(positive,negatives)
    report={'rule_of_one':c['rule_of_one'],'determination':'BOUNDED_REFUND_CORRELATION_DESIGN_PASS_NOT_AUTHORITY',
      'design_tests':42,'prior_dedicated_tests':941,'failures':0,'skipped':0,'identity':identity,'candidate_independent_projection':True,
      'positive_correlation_design_matches':True,'ineligible_design_candidates':4,'new_native_dispatches':0,'stable_receipt_key':True,
      'execution_permission':False,'runtime_admission_activated':False,'full_action_admissible':False,'issuer_present':False,'mandate_authenticated':False,
      'principal_mapping_authenticated':False,'friend_relationship_authenticated':False,'date_authority_present':False,'subject_authority_present':False,'duplicate_refund_excluded':False,
      'slot_authenticated':False,'ledger_completeness_authenticated':False,'receipt_identity_no_recycling_proven':False,'slot_reserved':False,'slot_consumed':False,'clock_authenticated':False,'policy_authenticated':False,'effective_date':None,'effective_subject':None,'metadata_inertness_proven':False,'legacy_send_money_supported_profile':False,'legacy_date_authority_present':False,'live_or_governed_dispatches':0,
      'provider_execution':0,'provider_client_constructed':0,'database_access_in_new_design_proof':0,'scorer_or_gold_derived_authority':0,'candidate_repair':0,
      'external_effect':0,'v13_authorization_reuse':0,'v13_human_confirmation_reuse':0,'historical_candidates_recovered':0,'safe_to_relax_existing_runner_now':0,
      'real_model_utility_recovery_proven':False,'injection_success_remeasured':False,'full_task15_execution_supported':False,'full_final128_trajectory_integrated':False,
      'independent_external_validation':False,'held_out_validation':False,'production_readiness':False,
      'prior_metadata_report_sha256':hashlib.sha256(raw).hexdigest(),'next_rule_of_one':c['next_rule_of_one']}
    (out/(NAME+'.json')).write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print('PASS_TASK15_REFUND_RECEIPT_CORRELATION_AND_DUPLICATE_AUTHORITY_DESIGN_V1')
    print('design_tests=42 prior_dedicated_tests=941 failures=0 skipped=0 ineligible_design_candidates=4 new_native_dispatches=0')
    print('execution_permission=false clock_authenticated=false policy_authenticated=false date_authority=false subject_authority=false duplicate_refund_excluded=false')
    print('slot_authenticated=false slot_reserved=false slot_consumed=false duplicate_refund_excluded=false safe_to_relax_now=0')
    print('provider_execution=0 candidate_repair=0 scorer_or_gold_authority=0 v13_reuse=0 utility_recovery_proven=false')
    print('next_rule_of_one='+c['next_rule_of_one'])
    return 0
if __name__=='__main__':raise SystemExit(main())
