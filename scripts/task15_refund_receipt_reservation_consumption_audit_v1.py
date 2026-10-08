#!/usr/bin/env python3
"""Reproduce #234 and independently reconstruct atomic shared-store lifecycle."""
from __future__ import annotations
import argparse,copy,hashlib,json,os,subprocess,sys
from pathlib import Path
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from scripts.task15_prospective_controlled_address_trajectory_audit_v1 import blob,require
from original_request_authority_lineage_v1 import OriginalRequestEnvelope
from task15_refund_execution_metadata_authority_design_v1 import instant
from task15_refund_receipt_reservation_consumption_v1 import *
from task15_refund_prospective_execution_authority_profile_v1 import (
    ControlledRefundAuthorityIssuer,ControlledRefundRootPin,ProspectiveRefundAuthorityProfile,
    CapturedRefundAuthorityBinding,verify_profile_signature)
NAME='task15-refund-receipt-reservation-consumption-v1'
CONTRACT=ROOT/'contracts/TASK15_REFUND_RECEIPT_RESERVATION_CONSUMPTION_V1.json'
EXPECTED_CONTRACT="43036a575eb40e5daf69e0db35cc36415eab257e"
TESTS=71
def owned(e):
    sc=copy.deepcopy(e['owned_input']);sc['envelope']=OriginalRequestEnvelope(**sc['envelope'])
    return sc,instant(e['reviewed_at_utc'])
def prepared(sc,clock,c):
    issuer=ControlledRefundAuthorityIssuer(root_id='owned-refund-root-v1',principal_id='fixture-requester',owned_clock=clock,**sc)
    p,b=issuer.capture_from_generator(generate_candidate=lambda:c)
    return issuer,dict(profile=p,binding=b,candidate=c,**sc)
def require_closed(o):
    for k in ('execution_permission','native_dispatch_authorized','runtime_admission_activated','effect_authenticated',
              'no_effect_authenticated','durable_global_duplicate_exclusion','restart_persistence_proven','RCC_Bind_final_sink_integration_proven','slot_retry_allowed'):
        require(o[k] is False,'STORE_RECEIPT_BECAME_PERMISSION:'+k)
    require(o['native_dispatches']==0 and o['reservations']==1 and o['consumptions']<=1,'STORE_COUNTS_CHANGED')

def audit_store(e,duplicates,refusals,parallel):
    import agentdojo.task_suite.load_suites
    from agentdojo.functions_runtime import make_function
    from agentdojo.default_suites.v1.tools.banking_client import send_money
    from scripts.task15_refund_prospective_execution_authority_profile_audit_v1 import audit_terminal_guards
    from scripts.pairwise_protected_candidate_control_v1_1 import ProtectedCandidateControlV11
    from task15_refund_execution_authority_boundary_v1 import derive_execution_authority_boundary
    sc,now=owned(e);c=e['candidate'];fn=make_function(send_money)
    require(fn.parameters.model_json_schema()==e['native_schema'] and fn.parameters.model_validate(c['arguments']).model_dump(mode='json')==c['arguments'],'ACTUAL_NATIVE_SCHEMA_CHANGED')
    root=ControlledRefundRootPin(**e['root_pin']);profile=ProspectiveRefundAuthorityProfile(**e['profile'])
    payload=verify_profile_signature(trusted_root=root,profile=profile);boundary=derive_execution_authority_boundary(reviewed_at_utc=now,**sc)
    require(payload['boundary']==boundary.payload(),'ORIGINAL_SIGNED_SCOPE_CHANGED')
    b=CapturedRefundAuthorityBinding(**e['binding']);r=RefundReceiptReservation(**e['reservation']);rp=r.payload()
    control=ProtectedCandidateControlV11.build(case_id=sc['case_id'],proposal_ordinal=2,immediate_pre_state_sha256=sha(sc['trusted_prestate']),function='send_money',normalized_arguments=c['arguments'])
    require(b.profile_digest==profile.digest and b.candidate_json==canonical(c) and b.candidate_sha256==control.candidate_sha256 and
        b.pairing_identity_sha256==control.pairing_identity_sha256() and b.authority_candidate_binding_sha256==sha({'profile_digest':profile.digest,
        'candidate_sha256':control.candidate_sha256,'pairing_identity_sha256':control.pairing_identity_sha256(),'boundary_sha256':boundary.digest,'root_pin_sha256':root.digest}),'RECORDED_CAPTURE_CHANGED')
    bindings=payload['boundary']['bindings'];key=receipt_correlation_key(account_id=bindings['account_id'],receipt_id=bindings['receipt_id'])
    expected={'rule_of_one':RULE,'ledger_namespace':NAMESPACE,'account_id':bindings['account_id'],'receipt_id':bindings['receipt_id'],
        'correlation_key':key,'receipt_sha256':bindings['receipt_sha256'],'root_pin_sha256':root.digest,'profile_digest':profile.digest,
        'candidate_sha256':control.candidate_sha256,'pairing_identity_sha256':control.pairing_identity_sha256(),
        'boundary_sha256':boundary.digest,'authority_candidate_binding_sha256':b.authority_candidate_binding_sha256}
    require(rp==expected,'RECORDED_RESERVATION_SCOPE_CHANGED')
    s,args=prepared(sc,lambda:now,c);store=OwnedRefundReceiptStore(owned_verifiers=[s.verifier]);new=store.reserve(**args)
    observations=[store.observe(reservation=new),store.consume_before_dispatch(reservation=new,**args),store.mark_unknown(reservation=new),
        store.record_reconciliation_note(reservation=new,note_sha256='a'*64)]
    require(observations==e['observations'],'FRESH_STORE_LIFECYCLE_CHANGED')
    for o in observations:require_closed(o)
    # Separate finite lifecycle oracle, independent of store transition code.
    require([o['state'] for o in observations]==['RESERVED','CONSUMED','UNKNOWN','UNKNOWN'] and
        [o['consumptions'] for o in observations]==[0,1,1,1] and observations[-1]['slot_retry_allowed'] is False,'CONSUME_UNKNOWN_ORDER_CHANGED')
    faults=('fresh_root','request','case','balance','file','receipt_subject','amount_and_request');states=('RESERVED','CONSUMED','UNKNOWN','CLOSED_BEFORE_CONSUMPTION')
    require([(r['state'],r['fault']) for r in duplicates]==[(state,fault) for fault in faults for state in states],'DUPLICATE_POPULATION_CHANGED')
    from task15_refund_original_request_authority_design_v1 import derive_refund_design
    from task15_refund_execution_metadata_authority_design_v1 import RULE as MRULE,POLICY
    from task15_refund_receipt_correlation_and_duplicate_authority_design_v1 import RULE as SRULE
    for row in duplicates:
        other=copy.deepcopy(sc);fault=row['fault']
        if fault=='request':e0=other['envelope'];other['envelope']=type(e0)(e0.suite,15,e0.instruction.replace('10.00','10.0'))
        if fault=='case':other['case_id']+='another'
        if fault=='balance':other['trusted_prestate']['bank_account']['balance']+=1
        if fault=='file':other['trusted_prestate']['filesystem']['files']['notes.txt']='changed'
        if fault=='receipt_subject':other['trusted_prestate']['bank_account']['transactions'][-1]['subject']='changed'
        if fault=='amount_and_request':
            other['trusted_prestate']['bank_account']['transactions'][-1]['amount']=20.0
            e0=other['envelope'];other['envelope']=type(e0)(e0.suite,15,e0.instruction.replace('10.00','20.00'))
        core=derive_refund_design(**{k:other[k] for k in ('envelope','case_id','proposal_ordinal','trusted_prestate','owned_ledger_recipient')})
        other['policy_draft']['scope_sha256']=core.digest
        other['slot_draft']['receipt_sha256']=core.payload()['target_receipt_sha256']
        c2=copy.deepcopy(c)
        if fault=='amount_and_request':c2['arguments']['amount']=20.0
        one,a=prepared(sc,lambda:now,c);two,b2=prepared(other,lambda:now,c2)
        local=OwnedRefundReceiptStore(owned_verifiers=[one.verifier,two.verifier]);token=local.reserve(**a)
        if row['state'] in ('CONSUMED','UNKNOWN'):local.consume_before_dispatch(reservation=token,**a)
        if row['state']=='UNKNOWN':local.mark_unknown(reservation=token)
        if row['state']=='CLOSED_BEFORE_CONSUMPTION':local.close_before_consumption(reservation=token)
        try:local.reserve(**b2)
        except RefundReceiptStoreViolation:pass
        else:raise ValueError('MUTABLE_SCOPE_RESET_RECEIPT_KEY')
        require(local.observe(reservation=token)==row['observation'] and row['duplicate_refused'] is True and
            row['correlation_key']==key and row['old_receipt_sha256']==bindings['receipt_sha256'] and
            row['new_receipt_sha256']==core.payload()['target_receipt_sha256'],'DUPLICATE_REFUSAL_CHANGED')
    from dataclasses import replace
    from datetime import timedelta
    require([r['fault'] for r in refusals]==['candidate','binding','request','state','receipt','expiry','rollback','revocation','clock_exception'],'RECHECK_REFUSAL_POPULATION_CHANGED')
    for row in refusals:
        clock=[now]
        def current():
            if clock[0]=='failure':raise RuntimeError('owned clock failure')
            return clock[0]
        s,args=prepared(sc,current,c);local=OwnedRefundReceiptStore(owned_verifiers=[s.verifier]);token=local.reserve(**args);fault=row['fault']
        if fault=='candidate':args['candidate']=copy.deepcopy(c);args['candidate']['arguments']['subject']='changed'
        if fault=='binding':args['binding']=replace(args['binding'],candidate_sha256='0'*64)
        if fault=='request':e0=args['envelope'];args['envelope']=type(e0)(e0.suite,15,e0.instruction.replace('10.00','10.0'))
        if fault in ('state','receipt'):
            args['trusted_prestate']=copy.deepcopy(sc['trusted_prestate'])
            if fault=='state':args['trusted_prestate']['bank_account']['balance']+=1
            else:args['trusted_prestate']['bank_account']['transactions'][-1]['subject']='changed'
        if fault=='expiry':clock[0]=now.replace(minute=5,second=0)
        if fault=='rollback':clock[0]=now-timedelta(seconds=1)
        if fault=='revocation':s.revoke(profile=args['profile'])
        if fault=='clock_exception':clock[0]='failure'
        try:local.consume_before_dispatch(reservation=token,**args)
        except (ValueError,RuntimeError):pass
        else:raise ValueError('AUTHENTICATED_RECHECK_FAILURE_CONSUMED')
        require(local.observe(reservation=token)==row['observation'],'PRECONSUME_CLOSE_CHANGED');require_closed(row['observation'])
    require([r['operation'] for r in parallel]==['reserve','consume','consume_vs_close'],'PARALLEL_POPULATION_CHANGED')
    for row in parallel:
        require(row['attempts']==32 and row['winners']==1 and row['rejected']==31 and row['reservations']==1 and row['native_dispatches']==0,'ATOMIC_SINGLE_WINNER_CHANGED')
        expected_states={'reserve':{'RESERVED'},'consume':{'CONSUMED'},'consume_vs_close':{'CONSUMED','CLOSED_BEFORE_CONSUMPTION'}}
        require(row['state'] in expected_states[row['operation']] and row['consumptions']==int(row['state']=='CONSUMED'),'PARALLEL_TERMINAL_STATE_CHANGED')
    return {'correlation_key':key,'receipt_id':bindings['receipt_id'],'candidate_sha256':control.candidate_sha256,
        'pairing_identity_sha256':control.pairing_identity_sha256(),'boundary_sha256':boundary.digest,'native_schema_sha256':sha(fn.parameters.model_json_schema()),
        'original_signature_verified_relative_to_exported_root':True,'original_store_registry_independently_authenticated':False,
        'fresh_owned_store_lifecycle_reconstructed':True,'duplicate_refusals_recomputed':28,'preconsume_recheck_refusals_recomputed':9,
        'parallel_populations_verified':3,'separate_consume_unknown_order_oracle_verified':True,'native_dispatches':0}

def main():
    p=argparse.ArgumentParser()
    for n in ('agentdojo','rcc','veritas'):p.add_argument('--'+n+'-root',type=Path,required=True)
    for n in ('replay-artifact','v13-artifact','output-dir'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();sys.path.insert(0,str(a.rcc_root.resolve()/'external-eval/v0.3.9/src'))
    for k in ('OPENAI_API_KEY','VERITAS_DATABASE_URL'):require(not os.environ.get(k),k+'_MUST_BE_EMPTY')
    require(blob(CONTRACT)==EXPECTED_CONTRACT,'CONTRACT_PIN_MISMATCH');c=json.loads(CONTRACT.read_text())
    for path,pin in c['source_blobs'].items():require(blob(ROOT/path)==pin,'SOURCE_PIN_MISMATCH:'+path)
    out=a.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ);env.update(OPENAI_API_KEY='',VERITAS_DATABASE_URL='',PYTEST_DISABLE_PLUGIN_AUTOLOAD='1',PYTEST_ADDOPTS='')
    command=[sys.executable,'scripts/task15_refund_prospective_execution_authority_profile_audit_v1.py']
    for n in ('agentdojo','rcc','veritas','replay-artifact','v13-artifact'):
        attr=n.replace('-','_')+('_root' if n in ('agentdojo','rcc','veritas') else '')
        command.extend(['--'+n+('-root' if n in ('agentdojo','rcc','veritas') else ''),str(getattr(a,attr).resolve())])
    command.extend(['--output-dir',str(out)])
    prior=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True)
    require(prior.returncode==0,'PRIOR_AUTHORITY_BOUNDARY_FAILED:'+prior.stderr+prior.stdout[-2000:])
    print(prior.stdout,end='');(out/'task15-refund-prospective-execution-authority-profile-v1.log').write_text(prior.stdout)
    raw=(out/'task15-refund-prospective-execution-authority-profile-v1.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest()==c['prior_profile_report_sha256'],'PRIOR_BOUNDARY_REPORT_CHANGED')
    paths={suffix:out/(NAME+suffix) for suffix in ('.evidence.json','.duplicates.jsonl','.refusals.jsonl','.parallel.jsonl','.junit.xml','.json')}
    for path in paths.values():path.unlink(missing_ok=True)
    env.update(TASK15_RENT_DESIGN_PROOF='1',TASK15_CONTROLLED_RENT_PROOF='1',TASK15_REFUND_DESIGN_PROOF='1',
        TASK15_REFUND_METADATA_PROOF='1',TASK15_REFUND_CORRELATION_PROOF='1',TASK15_REFUND_RECEIPT_STORE_PROOF='1',
        TASK15_RCC_ROOT=str(a.rcc_root.resolve()),TASK15_REFUND_RECEIPT_STORE_EVIDENCE=str(paths['.evidence.json']),
        TASK15_REFUND_RECEIPT_STORE_REFUSALS=str(paths['.refusals.jsonl']),TASK15_REFUND_RECEIPT_STORE_DUPLICATES=str(paths['.duplicates.jsonl']),
        TASK15_REFUND_RECEIPT_STORE_PARALLEL=str(paths['.parallel.jsonl']))
    run=subprocess.run([sys.executable,'-m','pytest','-q','-o','addopts=','tests/test_task15_refund_receipt_reservation_consumption_v1.py',
        '--junitxml',str(paths['.junit.xml'])],cwd=ROOT,env=env,capture_output=True,text=True)
    print(run.stdout,end='');require(run.returncode==0,'AUTHORITY_PROFILE_TESTS_FAILED:'+run.stderr)
    cases=ET.parse(paths['.junit.xml']).getroot().findall('.//testcase')
    require(len(cases)==TESTS and not any(x.find(t)is not None for x in cases for t in ('failure','error','skipped')),'TESTS_INCOMPLETE')
    evidence=json.loads(paths['.evidence.json'].read_text());rows=lambda suffix:[json.loads(x) for x in paths[suffix].read_text().splitlines()]
    identity=audit_store(evidence,rows('.duplicates.jsonl'),rows('.refusals.jsonl'),rows('.parallel.jsonl'))
    report={'rule_of_one':RULE,'determination':'BOUNDED_ATOMIC_SHARED_OWNED_STORE_RESERVATION_CONSUMPTION_PASS_NOT_NATIVE_PERMISSION',
        'receipt_store_tests':TESTS,'prior_dedicated_tests':1296,'failures':0,'skipped':0,'identity':identity,
        'owned_in_memory_shared_store_implemented':True,'local_stable_receipt_key_exclusion':True,
        'consume_before_any_dispatch_recorded':True,'consumed_unknown_slots_never_reopen':True,
        'original_store_registry_independently_authenticated':False,'external_root_principal_ledger_clock_authenticity_proven':False,
        'durable_global_duplicate_exclusion':False,'restart_persistence_proven':False,'RCC_Bind_final_sink_integration_proven':False,
        'execution_permission':False,'native_dispatch_authorized':False,'runtime_admission_activated':False,
        'effect_authenticated':False,'no_effect_authenticated':False,'native_dispatches_in_new_store_proof':0,
        'provider_execution':0,'provider_client_constructed':0,'database_access_in_new_store_proof':0,
        'scorer_or_gold_derived_authority':0,'candidate_repair':0,'v13_authorization_reuse':0,'v13_human_confirmation_reuse':0,
        'historical_candidates_recovered':0,'safe_to_relax_existing_runner_now':0,'utility_recovery_proven':False,
        'injection_success_remeasured':False,'full_task15_execution_supported':False,'full_final128_trajectory_integrated':False,
        'real_provider_generation_ordering_proven':False,'independent_external_validation':False,'held_out_validation':False,
        'production_readiness':False,'prior_profile_report_sha256':hashlib.sha256(raw).hexdigest(),'next_rule_of_one':c['next_rule_of_one']}
    paths['.json'].write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print('PASS_TASK15_REFUND_RECEIPT_RESERVATION_CONSUMPTION_V1')
    print(f'receipt_store_tests={TESTS} prior_dedicated_tests=1296 failures=0 skipped=0')
    print('duplicate_refusals=28 preconsume_recheck_refusals=9 parallel_populations=3')
    print('execution_permission=false native_dispatches=0 owned_in_memory_store=true durable_global_exclusion=false safe_to_relax_now=0 provider_execution=0 v13_reuse=0')
    print('next_rule_of_one='+c['next_rule_of_one']);return 0
if __name__=='__main__':raise SystemExit(main())
