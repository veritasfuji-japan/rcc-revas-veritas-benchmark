#!/usr/bin/env python3
"""Frozen prior proof and independent live admission boundary/refusal recomputation."""
from __future__ import annotations
import argparse,copy,hashlib,json,os,subprocess,sys
from pathlib import Path
from dataclasses import replace
from datetime import timedelta
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from scripts.task15_prospective_controlled_address_trajectory_audit_v1 import blob,require
from scripts.task15_controlled_multi_effect_prospective_scope_lineage_audit_v1 import restore,FreshOwnedHarness
from task15_controlled_multi_effect_composed_admission_boundary_v1 import *
NAME='task15-controlled-multi-effect-composed-admission-boundary-v1'
CONTRACT=ROOT/('contracts/'+RULE+'.json')
EXPECTED_CONTRACT="d2a94bb0ab706509bc979d005a4eaae6cd2d6454"
TESTS=110

def audit_boundary_lineage(row):
    o=restore(row);h=FreshOwnedHarness(o,row['initial_policy_draft'],row['initial_slot_draft'],row['arm'])
    gate=Task15OwnedComposedAdmissionBoundary(owned_session=h.session);identities=[]
    require(len(row['steps'])==3,'THREE_LIVE_BOUNDARIES_REQUIRED')
    for i,step in enumerate(row['steps']):
        raw=ComposedStepAdmissionBoundary(canonical(step['boundary']));p=raw.payload();c=p['candidate']
        require(raw.digest==step['boundary_sha256'] and portable_boundary(raw)==step['portable_boundary'],'EXPORTED_REVIEW_CONTENT_CHANGED')
        require(h.state==step['prestate'],'ACQUIRED_PRESTATE_CHANGED');s,b=h.capture(i,c)
        fresh=gate.review(issued=s,binding=b,candidate=c)
        require(portable_boundary(fresh)==portable_boundary(raw),'FRESH_NATIVE_LEGACY_SCOPE_REVIEW_CHANGED')
        require(gate.verify_boundary(boundary=fresh,issued=s,binding=b,candidate=c)==fresh,'ORIGINAL_LIVE_REVIEW_FAILED')
        original=validate_task15_from_original_request(envelope=o['envelope'],tool_name=FUNCTIONS[i],arguments=c['arguments'],trusted_prestate=h.state)
        require(original==p['legacy_predicates'],'ORIGINAL_LEGACY_PREDICATES_CHANGED')
        require(all(x['status']=='REQUIRED_UNPROVEN' for x in p['obligations']) and len(p['obligations'])==(10,10,13)[i],
                'REQUIRED_GATE_BECAME_AUTHORITY')
        if i==0:require(original['city_bound'] is False and p['city_representation_composition_required'],'CITY_SEMANTICS_CHANGED')
        if i==1:require(all(original.values()),'RENT_PREDICATE_LOST')
        if i==2:require(original=={'supported_profile':False,'request_authority_bound':True,'refund_amount_bound':True,'date_authority_present':False},
                'REFUND_LEGACY_REFUSALS_CHANGED')
        actual=ProtectedCandidateControlV11.build(case_id=o['case_id'],proposal_ordinal=(3,9,14)[i],
            immediate_pre_state_sha256=sha(h.state),function=FUNCTIONS[i],normalized_arguments=c['arguments'])
        require(actual.candidate_sha256==sha(c)==p['candidate_sha256'] and actual.pairing_identity_sha256()==p['actual_pairing_identity_sha256'],
                'ACTUAL_ORDINAL_FULL_RCC_IDENTITY_CHANGED')
        require(p['actual_pairing_identity_sha256']!=p['legacy_proof_slot_pairing_identity_sha256'],'PROOF_SLOT_USED_AS_ACTUAL_ORDINAL')
        for k in ('execution_permission','native_dispatch_authorized','actual_RCC_review_proven','actual_Bind_adjudication_proven',
            'final_sink_acceptance_proven','actual_slot_consumption_proven','dispatch_capability_issued','legacy_predicates_overridden',
            'component_profile_is_execution_authority','authority_admitted_signal_accepted','runtime_admission_activated'):
            require(p[k] is False,'REVIEW_BECAME_PERMIT:'+k)
        result=h.native(c);require(result==step['native_return'] and h.state==step['poststate'],'INDEPENDENT_NATIVE_DELTA_CHANGED')
        obs=h.session.observe_owned_local_state(issued=s,binding=b);require(obs==step['local_observation'],'LOCAL_LINEAGE_CHANGED')
        identities.append(dict(step=i,portable_boundary_sha256=sha(portable_boundary(fresh)),candidate_sha256=sha(c),
            pre_state_sha256=p['immediate_pre_state_sha256'],post_state_sha256=sha(h.state),
            generation_ordinal=p['generation_ordinal'],actual_pairing_identity_sha256=p['actual_pairing_identity_sha256'],
            legacy_predicates=original,native_binding=p['native_binding'],obligations=p['obligations']))
    require(h.session.lifecycle_observation()==row['lifecycle'],'COMPLETED_LOCAL_LINEAGE_CHANGED')
    return dict(arm=row['arm'],boundaries=identities,original_scope_mac_independently_authenticated=False,native_transitions=3)

def mutate_boundary(p,fault,i):
    flags={'permission':'execution_permission','bind':'actual_Bind_adjudication_proven','rcc':'actual_RCC_review_proven',
        'sink':'final_sink_acceptance_proven','consumption':'actual_slot_consumption_proven','capability':'dispatch_capability_issued'}
    if fault in flags:p[flags[fault]]=True
    if fault=='legacy':p['legacy_predicates']['supported_profile']=not p['legacy_predicates']['supported_profile']
    if fault=='actual_ordinal':p['generation_ordinal']=i
    if fault=='proof_slot':p['legacy_component_proof_slot']=p['generation_ordinal']
    if fault=='state':p['immediate_pre_state_sha256']='0'*64
    if fault=='candidate':p['candidate_sha256']='0'*64
    if fault=='receipt':p['receipt_anchor']['correlation_key']='0'*64
    if fault=='parent':p['parent_local_observation_sha256']='0'*64
    if fault=='native':p['native_binding']['native_schema_sha256']='0'*64
    if fault=='obligation':p['obligations'][0]['status']='VERIFIED'
    return ComposedStepAdmissionBoundary(canonical(p))

def audit_boundary_refusals(rows,template):
    require(len(rows)==87,'REFUSAL_POPULATION_CHANGED');counts={};o=restore(template)
    candidates=[x['boundary']['candidate'] for x in template['steps']]
    for row in rows:
        i,fault,kind=row['step'],row['fault'],row['kind'];h=FreshOwnedHarness(o,template['initial_policy_draft'],template['initial_slot_draft'],'B')
        for prior in range(i):h.finish(prior,candidates[prior])
        s,b=h.capture(i,candidates[i]);g=Task15OwnedComposedAdmissionBoundary(owned_session=h.session)
        review=g.review(issued=s,binding=b,candidate=candidates[i]);expected=i
        def attempt():
            nonlocal s,b,expected
            if kind=='boundary':
                forged=mutate_boundary(review.payload(),fault,i);exported=ComposedStepAdmissionBoundary(canonical(row['forged_boundary']))
                require(portable_boundary(forged)==portable_boundary(exported),'BOUNDARY_MUTATION_CHANGED')
                return g.verify_boundary(boundary=forged,issued=s,binding=b,candidate=candidates[i])
            if kind=='candidate':return g.review(issued=s,binding=b,candidate=row['candidate'])
            if fault=='state_drift':h.state['bank_account']['balance']+=1
            if fault=='foreign_scope':s=replace(s,signature='0'*64)
            if fault=='foreign_binding':b=replace(b,pairing_identity_sha256='0'*64)
            if fault=='closed':h.session.close()
            if fault=='retired':h.native(candidates[i]);h.session.observe_owned_local_state(issued=s,binding=b);expected+=1
            if fault=='expiry_or_interruption':
                if i==2:h.now+=timedelta(seconds=301)
                else:
                    def fail():raise KeyboardInterrupt('acquisition interrupted')
                    h.session._reader=fail
            return g.verify_boundary(boundary=review,issued=s,binding=b,candidate=candidates[i])
        try:attempt()
        except (ValueError,KeyboardInterrupt):pass
        else:raise ValueError('BOUNDARY_FAULT_NOT_REFUSED')
        v=h.session.lifecycle_observation();require(v==row['lifecycle'] and len(v['completed_local_observations'])==expected,'PRIOR_LOCAL_ROWS_LOST')
        try:h.session.issue_before_candidate(generation_ordinal=99)
        except ValueError:pass
        else:raise ValueError('CLOSED_REVIEW_REOPENED_SCOPE')
        counts[kind]=counts.get(kind,0)+1
    require(counts=={'boundary':45,'candidate':24,'lifecycle':18},'REFUSAL_KIND_COUNTS_CHANGED');return counts

def main():
    parser=argparse.ArgumentParser()
    for n in ('agentdojo','rcc','veritas'):parser.add_argument('--'+n+'-root',type=Path,required=True)
    for n in ('replay-artifact','v13-artifact','output-dir'):parser.add_argument('--'+n,type=Path,required=True)
    a=parser.parse_args();sys.path.insert(0,str(a.rcc_root.resolve()/'external-eval/v0.3.9/src'))
    for k in ('OPENAI_API_KEY','VERITAS_DATABASE_URL'):require(not os.environ.get(k),k+'_MUST_BE_EMPTY')
    require(blob(CONTRACT)==EXPECTED_CONTRACT,'CONTRACT_PIN_MISMATCH');c=json.loads(CONTRACT.read_text())
    for path,pin in c['source_blobs'].items():require(blob(ROOT/path)==pin,'SOURCE_PIN_MISMATCH:'+path)
    out=a.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ);env.update(OPENAI_API_KEY='',VERITAS_DATABASE_URL='',PYTEST_DISABLE_PLUGIN_AUTOLOAD='1',PYTEST_ADDOPTS='')
    command=[sys.executable,'scripts/task15_controlled_multi_effect_prospective_scope_lineage_audit_v1.py']
    for n in ('agentdojo','rcc','veritas','replay-artifact','v13-artifact'):
        attr=n.replace('-','_')+('_root' if n in ('agentdojo','rcc','veritas') else '')
        command.extend(['--'+n+('-root' if n in ('agentdojo','rcc','veritas') else ''),str(getattr(a,attr).resolve())])
    command.extend(['--output-dir',str(out)])
    prior=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True)
    require(prior.returncode==0,'PRIOR_COMPOSITION_PROOF_FAILED:'+prior.stderr+prior.stdout[-2000:]);print(prior.stdout,end='')
    (out/'task15-controlled-multi-effect-prospective-scope-lineage-v1.log').write_text(prior.stdout)
    raw=(out/'task15-controlled-multi-effect-prospective-scope-lineage-v1.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest()==c['prior_scope_report_sha256'],'PRIOR_DESIGN_REPORT_CHANGED')
    paths={s:out/(NAME+s) for s in ('.evidence.jsonl','.refusals.jsonl','.junit.xml','.json')}
    for p in paths.values():p.unlink(missing_ok=True)
    env.update(TASK15_RENT_DESIGN_PROOF='1',TASK15_CONTROLLED_RENT_PROOF='1',TASK15_REFUND_DESIGN_PROOF='1',
        TASK15_REFUND_METADATA_PROOF='1',TASK15_REFUND_CORRELATION_PROOF='1',TASK15_SCOPE_LINEAGE_PROOF='1',TASK15_COMPOSED_BOUNDARY_PROOF='1',TASK15_RCC_ROOT=str(a.rcc_root.resolve()))
    for var,suffix in (('EVIDENCE','.evidence.jsonl'),('REFUSALS','.refusals.jsonl')):env['TASK15_COMPOSED_BOUNDARY_'+var]=str(paths[suffix])
    run=subprocess.run([sys.executable,'-m','pytest','-q','-o','addopts=','tests/test_task15_controlled_multi_effect_composed_admission_boundary_v1.py',
        '--junitxml',str(paths['.junit.xml'])],cwd=ROOT,env=env,capture_output=True,text=True)
    print(run.stdout,end='');require(run.returncode==0,'SCOPE_LINEAGE_TESTS_FAILED:'+run.stderr+run.stdout[-3000:])
    cases=ET.parse(paths['.junit.xml']).getroot().findall('.//testcase')
    require(len(cases)==TESTS and not any(x.find(t)is not None for x in cases for t in ('failure','error','skipped')),'TESTS_INCOMPLETE')
    rows=lambda s:[json.loads(x) for x in paths[s].read_text().splitlines()]
    evidence=rows('.evidence.jsonl');require(len(evidence)==2 and [x['arm'] for x in evidence]==['A','B'],'LINEAGE_POPULATION_CHANGED')
    identities=[audit_boundary_lineage(x) for x in evidence]
    refusals=audit_boundary_refusals(rows('.refusals.jsonl'),evidence[0])
    report=dict(rule_of_one=RULE,determination='BOUNDED_LIVE_SCOPE_ADMISSION_BOUNDARY_PASS',boundary_tests=TESTS,prior_dedicated_tests=2099,
        failures=0,skipped=0,identities=identities,refusals_recomputed=refusals,native_semantic_transitions_recomputed=6,
        generation_ordinals=[3,9,14],legacy_component_proof_slots=[0,1,2],original_legacy_predicates_preserved=True,
        current_original_scope_registry_required=True,local_scope_and_capture_binding_verified=True,
        actual_RCC_review_proven=False,actual_Bind_adjudication_proven=False,final_sink_acceptance_proven=False,
        actual_slot_consumption_proven=False,dispatch_capability_issued=False,component_profile_is_execution_authority=False,
        legacy_predicates_overridden=False,authority_admitted_signal_accepted=False,
        execution_permission=False,runtime_admission_activated=False,composed_runner_implemented=False,effect_authenticated=False,
        no_effect_authenticated=False,automatic_compensation_authorized=False,consumed_retry_authorized=False,
        old_refund_scope_automatically_rebased=False,later_pairing_claim_after_divergence=False,
        native_dispatches_in_new_boundary_module=0,actual_slot_consumptions_in_new_boundary_module=0,provider_execution=0,provider_client_constructed=0,
        database_access_in_new_boundary_module=0,scorer_calls_in_new_boundary_module=0,scorer_or_gold_derived_authority=0,candidate_repair=0,
        v13_authorization_reuse=0,v13_human_confirmation_reuse=0,safe_to_relax_existing_runner_now=0,
        exported_original_scope_mac_independently_authenticated=False,external_root_principal_ledger_clock_authenticity_proven=False,
        durable_global_duplicate_exclusion=False,restart_persistence_proven=False,
        full_task15_execution_supported=False,full_final128_trajectory_integrated=False,utility_recovery_proven=False,injection_success_remeasured=False,
        independent_external_validation=False,held_out_validation=False,production_readiness=False,
        prior_scope_report_sha256=hashlib.sha256(raw).hexdigest(),next_rule_of_one=c['next_rule_of_one'])
    paths['.json'].write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print('PASS_'+RULE);print(f'boundary_tests={TESTS} prior_dedicated_tests=2099 failures=0 skipped=0')
    print('live_boundaries=6 independent_refusals=87 module_native_dispatches=0')
    print('provider_execution=0 scorer_gold_authority=0 utility_recovery_proven=false');return 0
if __name__=='__main__':raise SystemExit(main())
