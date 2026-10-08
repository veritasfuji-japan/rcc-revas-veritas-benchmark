#!/usr/bin/env python3
"""Source-pinned inert composition proof and detached native semantic replay."""
from __future__ import annotations
import argparse,copy,hashlib,json,os,subprocess,sys
from pathlib import Path
from datetime import datetime,timezone
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from scripts.task15_prospective_controlled_address_trajectory_audit_v1 import blob,require
from task15_controlled_multi_effect_composition_authority_design_v1 import *
from original_request_authority_lineage_v1 import OriginalRequestEnvelope
NAME='task15-controlled-multi-effect-composition-authority-design-v1'
CONTRACT=ROOT/('contracts/'+RULE+'.json')
EXPECTED_CONTRACT="f1fdac91f66ecb131198be3b51745ec1925cd5d7"
TESTS=107

def restore(row):
    s=copy.deepcopy(row['owned_input']);s['envelope']=OriginalRequestEnvelope(**s['envelope'])
    s['reviewed_at_utc']=datetime.strptime(s['reviewed_at_utc'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    return s

def audit_design(row):
    from agentdojo.functions_runtime import make_function
    from agentdojo.default_suites.v1.tools.user_account import update_user_info
    from agentdojo.default_suites.v1.tools.banking_client import update_scheduled_transaction,send_money
    s=restore(row);before=sha(s['trusted_prestate']);d=derive_composition_design(**s);p=d.payload();c=row['candidates']
    require(p==row['design'] and d.digest==row['design_sha256'],'COMPOSITION_PROJECTION_CHANGED')
    a=assess_composition_candidates(design=d,candidates=c,**s)
    require(a==row['assessment'] and a['effect_scope_candidates_match'] and not a['execution_permission'],'COMPOSITION_ASSESSMENT_CHANGED')
    definitions=[]
    for i,fn in enumerate((update_user_info,update_scheduled_transaction,send_money)):
        f=make_function(fn);args=f.parameters.model_validate(c[i]['arguments']).model_dump(mode='json')
        require(args==c[i]['arguments'],'NORMALIZED_REVIEW_OBJECT_CHANGED')
        require(p['steps'][i]['draft_pre_state_sha256']==sha(p['draft_states'][i]) and
            p['steps'][i]['draft_post_state_sha256']==sha(p['draft_states'][i+1]),'DRAFT_STATE_LINEAGE_CHANGED')
        definitions.append(sha(f.parameters.model_json_schema()))
    require(before==sha(s['trusted_prestate']) and p['initial_state_sha256']==before,'OWNED_INITIAL_STATE_CHANGED')
    require(all(x['fresh_scope_required_before_first_candidate'] and x['earlier_effect_is_authority'] is False for x in p['steps']),
        'INHERITED_AUTHORITY_PRESENT')
    for k in ('later_refund_policy_reuse_allowed','projection_states_are_acquired_evidence','initial_component_checks_cover_later_state',
        'execution_permission','runtime_admission_activated','issuer_present','effect_authenticated','native_dispatch_authorized',
        'global_duplicate_exclusion','full_task15_execution_supported','utility_recovery_proven','injection_success_remeasured'):
        require(p[k] is False,'DESIGN_BECAME_RUNTIME_CLAIM:'+k)
    return {'design_sha256':d.digest,'request_digest':p['request_digest'],'initial_state_sha256':before,
        'draft_state_sha256s':[sha(x) for x in p['draft_states']], 'receipt_correlation_key':p['receipt_correlation_key'],
        'candidate_sha256s':[sha(x) for x in c],'native_schema_sha256s':definitions,'execution_permission':False}

def audit_native_probe(row):
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.functions_runtime import FunctionsRuntime,make_function
    from agentdojo.default_suites.v1.tools.user_account import update_user_info
    from agentdojo.default_suites.v1.tools.banking_client import update_scheduled_transaction,send_money
    s=restore(row);d=derive_composition_design(**s);p=d.payload();require(row['design']==p,'NATIVE_PROBE_DESIGN_CHANGED')
    require(assess_composition_candidates(design=d,candidates=row['candidates'],**s)['effect_scope_candidates_match'],
        'DETACHED_NATIVE_PROBE_CANDIDATE_SCOPE_CHANGED')
    suite=get_suite('v1.2.2','banking');env=suite.environment_type.model_validate(copy.deepcopy(s['trusted_prestate']))
    runtime=FunctionsRuntime([make_function(x) for x in (update_user_info,update_scheduled_transaction,send_money)])
    returns=[]
    for i,c in enumerate(row['candidates']):
        require(env.model_dump(mode='json')==p['draft_states'][i],'FRESH_DETACHED_PRESTATE_CHANGED')
        value,error=runtime.run_function(env,c['name'],c['arguments'],raise_on_error=True)
        require(error is None and env.model_dump(mode='json')==p['draft_states'][i+1],'FRESH_DETACHED_NATIVE_EFFECT_CHANGED')
        returns.append(value)
    require(returns==row['native_returns'] and env.model_dump(mode='json')==row['final_state'] and row['governed_admission'] is False,
        'NATIVE_PROBE_RETURN_OR_SCOPE_CHANGED')
    return {'exact_optional':row['exact_optional'],'state_sha256s':[sha(x) for x in p['draft_states']],
        'native_return_sha256':sha(returns),'detached_native_transitions':3,'governed_admission':False}

def audit_stale_scopes(rows, owned):
    from task15_refund_original_request_authority_design_v1 import derive_refund_design
    from task15_refund_execution_authority_boundary_v1 import RefundAuthorityBoundaryViolation
    p=derive_composition_design(**owned).payload()
    require([x['stage'] for x in rows]==[1,2],'STALE_SCOPE_POPULATION_CHANGED')
    for row in rows:
        fresh=copy.deepcopy(owned);fresh['trusted_prestate']=p['draft_states'][row['stage']]
        try:derive_execution_authority_boundary(proposal_ordinal=2,**fresh)
        except RefundAuthorityBoundaryViolation:pass
        else:raise ValueError('INITIAL_REFUND_POLICY_ACCEPTED_LATER_STATE')
        core={k:fresh[k] for k in ('envelope','case_id','trusted_prestate','owned_ledger_recipient')}
        fresh['policy_draft']['scope_sha256']=derive_refund_design(proposal_ordinal=2,**core).digest
        f=derive_execution_authority_boundary(proposal_ordinal=2,**fresh).payload()
        require(row['initial_scope_refused'] and row['same_receipt_key']==p['receipt_correlation_key']==f['bindings']['correlation_key'] and
            row['fresh_draft_execution_permission'] is f['execution_permission'] is False and
            fresh['policy_draft']['scope_sha256']!=owned['policy_draft']['scope_sha256'],'STALE_SCOPE_REFUSAL_OR_RECEIPT_ID_CHANGED')
    return len(rows)

def audit_models(rows,owned):
    d=derive_composition_design(**owned);mutations=0;terminal={};partial=0
    cycle=['ISSUE_FRESH_SCOPE','CAPTURE_SAME_CANDIDATE_AND_PRESTATE','RCC_BIND_FINAL_SINK_RECHECK','CONSUME_ONCE','DISPATCH_ONCE','LOCAL_STEP_OBSERVED']
    require(len(rows)==34 and rows[0]['events']==cycle*3,'MODEL_POPULATION_CHANGED')
    for row in rows:
        events=row['events'];o=check_composition_specification(design=d,events=events,**owned)
        require(o==row['observation'],'MODEL_RECOMPUTATION_CHANGED')
        # Separate prefix grammar: any earlier complete cycle remains recorded;
        # last stage either has a complete cycle or exactly one legal stop suffix.
        complete=len(events)//6 if events[-1]=='LOCAL_STEP_OBSERVED' else events.count('LOCAL_STEP_OBSERVED')
        require(events[:6*complete]==cycle*complete and o['model_observed_steps']==list(range(complete)), 'MODEL_EARLIER_EFFECTS_LOST')
        suffix=events[6*complete:]
        if not suffix:expected='COMPLETE_SPECIFICATION';require(complete==3,'SHORT_COMPLETE_MODEL')
        else:
            last=suffix[-1];prefix=suffix[:-1]
            require(prefix==cycle[:len(prefix)],'MODEL_SKIPPED_STAGE_GATE')
            if last in ('STOP_BEFORE_CONSUME','PAIRING_DIVERGED'):
                require(len(prefix)<=3,'CONSUMED_MODEL_RECLASSIFIED_CLOSED')
                expected='PAIRING_STOPPED' if last=='PAIRING_DIVERGED' else 'STOPPED'
            else:
                require((last=='FAIL_AFTER_CONSUME' and len(prefix)==4) or
                    (last in ('FAIL_DISPATCH','RETURN_WITHOUT_OBSERVATION') and len(prefix)==5),'UNKNOWN_MODEL_GATE_CHANGED')
                expected='UNKNOWN'
        require(o['model_terminal']==expected and o['actual_native_dispatches']==o['actual_slot_consumptions']==0 and
            o['execution_permission'] is False and o['no_effect_authenticated'] is False and not o['events_are_authority_evidence'],
            'MODEL_BECAME_RUNTIME_EVIDENCE')
        terminal[expected]=terminal.get(expected,0)+1;partial+=o['model_partial_effects_preserved']
        for pos in range(len(events)+1):
            for event in ('CONSUME_ONCE','DISPATCH_ONCE','RETRY','LOCAL_STEP_OBSERVED'):
                try:check_composition_specification(design=d,events=events[:pos]+[event]+events[pos:],**owned)
                except CompositionDesignViolation:mutations+=1
                else:raise ValueError('MODEL_GATE_REPLAY_OR_RETRY_ACCEPTED')
    return {'terminal_models':len(rows),'terminal_counts':terminal,'partial_effect_terminal_models':partial,
        'single_event_mutations_rejected':mutations,'actual_native_dispatches':0}

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
    command=[sys.executable,'scripts/task15_refund_trajectory_native_scorer_observation_boundary_audit_v1.py']
    for n in ('agentdojo','rcc','veritas','replay-artifact','v13-artifact'):
        attr=n.replace('-','_')+('_root' if n in ('agentdojo','rcc','veritas') else '')
        command.extend(['--'+n+('-root' if n in ('agentdojo','rcc','veritas') else ''),str(getattr(a,attr).resolve())])
    command.extend(['--output-dir',str(out)])
    prior=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True)
    require(prior.returncode==0,'PRIOR_SCORER_PROOF_FAILED:'+prior.stderr+prior.stdout[-2000:]);print(prior.stdout,end='')
    (out/'task15-refund-trajectory-native-scorer-observation-boundary-v1.log').write_text(prior.stdout)
    raw=(out/'task15-refund-trajectory-native-scorer-observation-boundary-v1.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest()==c['prior_observer_report_sha256'],'PRIOR_OBSERVER_REPORT_CHANGED')
    suffixes=('.evidence.jsonl','.probes.jsonl','.stale-scopes.jsonl','.refusals.jsonl','.traces.jsonl','.mutations.jsonl','.junit.xml','.json')
    paths={s:out/(NAME+s) for s in suffixes}
    for p in paths.values():p.unlink(missing_ok=True)
    env.update(TASK15_RENT_DESIGN_PROOF='1',TASK15_CONTROLLED_RENT_PROOF='1',TASK15_REFUND_DESIGN_PROOF='1',
        TASK15_REFUND_METADATA_PROOF='1',TASK15_REFUND_CORRELATION_PROOF='1',TASK15_COMPOSITION_DESIGN_PROOF='1',
        TASK15_RCC_ROOT=str(a.rcc_root.resolve()))
    for var,suffix in (('EVIDENCE','.evidence.jsonl'),('PROBES','.probes.jsonl'),('STALE_SCOPES','.stale-scopes.jsonl'),
        ('REFUSALS','.refusals.jsonl'),('TRACES','.traces.jsonl'),('MUTATIONS','.mutations.jsonl')):
        env['TASK15_COMPOSITION_DESIGN_'+var]=str(paths[suffix])
    run=subprocess.run([sys.executable,'-m','pytest','-q','-o','addopts=','tests/test_task15_controlled_multi_effect_composition_authority_design_v1.py',
        '--junitxml',str(paths['.junit.xml'])],cwd=ROOT,env=env,capture_output=True,text=True)
    print(run.stdout,end='');require(run.returncode==0,'COMPOSITION_TESTS_FAILED:'+run.stderr+run.stdout[-3000:])
    cases=ET.parse(paths['.junit.xml']).getroot().findall('.//testcase')
    require(len(cases)==TESTS and not any(x.find(t)is not None for x in cases for t in ('failure','error','skipped')),'TESTS_INCOMPLETE')
    rows=lambda s:[json.loads(x) for x in paths[s].read_text().splitlines()]
    evidence=rows('.evidence.jsonl');require(len(evidence)==1,'DESIGN_POPULATION_CHANGED');identity=audit_design(evidence[0]);owned=restore(evidence[0])
    probes=rows('.probes.jsonl');require(len(probes)==2,'NATIVE_PROBE_POPULATION_CHANGED');native=[audit_native_probe(x) for x in probes]
    d=derive_composition_design(**owned);refusals=rows('.refusals.jsonl');require(len(refusals)==30,'REFUSAL_POPULATION_CHANGED')
    for row in refusals:
        o=assess_composition_candidates(design=d,candidates=row['candidates'],**owned)
        require(o==row['assessment'] and not o['effect_scope_candidates_match'] and o['candidate_repair']==0 and o['execution_permission'] is False,
            'INDEPENDENT_CANDIDATE_REFUSAL_CHANGED')
    stale_count=audit_stale_scopes(rows('.stale-scopes.jsonl'),owned);require(stale_count==2,'STALE_SCOPE_REFUSALS_CHANGED')
    models=audit_models(rows('.traces.jsonl'),owned)
    require(rows('.mutations.jsonl')==[{'mutated_model_traces':models['single_event_mutations_rejected'],
        'rejected':models['single_event_mutations_rejected'],'actual_native_dispatches':0}], 'MODEL_MUTATION_POPULATION_CHANGED')
    report={'rule_of_one':RULE,'determination':'BOUNDED_INERT_COMPOSITION_AUTHORITY_DESIGN_PASS','design_tests':TESTS,'prior_dedicated_tests':1903,
        'failures':0,'skipped':0,'identity':identity,'detached_native_probes':native,'detached_native_transitions_recomputed':6,
        'candidate_scope_mismatches_refused':30,'stale_initial_refund_policy_scopes_refused':2,'models':models,
        'fresh_per_step_scope_required':True,'same_candidate_same_prestate_required_per_pair':True,
        'later_pairing_claim_after_divergence':False,'effect_prediction_used_as_authority':False,'old_refund_scope_automatically_rebased':False,
        'execution_permission':False,'runtime_admission_activated':False,'composed_runner_implemented':False,'effect_authenticated':False,
        'no_effect_authenticated':False,'automatic_compensation_authorized':False,'consumed_retry_authorized':False,
        'actual_governed_dispatches_in_new_design':0,'actual_slot_consumptions_in_new_design':0,'provider_execution':0,'provider_client_constructed':0,
        'database_access_in_new_design':0,'scorer_or_gold_derived_authority':0,'scorer_calls_in_new_design':0,'candidate_repair':0,
        'v13_authorization_reuse':0,'v13_human_confirmation_reuse':0,'historical_candidates_recovered':0,'safe_to_relax_existing_runner_now':0,
        'original_registry_independently_authenticated':False,'external_root_principal_ledger_clock_authenticity_proven':False,
        'durable_global_duplicate_exclusion':False,'restart_persistence_proven':False,'effect_reconciliation_implemented':False,
        'full_task15_execution_supported':False,'full_final128_trajectory_integrated':False,'utility_recovery_proven':False,'injection_success_remeasured':False,
        'independent_external_validation':False,'held_out_validation':False,'production_readiness':False,
        'prior_observer_report_sha256':hashlib.sha256(raw).hexdigest(),'next_rule_of_one':c['next_rule_of_one']}
    paths['.json'].write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print('PASS_TASK15_CONTROLLED_MULTI_EFFECT_COMPOSITION_AUTHORITY_DESIGN_V1')
    print(f'design_tests={TESTS} prior_dedicated_tests=1903 failures=0 skipped=0')
    print('candidate_scope_mismatches=30 stale_initial_scopes=2 detached_native_transitions=6 governed_dispatches=0')
    print('terminal_models=34 single_event_mutations_rejected='+str(models['single_event_mutations_rejected']))
    print('provider_execution=0 scorer_gold_authority=0 candidate_repair=0 v13_reuse=0 utility_recovery_proven=false')
    print('next_rule_of_one='+c['next_rule_of_one']);return 0
if __name__=='__main__':raise SystemExit(main())
