"""Local scope binding never substitutes execution authority or legacy semantics."""
import copy,json,os
from pathlib import Path
from dataclasses import replace
from datetime import timedelta
import pytest
if os.environ.get('TASK15_COMPOSED_BOUNDARY_PROOF')!='1':
    pytest.skip('Requires pinned composed admission boundary proof',allow_module_level=True)
from test_task15_controlled_multi_effect_prospective_scope_lineage_v1 import (
    owned,no_provider_scorer_or_external_effect,prohibit_governed_execution,Harness,proposals,draft,slot,NOW,export,
)
from task15_controlled_multi_effect_composed_admission_boundary_v1 import *
from task15_controlled_multi_effect_prospective_scope_lineage_v1 import CapturedStepBinding

def save(suffix,row):
    p=os.environ.get('TASK15_COMPOSED_BOUNDARY_'+suffix)
    if p:
        with Path(p).open('a') as f:f.write(json.dumps(row,sort_keys=True)+'\n')
def setup(o,i,original,arm='B'):
    h=Harness(o,arm)
    for step in range(i):h.finish(step,original)
    s,b=h.capture(i);gate=Task15OwnedComposedAdmissionBoundary(owned_session=h.session)
    return h,s,b,gate

def closed(h,i):
    obs=h.session.lifecycle_observation();assert obs['phase'] in ('CLOSED','UNKNOWN_LOCAL_OBSERVATION')
    assert len(obs['completed_local_observations'])==i and not obs['execution_permission']
    with pytest.raises(ValueError):h.session.issue_before_candidate(generation_ordinal=99)
    return obs

@pytest.mark.parametrize('arm',['A','B'])
def test_three_live_boundaries_retain_distinct_original_semantics_without_dispatch(owned,prohibit_governed_execution,arm):
    h=Harness(owned,arm);gate=Task15OwnedComposedAdmissionBoundary(owned_session=h.session);steps=[]
    for i in range(3):
        s,b=h.capture(i);c=proposals()[i];pre=copy.deepcopy(h.state);before=h.session.lifecycle_observation()
        review=gate.review(issued=s,binding=b,candidate=c);p=review.payload()
        assert gate.verify_boundary(boundary=review,issued=s,binding=b,candidate=c)==review
        assert gate.review(issued=s,binding=b,candidate=c)==review and h.session.lifecycle_observation()==before
        assert p['generation_ordinal']==(3,9,14)[i] and p['legacy_component_proof_slot']==i
        assert p['actual_pairing_identity_sha256']!=p['legacy_proof_slot_pairing_identity_sha256']
        assert p['candidate']==c and p['candidate_sha256']==sha(c) and p['registered_scope_digest']==s.digest
        assert all(x['status']=='REQUIRED_UNPROVEN' for x in p['obligations'])
        assert len(p['obligations'])==(10,10,13)[i]
        for k in ('execution_permission','native_dispatch_authorized','actual_RCC_review_proven','actual_Bind_adjudication_proven',
                  'final_sink_acceptance_proven','actual_slot_consumption_proven','dispatch_capability_issued','legacy_predicates_overridden',
                  'component_profile_is_execution_authority','authority_admitted_signal_accepted','runtime_admission_activated'):
            assert p[k] is False
        old=validate_task15_from_original_request(envelope=owned['envelope'],tool_name=FUNCTIONS[i],arguments=c['arguments'],trusted_prestate=pre)
        assert p['legacy_predicates']==old
        if i==0:assert old['city_bound'] is False and p['city_representation_composition_required']
        if i==1:assert all(old.values())
        if i==2:assert old=={'supported_profile':False,'request_authority_bound':True,'refund_amount_bound':True,'date_authority_present':False}
        native_return=h.native(i,prohibit_governed_execution);obs=h.session.observe_owned_local_state(issued=s,binding=b)
        steps.append({'boundary':p,'boundary_sha256':review.digest,'portable_boundary':portable_boundary(review),
            'prestate':pre,'poststate':copy.deepcopy(h.state),'native_return':native_return,'local_observation':obs})
    save('EVIDENCE',{'owned_input':export(owned),'initial_policy_draft':draft(owned),'initial_slot_draft':slot(owned),
        'arm':arm,'steps':steps,'lifecycle':h.session.lifecycle_observation()})

FORGERIES=['permission','bind','rcc','sink','consumption','capability','legacy','actual_ordinal','proof_slot','state','candidate','receipt','parent','native','obligation']
@pytest.mark.parametrize('i',range(3))
@pytest.mark.parametrize('fault',FORGERIES)
def test_exported_boundary_self_attestation_and_field_substitution_cannot_pass_live_review(owned,prohibit_governed_execution,i,fault):
    h,s,b,g=setup(owned,i,prohibit_governed_execution);review=g.review(issued=s,binding=b,candidate=proposals()[i]);p=review.payload()
    if fault=='permission':p['execution_permission']=True
    if fault=='bind':p['actual_Bind_adjudication_proven']=True
    if fault=='rcc':p['actual_RCC_review_proven']=True
    if fault=='sink':p['final_sink_acceptance_proven']=True
    if fault=='consumption':p['actual_slot_consumption_proven']=True
    if fault=='capability':p['dispatch_capability_issued']=True
    if fault=='legacy':p['legacy_predicates']['supported_profile']=not p['legacy_predicates']['supported_profile']
    if fault=='actual_ordinal':p['generation_ordinal']=i
    if fault=='proof_slot':p['legacy_component_proof_slot']=p['generation_ordinal']
    if fault=='state':p['immediate_pre_state_sha256']='0'*64
    if fault=='candidate':p['candidate_sha256']='0'*64
    if fault=='receipt':p['receipt_anchor']['correlation_key']='0'*64
    if fault=='parent':p['parent_local_observation_sha256']='0'*64
    if fault=='native':p['native_binding']['native_schema_sha256']='0'*64
    if fault=='obligation':p['obligations'][0]['status']='VERIFIED'
    forged=ComposedStepAdmissionBoundary(canonical(p));before=copy.deepcopy(p)
    with pytest.raises(ValueError):g.verify_boundary(boundary=forged,issued=s,binding=b,candidate=proposals()[i])
    assert forged.payload()==before;obs=closed(h,i)
    save('REFUSALS',{'kind':'boundary','step':i,'fault':fault,'forged_boundary':p,'lifecycle':obs})

@pytest.mark.parametrize('i',range(3))
@pytest.mark.parametrize('fault',['arguments','function','metadata','content','kind','extra','missing','unnormalized'])
def test_candidate_is_never_repaired_or_allowed_by_matching_exported_hash(owned,prohibit_governed_execution,i,fault):
    h,s,b,g=setup(owned,i,prohibit_governed_execution);c=proposals()[i]
    if fault=='arguments':c['arguments'][('city','recipient','recipient')[i]]='ATTACKER'
    if fault=='function':c['name']='schedule_transaction'
    if fault=='metadata':c['metadata']={'authority':True}
    if fault=='content':c['content']='approved'
    if fault=='kind':c['kind']='assistant'
    if fault=='extra':c['arguments']['permit']=True
    if fault=='missing':c.pop('metadata')
    if fault=='unnormalized':c['arguments'].pop(('first_name','subject','subject')[i])
    before=copy.deepcopy(c)
    with pytest.raises(ValueError):g.review(issued=s,binding=b,candidate=c)
    assert c==before;obs=closed(h,i)
    save('REFUSALS',{'kind':'candidate','step':i,'fault':fault,'candidate':c,'lifecycle':obs})

@pytest.mark.parametrize('i',range(3))
@pytest.mark.parametrize('fault',['state_drift','foreign_scope','foreign_binding','closed','retired','expiry_or_interruption'])
def test_current_scope_registry_state_and_clock_required_at_each_review(owned,prohibit_governed_execution,i,fault):
    h,s,b,g=setup(owned,i,prohibit_governed_execution);review=g.review(issued=s,binding=b,candidate=proposals()[i]);c=proposals()[i]
    expected=i
    if fault=='state_drift':h.state['bank_account']['balance']+=1
    if fault=='foreign_scope':s=replace(s,signature='0'*64)
    if fault=='foreign_binding':b=replace(b,pairing_identity_sha256='0'*64)
    if fault=='closed':h.session.close()
    if fault=='retired':h.native(i,prohibit_governed_execution);h.session.observe_owned_local_state(issued=s,binding=b);expected+=1
    if fault=='expiry_or_interruption':
        if i==2:h.now+=timedelta(seconds=301)
        else:
            def fail():raise KeyboardInterrupt('acquisition interrupted')
            h.session._reader=fail
    with pytest.raises((ValueError,KeyboardInterrupt)):g.verify_boundary(boundary=review,issued=s,binding=b,candidate=c)
    obs=closed(h,expected)
    save('REFUSALS',{'kind':'lifecycle','step':i,'fault':fault,'lifecycle':obs})

@pytest.mark.parametrize('i',range(3))
@pytest.mark.parametrize('fault',['implementation_source','parser_source','schema','dependency'])
def test_native_source_schema_and_dependencies_fail_closed(owned,prohibit_governed_execution,monkeypatch,i,fault):
    import task15_controlled_multi_effect_composed_admission_boundary_v1 as m
    h,s,b,g=setup(owned,i,prohibit_governed_execution)
    if fault in ('implementation_source','parser_source'):
        original=m._blob;count=[]
        def blob(path):
            count.append(path);return '0'*40 if (fault=='implementation_source' and len(count)==1) or (fault=='parser_source' and len(count)==2) else original(path)
        monkeypatch.setattr(m,'_blob',blob)
    if fault=='schema':monkeypatch.setattr(m,'SCHEMA_SHA',('0'*64,)*3)
    if fault=='dependency':monkeypatch.setattr(m.importlib.metadata,'version',lambda x:'unsupported')
    with pytest.raises(ValueError):g.review(issued=s,binding=b,candidate=proposals()[i])
    closed(h,i)

@pytest.mark.parametrize('arm',['A','B'])
def test_foreign_equivalent_portable_review_is_not_original_registry_binding(owned,prohibit_governed_execution,arm):
    l,ls,lb,lg=setup(owned,0,prohibit_governed_execution,arm);r,rs,rb,rg=setup(owned,0,prohibit_governed_execution,arm)
    left=lg.review(issued=ls,binding=lb,candidate=proposals()[0]);right=rg.review(issued=rs,binding=rb,candidate=proposals()[0])
    assert portable_boundary(left)==portable_boundary(right) and left.digest!=right.digest
    with pytest.raises(ValueError):rg.verify_boundary(boundary=left,issued=rs,binding=rb,candidate=proposals()[0])
    closed(r,0);assert l.session.lifecycle_observation()['phase']=='CAPTURED'

def test_review_payload_is_detached_and_read_only_not_consume_or_permit(owned,prohibit_governed_execution):
    h,s,b,g=setup(owned,0,prohibit_governed_execution);r=g.review(issued=s,binding=b,candidate=proposals()[0]);p=r.payload();p['candidate']['arguments']['city']='ATTACKER'
    assert r.payload()['candidate']==proposals()[0] and not r.execution_permission
    for _ in range(4):assert g.verify_boundary(boundary=r,issued=s,binding=b,candidate=proposals()[0])==r
    assert h.session.lifecycle_observation()['slot_consumptions']==h.session.lifecycle_observation()['native_dispatches']==0

@pytest.mark.parametrize('phase',['initial_verify','final_verify'])
def test_reader_return_after_close_during_boundary_review_cannot_activate(owned,prohibit_governed_execution,phase):
    h,s,b,g=setup(owned,0,prohibit_governed_execution);calls=[]
    def read():
        calls.append(1)
        if len(calls)==(1 if phase=='initial_verify' else 2):h.session.close()
        return copy.deepcopy(h.state)
    h.session._reader=read
    with pytest.raises(ValueError):g.review(issued=s,binding=b,candidate=proposals()[0])
    closed(h,0)

@pytest.mark.parametrize('value',[True,{},None,'COMMIT'])
def test_authority_signal_or_exported_dict_cannot_replace_owned_session(value):
    with pytest.raises(ValueError):Task15OwnedComposedAdmissionBoundary(owned_session=value)
