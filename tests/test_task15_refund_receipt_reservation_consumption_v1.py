"""Shared-key exclusion, exact bearer ownership and terminal consumption states."""
import copy,json,os
from dataclasses import asdict,replace
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pytest
if os.environ.get('TASK15_REFUND_RECEIPT_STORE_PROOF')!='1':
    pytest.skip('Requires pinned refund receipt store proof',allow_module_level=True)
from test_task15_standing_order_original_request_authority_design_v1 import no_provider_scorer_or_external_effect
from test_task15_refund_original_request_authority_design_v1 import owned,candidate
from test_task15_refund_execution_metadata_authority_design_v1 import draft,NOW,SUBJECT
from test_task15_refund_receipt_correlation_and_duplicate_authority_design_v1 import slot
from task15_refund_prospective_execution_authority_profile_v1 import ControlledRefundAuthorityIssuer
from task15_refund_receipt_reservation_consumption_v1 import *
from agentdojo.functions_runtime import FunctionsRuntime,make_function
from agentdojo.default_suites.v1.tools.banking_client import send_money

@pytest.fixture(autouse=True)
def no_native_sink(monkeypatch):
    def forbidden(*a,**kw):pytest.fail('Receipt store reached native dispatch')
    monkeypatch.setattr(FunctionsRuntime,'run_function',forbidden)
def scope(o):return {**o,'policy_draft':draft(o),'slot_draft':slot(o)}
def issuer(sc,clock=None):
    return ControlledRefundAuthorityIssuer(root_id='owned-refund-root-v1',principal_id='fixture-requester',
        owned_clock=(lambda:NOW) if clock is None else clock,**sc)
def prepared(sc,clock=None,c=None):
    s=issuer(sc,clock);c=candidate(subject=SUBJECT) if c is None else c
    p,b=s.capture_from_generator(generate_candidate=lambda:c)
    return s,dict(profile=p,binding=b,candidate=c,**sc)
def setup(sc,clock=None):
    s,args=prepared(sc,clock);store=OwnedRefundReceiptStore(owned_verifiers=[s.verifier]);r=store.reserve(**args)
    return s,args,store,r
def closed(o):
    for k in ('execution_permission','native_dispatch_authorized','runtime_admission_activated','effect_authenticated',
              'no_effect_authenticated','durable_global_duplicate_exclusion','restart_persistence_proven','RCC_Bind_final_sink_integration_proven','slot_retry_allowed'):
        assert o[k] is False
    assert o['native_dispatches']==0 and o['reservations']==1 and o['consumptions']<=1
def save(var,row):
    if os.environ.get(var):
        with Path(os.environ[var]).open('a') as f:f.write(json.dumps(row,sort_keys=True)+'\n')

def test_reserve_consume_unknown_note_preserves_exact_receipt_and_no_permission(owned):
    sc=scope(owned);before=copy.deepcopy(sc);s,args,store,r=setup(sc);observations=[store.observe(reservation=r)]
    observations.append(store.consume_before_dispatch(reservation=r,**args))
    observations.append(store.mark_unknown(reservation=r))
    observations.append(store.record_reconciliation_note(reservation=r,note_sha256='a'*64))
    assert [x['state'] for x in observations]==['RESERVED','CONSUMED','UNKNOWN','UNKNOWN']
    for o in observations:closed(o)
    assert observations[-1]['consumptions']==1 and observations[-1]['reconciliation_notes']==['a'*64]
    assert observations[-1]['local_store_slot_consumed'] and r.execution_permission is False and sc==before
    path=os.environ.get('TASK15_REFUND_RECEIPT_STORE_EVIDENCE')
    if path:
        Path(path).write_text(json.dumps({'owned_input':{**sc,'envelope':asdict(sc['envelope'])},
            'reviewed_at_utc':NOW.strftime('%Y-%m-%dT%H:%M:%SZ'),'root_pin':asdict(s.root_pin),
            'profile':asdict(args['profile']),'binding':asdict(args['binding']),'candidate':args['candidate'],
            'reservation':asdict(r),'observations':observations,'native_schema':make_function(send_money).parameters.model_json_schema()},sort_keys=True)+'\n')

@pytest.mark.parametrize('state',['RESERVED','CONSUMED','UNKNOWN','CLOSED_BEFORE_CONSUMPTION'])
@pytest.mark.parametrize('fault',['fresh_root','request','case','balance','file','receipt_subject','amount_and_request'])
def test_mutable_scope_or_fresh_configured_issuer_cannot_reset_shared_receipt_key(owned,state,fault):
    sc=scope(owned);other=copy.deepcopy(owned)
    if fault=='request':e=other['envelope'];other['envelope']=type(e)(e.suite,15,e.instruction.replace('10.00','10.0'))
    if fault=='case':other['case_id']+='another'
    if fault=='balance':other['trusted_prestate']['bank_account']['balance']+=1
    if fault=='file':other['trusted_prestate']['filesystem']['files']['notes.txt']='changed'
    if fault=='receipt_subject':other['trusted_prestate']['bank_account']['transactions'][-1]['subject']='changed'
    if fault=='amount_and_request':
        other['trusted_prestate']['bank_account']['transactions'][-1]['amount']=20.0
        e=other['envelope'];other['envelope']=type(e)(e.suite,15,e.instruction.replace('10.00','20.00'))
    sc2=scope(other);c2=candidate(subject=SUBJECT,amount=20.0) if fault=='amount_and_request' else candidate(subject=SUBJECT)
    one,a=prepared(sc);two,b=prepared(sc2,c=c2);store=OwnedRefundReceiptStore(owned_verifiers=[one.verifier,two.verifier])
    r=store.reserve(**a)
    if state in {'CONSUMED','UNKNOWN'}:store.consume_before_dispatch(reservation=r,**a)
    if state=='UNKNOWN':store.mark_unknown(reservation=r)
    if state=='CLOSED_BEFORE_CONSUMPTION':store.close_before_consumption(reservation=r)
    before=store.observe(reservation=r)
    assert one.root_pin.payload()['boundary_sha256']!=two.root_pin.payload()['boundary_sha256'] or fault=='fresh_root'
    with pytest.raises(RefundReceiptStoreViolation):store.reserve(**b)
    assert store.observe(reservation=r)==before;closed(before)
    save('TASK15_REFUND_RECEIPT_STORE_DUPLICATES',{'state':state,'fault':fault,'correlation_key':r.payload()['correlation_key'],
        'old_receipt_sha256':r.payload()['receipt_sha256'],'new_receipt_sha256':b['profile'].payload()['boundary']['bindings']['receipt_sha256'],
        'duplicate_refused':True,'observation':before})

@pytest.mark.parametrize('fault',['nonce','key','fingerprint','root','candidate','extra','wrong_type','foreign_store'])
def test_forged_or_foreign_reservation_cannot_close_or_consume_owned_slot(owned,fault):
    sc=scope(owned);s,args,store,r=setup(sc);bad=r;v=r.payload()
    if fault=='nonce':bad=replace(r,nonce='0'*64)
    if fault=='key':v['correlation_key']='0'*64
    if fault=='fingerprint':v['receipt_sha256']='0'*64
    if fault=='root':v['root_pin_sha256']='0'*64
    if fault=='candidate':v['candidate_sha256']='0'*64
    if fault=='extra':v['verified']=True
    if fault in {'key','fingerprint','root','candidate','extra'}:bad=replace(r,payload_json=canonical(v))
    if fault=='wrong_type':bad={'verified':True}
    if fault=='foreign_store':bad=OwnedRefundReceiptStore(owned_verifiers=[s.verifier]).reserve(**args)
    before=store.observe(reservation=r)
    with pytest.raises(RefundReceiptStoreViolation):store.consume_before_dispatch(reservation=bad,**args)
    assert store.observe(reservation=r)==before
    closed(store.consume_before_dispatch(reservation=r,**args))

@pytest.mark.parametrize('fault',['candidate','binding','request','state','receipt','expiry','rollback','revocation','clock_exception'])
def test_current_authenticated_recheck_failure_closes_slot_before_consumption(owned,fault):
    sc=scope(owned);clock=[NOW]
    def now():
        if clock[0]=='failure':raise RuntimeError('owned clock failure')
        return clock[0]
    s,args,store,r=setup(sc,now)
    if fault=='candidate':args['candidate']=candidate(subject='changed')
    if fault=='binding':args['binding']=replace(args['binding'],candidate_sha256='0'*64)
    if fault=='request':e=args['envelope'];args['envelope']=type(e)(e.suite,15,e.instruction.replace('10.00','10.0'))
    if fault=='state':args['trusted_prestate']['bank_account']['balance']+=1
    if fault=='receipt':args['trusted_prestate']['bank_account']['transactions'][-1]['subject']='changed'
    if fault=='expiry':clock[0]=NOW.replace(minute=5,second=0)
    if fault=='rollback':clock[0]=NOW-timedelta(seconds=1)
    if fault=='revocation':s.revoke(profile=args['profile'])
    if fault=='clock_exception':clock[0]='failure'
    with pytest.raises((ValueError,RuntimeError)):store.consume_before_dispatch(reservation=r,**args)
    o=store.observe(reservation=r);assert o['state']=='CLOSED_BEFORE_CONSUMPTION' and o['consumptions']==0;closed(o)
    with pytest.raises(RefundReceiptStoreViolation):store.consume_before_dispatch(reservation=r,**args)
    save('TASK15_REFUND_RECEIPT_STORE_REFUSALS',{'fault':fault,'observation':o})

@pytest.mark.parametrize('state',['RESERVED','CONSUMED','UNKNOWN','CLOSED_BEFORE_CONSUMPTION'])
def test_state_machine_rejects_reset_replay_or_reclassifying_consumed_as_preconsume(owned,state):
    sc=scope(owned);s,args,store,r=setup(sc)
    if state in {'CONSUMED','UNKNOWN'}:store.consume_before_dispatch(reservation=r,**args)
    if state=='UNKNOWN':store.mark_unknown(reservation=r)
    if state=='CLOSED_BEFORE_CONSUMPTION':store.close_before_consumption(reservation=r)
    before=store.observe(reservation=r)
    if state!='RESERVED':
        with pytest.raises(RefundReceiptStoreViolation):store.consume_before_dispatch(reservation=r,**args)
        with pytest.raises(RefundReceiptStoreViolation):store.close_before_consumption(reservation=r)
    if state!='CONSUMED':
        with pytest.raises(RefundReceiptStoreViolation):store.mark_unknown(reservation=r)
    if state!='UNKNOWN':
        with pytest.raises(RefundReceiptStoreViolation):store.record_reconciliation_note(reservation=r,note_sha256='a'*64)
    for method in ('release','reset','retry','reissue','mark_no_effect','dispatch'):
        assert not hasattr(store,method)
    assert store.observe(reservation=r)==before

@pytest.mark.parametrize('note',[True,None,'approved','A'*64,{'verified':True,'outcome':'NO_EFFECT'}])
def test_reconciliation_claims_cannot_become_authenticated_effect_or_release(owned,note):
    sc=scope(owned);s,args,store,r=setup(sc);store.consume_before_dispatch(reservation=r,**args);store.mark_unknown(reservation=r)
    before=store.observe(reservation=r)
    with pytest.raises(RefundReceiptStoreViolation):store.record_reconciliation_note(reservation=r,note_sha256=note)
    assert store.observe(reservation=r)==before

def test_note_limit_duplicate_and_return_value_mutation_do_not_change_store_state(owned):
    sc=scope(owned);s,args,store,r=setup(sc);store.consume_before_dispatch(reservation=r,**args);store.mark_unknown(reservation=r)
    for i in range(16):o=store.record_reconciliation_note(reservation=r,note_sha256=f'{i:064x}')
    o['events'].clear();o['reconciliation_notes'].clear();o['state']='AVAILABLE'
    with pytest.raises(RefundReceiptStoreViolation):store.record_reconciliation_note(reservation=r,note_sha256='a'*64)
    with pytest.raises(RefundReceiptStoreViolation):store.record_reconciliation_note(reservation=r,note_sha256='0'*64)
    assert store.observe(reservation=r)['state']=='UNKNOWN' and len(store.observe(reservation=r)['reconciliation_notes'])==16

@pytest.mark.parametrize('operation',['reserve','consume','consume_vs_close'])
def test_parallel_shared_key_or_consumption_has_one_winner(owned,operation):
    sc=scope(owned)
    if operation=='reserve':
        pairs=[prepared(sc) for _ in range(32)];store=OwnedRefundReceiptStore(owned_verifiers=[s.verifier for s,a in pairs]);tokens=[]
    else:
        s,args,store,r=setup(sc);pairs=[(s,args)]*32
    def attempt(i):
        try:
            if operation=='reserve':tokens.append(store.reserve(**pairs[i][1]))
            elif operation=='consume':store.consume_before_dispatch(reservation=r,**args)
            elif i%2:store.close_before_consumption(reservation=r)
            else:store.consume_before_dispatch(reservation=r,**args)
            return True
        except RefundReceiptStoreViolation:return False
    with ThreadPoolExecutor(max_workers=16) as pool:results=list(pool.map(attempt,range(32)))
    assert sum(results)==1
    if operation=='reserve':r=tokens[0]
    o=store.observe(reservation=r);closed(o)
    assert o['state'] in {'CONSUMED','CLOSED_BEFORE_CONSUMPTION'} if operation=='consume_vs_close' else o['state']==('RESERVED' if operation=='reserve' else 'CONSUMED')
    save('TASK15_REFUND_RECEIPT_STORE_PARALLEL',{'operation':operation,'attempts':32,'winners':1,'rejected':31,
        'reservations':1,'consumptions':o['consumptions'],'state':o['state'],'native_dispatches':0})

@pytest.mark.parametrize('configuration',[[],True,[True]])
def test_unowned_configuration_cannot_be_supplied_as_verified_bool(configuration):
    with pytest.raises(RefundReceiptStoreViolation):OwnedRefundReceiptStore(owned_verifiers=configuration)

def test_duplicate_root_configuration_is_rejected(owned):
    s=issuer(scope(owned))
    with pytest.raises(RefundReceiptStoreViolation):OwnedRefundReceiptStore(owned_verifiers=[s.verifier,s.verifier])

def test_unconfigured_root_cannot_reserve_or_invalidate_owned_store(owned):
    sc=scope(owned);s,args,store,r=setup(sc);foreign,bad=prepared(sc)
    with pytest.raises(RefundReceiptStoreViolation):store.reserve(**bad)
    with pytest.raises(RefundReceiptStoreViolation):store.consume_before_dispatch(reservation=r,**bad)
    assert store.observe(reservation=r)['state']=='RESERVED';closed(store.consume_before_dispatch(reservation=r,**args))

def test_new_store_can_reuse_same_receipt_so_restart_or_durable_exclusion_is_unproven(owned):
    sc=scope(owned);s,args,one,r=setup(sc);one.consume_before_dispatch(reservation=r,**args)
    two=OwnedRefundReceiptStore(owned_verifiers=[s.verifier]);q=two.reserve(**args);closed(two.consume_before_dispatch(reservation=q,**args))
    assert one.observe(reservation=r)['durable_global_duplicate_exclusion'] is False

@pytest.mark.parametrize('change',['account','receipt'])
def test_distinct_typed_receipt_identity_is_not_collapsed_into_same_key(owned,change):
    sc=scope(owned);other=copy.deepcopy(owned)
    if change=='account':other['trusted_prestate']['bank_account']['iban']='GB82WEST12345698765432'
    else:other['trusted_prestate']['bank_account']['transactions'][-1]['id']=50
    two_sc=scope(other);one,a=prepared(sc);two,b=prepared(two_sc)
    store=OwnedRefundReceiptStore(owned_verifiers=[one.verifier,two.verifier]);r,q=store.reserve(**a),store.reserve(**b)
    assert r.payload()['correlation_key']!=q.payload()['correlation_key']
    closed(store.consume_before_dispatch(reservation=r,**a));closed(store.consume_before_dispatch(reservation=q,**b))

@pytest.mark.parametrize('name',['execution_permission','verified','scorer','gold'])
def test_extra_runtime_permit_or_authority_flags_cannot_enter_store_methods(owned,name):
    sc=scope(owned);s,args,store,r=setup(sc)
    with pytest.raises(RefundReceiptStoreViolation):store.consume_before_dispatch(reservation=r,**args,**{name:True})
    assert store.observe(reservation=r)['state']=='CLOSED_BEFORE_CONSUMPTION'
