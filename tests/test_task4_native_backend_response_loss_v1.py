"""Portable safety boundaries; actual separated-UID Native proof is mandatory CI."""
import copy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import task4_native_backend_response_loss_v1 as z


def test_existing_normal_ack_and_authority_sources_are_frozen():
    pins=z.sources()
    assert pins['acknowledgement_profile']['profile']==z.ACK_PIN
    assert len(pins['acknowledgement_profile']['normal']['frozen'])==15


def test_ack_required_before_root(monkeypatch):
    monkeypatch.setattr(z.e,'require_root',lambda:pytest.fail('root before ack'))
    with pytest.raises(ValueError):z.run(Path('/tmp/not-created'))


def test_one_unknown_row_without_result_is_required_for_reopen():
    assert z.validate_unknown_rows([['A0','CONSUMED_UNKNOWN','1'*64,None,None,None,None]],'1'*64)


@pytest.mark.parametrize('fault',['empty','duplicate','observed','other_op','wrong_request','known_response'])
def test_reopen_never_accepts_empty_completed_or_substituted_storage(fault):
    rows=[['A0','CONSUMED_UNKNOWN','1'*64,None,None,None,None]]
    if fault=='empty':rows=[]
    elif fault=='duplicate':rows*=2
    elif fault=='observed':rows[0][1]='MOCK_OBSERVED'
    elif fault=='other_op':rows[0][0]='A1'
    elif fault=='wrong_request':rows[0][2]='2'*64
    else:rows[0][3]='3'*64
    with pytest.raises(ValueError):z.validate_unknown_rows(rows,'1'*64)


@pytest.fixture
def committed_response(tmp_path,monkeypatch):
    wire=b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'
    q='1'*64;r='2'*64
    effect=['A0',q,r,z.n.digest(dict(operation_id='A0',request_sha256=q,response_sha256=r))]
    post=dict(op='A0',authorized=True,request_sha256=q,response_sha256=r,wire_sha256=z.e.sha(wire),wire_bytes=len(wire),
              path=z.ingress.raw.PATH,host=z.tls.NAME)
    writes=[]
    monkeypatch.setattr(z,'fixture',lambda _:None)
    monkeypatch.setattr(z.n.kernel,'role_identity',lambda uid:None)
    monkeypatch.setattr(z.u,'effects',lambda _: [effect])
    monkeypatch.setattr(z.u,'read_lines',lambda _: [post])
    monkeypatch.setattr(z.u,'append',lambda path,row:writes.append(row))
    return tmp_path,wire,effect,post,writes


def test_drop_boundary_requires_durable_effect_and_logs_no_forwarded_bytes(committed_response):
    base,wire,effect,post,writes=committed_response
    assert z.drop_committed_response(base,wire) is None
    assert len(writes)==1 and writes[0]['response_bytes_sent']==0 and writes[0]['produced_bytes']==len(wire)
    assert writes[0]['produced_wire_sha256']==post['wire_sha256']


@pytest.mark.parametrize('fault',['missing_effect','missing_post','wrong_wire','wrong_receipt','unauthorized','wrong_path','already_used'])
def test_drop_never_fabricates_a_successful_backend_witness(committed_response,monkeypatch,fault):
    base,wire,effect,post,writes=committed_response
    if fault=='missing_effect':monkeypatch.setattr(z.u,'effects',lambda _: [])
    elif fault=='missing_post':monkeypatch.setattr(z.u,'read_lines',lambda _: [])
    elif fault=='wrong_wire':wire=b'other'
    elif fault=='wrong_receipt':effect[3]='0'*64
    elif fault=='unauthorized':post['authorized']=False
    elif fault=='wrong_path':post['path']='/other'
    else:
        (base/'backend').mkdir();(base/'backend/response-loss.jsonl').write_text('used')
    with pytest.raises(ValueError):z.drop_committed_response(base,wire)
    assert writes==[]


@pytest.fixture
def gate_vectors():
    key=Ed25519PrivateKey.generate();binding=dict(schema=z.contract.SCHEMA,ledger_id='1'*64,run_id='2'*64,
        manifest_sha256='3'*64,issuer_public_sha256='4'*64,custody_public_sha256='5'*64)
    a=dict(binding=binding,service_public=key.public_key().public_bytes_raw().hex())
    q='6'*64;grant='7'*64
    rows={}
    for role,revision in [('issuer',1),('custody',2)]:
        g=None if role=='issuer' else grant;action='reserve' if role=='issuer' else 'consume'
        attempt=dict(operation_id='A0',request_sha256=q,grant_sha256=g,state='RESERVED' if role=='issuer' else 'CONSUMED_UNKNOWN')
        before=dict(revision=revision-1,attempts=[] if role=='issuer' else [dict(attempt,grant_sha256=None,state='RESERVED')])
        after=dict(revision=revision,attempts=[attempt]);pairs=[]
        for i,(command_action,snapshot) in enumerate([('view',before),(action,after)],1):
            c=dict(schema=z.contract.SCHEMA,binding_sha256=z.n.digest(binding),nonce=str(revision*2+i)*64,action=command_action,
                expected_revision=None if i==1 else revision-1,operation_id=None if i==1 else 'A0',
                request_sha256=None if i==1 else q,grant_sha256=None if i==1 else g)
            statement=dict(schema=z.contract.SCHEMA,ledger_id=binding['ledger_id'],binding_sha256=z.n.digest(binding),
                command_sha256=z.n.digest(c),nonce=c['nonce'],action=command_action,snapshot=snapshot)
            receipt=dict(statement=statement,signature=key.sign(z.contract.DOMAIN+z.contract.canonical(statement)).hex())
            pairs.append(dict(command=c,receipt=receipt))
        intent=dict(role=role,action=action,operation_id='A0',binding_sha256=z.n.digest(binding),request_sha256=q,grant_sha256=g)
        rows[role]={'intent.json':intent,'verified-receipts.json':dict(intent_sha256=z.n.digest(intent),exchanges=pairs,snapshot=after),
                    'effect-returned.json':dict(effect_returned=True,intent_sha256=z.n.digest(intent)) if role=='issuer' else None}
    return rows,a,q,grant


def test_verified_consume_ack_does_not_mean_effect_callback_returned(gate_vectors):
    rows,a,q,grant=gate_vectors
    assert len(z.verify_gate(rows['issuer'],a,'issuer',q,None))==2
    assert len(z.verify_gate(rows['custody'],a,'custody',q,grant))==2
    assert rows['custody']['verified-receipts.json'] is not None and rows['custody']['effect-returned.json'] is None


@pytest.mark.parametrize('fault',['signature','nonce','binding','grant','callback','revision'])
def test_changed_gate_receipt_or_callback_cannot_pass(gate_vectors,fault):
    rows,a,q,grant=gate_vectors;row=copy.deepcopy(rows['custody'])
    if fault=='signature':row['verified-receipts.json']['exchanges'][1]['receipt']['signature']='00'*64
    elif fault=='nonce':row['verified-receipts.json']['exchanges'][1]['command']['nonce']='a'*64
    elif fault=='binding':row['intent.json']['binding_sha256']='0'*64
    elif fault=='grant':grant='8'*64
    elif fault=='callback':row['effect-returned.json']=dict(effect_returned=True)
    else:row['verified-receipts.json']['snapshot']=dict(revision=3,attempts=[])
    with pytest.raises(Exception):z.verify_gate(row,a,'custody',q,grant)


def test_reconciliation_is_one_authenticated_get_and_issues_no_permission(monkeypatch,tmp_path):
    monkeypatch.setattr(z,'fixture',lambda _:None)
    monkeypatch.setattr(z.signed,'admit',lambda base,role:None)
    monkeypatch.setattr(z.os,'umask',lambda _:None)
    monkeypatch.setattr(z.retained,'regular',lambda *a:b'local-test-material')
    calls=[]
    def get(base,method,path,body,key):
        calls.append((method,path,body));return 200,dict(effect_count=1,operation_receipt='1'*64)
    monkeypatch.setattr(z.m,'status_call',get)
    result=z.reconcile(tmp_path)
    assert calls==[('GET','/status/A0',None)]
    assert result['permission_issued'] is result['mutation_attempted'] is False


def test_scope_covers_local_response_loss_without_claiming_live_or_backend_restart():
    limits=z.limits()
    assert limits['raw_backend_response_loss_tested'] is True
    assert limits['real_provider_completion_loss_tested'] is limits['backend_restart_tested'] is False
    assert limits['repair_or_retry_permission_issued'] is False
    assert limits['real_provider_posts']==0 and limits['provider_dispatch']=='DENY' and limits['utility']=='UNSCORED'
