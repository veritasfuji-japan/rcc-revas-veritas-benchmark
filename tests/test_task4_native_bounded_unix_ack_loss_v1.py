"""Portable negative coverage for the new fault-report and signed-view boundary."""
import copy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import task4_native_bounded_unix_ack_loss_v1 as f


def test_frozen_normal_and_fault_integration_sources_match():
    assert f.sources()['normal']['profile']==f.NORMAL_PIN
    assert len(f.sources()['normal']['frozen'])==15
    assert f.FAULTS==('api-reserve-ack-lost','tls-consume-ack-lost')


@pytest.mark.parametrize('mode',['','wrong',True,None,'tls-consume-ack-lost;'])
def test_unknown_fault_refuses_before_root(monkeypatch,mode):
    monkeypatch.setattr(f.e,'require_root',lambda:pytest.fail('root before fault'))
    with pytest.raises(ValueError):f.run(Path('/tmp/unused'),mode,True)


@pytest.mark.parametrize('mode',f.FAULTS)
def test_no_ack_refuses_before_root(monkeypatch,mode):
    monkeypatch.setattr(f.e,'require_root',lambda:pytest.fail('root before ack'))
    with pytest.raises(ValueError):f.run(Path('/tmp/unused'),mode)


def test_no_live_remote_raw_response_or_repair_claims():
    limits=f.limits()
    assert limits['raw_backend_response_loss_tested'] is False
    assert limits['real_provider_completion_loss_tested'] is False
    assert limits['repair_or_retry_permission_issued'] is False
    assert limits['real_provider_posts']==0 and limits['provider_dispatch']=='DENY'
    assert limits['operator_vm_trial_executed'] is limits['production_bypass_resistance_proven'] is False


@pytest.fixture
def signed_views(monkeypatch):
    key=Ed25519PrivateKey.generate();pin='c'*64
    binding=dict(schema=f.contract.SCHEMA,ledger_id='1'*64,run_id='2'*64,manifest_sha256='3'*64,
                 issuer_public_sha256='4'*64,custody_public_sha256='5'*64)
    enrollment=dict(binding=binding,service_public=key.public_key().public_bytes_raw().hex(),
                    github_mtls=dict(peers=dict(issuer=dict(certificate_sha256=pin))))
    snapshot=dict(revision=1,attempts=[dict(operation_id='A0',state='RESERVED',request_sha256='6'*64,grant_sha256=None)])
    namespace=dict(device=4,inode=123)
    rows=[];events=[];commits={}
    for i in (1,2):
        nonce=str(i)*64;oid='commit'+str(i)
        command=dict(schema=f.contract.SCHEMA,binding_sha256=f.contract.digest(binding),nonce=nonce,action='view',
                     expected_revision=None,operation_id=None,request_sha256=None,grant_sha256=None)
        statement=dict(schema=f.contract.SCHEMA,ledger_id=binding['ledger_id'],binding_sha256=f.contract.digest(binding),
                       command_sha256=f.contract.digest(command),nonce=nonce,action='view',snapshot=snapshot)
        receipt=dict(statement=statement,signature=key.sign(f.contract.DOMAIN+f.contract.canonical(statement)).hex())
        rows.append(dict(uid=f.n.ISSUER,namespace=namespace,exchange=dict(command=command,receipt=receipt),snapshot=snapshot))
        events.extend([['mtls',f.n.ISSUER,pin,'TLSv1.3',f.contract.digest(command)],['sign',oid,nonce,'view',1]])
        commits[oid]=dict(state=dict(runs={binding['run_id']:dict(snapshot=snapshot)}))
    # Unit fixture only: the complete model validator is exercised by mandatory root CI.
    monkeypatch.setattr(f.github,'validate_model',lambda a,p:commits)
    return rows,enrollment,dict(events=events),snapshot,namespace,key


def test_two_actual_ed25519_view_signatures_and_nonce_joins(signed_views):
    rows,a,model,snapshot,namespace,_=signed_views
    assert f.validate_views(rows,a,model,snapshot,namespace) is True


@pytest.mark.parametrize('fault',['signature','command','command_binding','uid','namespace','snapshot','nonce','auth_uid','auth_pin','tls_version','missing_sign','duplicate_nonce'])
def test_altered_signed_view_evidence_is_refused(signed_views,fault):
    rows,a,model,snapshot,namespace,key=signed_views
    rows=copy.deepcopy(rows);model=copy.deepcopy(model)
    pair=rows[0]['exchange']
    if fault=='signature':pair['receipt']['signature']='00'*64
    elif fault=='command':pair['command']['nonce']='a'*64
    elif fault=='command_binding':
        pair['command']['binding_sha256']='a'*64
        pair['receipt']['statement']['command_sha256']=f.contract.digest(pair['command'])
        pair['receipt']['signature']=key.sign(f.contract.DOMAIN+f.contract.canonical(pair['receipt']['statement'])).hex()
        model['events'][0][-1]=f.contract.digest(pair['command'])
    elif fault=='uid':rows[0]['uid']=0
    elif fault=='namespace':rows[0]['namespace']=dict(device=4,inode=999)
    elif fault=='snapshot':rows[0]['snapshot']=dict(revision=0,attempts=[])
    elif fault=='nonce':
        pair['receipt']['statement']['nonce']='a'*64
        pair['receipt']['signature']=key.sign(f.contract.DOMAIN+f.contract.canonical(pair['receipt']['statement'])).hex()
    elif fault=='auth_uid':model['events'][0][1]=61104
    elif fault=='auth_pin':model['events'][0][2]='0'*64
    elif fault=='tls_version':model['events'][0][3]='TLSv1'
    elif fault=='missing_sign':model['events'].pop(1)
    else:rows[1]=copy.deepcopy(rows[0])
    with pytest.raises(Exception):f.validate_views(rows,a,model,snapshot,namespace)


def test_process_lifetime_is_distinct_from_recyclable_namespace_inode():
    identity=f.lifetime(1)
    assert f.validate_lifetime(identity)==(identity['supervisor_pid'],identity['supervisor_start_ticks'])


@pytest.mark.parametrize('fault',['bool_pid','zero_ticks','same_pid','extra','missing'])
def test_invalid_supervisor_lifetime_is_refused(fault):
    identity=dict(controller_pid=10,supervisor_pid=11,supervisor_start_ticks=123)
    if fault=='bool_pid':identity['supervisor_pid']=True
    elif fault=='zero_ticks':identity['supervisor_start_ticks']=0
    elif fault=='same_pid':identity['supervisor_pid']=10
    elif fault=='extra':identity['namespace_inode']=123
    else:del identity['supervisor_start_ticks']
    with pytest.raises(ValueError):f.validate_lifetime(identity)
