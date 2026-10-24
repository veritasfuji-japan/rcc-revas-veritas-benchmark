"""Retained API model + actual Native handlers; real socket cases run in CI."""
import copy
import json
import os
from pathlib import Path
import socket
import sqlite3
from threading import Thread

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import task4_native_github_mtls_v1 as m
from scripts import task4_native_signed_ledger_integration_v1 as s
from scripts import task4_native_signed_ledger_gate_v1 as g
from scripts import task4_native_bounded_continuation_v1 as b
from scripts import task4_native_os_custody_v1 as n
from test_task4_native_signed_ledger_integration_v1 import joined, enrolled

RealTransport=m.Transport


@pytest.fixture
def github(joined,monkeypatch):
    f=joined;base=f['base'];key=Ed25519PrivateKey.generate();public=key.public_key().public_bytes_raw()
    folder=base/'ledger';folder.mkdir(mode=0o700)
    (base/'ledger-ipc').mkdir(mode=0o755)
    (folder/'signing-key').write_bytes(key.private_bytes_raw());(folder/'signing-key').chmod(0o600)
    api=m.RetainedModelGitAPI.bootstrap(folder/m.MODEL,m.l.sha(public))
    a=f['a'];a['binding']['ledger_id']=m.signed.LEDGER_ID;a['service_public']=public.hex()
    for role,e in a['gates'].items():
        e['service_public_sha256']=m.l.sha(public)
        path=base/role/'signed-ledger'/g.ENROLLMENT_FILE;path.write_bytes(m.l.canonical(e));path.chmod(0o600)
    material,pins=m.certificate_material()
    for role in ('server','issuer','custody'):
        where=folder if role=='server' else base/role
        for name,data in material[role].items():
            path=where/name;path.write_bytes(data);path.chmod(0o600)
    a['github_mtls']=dict(schema=m.PROFILE,genesis=api.genesis,fault='',
        ca_sha256=m.l.sha(material['server']['mtls-ca.pem']),server_certificate_sha256=pins['server'],
        peers={role:dict(certificate_sha256=pins[role],authority_public_sha256=a['binding'][role+'_public_sha256'])
               for role in ('issuer','custody')})
    from scripts import task4_native_retained_authority_v1 as r
    a['ledger_storage']={name:r.identity(folder/name,os.geteuid(),0o600) for name in ('signing-key',m.MODEL)}
    def seal():
        path=s.DIRECTORY/'enrollment.json';path.chmod(0o600);path.write_bytes(m.l.canonical(a));path.chmod(0o444)
        path=base/s.LOCAL;path.chmod(0o600);path.write_bytes(m.l.canonical(dict(schema=s.SCHEMA,enrollment_sha256=m.l.digest(a))));path.chmod(0o444)
    seal()
    service=m.signed.SignedGitHubService(m.signed.GitState(api,api.genesis,api.signer),m.ReadbackWitness(key,api))
    service.enroll(a['binding'])
    f.update(api=api,remote_service=service,remote_key=key,public=public,seal=seal,calls=[])
    def transport(role):
        def exchange(raw):
            f['calls'].append((role,m.l.strict(raw)))
            return f['remote_service'].exchange(raw,a['binding'][role+'_public_sha256'])
        return exchange
    monkeypatch.setattr(m,'Transport',lambda base,a,role:transport(role))
    f['direct']=transport
    f['snapshot']=lambda:m.l.LedgerClient(a['binding'],public,transport('issuer')).exchange('view')
    return f


def test_native_signature_follows_exact_git_readback(github,monkeypatch):
    f=github;original=b.p.sign;seen=[]
    def sign(key,domain,statement):
        assert (f['slot']('issuer')/'verified-receipts.json').exists()
        events=f['api'].projection()['events']
        assert any(x[0]=='readback' and x[1]==f['api'].head for x in events)
        assert events[-1][0]=='sign' and events[-1][3]=='reserve'
        seen.append(1);return original(key,domain,statement)
    monkeypatch.setattr(b.p,'sign',sign)
    grant=f['policy'].authorize('A',f['wire'])
    assert seen==[1] and grant['statement']['request_sha256']==m.l.sha(f['wire'])
    assert f['snapshot']()['revision']==1


@pytest.mark.parametrize('fault',['timeout','bad-nonce','wrong-ref'])
def test_committed_api_ack_fault_never_issues_and_survives_reopen(github,monkeypatch,fault):
    f=github
    def damaged(reply):
        if fault=='timeout':raise TimeoutError('commit acknowledged nowhere')
        reply=copy.deepcopy(reply);result=reply['data']['createCommitOnBranch']
        if fault=='bad-nonce':result['clientMutationId']='0'*64
        else:result['ref']['target']['oid']='0'*40
        return reply
    f['api'].response_fault=damaged
    with pytest.raises(g.GateDenied):f['policy'].authorize('A',f['wire'])
    assert f['policy'].snapshot()['attempts']==[]
    assert f['snapshot']()['revision']==1
    api,service=m.reopen(f['base'],f['a'],f['remote_key']);f['remote_service']=service
    posts=sum(x[0]=='api' and x[1]=='POST' for x in api.projection()['events'])
    with pytest.raises(g.GateDenied):b.NativePolicy(f['policy'].file,f['m'],f['issuer']).authorize('A',f['wire'])
    assert sum(x[0]=='api' and x[1]=='POST' for x in api.projection()['events'])==posts==2
    assert not any(x[0]=='sign' and x[3]=='reserve' for x in api.projection()['events'])


def test_git_blob_readback_failure_stops_signing_after_commit(github,monkeypatch):
    f=github;call=f['api'].call;committed=[]
    def corrupt(method,path,value=None):
        result=call(method,path,value)
        if method=='POST':committed.append(True)
        elif committed and '/git/blobs/' in path:result=dict(result,content='e30=')
        return result
    monkeypatch.setattr(f['api'],'call',corrupt)
    with pytest.raises(g.GateDenied):f['policy'].authorize('A',f['wire'])
    assert f['policy'].snapshot()['attempts']==[]
    assert not any(x[0]=='sign' for x in f['api'].projection()['events'] if len(x)>3 and x[3]=='reserve')
    api,_=m.reopen(f['base'],f['a'],f['remote_key'])
    assert len(api.projection()['commits'])==3


def test_signed_consume_reply_loss_never_reaches_actual_bind_handler(github,monkeypatch):
    f=github;grant=f['policy'].authorize('A',f['wire']);effects=[]
    def transport(base,a,role):
        direct=f['direct'](role)
        def exchange(raw):
            reply=direct(raw)
            if m.l.strict(raw)['action']=='consume':raise ConnectionError('lost signed TLS response')
            return reply
        return exchange
    monkeypatch.setattr(m,'Transport',transport)
    monkeypatch.setattr(n,'bind_post',lambda *args:effects.append(1))
    with pytest.raises(g.GateDenied):f['consume'](grant)
    assert effects==[] and f['consumed']()==[] and f['snapshot']()['revision']==2
    _,f['remote_service']=m.reopen(f['base'],f['a'],f['remote_key'])
    calls=len(f['calls'])
    with pytest.raises(g.GateDenied):f['consume'](grant)
    assert len(f['calls'])==calls and effects==[]


def test_native_custody_bind_waits_for_git_commit_and_saved_consume_receipt(github,monkeypatch):
    f=github;grant=f['policy'].authorize('A',f['wire']);seen=[]
    monkeypatch.setattr(b.ingress,'consumed',lambda *args:None)
    def bind(*args):
        assert (f['slot']('custody')/'verified-receipts.json').exists()
        assert f['consumed']()==[('A0','CONSUMED_UNKNOWN')]
        snapshot=f['snapshot']();assert snapshot['revision']==2
        assert snapshot['attempts'][0]['grant_sha256']==m.l.digest(grant)
        seen.append(1);raise OSError('stop at actual Bind call')
    monkeypatch.setattr(n,'bind_post',bind)
    with pytest.raises(g.GateDenied):f['consume'](grant)
    assert seen==[1]
    assert f['consume'](grant)==dict(decision='REPLAY_DENIED')


@pytest.mark.parametrize('fault',['missing','corrupt','mode','replacement'])
def test_model_storage_is_reopen_only_and_never_repaired(github,fault):
    f=github;path=f['base']/'ledger'/m.MODEL
    if fault=='missing':path.unlink()
    elif fault=='corrupt':path.write_bytes(b'broken')
    elif fault=='mode':path.chmod(0o644)
    else:
        raw=path.read_bytes();path.rename(path.with_suffix('.saved'));path.write_bytes(raw);path.chmod(0o600)
    # Actual service startup also checks the root-enrolled inode, before loading.
    from scripts import task4_native_retained_authority_v1 as r
    with pytest.raises((ValueError,OSError,sqlite3.Error)):
        for value in f['a']['ledger_storage'].values():r.check_identity(value)
        m.reopen(f['base'],f['a'],f['remote_key'])
    if fault=='missing':assert not path.exists()
    elif fault=='corrupt':assert path.read_bytes()==b'broken'
    elif fault=='mode':assert path.stat().st_mode&0o777==0o644


@pytest.mark.parametrize('fault',['ca','certificate','key','mode','symlink'])
def test_tls_private_files_and_pins_are_required(github,fault):
    f=github;folder=f['base']/'issuer'
    if fault=='ca':(folder/'mtls-ca.pem').write_bytes(b'bad ca')
    elif fault=='certificate':(folder/'mtls-cert.pem').write_bytes((f['base']/'custody/mtls-cert.pem').read_bytes())
    elif fault=='key':(folder/'mtls-key.pem').write_bytes(b'bad key')
    elif fault=='mode':(folder/'mtls-key.pem').chmod(0o644)
    else:
        path=folder/'mtls-key.pem';path.rename(folder/'original.key');path.symlink_to(folder/'original.key')
    with pytest.raises((ValueError,OSError)):m.context(f['base'],f['a'],'issuer')
    assert f['calls']==[]


@pytest.mark.parametrize('fault',['genesis','ledger','peer','same-cert','extra'])
def test_root_model_tls_enrollment_cannot_be_substituted(github,fault):
    f=github;a=f['a']
    if fault=='genesis':a['github_mtls']['genesis']='invalid'
    elif fault=='ledger':a['binding']['ledger_id']='0'*64
    elif fault=='peer':a['github_mtls']['peers']['issuer']['authority_public_sha256']='0'*64
    elif fault=='same-cert':a['github_mtls']['server_certificate_sha256']=a['github_mtls']['peers']['issuer']['certificate_sha256']
    else:a['github_mtls']['extra']=True
    f['seal']()
    with pytest.raises(ValueError):f['policy'].authorize('A',f['wire'])
    assert f['calls']==[]


def test_two_model_objects_use_expected_head_cas_without_lost_update(github):
    f=github;other=m.RetainedModelGitAPI(f['base']/'ledger'/m.MODEL)
    one=m.signed.GitState(f['api'],f['api'].genesis,f['api'].signer)
    two=m.signed.GitState(other,other.genesis,other.signer)
    previous,state=one.read();stale,duplicate=two.read()
    row=state['runs'][f['a']['binding']['run_id']]
    row['snapshot']=dict(revision=1,attempts=[dict(operation_id='A0',request_sha256='0'*64,grant_sha256=None,state='RESERVED')]);state['revision']+=1
    one.mutate(previous,state)
    with pytest.raises(ValueError):two.mutate(stale,state)
    assert len(other.projection()['commits'])==3


def test_evidence_rejects_sign_event_without_readback(github):
    f=github;f['policy'].authorize('A',f['wire']);p=f['api'].projection()
    m.validate_model(f['a'],p)
    p['events']=[x for x in p['events'] if x[0]!='readback']
    with pytest.raises(ValueError,match='READBACK'):m.validate_model(f['a'],p)


@pytest.mark.parametrize('fault',['none','wrong-role-cert','no-client-cert'])
def test_real_mtls_checks_both_certificate_and_kernel_role(github,monkeypatch,fault):
    f=github
    try:server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    except PermissionError:pytest.skip('Execution host prohibits sockets; mandatory kernel CI requires this case without skips')
    monkeypatch.setattr(s,'LEDGER',os.geteuid())
    monkeypatch.setattr(b.kernel,'ISSUER',os.geteuid());monkeypatch.setattr(b.kernel,'CUSTODY',os.geteuid()+10000)
    ctx=m.context(f['base'],f['a'],'server');errors=[]
    with server:
        server.bind(str(f['base']/'ledger-ipc/service.sock'));server.listen(2);server.settimeout(10)
        def run():
            for _ in range(2 if fault=='none' else 1):
                conn,_=server.accept()
                with conn:
                    try:m.handle(f['base'],f['a'],f['api'],f['remote_service'],ctx,conn)
                    except Exception as error:errors.append(type(error).__name__)
        job=Thread(target=run);job.start()
        actual=RealTransport(f['base'],f['a'],'custody' if fault=='wrong-role-cert' else 'issuer')
        if fault=='no-client-cert':
            import ssl
            actual.context=ssl.create_default_context(cafile=str(f['base']/'issuer/mtls-ca.pem'))
        monkeypatch.setattr(m,'Transport',lambda *args:actual)
        try:
            if fault=='none':assert f['policy'].authorize('A',f['wire'])['statement']['ordinal']==0
            else:
                with pytest.raises(g.GateDenied):f['policy'].authorize('A',f['wire'])
        finally:job.join(10)
        assert not job.is_alive()
    events=f['api'].projection()['events']
    if fault=='none':assert not errors and len([x for x in events if x[0]=='mtls'])==2
    else:assert errors and not any(x[0]=='mtls' for x in events)
