import copy
import json
import ssl

import pytest

from scripts import task4_signed_github_ledger_v1 as s
from scripts import task4_signed_github_ledger_rehearsal_v1 as demo
from scripts import task4_external_ledger_mtls_v1 as mtls
from scripts.task4_external_ledger_contract_v1 import Denied, LedgerClient, OPERATIONS, canonical, digest, sha


@pytest.fixture
def store():
    return demo.setup()


def wire(b, action, revision=None, op=None, request=None, grant=None):
    return canonical(dict(schema=s.SCHEMA, binding_sha256=digest(b), nonce='f'*64, action=action,
        expected_revision=revision, operation_id=op, request_sha256=request, grant_sha256=grant))


def client(store, role):
    api, backend, service, witness, b=store
    return LedgerClient(b, witness.public_key().public_bytes_raw(),
                        lambda data: service.exchange(data,b[role+'_public_sha256']))


REQ, GRANT=sha(b'request'),sha(b'grant')


def test_all_eight_slots_signed_after_exact_readback(store):
    api, backend, service, witness, b=store
    issuer,custody=client(store,'issuer'),client(store,'custody');effects=[]
    for op in sorted(OPERATIONS):
        issuer.gate('reserve',op,REQ,lambda _: effects.append('issue'))
        custody.gate('consume',op,REQ,lambda _: effects.append('send'),GRANT)
    _,state=backend.read();snapshot=state['runs'][b['run_id']]['snapshot']
    assert snapshot['revision']==16 and len(snapshot['attempts'])==8 and state['revision']==17
    assert effects.count('issue')==effects.count('send')==8
    for i,(event,oid) in enumerate(api.events):
        if event=='sign':
            assert ('readback',oid) in api.events[:i]
    assert json.loads(witness.signatures[-1].split(s.DOMAIN,1)[1])['snapshot']['revision']==16


@pytest.mark.parametrize('fault',['timeout','partial','null','errors','nonce','parent','ref','oid','readback'])
def test_committed_but_unverified_mutation_never_signed_or_retried(store,fault):
    api,backend,service,witness,b=store
    client(store,'issuer').gate('reserve','A0',REQ,lambda _:None)
    before=len(witness.signatures);posts=len([c for c in api.calls if c[0]=='POST'])
    original=backend.document
    def broken(reply):
        if fault=='timeout':raise TimeoutError()
        if fault=='partial':return {}
        if fault=='null':return dict(data=None)
        if fault=='errors':return dict(errors=[dict(type='ERROR')],data=reply['data'])
        mutation=reply['data']['createCommitOnBranch']
        if fault=='nonce':mutation['clientMutationId']='0'*64
        if fault=='parent':mutation['commit']['parents']['nodes']=[]
        if fault=='ref':mutation['ref']['name']='main'
        if fault=='oid':mutation['commit']['oid']='not-an-oid'
        if fault=='readback':
            def changed(oid):
                value,parents=original(oid)
                if oid==api.head:value['revision']+=1
                return value,parents
            backend.document=changed
        return reply
    api.response_fault=broken
    with pytest.raises(Denied):
        service.exchange(wire(b,'consume',1,'A0',REQ,GRANT),b['custody_public_sha256'])
    assert len(witness.signatures)==before
    assert len([c for c in api.calls if c[0]=='POST'])==posts+1
    backend.document=original;api.response_fault=None
    assert backend.read()[1]['runs'][b['run_id']]['snapshot']['attempts'][0]['state']=='CONSUMED_UNKNOWN'
    with pytest.raises(Denied):
        client(store,'custody').gate('consume','A0',REQ,lambda _:pytest.fail('replay'),GRANT)
    assert len([c for c in api.calls if c[0]=='POST'])==posts+1


@pytest.mark.parametrize('role,action',[('issuer','consume'),('custody','reserve'),('foreign','view')])
def test_roles_reject_before_backend_mutation_or_signature(store,role,action):
    api,backend,service,witness,b=store
    before=len(witness.signatures);posts=sum(c[0]=='POST' for c in api.calls)
    peer=b.get(role+'_public_sha256','0'*64)
    with pytest.raises(Denied):
        service.exchange(wire(b,action,None if action=='view' else 0,None if action=='view' else 'A0',
                             None if action=='view' else REQ,GRANT if action=='consume' else None),peer)
    assert len(witness.signatures)==before and sum(c[0]=='POST' for c in api.calls)==posts


@pytest.mark.parametrize('change',['manifest_sha256','issuer_public_sha256','custody_public_sha256'])
def test_duplicate_run_id_cannot_reset_by_changing_binding(store,change):
    api,backend,service,witness,b=store
    other=copy.deepcopy(b);other[change]='d'*64
    before=api.head
    with pytest.raises(Denied):service.enroll(other)
    assert api.head==before


def test_other_runs_and_prior_consumption_preserved(store):
    api,backend,service,witness,b=store
    client(store,'issuer').gate('reserve','A0',REQ,lambda _:None)
    client(store,'custody').gate('consume','A0',REQ,lambda _:None,GRANT)
    old=copy.deepcopy(backend.read()[1]['runs'][b['run_id']])
    another=copy.deepcopy(b);another['run_id']='e'*64
    service.enroll(another)
    assert backend.read()[1]['runs'][b['run_id']]==old


def test_stale_expected_head_stops_without_signing(store):
    api,backend,service,witness,b=store
    prior=backend.read
    def stale():
        head,state=prior()
        api.add(state,head) # competing trusted writer advances ref
        return head,state
    backend.read=stale;before=len(witness.signatures)
    with pytest.raises(Denied):service.exchange(wire(b,'reserve',0,'A0',REQ),b['issuer_public_sha256'])
    assert len(witness.signatures)==before
    assert prior()[1]['runs'][b['run_id']]['snapshot']['revision']==0


@pytest.mark.parametrize('fault',['binding','revision','operation','request','unknown_field','client_enroll'])
def test_bad_client_command_cannot_sign(store,fault):
    api,backend,service,witness,b=store
    value=json.loads(wire(b,'reserve',0,'A0',REQ))
    if fault=='binding':value['binding_sha256']='0'*64
    if fault=='revision':value['expected_revision']=1
    if fault=='operation':value['operation_id']='C0'
    if fault=='request':value['request_sha256']='invalid'
    if fault=='unknown_field':value['role']='custody'
    if fault=='client_enroll':value['action']='enroll'
    before=len(witness.signatures);head=api.head
    with pytest.raises(Denied):service.exchange(canonical(value),b['issuer_public_sha256'])
    assert len(witness.signatures)==before and api.head==head


@pytest.mark.parametrize('fault',['schema','signer','revision','run_binding','snapshot','oversize'])
def test_corrupt_registry_never_signed(store,fault):
    api,backend,service,witness,b=store
    state=copy.deepcopy(api.commits[api.head]['state'])
    if fault=='schema':state['schema']='other'
    if fault=='signer':state['service_public_sha256']='0'*64
    if fault=='revision':state['revision']+=1
    if fault=='run_binding':state['runs'][b['run_id']]['binding']['run_id']='0'*64
    if fault=='snapshot':state['runs'][b['run_id']]['snapshot']['revision']=1
    if fault=='oversize':state['runs']['x'*70000]={}
    api.add(state,api.head);before=len(witness.signatures)
    with pytest.raises(Denied):service.exchange(wire(b,'view'),b['issuer_public_sha256'])
    assert len(witness.signatures)==before


def test_registry_capacity_stops_without_pruning(store):
    api,backend,service,witness,b=store
    for i in range(31):
        another=copy.deepcopy(b);another['run_id']=sha(str(i).encode());service.enroll(another)
    before=api.head;another=copy.deepcopy(b);another['run_id']='e'*64
    with pytest.raises(Denied):service.enroll(another)
    assert api.head==before and len(backend.read()[1]['runs'])==32


@pytest.mark.parametrize('fault',['missing_ref','wrong_ref','wrong_blob_hash','extra_file','bad_ancestry','root_parent'])
def test_backend_identity_and_integrity_failure_prevents_signing(store,fault):
    api,backend,service,witness,b=store
    original=api.call
    def tamper(method,path,value=None):
        result=original(method,path,value)
        if fault=='missing_ref' and '/git/ref/' in path:raise FileNotFoundError()
        if fault=='wrong_ref' and '/git/ref/' in path:result['ref']='refs/heads/main'
        if fault=='wrong_blob_hash' and '/git/blobs/' in path:result['content']='e30='
        if fault=='extra_file' and '/git/trees/' in path:result['tree']*=2
        if fault=='bad_ancestry' and '/compare/' in path:result['status']='diverged'
        if fault=='root_parent' and path.endswith('/git/commits/'+api.genesis):result['parents']=[dict(sha='a'*40)]
        return result
    api.call=tamper;before=len(witness.signatures)
    with pytest.raises(Denied):service.exchange(wire(b,'view'),b['issuer_public_sha256'])
    assert len(witness.signatures)==before


def test_no_default_backend_and_no_silent_new_signer(store):
    with pytest.raises(Denied):s.GitState()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    with pytest.raises(Denied):s.SignedGitHubService(store[1],Ed25519PrivateKey.generate())


def test_listener_rejects_tls_without_client_auth():
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with pytest.raises(Denied):mtls.listener(None,context,{'a'*64:'b'*64,'c'*64:'d'*64})


def test_actual_mtls_to_signed_backend_model_and_uncertain_commit():
    report=demo.rehearsal()
    assert len(report['checks'])==7 and all(report['checks'].values())
    assert report['remote_github_experiment_executed'] is False
