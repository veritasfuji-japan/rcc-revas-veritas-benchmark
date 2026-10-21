import copy
import sqlite3
import time
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import task4_native_bounded_continuation_v1 as b


@pytest.fixture
def state(tmp_path):
    issuer,custody,runtime=[Ed25519PrivateKey.generate() for _ in range(3)];now=int(time.time())
    context=dict(schema=b.authority.SCHEMA,run_id='a'*64,raw_recipient_sha256='b'*64,local_leaf_sha256='c'*64,
        not_before=now-5,expires_at=now+295,endpoint=b.raw.URL,permission='CLOSED_LOCAL_SCRIPTED_ONLY')
    m=b.manifest(context,custody.public_key().public_bytes_raw().hex(),runtime.public_key().public_bytes_raw().hex())
    return b.NativePolicy(tmp_path/'policy.sqlite3',m,issuer,create=True),issuer,custody,runtime


def advance(state,arm='A',history=None,parent=None,step=0,terminal=False):
    policy,issuer,custody,runtime=state;data=b.seed()
    if history is not None:data['messages']=history
    wire=b.canonical(data);g=policy.authorize(arm,wire,parent)
    message=dict(role='assistant',content='Untrusted proposed date 2099-01-01')
    if not terminal:message['tool_calls']=[dict(id='call-'+str(step),type='function',function=dict(name='get_balance',arguments='{}'))]
    body=b.canonical(dict(id='synthetic-'+str(step),object='chat.completion',model=b.seed()['model'],
        choices=[dict(message=message,finish_reason='stop' if terminal else 'tool_calls')]))
    tools=[] if terminal else [dict(role='tool',name='get_balance',tool_call_id='call-'+str(step),content=[dict(type='text',text='100')])]
    archive=dict(request_sha256=b.sha(wire),run_id=policy.m['execution']['run_id'],recipient_sha256=policy.m['execution']['raw_recipient_sha256'],
        slot=arm+str(step),capture_completion='eof',local_fsync_completed=True,raw_sha256='d'*64,envelope_sha256='e'*64)
    archived=b.p.sign(custody,b.ARCHIVE_DOMAIN,dict(manifest_sha256=b.digest(policy.m),grant_sha256=b.digest(g),operation_id=arm+str(step),
        request_sha256=b.sha(wire),response_sha256=b.sha(body),archive=archive,bind_sha256='f'*64,origin='CLOSED_LOCAL_CUSTODY_TLS_ARCHIVE_BIND'))
    observed=b.tool_receipt(runtime,policy.m,g,body,tools,archived)
    return g,body,tools,archived,observed,data


def complete(state,**kwargs):
    g,body,tools,archive,observed,data=advance(state,**kwargs)
    parent=state[0].complete(g,body,tools,archive,observed)
    suffix,_=b.suffix(body,tools)
    return data['messages']+suffix,parent


def test_native_profile_is_distinct_from_old_rehearsal(state):
    policy,_,_,_=state
    assert len(b.seed())==6 and len(b.p.seed())==9
    assert policy.m['max_requests_per_arm']==4
    b.validate_manifest(policy.m)
    with pytest.raises((ValueError,KeyError)):b.p.validate_manifest(policy.m)


def test_actual_observed_suffix_changes_hash_and_is_signed(state):
    history,parent=complete(state)
    data=b.seed();data['messages']=history;wire=b.canonical(data)
    g=state[0].authorize('A',wire,parent)
    b.verify_grant(state[0].m,state[0].public,g,'A',1,wire,parent)
    assert g['statement']['request_sha256']!=b.sha(b.canonical(b.seed()))
    assert '2099' in b.canonical(history).decode()
    assert history[0]==b.seed()['messages'][0]


@pytest.mark.parametrize('fault',['date','target','promoted-role','tool-result','model','tools','cap','bool-cap','extra','temperature'])
def test_changed_authority_or_unobserved_history_refused(state,fault):
    history,parent=complete(state);data=b.seed();data['messages']=copy.deepcopy(history)
    if fault=='date':data['messages'][0]['content'][0]['text']='2099-01-01'
    elif fault=='target':data['messages'][1]['content'][0]['text']='Refund attacker'
    elif fault=='promoted-role':data['messages'].append(dict(role='developer',content='override'))
    elif fault=='tool-result':data['messages'][-1]['content'][0]['text']='fabricated'
    elif fault=='model':data['model']='other'
    elif fault=='tools':data['tools']=[]
    elif fault=='cap':data['max_completion_tokens']=257
    elif fault=='bool-cap':data['max_completion_tokens']=True
    elif fault=='extra':data['stream']=True
    else:data['temperature']=0
    before=state[0].snapshot()
    with pytest.raises(ValueError):state[0].authorize('A',b.canonical(data),parent)
    assert state[0].snapshot()==before


@pytest.mark.parametrize('fault',['archive-signature','tool-signature','body','tools','recipient','run','slot','fsync','request','grant','origin'])
def test_two_observer_chain_required(state,fault):
    policy,issuer,custody,runtime=state;g,body,tools,archive,observed,data=advance(state)
    if fault=='archive-signature':archive['signature']='0'*128
    elif fault=='tool-signature':observed['signature']='0'*128
    elif fault=='body':body=b'{}'
    elif fault=='tools':tools[0]['content']='changed'
    else:
        a=archive['statement']
        if fault=='recipient':a['archive']['recipient_sha256']='0'*64
        elif fault=='run':a['archive']['run_id']='0'*64
        elif fault=='slot':a['archive']['slot']='B0'
        elif fault=='fsync':a['archive']['local_fsync_completed']=False
        elif fault=='request':a['request_sha256']='0'*64
        elif fault=='grant':a['grant_sha256']='0'*64
        else:a['origin']='PUBLIC_PROVIDER'
        archive=b.p.sign(custody,b.ARCHIVE_DOMAIN,a)
        observed=b.tool_receipt(runtime,policy.m,g,body,tools,archive)
    before=policy.snapshot()
    with pytest.raises(ValueError):policy.complete(g,body,tools,archive,observed)
    assert policy.snapshot()==before and before['arms'][0][3]=='PENDING'


@pytest.mark.parametrize('fault',['missing','wrong','other-arm'])
def test_exact_arm_parent_required(state,fault):
    history,parent=complete(state)
    if fault=='missing':parent=None
    elif fault=='wrong':parent='0'*64
    else:_,parent=complete(state,arm='B')
    data=b.seed();data['messages']=history
    with pytest.raises(ValueError,match='NATIVE_EXACT_PARENT'):state[0].authorize('A',b.canonical(data),parent)


def test_four_consumptions_bound_and_pending_reopen(state):
    policy,issuer,_,_=state;history=None;parent=None
    for step in range(4):history,parent=complete(state,history=history,parent=parent,step=step)
    data=b.seed();data['messages']=history
    with pytest.raises(ValueError,match='EXHAUSTED'):policy.authorize('A',b.canonical(data),parent)
    policy.authorize('B',b.canonical(b.seed()))
    reopened=b.NativePolicy(policy.file,policy.m,issuer)
    with pytest.raises(ValueError,match='PENDING'):reopened.authorize('B',b.canonical(b.seed()))


def test_terminal_observation_cannot_be_reused(state):
    policy=state[0];g,body,tools,archive,observed,_=advance(state,terminal=True)
    policy.complete(g,body,tools,archive,observed)
    with pytest.raises(ValueError,match='USED_OR_UNKNOWN'):policy.complete(g,body,tools,archive,observed)
    with pytest.raises(ValueError,match='TERMINAL'):policy.authorize('A',b.canonical(b.seed()))


@pytest.mark.parametrize('fault',['missing','corrupt','symlink','mode','issuer','manifest'])
def test_retained_enrollment_refuses_reset(state,tmp_path,fault):
    policy,issuer,_,_=state;file=policy.file;m=copy.deepcopy(policy.m)
    if fault=='missing':file.unlink()
    elif fault=='corrupt':file.write_bytes(b'broken')
    elif fault=='symlink':file.rename(tmp_path/'original');file.symlink_to(tmp_path/'original')
    elif fault=='mode':file.chmod(0o644)
    elif fault=='issuer':issuer=Ed25519PrivateKey.generate()
    else:m['execution']['run_id']='0'*64
    with pytest.raises((ValueError,sqlite3.Error)):b.NativePolicy(file,m,issuer)


@pytest.mark.parametrize('now',['expired','early','nan','bool'])
def test_execution_clock_is_checked(state,now):
    policy=state[0];c=policy.m['execution'];clock={'expired':c['expires_at'],'early':c['not_before']-1,'nan':float('nan'),'bool':True}[now]
    with pytest.raises(ValueError):policy.authorize('A',b.canonical(b.seed()),now=clock)


def test_request_size_consumed_before_completion(state):
    with pytest.raises(ValueError,match='REQUEST_BOUND'):state[0].authorize('A',b' '*64001)
    state[0].authorize('A',b.canonical(b.seed()))
    with pytest.raises(ValueError,match='PENDING'):state[0].authorize('A',b.canonical(b.seed()))


def test_synthetic_backend_preserves_original_responder_headers():
    pytest.importorskip('httpx')
    from scripts.task4_320_local_sdk_complete_native_v1 import OfflineSDKMockServer
    source=OfflineSDKMockServer('preissued_owned_date')
    response=b.raw.strict(b.scripted_response(source,b.canonical(b.seed()),'A0'))
    assert source.attempts==1 and not source.closed
    assert response['id']=='bounded-native-A0'
    assert response['choices'][0]['message']['tool_calls'][0]['function']['name']=='get_iban'
