import copy
import errno
import json
import os
import socket
import sqlite3

import pytest

from scripts import task4_provider_shaped_raw_ingress_v1 as p


def test_complete_raw_http_can_be_parsed_after_capture():
    status,headers,body=p.parse_wire(p.wire('success'),'eof')
    assert status==200 and p.strict(body)['id']=='chatcmpl-local-success'
    assert dict(headers)['X-Request-Id']=='local-request-success'


def test_actual_pinned_sdk_serializes_original_parameters_and_parses_one_completion():
    import httpx
    calls=[]
    class Transport(httpx.BaseTransport):
        def handle_request(self,request):
            calls.append(request)
            assert request.method=='POST' and str(request.url)==p.URL
            assert p.strict(request.content)==p.request_parameters()
            status,headers,body=p.parse_wire(p.wire('success'),'eof')
            return httpx.Response(status,headers=headers,content=body,request=request)
    answer=p.sdk_call(Transport())
    assert len(calls)==1 and answer.id=='chatcmpl-local-success'


@pytest.mark.parametrize('mode',['http403','malformed-json','malformed-http','missing-id','truncated','oversized','timeout','dropped'])
def test_bad_or_incomplete_wire_never_becomes_completion(mode):
    completion='timeout' if mode=='timeout' else 'limit' if mode=='oversized' else 'eof'
    with pytest.raises((ValueError,p.http.client.HTTPException)):
        p.parse_wire(p.wire(mode)[:p.LIMIT+1],completion)


@pytest.mark.parametrize('kind',['eof','timeout','limit'])
def test_capture_preserves_exact_bytes_and_completion_class(kind):
    class Stream:
        def __init__(self):self.data=b'prefix' if kind!='limit' else b'x'*(p.LIMIT+100);self.done=False
        def recv(self,n):
            if self.data:r,self.data=self.data[:n],self.data[n:];return r
            if kind=='timeout':raise socket.timeout()
            return b''
    raw,completion=p.capture(Stream())
    assert raw==(b'x'*(p.LIMIT+1) if kind=='limit' else b'prefix')
    assert completion==kind


def test_reservation_is_durable_and_duplicate_never_resets(tmp_path):
    (tmp_path/'custody').mkdir()
    plan=dict(run_id='a'*64,request_sha256='b'*64)
    p.initialize_ledger(tmp_path,plan)
    assert p.reserve(tmp_path,'success',plan) is True
    assert p.reserve(tmp_path,'success',plan) is False
    with sqlite3.connect(tmp_path/'custody/attempts.sqlite3') as db:
        assert db.execute('SELECT * FROM attempts').fetchall()==[('a'*64,'success','b'*64,'CONSUMED_UNKNOWN')]


def test_missing_retained_ledger_is_not_recreated(tmp_path):
    (tmp_path/'custody').mkdir();plan=dict(run_id='a'*64,request_sha256='b'*64)
    with pytest.raises(ValueError,match='RETAINED_PRIVATE_LEDGER_REQUIRED'):
        p.reserve(tmp_path,'success',plan)
    assert not (tmp_path/'custody/attempts.sqlite3').exists()


@pytest.mark.parametrize('tamper',[None,'header','ciphertext','wrong-key'])
def test_aead_archive_recovers_exact_wire_and_authenticates_metadata(tmp_path,tamper):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    (tmp_path/'public').mkdir();(tmp_path/'custody/archives').mkdir(parents=True)
    key=X25519PrivateKey.generate();public=key.public_key().public_bytes_raw()
    (tmp_path/'public/recipient.pub').write_bytes(public)
    plan=dict(run_id='a'*64,request_sha256='b'*64,recipient_sha256=p.sha(public))
    raw=p.wire('success');receipt=p.seal(tmp_path,'success',raw,'eof',plan)
    file=tmp_path/'custody/archives/success.enc.json';blob=file.read_bytes();e=p.strict(blob)
    assert receipt['envelope_sha256']==p.sha(blob) and receipt['local_fsync_completed'] is True
    assert 'private_key' not in e and raw not in blob
    if tamper=='header':e['header']['slot']='other'
    if tamper=='ciphertext':e['ciphertext']=p.base64.b64encode(b'wrong').decode()
    if tamper=='wrong-key':key=X25519PrivateKey.generate()
    def decrypt():
        return AESGCM(p.derive(key,X25519PublicKey.from_public_bytes(bytes.fromhex(e['ephemeral'])))).decrypt(
            bytes.fromhex(e['nonce']),p.base64.b64decode(e['ciphertext']),p.canonical(e['header']))
    if tamper:
        with pytest.raises(InvalidTag):decrypt()
    else:assert decrypt()==raw


def evidence():
    sdk=dict(fixture_sha256=p.FIXTURE_SHA,request_sha256='a'*64,request_bytes=1)
    plan=dict(modes=list(p.MODES),request_sha256='a'*64,run_id='b'*64,leaf_sha256='c'*64,recipient_sha256='d'*64)
    probes=[dict(placement='isolated',network_errno=errno.ENETUNREACH,uid=p.kernel.AGENT,private_reads_denied=4),
        dict(placement='firewall',network_errno=errno.ECONNREFUSED,uid=p.kernel.AGENT,private_reads_denied=4),
        dict(placement='reachable',status=403,uid=p.kernel.AGENT,private_reads_denied=4)]
    posts=[dict(mode='unauthorized',authorized=False)]
    results={};replays={};events=[];recovered=[]
    for mode in p.MODES:
        replays[mode]=dict(decision='REPLAY_DENIED',socket_attempts=0,parse_calls=0,sdk_delivered=False)
        events.append(dict(slot=mode,phase='CONSUMED',uid=p.kernel.CUSTODY,pid=1))
        if mode=='after-consume-crash':results[mode]={'crash_exit_code':88};continue
        full=p.wire(mode);raw=full[:p.LIMIT+1]
        completion='timeout' if mode=='timeout' else 'limit' if mode=='oversized' else 'eof'
        posts.append(dict(mode=mode,authorized=True,method='POST',path=p.PATH,host=p.NAME,request_sha256='a'*64,
            wire_sha256=p.sha(full),wire_bytes=len(full),prefix_sha256=p.sha(raw),tls_version='TLSv1.3'))
        peer=dict(ip=p.IP,leaf_sha256='c'*64,tls_version='TLSv1.3',hostname=p.NAME,port=443,certificate_required=True,hostname_checked=True)
        for phase,extra in [('PEER_VERIFIED',{'peer':peer}),('POST_ATTEMPTED',{}),('RAW_OBSERVED',dict(raw_sha256=p.sha(raw),observed_bytes=len(raw),capture_completion=completion))]:
            events.append(dict(slot=mode,phase=phase,uid=p.kernel.CUSTODY,pid=1,**extra))
        if mode=='archive-failure':
            events.append(dict(slot=mode,phase='ARCHIVE_FAILED',uid=p.kernel.CUSTODY,pid=1))
            results[mode]=dict(decision='UNKNOWN_ARCHIVE_FAILED_NO_RETRY',parse_calls=0,sdk_delivered=False);continue
        a=dict(raw_sha256=p.sha(raw),observed_bytes=len(raw),recipient_sha256='d'*64,envelope_sha256='e'*64,
            local_fsync_completed=True,run_id='b'*64,slot=mode,request_sha256='a'*64,capture_completion=completion)
        events.append(dict(slot=mode,phase='SEALED_FSYNCED',uid=p.kernel.CUSTODY,pid=1,archive=a))
        recovered.append({k:a[k] for k in ['slot','raw_sha256','observed_bytes','recipient_sha256','envelope_sha256','capture_completion']})
        if mode=='after-seal-crash':results[mode]={'crash_exit_code':89};continue
        if mode in {'timeout','oversized'}:results[mode]=dict(decision='SEALED_PARTIAL_NO_RETRY',parse_calls=0,sdk_delivered=False);continue
        events.append(dict(slot=mode,phase='PARSE_STARTED',uid=p.kernel.CUSTODY,pid=1))
        results[mode]=dict(decision='SDK_RESPONSE' if mode=='success' else 'SEALED_REJECTED_NO_RETRY',parse_calls=1,sdk_delivered=mode=='success')
        if mode=='success':events.append(dict(slot=mode,phase='SDK_RESPONSE_RELEASED',uid=p.kernel.CUSTODY,pid=1))
    network={name:dict(links=['lo'] if name=='isolated' else ['lo','veth'],routes=[],routes6=[]) for name in ['client','sink','isolated']}
    return dict(sdk=sdk,plan=plan,probes=probes,posts=posts,results=results,replays=replays,events=events,recovered=recovered,topology=network,
        ledger=[['b'*64,m,'a'*64,'CONSUMED_UNKNOWN'] for m in sorted(p.MODES)],
        post_replay_posts_sha256=p.digest(posts),post_replay_events_sha256=p.digest(events))


def test_complete_boundary_evidence_accepted():assert p.validate(evidence())


@pytest.mark.parametrize('fault',['source','probe','body','ledger','retry','parse-before-seal','missing-seal','recovery',
    'recipient','partial-complete','sdk-release','extra-post','external-route'])
def test_false_green_boundary_evidence_rejected(fault):
    e=copy.deepcopy(evidence())
    if fault=='source':e['sdk']['fixture_sha256']='0'*64
    elif fault=='probe':e['probes'][0]['network_errno']=0
    elif fault=='body':e['posts'][1]['request_sha256']='0'*64
    elif fault=='ledger':e['ledger'].pop()
    elif fault=='retry':e['replays']['success']['socket_attempts']=1
    elif fault=='parse-before-seal':
        group=[x for x in e['events'] if x['slot']=='success'];group[4]['phase']='PARSE_STARTED'
    elif fault=='missing-seal':e['events']=[x for x in e['events'] if not(x['slot']=='http403' and x['phase']=='SEALED_FSYNCED')]
    elif fault=='recovery':e['recovered'][0]['raw_sha256']='0'*64
    elif fault=='recipient':e['plan']['recipient_sha256']='0'*64
    elif fault=='partial-complete':next(x for x in e['events'] if x['slot']=='timeout' and x['phase']=='SEALED_FSYNCED')['archive']['capture_completion']='eof'
    elif fault=='sdk-release':e['results']['http403']['sdk_delivered']=True
    elif fault=='extra-post':e['posts'].append(e['posts'][-1])
    else:e['topology']['client']['routes']=[{'dst':'default','gateway':'1.1.1.1'}]
    with pytest.raises((ValueError,IndexError)):p.validate(e)
