"""Original archive calls, failure isolation and evidence joins; Native UID proof is CI."""
import copy
import errno
import os
from pathlib import Path
import time
import pytest
from scripts import task4_native_archive_fault_fixture_v1 as storage
from scripts import task4_native_archive_failure_v1 as z
from scripts import task4_native_archive_audit_normal_v1 as normal


def wire(op='A0'):
    body=z.n.canonical(dict(id='public-'+op,object='chat.completion',model=z.ingress.raw.request_parameters()['model'],choices=[dict(index=0)]))
    return z.ingress.response_wire(body,op,'success')


@pytest.fixture
def archive_base(tmp_path,monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    private=X25519PrivateKey.generate();public=private.public_key().public_bytes_raw()
    (tmp_path/'public').mkdir();(tmp_path/'public/recipient.pub').write_bytes(public)
    (tmp_path/'custody').mkdir(mode=0o700);(tmp_path/'custody/archives').mkdir(mode=0o700)
    monkeypatch.setattr(storage.n,'CUSTODY',os.geteuid())
    # Portable I/O/crypto probe; actual unprivileged UID/caps/NNP are proved in CI.
    monkeypatch.setattr(storage.n.kernel,'role_identity',lambda _:None)
    ns={'device':4,'inode':123};monkeypatch.setattr(storage.e,'namespace',lambda:ns)
    old=os.umask(0o077)
    try:yield tmp_path,private,dict(run_id='a'*64,request_sha256=z.e.sha(b'public request'),recipient_sha256=z.e.sha(public)),ns
    finally:os.umask(old)


def invoke(archive_base,fault,monkeypatch,slot='A0'):
    base,private,plan,ns=archive_base;events=[];data=wire(slot)
    if fault=='create-denied':
        (base/'custody/archives').chmod(0o500)
        # Portable permission-error simulation also works for UID 0; the actual
        # root Native case uses real UID 61106 and mode 0500 without this stub.
        original=Path.open;target=base/'custody/archives'/(slot+'.enc.json')
        def denied(file,mode='r',*args,**kwargs):
            if file==target and mode=='xb':raise PermissionError(errno.EACCES,'portable permission simulation')
            return original(file,mode,*args,**kwargs)
        monkeypatch.setattr(Path,'open',denied)
    result=None;error=None
    try:result=storage.audit_seal(z.ingress.raw.seal,base,slot,data,'eof',plan,fault,events.append)
    except Exception as caught:error=caught
    return result,error,events,storage.snapshot(base,slot)


@pytest.mark.parametrize('fault',['normal',*storage.MODES])
def test_real_original_seal_phases_snapshot_and_owner_decrypt(archive_base,fault,monkeypatch):
    from cryptography.hazmat.primitives.ciphers import aead
    base,private,plan,ns=archive_base;encryptor=aead.AESGCM;sync=os.fsync
    result,error,events,final=invoke(archive_base,fault,monkeypatch)
    assert aead.AESGCM is encryptor and os.fsync is sync
    assert storage.validate_audit(events,wire(),plan,'A0',fault,ns,final)
    if fault=='normal':assert result['local_fsync_completed'] is True and error is None
    else:assert result is None and isinstance(error,ValueError if fault=='encrypt-failure' else OSError)
    if final['exists']:
        import base64
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        value=z.ingress.raw.strict(z.n.decode(final['blob_b64']))
        key=z.ingress.raw.derive(private,X25519PublicKey.from_public_bytes(bytes.fromhex(value['ephemeral'])))
        assert aead.AESGCM(key).decrypt(bytes.fromhex(value['nonce']),base64.b64decode(value['ciphertext']),z.n.canonical(value['header']))==wire()
    else:assert fault in ('encrypt-failure','create-denied')
    assert [x['phase'] for x in events].count('SEAL_RETURN')==(1 if fault=='normal' else 0)


@pytest.mark.parametrize('fault',['normal',*storage.MODES])
def test_actual_fsync_call_counts_stop_at_selected_boundary(archive_base,fault,monkeypatch):
    real=os.fsync;calls=[]
    def spy(fd):calls.append(os.fstat(fd).st_mode);return real(fd)
    monkeypatch.setattr(os,'fsync',spy)
    _,_,events,_=invoke(archive_base,fault,monkeypatch)
    assert len(calls)=={'normal':2,'encrypt-failure':0,'create-denied':0,'file-fsync-failure':0,'directory-fsync-failure':1}[fault]
    assert os.fsync is spy and events[-1]['functions_restored'] is True


@pytest.fixture(params=['normal',*storage.MODES])
def audit_vector(request,archive_base,monkeypatch):
    _,_,events,final=invoke(archive_base,request.param,monkeypatch)
    return events,wire(),archive_base[2],'A0',request.param,archive_base[3],final


@pytest.mark.parametrize('change',['missing','extra','phase','uid','namespace','time','raw_hash','bytes','completion','aad','restore','directory_owner','directory_mode','result_snapshot'])
def test_archive_boundary_evidence_changes_are_refused(audit_vector,change):
    events,data,plan,slot,fault,ns,final=audit_vector
    if change=='missing':events.pop()
    elif change=='extra':events.append(copy.deepcopy(events[-1]))
    elif change=='phase':events[0]['phase']='AFTER_SEAL'
    elif change=='uid':events[0]['uid']+=1
    elif change=='namespace':events[0]['namespace']={}
    elif change=='time':events[-1]['at_ns']=events[0]['at_ns']-1
    elif change=='raw_hash':events[0]['raw_sha256']='0'*64
    elif change=='bytes':events[0]['observed_bytes']+=1
    elif change=='completion':events[0]['capture_completion']='limit'
    elif change=='aad':events[1]['aad_sha256']='0'*64
    elif change=='restore':events[-1]['functions_restored']=False
    elif change=='directory_owner':final['directory']['uid']+=1
    elif change=='directory_mode':final['directory']['mode']=0o777
    else:events[-1]['snapshot']=dict(exists=True)
    with pytest.raises((ValueError,KeyError,TypeError)):storage.validate_audit(events,data,plan,slot,fault,ns,final)


@pytest.mark.parametrize('fault',storage.MODES)
def test_failure_never_claims_returned_archive_or_completed_directory_fsync(archive_base,fault,monkeypatch):
    result,error,events,final=invoke(archive_base,fault,monkeypatch)
    assert result is None and error is not None
    assert not any(x['phase'] in ('SEAL_RETURN','DIRECTORY_FSYNC_DONE') for x in events)
    if fault in ('file-fsync-failure','directory-fsync-failure'):
        assert final['exists'] and final['file']['size']>0
        assert ('FILE_FSYNC_DONE' in [x['phase'] for x in events])==(fault=='directory-fsync-failure')


def test_original_exclusive_create_does_not_replace_existing_archive(archive_base,monkeypatch):
    base,_,plan,_=archive_base
    _,_,_,before=invoke(archive_base,'normal',monkeypatch)
    events=[]
    with pytest.raises(FileExistsError):storage.audit_seal(z.ingress.raw.seal,base,'A0',wire(),'eof',plan,'normal',events.append)
    assert storage.snapshot(base,'A0')==before and events[-1]['phase']=='SEAL_EXCEPTION'


@pytest.mark.parametrize('phase',['ENCRYPT_BEGIN','FILE_FSYNC_BEGIN','DIRECTORY_FSYNC_BEGIN'])
def test_observer_exception_restores_scoped_crypto_and_fsync(archive_base,phase):
    from cryptography.hazmat.primitives.ciphers import aead
    base,_,plan,_=archive_base;encryptor=aead.AESGCM;sync=os.fsync
    def emit(row):
        if row['phase']==phase:raise RuntimeError('portable observer failure')
    with pytest.raises(RuntimeError):storage.audit_seal(z.ingress.raw.seal,base,'A0',wire(),'eof',plan,'normal',emit)
    assert aead.AESGCM is encryptor and os.fsync is sync


@pytest.mark.parametrize('profile',[z,normal])
def test_no_root_or_output_without_explicit_ack(profile,monkeypatch):
    monkeypatch.setattr(profile.e,'require_root',lambda:pytest.fail('root before ack'))
    with pytest.raises(ValueError):profile.run(Path('/tmp/unused'))


@pytest.mark.parametrize('profile',[z,normal])
def test_exact_cli_ack_is_forwarded(profile,monkeypatch,tmp_path):
    calls=[];monkeypatch.setattr(profile,'run',lambda *args:calls.append(args))
    argv=['--run','--output',str(tmp_path/'proof')]
    if profile is z:argv+=['--fault','file-fsync-failure','--acknowledge-isolated-archive-failure-test'];expected=(tmp_path/'proof','file-fsync-failure',True)
    else:argv+=['--acknowledge-isolated-archive-audit-normal-test'];expected=(tmp_path/'proof',True)
    profile.main(argv);assert calls==[expected]


def test_selected_original_sealer_sources_are_pinned():
    assert z.sources()['archive_fixture']==normal.sources()['archive_fixture']==storage.source_sha256()


@pytest.fixture(params=storage.MODES)
def trace_vector(request,archive_base,monkeypatch):
    start=time.monotonic_ns();_,_,events,final=invoke(archive_base,request.param,monkeypatch);finish=time.monotonic_ns()
    data=wire();ns=archive_base[3]
    c=dict(started_ns=start-100,finished_ns=start-90,deadline_ns=start-100+z.deadline.TOTAL_NS,total_budget_ns=z.deadline.TOTAL_NS,
        inactivity_seconds=.7,stop_reason='eof',reads=[dict(before_ns=start-99,after_ns=start-98,wait_seconds=.7,outcome='bytes',part_b64=z.n.encode(data)),
        dict(before_ns=start-97,after_ns=start-96,wait_seconds=.7,outcome='eof',part_b64='')],observed_b64=z.n.encode(data),observed_bytes=len(data),raw_sha256=z.e.sha(data),capture_completion='eof')
    common=dict(op='A0',uid=z.n.CUSTODY,namespace=ns)
    trace=[dict(common,phase='CAPTURE',collection=c,channel_open=True,restored_timeout_seconds=.7),
        dict(common,phase='CLOSE',started_ns=start-80,finished_ns=start-70,socket_closed=True,connection_socket_cleared=True),
        dict(common,phase='SEAL_REFUSED',finished_ns=finish,error_class=events[-1]['error_class'],error_errno=events[-1]['error_errno'])]
    return trace,data,ns,request.param,events


def test_complete_capture_close_and_archive_exception_are_joined_before_parser(trace_vector):
    assert z.validate_trace(*trace_vector)


@pytest.mark.parametrize('change',['open','restore','not_closed','socket_retained','closed_after_seal','error_class','errno','false_return','parser_called'])
def test_failure_dispatch_trace_cannot_claim_archive_or_parser_permission(trace_vector,change):
    trace,data,ns,fault,events=trace_vector;cap,closed,refused=trace
    if change=='open':cap['channel_open']=False
    elif change=='restore':cap['restored_timeout_seconds']=2
    elif change=='not_closed':closed['socket_closed']=False
    elif change=='socket_retained':closed['connection_socket_cleared']=False
    elif change=='closed_after_seal':closed['finished_ns']=events[0]['at_ns']+1
    elif change=='error_class':refused['error_class']='fabricated'
    elif change=='errno':refused['error_errno']=999
    elif change=='false_return':refused['phase']='SEALED'
    else:trace.append(dict(refused,phase='PARSER_RETURNED'))
    with pytest.raises((ValueError,KeyError)):z.validate_trace(trace,data,ns,fault,events)


@pytest.fixture
def normal_audit_vector(archive_base):
    base,_,plan,ns=archive_base;trace=[];audits=[];evidence=dict(posts=[],recovered=[],native=dict(records=[]),events=[],manifest=dict(execution=dict(run_id=plan['run_id'],raw_recipient_sha256=plan['recipient_sha256'])))
    for i,op in enumerate(a+str(j) for a in 'AB' for j in range(4)):
        data=wire(op);body=z.ingress.raw.parse_wire(data,'eof')[2];q=z.e.sha(('public-'+op).encode());p=dict(plan,request_sha256=q)
        start=time.monotonic_ns();c=dict(started_ns=start,finished_ns=start+2,deadline_ns=start+z.deadline.TOTAL_NS,
            total_budget_ns=z.deadline.TOTAL_NS,inactivity_seconds=.7,stop_reason='eof',
            reads=[dict(before_ns=start,after_ns=start,wait_seconds=.7,outcome='bytes',part_b64=z.n.encode(data)),
                dict(before_ns=start+1,after_ns=start+1,wait_seconds=.7,outcome='eof',part_b64='')],
            observed_b64=z.n.encode(data),observed_bytes=len(data),raw_sha256=z.e.sha(data),capture_completion='eof')
        archive=storage.audit_seal(z.ingress.raw.seal,base,op,data,'eof',p,'normal',audits.append);finish=time.monotonic_ns()
        common=dict(op=op,uid=z.n.CUSTODY,namespace=ns)
        trace.extend([dict(common,phase='CAPTURE',collection=c,channel_open=True,restored_timeout_seconds=.7),
            dict(common,phase='CLOSE',started_ns=start+3,finished_ns=start+4,socket_closed=True,connection_socket_cleared=True),
            dict(common,phase='SEALED',finished_ns=finish,archive=archive),
            dict(common,phase='PARSED',started_ns=finish+1,finished_ns=finish+2,raw_sha256=z.e.sha(data),response_sha256=z.e.sha(body),status=200,
                request_id='native-local-'+op,id_guard_result=dict(field_count=1,request_id='native-local-'+op),framing_guard_result=z.frame.require_framing(data))])
        evidence['posts'].append(dict(op=op,wire_sha256=z.e.sha(data),wire_bytes=len(data),response_sha256=z.e.sha(body),request_sha256=q))
        evidence['recovered'].append(dict(slot=op,raw_sha256=z.e.sha(data),observed_bytes=len(data),capture_completion='eof',envelope_sha256=archive['envelope_sha256']))
        evidence['native']['records'].append(dict(arm=op[0],ordinal=int(op[1]),response_sha256=z.e.sha(body),archive=dict(statement=dict(archive=archive))))
        evidence['events'].extend([dict(op=op) for _ in range(5)]+[dict(op=op,archive=archive)])
    report=dict(native=dict(evidence=evidence),namespace=ns)
    return audits,trace,report


def test_eight_original_seals_join_fsync_order_archive_and_parser(normal_audit_vector):
    audits,trace,report=normal_audit_vector
    assert normal.validate_trace(trace,report,report['namespace'])
    assert normal.validate_archive_audits(audits,trace,report)
    assert len(audits)==64 and sum(x['phase']=='FILE_FSYNC_DONE' for x in audits)==8 and sum(x['phase']=='DIRECTORY_FSYNC_DONE' for x in audits)==8


@pytest.mark.parametrize('change',['missing','extra','wrong_op','file_fsync_missing','directory_fsync_missing','false_exception','returned_before_sync',
    'snapshot_hash','descriptor_inode','recipient','ack_flag','seal_before_close','parse_before_return'])
def test_normal_archive_acknowledgement_is_not_inferred_from_file_visibility(normal_audit_vector,change):
    audits,trace,report=normal_audit_vector
    if change=='missing':audits.pop()
    elif change=='extra':audits.append(copy.deepcopy(audits[-1]))
    elif change=='wrong_op':audits[0]['op']='B0'
    elif change=='file_fsync_missing':audits[4]['phase']='FILE_FSYNC_BEGIN'
    elif change=='directory_fsync_missing':audits[6]['phase']='DIRECTORY_FSYNC_BEGIN'
    elif change=='false_exception':audits[7]['phase']='SEAL_EXCEPTION'
    elif change=='returned_before_sync':audits[7]['at_ns']=audits[6]['at_ns']-1
    elif change=='snapshot_hash':audits[7]['snapshot']['blob_sha256']='0'*64
    elif change=='descriptor_inode':audits[3]['descriptor']['inode']+=1
    elif change=='recipient':report['native']['evidence']['manifest']['execution']['raw_recipient_sha256']='0'*64
    elif change=='ack_flag':audits[7]['archive']['local_fsync_completed']=False
    elif change=='seal_before_close':trace[1]['finished_ns']=audits[0]['at_ns']+1
    else:trace[3]['started_ns']=audits[7]['at_ns']-1
    with pytest.raises((ValueError,KeyError,TypeError)):
        normal.validate_trace(trace,report,report['namespace'])
        normal.validate_archive_audits(audits,trace,report)
