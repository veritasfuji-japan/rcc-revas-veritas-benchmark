"""Actual child SIGKILL and storage bytes; portable role stubs are not Native proof."""
import copy
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import pytest
from scripts import task4_native_archive_crash_fixture_v1 as storage
from scripts import task4_native_archive_crash_v1 as z
from scripts import task4_native_archive_crash_normal_v1 as normal


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
    # Actual SIGKILL below is real, but this portable same-UID role stub is not
    # evidence of the mandatory root CI's separated Native UID/caps/namespace.
    monkeypatch.setattr(storage.n.kernel,'role_identity',lambda _:None)
    ns=storage.e.namespace();old=os.umask(0o077)
    try:yield tmp_path,private,dict(run_id='a'*64,request_sha256=z.e.sha(b'public request'),recipient_sha256=z.e.sha(public)),ns
    finally:os.umask(old)


def invoke(vector,fault):
    base,_,plan,_=vector;events=[];data=wire();pid=None;result=None
    if fault=='normal':
        result=storage.audit_seal(z.ingress.raw.seal,base,'A0',data,'eof',plan,fault,events.append);code=0
    else:
        source=str(Path(__file__).parents[1]);record=base/'portable-audit.jsonl'
        program='''import sys,os,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from scripts import task4_native_archive_crash_fixture_v1 as f
f.n.CUSTODY=os.geteuid()
f.n.kernel.role_identity=lambda uid:None
base=Path(sys.argv[2]);plan=json.loads(sys.argv[3]);wire=f.n.decode(sys.argv[4])
f.audit_seal(f.ingress.raw.seal,base,'A0',wire,'eof',plan,sys.argv[5],lambda row:f.u.append(base/'portable-audit.jsonl',row))
'''
        child=subprocess.Popen([sys.executable,'-I','-B','-c',program,source,str(base),json.dumps(plan),z.n.encode(data),fault],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:out,err=child.communicate(timeout=10)
        except BaseException:child.kill();child.wait(timeout=5);raise
        code=child.returncode;pid=child.pid
        assert code==-signal.SIGKILL and out==b'' and err==b''
        events=[json.loads(x) for x in record.read_bytes().splitlines()]
    return dict(result=result,events=events,final=storage.snapshot(base,'A0'),exit_code=code,pid=pid)


@pytest.fixture(params=storage.MODES)
def crash_vector(request,archive_base):
    return invoke(archive_base,request.param),archive_base,request.param


def test_actual_crash_prefix_no_python_unwind_or_fabricated_return(crash_vector):
    v,base,fault=crash_vector;events=v['events'];phases=[x['phase'] for x in events]
    assert storage.validate_audit(events,wire(),base[2],'A0',fault,base[3],v['final'])
    assert v['exit_code']==-9 and v['pid']==events[-1]['pid']
    assert phases[-1]=='CRASH_INTENT' and not any(x in phases for x in ('SEAL_EXCEPTION','SEAL_RETURN','CLOSE_CLEANUP_BEGIN','CLOSE_CLEANUP_DONE'))
    assert sum(x=='FILE_FSYNC_DONE' for x in phases)==(0 if fault=='after-create' else 1)
    assert sum(x=='DIRECTORY_FSYNC_DONE' for x in phases)==(1 if fault=='after-directory-fsync' else 0)
    assert events[-1]['descriptor_open'] is True
    assert v['final']['file']['size']==(0 if fault=='after-create' else events[4]['blob_bytes'])


@pytest.mark.parametrize('change',['missing','extra','wrong_phase','uid','namespace','time','raw_hash','raw_bytes','completion','aad','cipher_hash','cipher_bytes',
    'fault','signal','pid','descriptor_kind','descriptor_open','descriptor_inode','snapshot_hash','snapshot_changed','directory_mode','file_mode','links','file_size_bool'])
def test_actual_killed_child_proof_cannot_be_promoted(crash_vector,change):
    v,base,fault=crash_vector;events=v['events'];final=v['final'];crash=events[-1]
    if change=='missing':events.pop()
    elif change=='extra':events.append(copy.deepcopy(crash))
    elif change=='wrong_phase':crash['phase']='SEAL_RETURN'
    elif change=='uid':events[0]['uid']+=1
    elif change=='namespace':events[0]['namespace']={}
    elif change=='time':crash['at_ns']=events[0]['at_ns']-1
    elif change=='raw_hash':events[0]['raw_sha256']='0'*64
    elif change=='raw_bytes':events[0]['observed_bytes']+=1
    elif change=='completion':events[0]['capture_completion']='timeout'
    elif change=='aad':events[1]['aad_sha256']='0'*64
    elif change=='cipher_hash':events[2]['ciphertext_sha256']='not-a-hash'
    elif change=='cipher_bytes':events[2]['ciphertext_bytes']+=1
    elif change=='fault':crash['boundary']='other'
    elif change=='signal':crash['signal']=signal.SIGTERM
    elif change=='pid':crash['pid']=0
    elif change=='descriptor_kind':crash['descriptor_kind']='socket'
    elif change=='descriptor_open':crash['descriptor_open']=False
    elif change=='descriptor_inode':crash['descriptor']['inode']+=1
    elif change=='snapshot_hash':final['blob_sha256']='0'*64
    elif change=='snapshot_changed':crash['snapshot']['blob_sha256']='0'*64
    elif change=='directory_mode':final['directory']['mode']=0o777
    elif change=='file_mode':final['file']['mode']=0o644
    elif change=='links':final['file']['links']=2
    else:final['file']['size']=False
    with pytest.raises((ValueError,KeyError,TypeError)):
        storage.validate_audit(events,wire(),base[2],'A0',fault,base[3],final)


def test_killed_archive_remains_create_once_and_unchanged(crash_vector):
    v,base,fault=crash_vector;path,_,plan,_=base;before=copy.deepcopy(v['final']);events=[]
    with pytest.raises(FileExistsError):storage.audit_seal(z.ingress.raw.seal,path,'A0',wire(),'eof',plan,'normal',events.append)
    assert storage.snapshot(path,'A0')==before and events[-1]['phase']=='SEAL_EXCEPTION'


def test_fresh_owner_original_recovery_never_restores_permission(crash_vector,monkeypatch):
    v,base,fault=crash_vector;path,private,_,_=base
    (path/'owner').mkdir(mode=0o700);(path/'owner/recovery').mkdir(mode=0o700)
    (path/'owner/private-key').write_bytes(private.private_bytes_raw())
    (path/'owner/recovery/A0.enc.json').write_bytes(z.n.decode(v['final']['blob_b64']))
    monkeypatch.setattr(z,'fixture',lambda _:fault)
    r=z.owner_recovery(path)
    assert r['error_class']==('JSONDecodeError' if fault=='after-create' else None)
    assert r['unchanged'] is True and r['permission_issued'] is False and r['ciphertext_sha256']==v['final']['blob_sha256']
    assert len(r['recovered'])==(0 if fault=='after-create' else 1)
    if r['recovered']:assert r['recovered'][0]['raw_sha256']==z.e.sha(wire())


def test_normal_original_calls_and_closed_descriptor_are_acknowledged_only_after_directory_fsync(archive_base):
    from cryptography.hazmat.primitives.ciphers import aead
    enc,opened,sync=aead.AESGCM,Path.open,os.fsync
    v=invoke(archive_base,'normal')
    assert storage.validate_audit(v['events'],wire(),archive_base[2],'A0','normal',archive_base[3],v['final'])
    assert v['result']['local_fsync_completed'] is True and len(v['events'])==15
    assert aead.AESGCM is enc and Path.open is opened and os.fsync is sync


@pytest.mark.parametrize('profile',[z,normal])
def test_no_output_or_root_before_explicit_ack(profile,monkeypatch):
    monkeypatch.setattr(profile.e,'require_root',lambda:pytest.fail('root before ack'))
    with pytest.raises(ValueError):profile.run(Path('/tmp/unused'))


@pytest.mark.parametrize('profile',[z,normal])
def test_exact_cli_ack_is_forwarded(profile,monkeypatch,tmp_path):
    calls=[];monkeypatch.setattr(profile,'run',lambda *args:calls.append(args))
    argv=['--run','--output',str(tmp_path/'proof')]
    if profile is z:argv+=['--crash-point','after-create','--acknowledge-isolated-archive-crash-test'];expected=(tmp_path/'proof','after-create',True)
    else:argv+=['--acknowledge-isolated-archive-crash-normal-test'];expected=(tmp_path/'proof',True)
    profile.main(argv);assert calls==[expected]


def test_selected_original_profiles_and_crash_fixture_are_pinned():
    assert z.sources()['archive_fixture']==normal.sources()['archive_fixture']==storage.source_sha256()


@pytest.fixture
def trace_vector(crash_vector):
    v,base,fault=crash_vector;data=wire();start=v['events'][0]['at_ns']-1000
    c=dict(started_ns=start,finished_ns=start+2,deadline_ns=start+z.deadline.TOTAL_NS,total_budget_ns=z.deadline.TOTAL_NS,inactivity_seconds=.7,stop_reason='eof',
        reads=[dict(before_ns=start,after_ns=start,wait_seconds=.7,outcome='bytes',part_b64=z.n.encode(data)),
            dict(before_ns=start+1,after_ns=start+1,wait_seconds=.7,outcome='eof',part_b64='')],observed_b64=z.n.encode(data),observed_bytes=len(data),raw_sha256=z.e.sha(data),capture_completion='eof')
    common=dict(op='A0',uid=z.n.CUSTODY,namespace=base[3])
    trace=[dict(common,phase='CAPTURE',collection=c,channel_open=True,restored_timeout_seconds=.7),
        dict(common,phase='CLOSE',started_ns=start+3,finished_ns=start+4,socket_closed=True,connection_socket_cleared=True)]
    return trace,data,base[3],fault,v['events']


def test_capture_close_and_actual_crash_are_joined_before_any_parse(trace_vector):
    assert z.validate_trace(*trace_vector)


@pytest.mark.parametrize('change',['open','restore','socket_open','socket_retained','close_after_seal','late_read','wrong_raw','false_seal_return'])
def test_no_ack_or_permission_is_inferred_from_dead_process(trace_vector,change):
    trace,data,ns,fault,events=trace_vector;cap,closed=trace
    if change=='open':cap['channel_open']=False
    elif change=='restore':cap['restored_timeout_seconds']=2
    elif change=='socket_open':closed['socket_closed']=False
    elif change=='socket_retained':closed['connection_socket_cleared']=False
    elif change=='close_after_seal':closed['finished_ns']=events[0]['at_ns']+1
    elif change=='late_read':cap['collection']['deadline_ns']+=1
    elif change=='wrong_raw':cap['collection']['reads'][0]['part_b64']=''
    else:trace.append(dict(closed,phase='SEALED'))
    with pytest.raises((ValueError,KeyError,TypeError)):z.validate_trace(trace,data,ns,fault,events)


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
    assert len(audits)==120 and sum(x['phase']=='FILE_FSYNC_DONE' for x in audits)==8 and sum(x['phase']=='DIRECTORY_FSYNC_DONE' for x in audits)==8


@pytest.mark.parametrize('change',['missing','extra','wrong_op','file_fsync_missing','directory_fsync_missing','false_exception','returned_before_sync',
    'snapshot_hash','descriptor_inode','recipient','ack_flag','seal_before_close','parse_before_return'])
def test_normal_archive_acknowledgement_is_not_inferred_from_file_visibility(normal_audit_vector,change):
    audits,trace,report=normal_audit_vector
    if change=='missing':audits.pop()
    elif change=='extra':audits.append(copy.deepcopy(audits[-1]))
    elif change=='wrong_op':audits[0]['op']='B0'
    elif change=='file_fsync_missing':audits[9]['phase']='FILE_FSYNC_BEGIN'
    elif change=='directory_fsync_missing':audits[13]['phase']='DIRECTORY_FSYNC_BEGIN'
    elif change=='false_exception':audits[14]['phase']='SEAL_EXCEPTION'
    elif change=='returned_before_sync':audits[14]['at_ns']=audits[13]['at_ns']-1
    elif change=='snapshot_hash':audits[14]['snapshot']['blob_sha256']='0'*64
    elif change=='descriptor_inode':audits[3]['descriptor']['inode']+=1
    elif change=='recipient':report['native']['evidence']['manifest']['execution']['raw_recipient_sha256']='0'*64
    elif change=='ack_flag':audits[14]['archive']['local_fsync_completed']=False
    elif change=='seal_before_close':trace[1]['finished_ns']=audits[0]['at_ns']+1
    else:trace[3]['started_ns']=audits[14]['at_ns']-1
    with pytest.raises((ValueError,KeyError,TypeError)):
        normal.validate_trace(trace,report,report['namespace'])
        normal.validate_archive_audits(audits,trace,report)




def test_actual_empty_ipc_eof_is_a_refusal_not_a_native_response():
    import socket
    left,right=socket.socketpair()
    try:
        right.close()
        with pytest.raises(ValueError,match='BOUNDED_FRAME'):z.n.frame(left)
    finally:left.close();right.close()


@pytest.fixture
def crash_join():
    ns={'device':4,'inode':123};intent=dict(phase='CRASH_INTENT',pid=101,at_ns=1000)
    v=dict(custody_crash=dict(pid=101,exit_code=-9,controller_kill_sent=False,observed_ns=1001,controller_killed_roles=['ledger','issuer','backend']),
        pids_before=dict(custody=101),archive_audit=[intent],initial=dict(pid=102),repeated=dict(pid=103),
        native_ipc=[dict(uid=z.b.RUNTIME,pid=102,namespace=ns,observed_bytes=0,observed_sha256=z.e.sha(b''),read_outcomes=['eof'],error_class='ValueError',reason='BOUNDED_FRAME')])
    return v,ns


def test_process_exit_pid_intent_and_empty_native_ipc_are_joined(crash_join):
    assert z.validate_crash_join(*crash_join)


@pytest.mark.parametrize('change',['pid','intent_pid','exit','controller','clock','controlled_roles','runtime_pid','repeated_pid','ipc_pid','ipc_uid','ipc_namespace','ipc_bytes',
    'ipc_bytes_bool','ipc_hash','ipc_reads','ipc_exception','ipc_reason','missing_ipc','extra_ipc'])
def test_crash_is_not_inferred_from_an_intent_marker_or_empty_reply_alone(crash_join,change):
    v,ns=crash_join;c=v['custody_crash'];ipc=v['native_ipc'][0]
    if change=='pid':c['pid']+=1
    elif change=='intent_pid':v['archive_audit'][-1]['pid']+=1
    elif change=='exit':c['exit_code']=0
    elif change=='controller':c['controller_kill_sent']=True
    elif change=='clock':c['observed_ns']=999
    elif change=='controlled_roles':c['controller_killed_roles'].append('custody')
    elif change=='runtime_pid':v['initial']['pid']=False
    elif change=='repeated_pid':v['repeated']['pid']=102
    elif change=='ipc_pid':ipc['pid']+=1
    elif change=='ipc_uid':ipc['uid']=0
    elif change=='ipc_namespace':ipc['namespace']={}
    elif change=='ipc_bytes':ipc['observed_bytes']=1
    elif change=='ipc_bytes_bool':ipc['observed_bytes']=False
    elif change=='ipc_hash':ipc['observed_sha256']='0'*64
    elif change=='ipc_reads':ipc['read_outcomes']=['bytes','eof']
    elif change=='ipc_exception':ipc['error_class']='ConnectionResetError'
    elif change=='ipc_reason':ipc['reason']='success'
    elif change=='missing_ipc':v['native_ipc']=[]
    else:v['native_ipc'].append(copy.deepcopy(ipc))
    with pytest.raises((ValueError,KeyError,TypeError)):z.validate_crash_join(v,ns)
