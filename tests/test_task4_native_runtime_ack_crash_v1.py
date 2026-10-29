"""Real full-frame pipe receives and child SIGKILL; labelled caller stand-ins.

Actual SDK/Unix socket/handler/UID proof remains mandatory disposable-root CI.
"""
import copy,json,os,signal,subprocess,sys
from pathlib import Path
import pytest
from scripts import task4_native_runtime_ack_fixture_v1 as f
from scripts import task4_native_runtime_ack_crash_v1 as z
from scripts import task4_native_runtime_ack_normal_v1 as normal

CHILD='''import sys,os,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from scripts import task4_native_runtime_ack_fixture_v1 as f
from scripts.task4_471_same_run_capped_sdk_aead_native_no_go_v1 import verify_pins
f.b.RUNTIME=os.geteuid();f.n.kernel.role_identity=lambda uid:None
base=Path(sys.argv[2]);fault=sys.argv[3];fds=iter(json.loads(sys.argv[4]));os.umask(0o077)
emit=lambda x:f.u.append(base/'events.jsonl',x)
# Labelled stand-in caller markers. Actual original SDK returns run in root CI.
emit(f.event('NATIVE_ENTER',frozen_source_git_blobs=verify_pins()))
class Conn:
 def __init__(self,fd):self.fd=fd
 def recv(self,count):return os.read(self.fd,count)
 def fileno(self):
  try:os.fstat(self.fd);return self.fd
  except OSError:return -1
def original(base,packet,name):
 conn=Conn(next(fds))
 try:return f.n.frame(conn)
 finally:os.close(conn.fd)
for _ in range(8 if fault=='normal' else 1):
 emit(f.event('SDK_CALL_ENTER'))
 reply=f.receive(original,base,{},'native',fault,emit)
 emit(f.event('SDK_CALL_RETURNED'))
result=dict(records=[None]*8,scorer_calls=2,frozen_source_git_blobs=verify_pins())
emit(f.event('NATIVE_RETURNED',result_sha256=f.n.digest(result),records=8,scorer_calls=2))
'''


@pytest.fixture(params=['normal',*f.MODES])
def vector(request,tmp_path,monkeypatch):
    monkeypatch.setattr(f.b,'RUNTIME',os.geteuid())
    reply=dict(decision='ARCHIVED_NATIVE_RESPONSE',body_b64=f.n.encode(b'portable body'),archive=dict(statement=dict(operation_id='A0'),signature='portable-stand-in'))
    wire=f.n.canonical(reply)+b'\n';fds=[os.pipe() for _ in range(8 if request.param=='normal' else 1)]
    child=subprocess.Popen([sys.executable,'-I','-B','-c',CHILD,str(Path(__file__).parents[1]),str(tmp_path),request.param,json.dumps([r for r,w in fds])],
        pass_fds=tuple(r for r,w in fds),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        for r,w in fds:os.close(r);os.write(w,wire);os.close(w)
        try:out,err=child.communicate(timeout=10)
        except BaseException:child.kill();child.wait(timeout=5);raise
        assert child.returncode==(0 if request.param=='normal' else -signal.SIGKILL) and not out and not err
        events=[json.loads(x) for x in (tmp_path/'events.jsonl').read_bytes().splitlines()]
        result=dict(records=[None]*8,scorer_calls=2,frozen_source_git_blobs=events[0]['frozen_source_git_blobs'])
        yield dict(fault=request.param,pid=child.pid,events=events,reply=reply,wire=wire,result=result)
    finally:
        if child.poll() is None:child.kill();child.wait(timeout=5)


def validate(v):
    return f.validate_events(v['events'],v['fault'],v['events'][0]['namespace'],[v['reply']]*(8 if v['fault']=='normal' else 1),v['pid'],native_result=v['result'] if v['fault']=='normal' else None)


def test_original_full_frame_then_real_child_sigkill_is_not_sdk_return(vector):
    v=vector;assert validate(v)
    frames=[x for x in v['events'] if x['phase']=='FRAME_RETURNED']
    assert all(f.n.decode(x['wire_b64'])==v['wire'] and x['socket_open'] for x in frames)
    if v['fault']=='normal':assert len(frames)==8 and sum(x['phase']=='SDK_CALL_RETURNED' for x in v['events'])==8
    else:
        assert len(frames)==1 and not any(x['phase']=='SDK_CALL_RETURNED' for x in v['events'])
        assert v['events'][-1]['pid']==v['pid'] and v['events'][-1]['signal']==9
        assert sum(x['phase']=='RPC_RETURNED' for x in v['events'])==(v['fault']=='after-rpc-return')


@pytest.mark.parametrize('change',['missing','extra','phase','uid','pid','namespace','time','source_pin','wire','hash','size','bool_size','read_size','read_bool','read_eof','socket_open','reply','rpc_closed','rpc_reply','signal','boundary','sdk_return','native_return'])
def test_frame_rpc_and_caller_evidence_tampering_is_rejected(vector,change):
    v=copy.deepcopy(vector);events=v['events'];frame=next(x for x in events if x['phase']=='FRAME_RETURNED');last=events[-1]
    rpc=next((x for x in events if x['phase']=='RPC_RETURNED'),None)
    if change=='missing':events.pop()
    elif change=='extra':events.append(copy.deepcopy(last))
    elif change=='phase':frame['phase']='SDK_CALL_RETURNED'
    elif change=='uid':frame['uid']+=1
    elif change=='pid':frame['pid']+=1
    elif change=='namespace':frame['namespace']={}
    elif change=='time':frame['at_ns']=events[0]['at_ns']-1
    elif change=='source_pin':events[0]['frozen_source_git_blobs'][0]['git_blob']='0'*40
    elif change=='wire':frame['wire_b64']=f.n.encode(v['wire'][:-1])
    elif change=='hash':frame['observed_sha256']='0'*64
    elif change=='size':frame['observed_bytes']-=1
    elif change=='bool_size':frame['observed_bytes']=True
    elif change=='read_size':frame['read_sizes'][0]+=1
    elif change=='read_bool':frame['read_sizes'][0]=True
    elif change=='read_eof':frame['read_outcomes'].append('eof');frame['read_sizes'].append(0)
    elif change=='socket_open':frame['socket_open']=False
    elif change=='reply':frame['reply']['body_b64']=f.n.encode(b'other')
    elif change=='rpc_closed':
        if rpc is not None:rpc['socket_closed']=False
        else:frame['socket_open']=False
    elif change=='rpc_reply':
        if rpc is not None:rpc['reply']['decision']='other'
        else:frame['reply']['decision']='other'
    elif change=='signal':
        if v['fault']=='normal':last['scorer_calls']=0
        else:last['signal']=15
    elif change=='boundary':
        if v['fault']=='normal':last['result_sha256']='0'*64
        else:last['boundary']='other'
    elif change=='sdk_return':events.insert(-1,f.event('SDK_CALL_RETURNED'))
    elif change=='native_return':last['phase']='NATIVE_RETURNED' if v['fault']!='normal' else 'RUNTIME_CRASH_INTENT'
    with pytest.raises((ValueError,KeyError,TypeError)):validate(v)


def test_non_native_rpc_delegates_without_observation():
    calls=[];events=[]
    def original(*args):calls.append(args);return dict(decision='DENIED')
    assert f.receive(original,Path('/unused'),{},'issuer',f.MODES[0],events.append)==dict(decision='DENIED')
    assert calls==[(Path('/unused'),{},'issuer')] and events==[]


def test_disposable_only_sources_and_unchanged_receive_limits():
    assert z.sources()['archive_fixture']==normal.sources()['archive_fixture']==f.source_sha256()
    assert z.deadline.TOTAL_NS==2_000_000_000 and z.deadline.MAX_READS==256 and z.ingress.raw.LIMIT==32768
    assert 'DISPOSABLE_UID_COLLISION_NO_REPAIR' in Path(z.__file__).read_text()
