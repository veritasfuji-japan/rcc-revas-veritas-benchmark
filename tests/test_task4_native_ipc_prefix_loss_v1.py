"""Real pipe send/receive and SIGKILL, with explicitly labelled portable role stubs.

Actual Unix sockets, original handlers, signatures, SDK and kernel roles run in root CI.
"""
import copy,json,os,signal,socket,subprocess,sys,time
from pathlib import Path
import pytest
from scripts import task4_native_ipc_prefix_fixture_v1 as f
from scripts import task4_native_ipc_prefix_loss_v1 as z
from scripts import task4_native_ipc_prefix_normal_v1 as normal

CHILD='''import sys,os,json,sqlite3,socket
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from scripts import task4_native_ipc_prefix_fixture_v1 as f
f.n.CUSTODY=os.geteuid();f.n.kernel.role_identity=lambda uid:None
base=Path(sys.argv[2]);fault=sys.argv[3];os.umask(0o077)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
pub=X25519PrivateKey.generate().public_key().public_bytes_raw()
(base/'public').mkdir();(base/'public/recipient.pub').write_bytes(pub)
(base/'custody').mkdir(mode=0o700);(base/'custody/archives').mkdir(mode=0o700);(base/'ipc').mkdir()
plan=dict(run_id='a'*64,request_sha256=f.e.sha(b'portable request'),recipient_sha256=f.e.sha(pub))
emit=lambda x:f.u.append(base/'audit.jsonl',x)
ack=lambda x:f.u.append(base/'acks.jsonl',x)
wire=b'portable raw HTTP bytes'
archive=f.audit_seal(f.ingress.raw.seal,base,'A0',wire,'eof',plan,fault=fault,emit=emit,ack_emit=ack)
db=sqlite3.connect(base/'portable.sqlite3',isolation_level=None)
db.execute('CREATE TABLE consumed(op TEXT PRIMARY KEY,state TEXT,request_sha TEXT,response_sha TEXT,backend_receipt TEXT,envelope_sha TEXT,bind_sha TEXT)')
# Labelled stand-in for local IPC tests; disposable-root CI uses original handler.
def handler(base,db,packet,public,key,signer):
 db.execute('INSERT INTO consumed VALUES (?,?,?,?,?,?,?)',('A0','MOCK_OBSERVED',plan['request_sha256'],'b'*64,'c'*64,archive['envelope_sha256'],'d'*64))
 return dict(decision='ARCHIVED_NATIVE_RESPONSE',body_b64=f.n.encode(b'portable Native body'),archive=dict(statement=dict(operation_id='A0'),signature='portable-stand-in'))
reply=f.consume(handler,base,db,dict(arm='A',ordinal=0),None,None,None,fault=fault,emit=ack)
class Pipe:
 def sendall(self,wire):
  view=memoryview(wire)
  while view:
   count=os.write(int(sys.argv[4]),view);assert count>0;view=view[count:]
f.send(Pipe(),f.n.canonical(reply)+b'\\n',base,fault,lambda x:f.u.append(base/'send.jsonl',x),ack)
'''


@pytest.fixture(params=['normal',*f.MODES])
def vector(request,tmp_path,monkeypatch):
    monkeypatch.setattr(f.n,'CUSTODY',os.geteuid())
    read_fd,write_fd=os.pipe()
    child=subprocess.Popen([sys.executable,'-I','-B','-c',CHILD,str(Path(__file__).parents[1]),str(tmp_path),request.param,str(write_fd)],pass_fds=(write_fd,),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    os.close(write_fd)
    parts=[];result=None;error=None
    try:
        class Reader:
            def recv(self,limit):
                part=os.read(read_fd,limit);parts.append(part);return part
        try:result=f.n.frame(Reader())
        except ValueError as exc:error=str(exc)
        out,err=child.communicate(timeout=5)
        assert child.returncode==(0 if request.param=='normal' else -signal.SIGKILL) and not out and not err
        read=lambda name:[json.loads(x) for x in (tmp_path/name).read_bytes().splitlines()]
        yield dict(mode=request.param,audit=read('audit.jsonl'),acks=read('acks.jsonl'),send=read('send.jsonl'),
            observed=b''.join(parts),parts=parts,result=result,error=error,pid=child.pid,base=tmp_path)
    finally:
        os.close(read_fd)
        if child.poll() is None:child.kill();child.wait(timeout=5)


def test_real_pipe_prefix_is_not_a_native_frame_ack(vector):
    v=vector;acks=v['acks'];event=v['send'][0];reply=acks[1]['reply']
    prefix=f.validate_send(event,reply,'A0',event['namespace'],v['mode'],acks[1]['at_ns'])
    assert v['observed']==prefix and event['pid']==v['pid'] and len(v['audit'])==15
    with __import__('sqlite3').connect(v['base']/'portable.sqlite3') as db:
        assert db.execute('SELECT state FROM consumed').fetchall()==[('MOCK_OBSERVED',)]
    if v['mode']=='normal':assert v['result']==reply and v['error'] is None and prefix.endswith(b'\n')
    else:
        assert v['error']=='BOUNDED_FRAME' and v['result'] is None and v['parts'][-1]==b'' and not prefix.endswith(b'\n')
        assert acks[-1]['pid']==event['pid'] and event['at_ns']<=acks[-1]['at_ns']
        if v['mode']=='without-newline':assert json.loads(prefix)==reply


@pytest.mark.parametrize('change',['missing','extra','uid','pid','namespace','time','mode','full_size','full_hash','sent_size','sent_bool','sent_hash','sent_b64','newline','reply','phase'])
def test_send_evidence_changes_are_rejected(vector,change):
    v=vector;x=copy.deepcopy(v['send'][0]);reply=copy.deepcopy(v['acks'][1]['reply']);after=v['acks'][1]['at_ns']
    if change=='missing':x.pop('pid')
    elif change=='extra':x['acknowledged']=True
    elif change=='uid':x['uid']+=1
    elif change=='pid':x['pid']=0
    elif change=='namespace':x['namespace']={}
    elif change=='time':x['at_ns']=after-1
    elif change=='mode':x['boundary']='other'
    elif change=='full_size':x['full_bytes']+=1
    elif change=='full_hash':x['full_sha256']='0'*64
    elif change=='sent_size':x['sent_bytes']+=1
    elif change=='sent_bool':x['sent_bytes']=True
    elif change=='sent_hash':x['sent_sha256']='0'*64
    elif change=='sent_b64':x['sent_b64']=f.n.encode(v['observed']+b'!')
    elif change=='newline':x['newline_sent']=not x['newline_sent']
    elif change=='reply':reply['body_b64']=f.n.encode(b'other body')
    elif change=='phase':x['phase']='NATIVE_ACK_RECEIVED'
    with pytest.raises((ValueError,KeyError,TypeError)):f.validate_send(x,reply,'A0',v['send'][0]['namespace'],v['mode'],after)


def test_runtime_eof_and_sender_join(vector):
    v=vector
    if v['mode']=='normal':return
    ack=v['acks'][-1];ns=ack['namespace'];parts=v['parts'];observed=v['observed']
    record=dict(custody_crash=dict(pid=v['pid'],exit_code=-9,controller_kill_sent=False,observed_ns=ack['at_ns']+1,controller_killed_roles=['ledger','issuer','backend']),
        ack_events=v['acks'],pids_before=dict(custody=v['pid']),initial=dict(pid=12345),repeated=dict(pid=12346),fault=v['mode'],send_events=v['send'],
        native_ipc=[dict(uid=z.b.RUNTIME,pid=12345,namespace=ns,observed_bytes=len(observed),observed_sha256=f.e.sha(observed),observed_b64=f.n.encode(observed),
            read_sizes=[len(p) for p in parts],read_outcomes=['bytes' if p else 'eof' for p in parts],error_class='ValueError',reason='BOUNDED_FRAME')])
    assert z.validate_crash_join(record,ns)
    for field,value in [('observed_bytes',0),('observed_b64',f.n.encode(observed+b'\n')),('read_sizes',[len(observed)]),('read_outcomes',['bytes']),('reason','timeout'),('pid',0)]:
        bad=copy.deepcopy(record);bad['native_ipc'][0][field]=value
        with pytest.raises((ValueError,TypeError,KeyError)):z.validate_crash_join(bad,ns)


def test_explicit_disposable_only_source_and_no_policy_relaxation():
    assert z.sources()['archive_fixture']==f.source_sha256()
    assert normal.sources()['archive_fixture']==f.source_sha256()
    assert z.deadline.TOTAL_NS==2_000_000_000 and z.deadline.MAX_READS==256
    assert z.ingress.raw.LIMIT==32768
    text=Path(z.__file__).read_text()
    assert 'DISPOSABLE_UID_COLLISION_NO_REPAIR' in text and 'socket' in Path(f.__file__).read_text()


@pytest.mark.parametrize('path',['native','backend','other'])
@pytest.mark.parametrize('decision',['ARCHIVED_NATIVE_RESPONSE','REPLAY_DENIED'])
def test_socket_observer_is_scoped_to_success_on_exact_native_path(tmp_path,monkeypatch,path,decision):
    # Explicit fake sockets: routing test only, not a kernel transport claim.
    calls=[]
    class Conn:
        def sendall(self,wire):calls.append(('delegated',wire))
    conn=Conn()
    class Server:
        family=socket.AF_UNIX
        def accept(self):return conn,'peer'
        def getsockname(self):
            return str(tmp_path/('ipc/native.sock' if path=='native' else 'backend-ipc/backend.sock' if path=='backend' else 'other.sock'))
    monkeypatch.setattr(socket,'socket',Server)
    monkeypatch.setattr(f,'send',lambda conn,wire,*args:calls.append(('selected',wire)))
    f.install(tmp_path,'one-byte',lambda _:None,lambda _:None)
    accepted,_=socket.socket().accept()
    wire=f.n.canonical(dict(decision=decision))+b'\n';accepted.sendall(wire)
    assert calls==[('selected' if path=='native' and decision=='ARCHIVED_NATIVE_RESPONSE' else 'delegated',wire)]
