"""Actual portable SIGKILL after returns; original full Native handler proof is CI."""
import copy,json,os,signal,sqlite3,subprocess,sys,time
from pathlib import Path
import pytest
from scripts import task4_native_reply_ack_fixture_v1 as f
from scripts import task4_native_reply_ack_loss_v1 as z
from scripts import task4_native_reply_ack_normal_v1 as normal


def wire():
    body=z.n.canonical(dict(id='local',object='chat.completion',model=z.ingress.raw.request_parameters()['model'],choices=[dict(index=0)]))
    return z.ingress.response_wire(body,'A0','success')


@pytest.fixture
def base(tmp_path,monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    key=X25519PrivateKey.generate();pub=key.public_key().public_bytes_raw()
    (tmp_path/'public').mkdir();(tmp_path/'public/recipient.pub').write_bytes(pub)
    (tmp_path/'custody').mkdir(mode=0o700);(tmp_path/'custody/archives').mkdir(mode=0o700)
    monkeypatch.setattr(f.n,'CUSTODY',os.geteuid());monkeypatch.setattr(f.n.kernel,'role_identity',lambda _:None)
    old=os.umask(0o077)
    try:yield tmp_path,key,dict(run_id='a'*64,request_sha256=f.e.sha(b'public request'),recipient_sha256=f.e.sha(pub))
    finally:os.umask(old)


CHILD='''import sys,os,json,sqlite3
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from scripts import task4_native_reply_ack_fixture_v1 as f
f.n.CUSTODY=os.geteuid();f.n.kernel.role_identity=lambda uid:None
base=Path(sys.argv[2]);plan=json.loads(sys.argv[3]);wire=f.n.decode(sys.argv[4]);fault=sys.argv[5]
emit=lambda x:f.u.append(base/'audit.jsonl',x)
ack=lambda x:f.u.append(base/'acks.jsonl',x)
archive=f.audit_seal(f.ingress.raw.seal,base,'A0',wire,'eof',plan,fault,emit,ack)
db=sqlite3.connect(base/'portable.sqlite3',isolation_level=None)
db.execute('CREATE TABLE consumed(op TEXT PRIMARY KEY,state TEXT,request_sha TEXT,response_sha TEXT,backend_receipt TEXT,envelope_sha TEXT,bind_sha TEXT)')
# Explicit portable stand-in, not the original signed Native handler. Root CI
# delegates the real frozen consume_packet including Bind and ledger gates.
def original(base,db,packet,public,key,signer):
 db.execute('INSERT INTO consumed VALUES (?,?,?,?,?,?,?)',('A0','MOCK_OBSERVED',plan['request_sha256'],'b'*64,'c'*64,archive['envelope_sha256'],'d'*64))
 return dict(decision='ARCHIVED_NATIVE_RESPONSE',body_b64=f.n.encode(wire),archive=archive)
f.consume(original,base,db,dict(arm='A',ordinal=0),None,None,None,fault,ack)
'''


def make_vector(mode,base):
    path,_,plan=base
    child=subprocess.Popen([sys.executable,'-I','-B','-c',CHILD,str(Path(__file__).parents[1]),str(path),json.dumps(plan),z.n.encode(wire()),mode],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:out,err=child.communicate(timeout=10)
    except BaseException:child.kill();child.wait(timeout=5);raise
    assert child.returncode==(0 if mode=='normal' else -9) and not out and not err
    audit=[json.loads(x) for x in (path/'audit.jsonl').read_bytes().splitlines()]
    ack=[json.loads(x) for x in (path/'acks.jsonl').read_bytes().splitlines()]
    return dict(mode=mode,audit=audit,acks=ack,final=f.snapshot(path,'A0'),pid=child.pid),base


@pytest.fixture(params=['normal',*f.MODES])
def vector(request,base):return make_vector(request.param,base)


def validate(v,base):
    mode=v['mode'];a=v['audit'];x=v['acks'];ns=a[0]['namespace'];reply=None;row=None
    if mode!='after-seal-return':reply=x[1]['reply'];row=x[1]['row']
    f.validate_audit(a,wire(),base[2],'A0',mode,ns,v['final'])
    return f.validate_ack(x,'A0',ns,mode,a,v['final'],row,reply)


def test_actual_child_death_after_original_return_is_not_native_ack(vector):
    v,base=vector;assert validate(v,base)
    assert len(v['audit'])==15 and v['audit'][-1]['phase']=='SEAL_RETURN' and v['audit'][-1]['functions_restored'] is True
    assert v['final']['file']['size']>0
    if v['mode']!='normal':assert v['acks'][-1]['pid']==v['pid'] and v['acks'][-1]['signal']==9
    if v['mode']=='after-seal-return':assert not (base[0]/'portable.sqlite3').exists()
    else:
        with sqlite3.connect(base[0]/'portable.sqlite3') as db:assert db.execute('SELECT count(*) FROM consumed').fetchone()[0]==1


@pytest.mark.parametrize('change',['missing','extra','phase','uid','namespace','time','archive_hash','archive_ack','archive_return','snapshot','mode','pid','signal','transaction','row','reply'])
def test_return_and_ack_event_evidence_tampering_is_rejected(vector,change):
    v,base=vector;x=v['acks'];a=v['audit'];last=x[-1]
    if change=='missing':x.pop()
    elif change=='extra':x.append(copy.deepcopy(last))
    elif change=='phase':last['phase']='NATIVE_ACK_RECEIVED'
    elif change=='uid':x[0]['uid']+=1
    elif change=='namespace':x[0]['namespace']={}
    elif change=='time':x[0]['at_ns']=a[-1]['at_ns']-1
    elif change=='archive_hash':x[0]['archive']['envelope_sha256']='0'*64
    elif change=='archive_ack':x[0]['archive']['local_fsync_completed']=False
    elif change=='archive_return':a[-1]['phase']='SEAL_EXCEPTION'
    elif change=='snapshot':v['final']['blob_sha256']='0'*64
    elif change=='mode':
        if v['mode']=='normal':x[0]['op']='B0'
        else:last['boundary']='other'
    elif change=='pid':
        if v['mode']=='normal':x[0]['uid']=-1
        else:last['pid']=0
    elif change=='signal':
        if v['mode']=='normal':x[0]['at_ns']=0
        else:last['signal']=15
    elif change=='transaction':
        if v['mode']=='after-seal-return':last['snapshot']['exists']=False
        else:x[1]['in_transaction']=True
    elif change=='row':
        if v['mode']=='after-seal-return':last['snapshot']['blob_sha256']='0'*64
        else:x[1]['row']=['other']
    else:
        if v['mode']=='after-seal-return':last['snapshot']['file']['inode']+=1
        else:x[1]['reply']={'decision':'REPLAY_DENIED'}
    # Hold independent expected handler outputs; do not validate a changed value
    # against itself when exercising the helper's join to original evidence.
    row=['A0','MOCK_OBSERVED',base[2]['request_sha256'],'b'*64,'c'*64,a[-1].get('archive',{}).get('envelope_sha256'),'d'*64]
    reply=dict(decision='ARCHIVED_NATIVE_RESPONSE',body_b64=z.n.encode(wire()),archive=a[-1].get('archive'))
    with pytest.raises((ValueError,KeyError,TypeError)):
        f.validate_audit(a,wire(),base[2],'A0',v['mode'],a[0]['namespace'],v['final'])
        f.validate_ack(x,'A0',a[0]['namespace'],v['mode'],a,v['final'],row,reply)



def test_replay_refusal_is_delegated_without_new_ack_or_crash(base):
    calls=[]
    def original(*args):calls.append(1);return {'decision':'REPLAY_DENIED'}
    assert f.consume(original,base[0],None,{},None,None,None,'before-native-reply',lambda x:pytest.fail('unexpected evidence'))=={'decision':'REPLAY_DENIED'}
    assert calls==[1]


@pytest.mark.parametrize('module',[z,normal])
def test_no_privilege_or_output_before_ack(module,monkeypatch):
    monkeypatch.setattr(module.e,'require_root',lambda:pytest.fail('privilege before ack'))
    with pytest.raises(ValueError):module.run(Path('/tmp/unused'))


@pytest.mark.parametrize('module',[z,normal])
def test_cli_ack_is_exact(module,tmp_path,monkeypatch):
    calls=[];monkeypatch.setattr(module,'run',lambda *args:calls.append(args))
    args=['--run','--output',str(tmp_path/'proof')]
    if module is z:args+=['--crash-point','after-seal-return','--acknowledge-isolated-reply-ack-loss-test'];expected=(tmp_path/'proof','after-seal-return',True)
    else:args+=['--acknowledge-isolated-reply-ack-normal-test'];expected=(tmp_path/'proof',True)
    module.main(args);assert calls==[expected]


def test_source_pins_cover_original_archive_observer():
    assert z.sources()['archive_fixture']==normal.sources()['archive_fixture']==f.source_sha256()


def test_json_row_representation_and_strict_ack_flag(vector):
    v,base=vector
    if v['mode']!='after-seal-return':
        row=tuple(v['acks'][1]['row']);reply=copy.deepcopy(v['acks'][1]['reply'])
        assert f.validate_ack(v['acks'],'A0',v['audit'][0]['namespace'],v['mode'],v['audit'],v['final'],row,reply)
    v['acks'][0]['archive']['local_fsync_completed']=1
    with pytest.raises(ValueError):f.validate_ack(v['acks'],'A0',v['audit'][0]['namespace'],v['mode'],v['audit'],v['final'])


@pytest.mark.parametrize('mode',f.MODES)
@pytest.mark.parametrize('change',['length','state','request','digest','empty'])
def test_retained_row_reopen_requires_the_exact_selected_state(mode,change):
    q='a'*64;row=['A0','CONSUMED_UNKNOWN',q,None,None,None,None] if mode=='after-seal-return' else ['A0','MOCK_OBSERVED',q,*(['b'*64]*4)]
    assert z.validate_rows([row],q,mode)
    if change=='length':row.pop()
    elif change=='state':row[1]='OBSERVED'
    elif change=='request':row[2]='c'*64
    elif change=='digest':row[3]='bad'
    else:row=[]
    with pytest.raises((ValueError,IndexError)):z.validate_rows([row],q,mode)


@pytest.fixture(params=f.MODES)
def trace(request,base):
    v,base=make_vector(request.param,base)
    a=v['audit'];ns=a[0]['namespace'];start=a[0]['at_ns']-1000;data=wire()
    c=dict(started_ns=start,finished_ns=start+2,deadline_ns=start+z.deadline.TOTAL_NS,total_budget_ns=z.deadline.TOTAL_NS,inactivity_seconds=.7,stop_reason='eof',
        reads=[dict(before_ns=start,after_ns=start,wait_seconds=.7,outcome='bytes',part_b64=z.n.encode(data)),dict(before_ns=start+1,after_ns=start+1,wait_seconds=.7,outcome='eof',part_b64='')],
        observed_b64=z.n.encode(data),observed_bytes=len(data),raw_sha256=z.e.sha(data),capture_completion='eof')
    common=dict(op='A0',uid=z.n.CUSTODY,namespace=ns)
    t=[dict(common,phase='CAPTURE',collection=c,channel_open=True,restored_timeout_seconds=.7),dict(common,phase='CLOSE',started_ns=start+3,finished_ns=start+4,socket_closed=True,connection_socket_cleared=True)]
    if v['mode']=='before-native-reply':
        parsed=z.ingress.raw.parse_wire(data,'eof');now=v['acks'][0]['at_ns']
        t.extend([dict(common,phase='SEALED',finished_ns=now,archive=a[-1]['archive']),dict(common,phase='PARSED',started_ns=now+1,finished_ns=now+2,raw_sha256=z.e.sha(data),response_sha256=z.e.sha(parsed[2]),
            status=200,request_id='native-local-A0',id_guard_result=z.guard.require_one_id(parsed[1]),framing_guard_result=z.frame.require_framing(data))])
    return t,data,ns,v['mode'],a


def test_actual_seal_return_and_later_parser_trace_are_not_native_delivery(trace):
    assert z.validate_trace(*trace)


@pytest.mark.parametrize('change',['not_closed','restore','close_after_archive','false_return','bad_parse_or_frame'])
def test_delivery_trace_changes_are_rejected_without_inferred_permission(trace,change):
    t,data,ns,mode,a=trace
    if change=='not_closed':t[1]['socket_closed']=False
    elif change=='restore':t[0]['restored_timeout_seconds']=2
    elif change=='close_after_archive':t[1]['finished_ns']=a[0]['at_ns']+1
    elif change=='false_return':t.append(dict(t[-1],phase='NATIVE_ACKNOWLEDGED'))
    elif mode=='before-native-reply':t[3]['framing_guard_result']={}
    else:t[0]['collection']['reads'][0]['part_b64']=''
    with pytest.raises((ValueError,KeyError,TypeError)):z.validate_trace(t,data,ns,mode,a)
