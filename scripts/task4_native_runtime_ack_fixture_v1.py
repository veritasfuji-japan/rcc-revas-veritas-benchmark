"""Full original Native frame/RPC returns before delivery to the SDK caller.

The original framer parses JSON. This observer does not add a signature check or
turn an internal return into permission. Selected negative modes self-SIGKILL;
the positive mode delegates the same original call path and returns unchanged.
"""
import os
from pathlib import Path
import signal
import time
from unittest.mock import patch
from scripts import task4_native_ipc_prefix_fixture_v1 as old
m,n,u,e,ingress,need=old.m,old.n,old.u,old.e,old.ingress,old.need
b=m.b
MODES=('after-frame-return','after-rpc-return')
snapshot=old.snapshot


def source_sha256():
    need(old.source_sha256()=='7fe53b2855e8f0d997ff7d723dae8a12fd1b837c84932f234d956e1b0cb729c3')
    return e.sha(Path(__file__).read_bytes())


def event(phase,**data):
    return dict(phase=phase,uid=os.geteuid(),pid=os.getpid(),namespace=e.namespace(),at_ns=time.monotonic_ns(),**data)


def halt(fault,emit):
    emit(event('RUNTIME_CRASH_INTENT',boundary=fault,signal=int(signal.SIGKILL)))
    os.kill(os.getpid(),signal.SIGKILL)
    raise AssertionError('RUNTIME_SIGKILL_MUST_NOT_RETURN')


def receive(original,base,packet,name,fault,emit):
    need(fault=='normal' or fault in MODES)
    if name!='native':return original(base,packet,name)
    frame=n.frame;parts=[];connections=[]
    def observed(conn):
        connections.append(conn)
        class Reader:
            def recv(self,limit):
                part=conn.recv(limit);parts.append(part);return part
        reply=frame(Reader())  # Actual original newline framing and JSON parsing.
        if type(reply) is not dict or reply.get('decision')!='ARCHIVED_NATIVE_RESPONSE':return reply
        wire=b''.join(parts)
        emit(event('FRAME_RETURNED',reply=reply,wire_b64=n.encode(wire),observed_bytes=len(wire),observed_sha256=e.sha(wire),
            read_sizes=[len(p) for p in parts],read_outcomes=['bytes' if p else 'eof' for p in parts],socket_open=conn.fileno()>=0))
        if fault=='after-frame-return':halt(fault,emit)
        return reply
    with patch.object(n,'frame',observed):result=original(base,packet,name)
    need(len(connections)==1)
    if type(result) is not dict or result.get('decision')!='ARCHIVED_NATIVE_RESPONSE':return result
    emit(event('RPC_RETURNED',reply=result,socket_closed=connections[0].fileno()==-1))
    if fault=='after-rpc-return':halt(fault,emit)
    return result


def native(original,base,fault,emit):
    n.kernel.role_identity(b.RUNTIME);need(fault=='normal' or fault in MODES)
    from scripts import task4_325_exact_sdk_wire_offline_v1 as cap
    from scripts.task4_471_same_run_capped_sdk_aead_native_no_go_v1 import verify_pins
    emit(event('NATIVE_ENTER',frozen_source_git_blobs=verify_pins()))
    rpc=b.rpc;sdk=cap.adapter.create_completion_once
    def observe(base,packet,name='issuer'):
        if fault!='normal':
            if name=='issuer' and packet.get('action')=='authorize' and packet.get('arm')=='A' and packet.get('parent') is None:
                wire=n.decode(packet['wire_b64'])
                if b.canonical(b.raw.strict(wire))==b.canonical(b.seed()):
                    file=base/'runtime/backend-loss-query.json'
                    if file.exists():need(b.raw.strict(file.read_bytes())==packet)
                    else:n.durable_marker(file,packet)
            if name=='native':
                file=base/'runtime/backend-loss-packet.json';need(not file.exists());n.durable_marker(file,packet)
        return receive(rpc,base,packet,name,fault,emit)
    def observed_sdk(**kwargs):
        emit(event('SDK_CALL_ENTER'))
        result=sdk(**kwargs)
        emit(event('SDK_CALL_RETURNED'))
        return result
    with patch.object(b,'rpc',observe),patch.object(cap.adapter,'create_completion_once',observed_sdk):
        result=original(base)
    emit(event('NATIVE_RETURNED',result_sha256=n.digest(result),records=len(result['records']),scorer_calls=result['scorer_calls']))
    return result


def audit_seal(original,*args,fault,emit,ack_emit,**kwargs):
    need(fault=='normal' or fault in MODES)
    return old.audit_seal(original,*args,**kwargs,fault='normal',emit=emit,ack_emit=ack_emit)


def consume(original,*args,fault,emit):
    need(fault=='normal' or fault in MODES)
    return old.consume(original,*args,fault='normal',emit=emit)


def install(base,fault,emit,ack_emit):
    need(fault=='normal' or fault in MODES)
    return old.install(base,'normal',emit,ack_emit)


def validate_audit(events,wire,plan,slot,fault,namespace,final):
    need(fault=='normal' or fault in MODES)
    return old.validate_audit(events,wire,plan,slot,'normal',namespace,final)


def validate_ack(events,slot,namespace,fault,audit,final,row=None,reply=None):
    need(fault=='normal' or fault in MODES)
    return old.validate_ack(events,slot,namespace,'normal',audit,final,row,reply)


validate_send=old.validate_send


def validate_events(events,fault,namespace,replies,pid,after_ns=0,native_result=None):
    need(fault=='normal' or fault in MODES)
    common={'phase','uid','pid','namespace','at_ns'}
    extra={'NATIVE_ENTER':{'frozen_source_git_blobs'},'SDK_CALL_ENTER':set(),'SDK_CALL_RETURNED':set(),
        'FRAME_RETURNED':{'reply','wire_b64','observed_bytes','observed_sha256','read_sizes','read_outcomes','socket_open'},
        'RPC_RETURNED':{'reply','socket_closed'},'RUNTIME_CRASH_INTENT':{'boundary','signal'},
        'NATIVE_RETURNED':{'result_sha256','records','scorer_calls'}}
    middle=['SDK_CALL_ENTER','FRAME_RETURNED']+([] if fault=='after-frame-return' else ['RPC_RETURNED'])
    phases=['NATIVE_ENTER']+(middle+['SDK_CALL_RETURNED'])*8+['NATIVE_RETURNED'] if fault=='normal' else ['NATIVE_ENTER']+middle+['RUNTIME_CRASH_INTENT']
    need(type(events) is list and [x['phase'] for x in events]==phases and type(pid) is int and pid>0)
    last=0
    for x in events:
        need(set(x)==common|extra[x['phase']] and type(x['uid']) is int and x['uid']==b.RUNTIME and type(x['pid']) is int and x['pid']==pid
            and x['namespace']==namespace and type(x['at_ns']) is int and x['at_ns']>0 and x['at_ns']>=last);last=x['at_ns']
    from scripts.task4_471_same_run_capped_sdk_aead_native_no_go_v1 import verify_pins
    pins=events[0]['frozen_source_git_blobs'];need(pins==verify_pins())
    frames=[x for x in events if x['phase']=='FRAME_RETURNED'];returned=[x for x in events if x['phase']=='RPC_RETURNED']
    need(len(frames)==len(replies)==(8 if fault=='normal' else 1))
    for i,(x,reply) in enumerate(zip(frames,replies)):
        wire=n.canonical(reply)+b'\n';sizes=x['read_sizes']
        need(type(sizes) is list and len(sizes)>0 and all(type(v) is int and 0<v<=4096 for v in sizes) and sum(sizes)==len(wire)
            and x['read_outcomes']==['bytes']*len(sizes) and type(x['observed_bytes']) is int and x['observed_bytes']==len(wire)
            and x['wire_b64']==n.encode(wire) and x['observed_sha256']==e.sha(wire) and n.canonical(x['reply'])==n.canonical(reply)
            and x['socket_open'] is True and x['at_ns']>=after_ns)
        if fault!='after-frame-return':need(n.canonical(returned[i]['reply'])==n.canonical(reply) and returned[i]['socket_closed'] is True)
    if fault=='normal':
        x=events[-1];need(native_result is not None and x['result_sha256']==n.digest(native_result) and type(x['records']) is int and x['records']==8
            and type(x['scorer_calls']) is int and x['scorer_calls']==2 and native_result['frozen_source_git_blobs']==pins)
    else:
        x=events[-1];need(x['boundary']==fault and type(x['signal']) is int and x['signal']==9)
    return True
