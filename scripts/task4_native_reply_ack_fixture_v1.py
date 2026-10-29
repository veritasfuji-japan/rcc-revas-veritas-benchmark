"""Actual response-acknowledgement loss after original archive/handler returns."""
import os
from pathlib import Path
import signal
import time
from scripts import task4_native_archive_close_fixture_v1 as storage
m,n,u,e,ingress,need=storage.m,storage.n,storage.u,storage.e,storage.ingress,storage.need
MODES=('after-seal-return','before-native-reply')
snapshot=storage.snapshot


def source_sha256():
    need(storage.source_sha256()=='69dd5c9269cd72e965549a098a8b15ec6e6b224c29a7d43df820284fa8f21ea0')
    return e.sha(Path(__file__).read_bytes())


def event(slot,phase,**data):
    return dict(op=slot,phase=phase,uid=os.geteuid(),namespace=e.namespace(),at_ns=time.monotonic_ns(),**data)


def halt(base,slot,fault,emit):
    emit(event(slot,'CRASH_INTENT',boundary=fault,pid=os.getpid(),signal=int(signal.SIGKILL),snapshot=snapshot(base,slot)))
    os.kill(os.getpid(),signal.SIGKILL)
    raise AssertionError('SIGKILL_MUST_NOT_RETURN')


def audit_seal(original,base,slot,wire,completion,plan,fault,emit,ack_emit):
    need(fault=='normal' or fault in MODES)
    result=storage.audit_seal(original,base,slot,wire,completion,plan,'normal',emit)
    ack_emit(event(slot,'SEAL_ACK_RETURNED',archive=result))
    if fault=='after-seal-return':halt(base,slot,fault,ack_emit)
    return result


def consume(original,base,db,packet,public,key,signer,fault,emit):
    need(fault=='normal' or fault in MODES);n.kernel.role_identity(n.CUSTODY)
    result=original(base,db,packet,public,key,signer)
    if result.get('decision')!='ARCHIVED_NATIVE_RESPONSE':return result
    slot=packet['arm']+str(packet['ordinal'])
    row=list(db.execute('SELECT op,state,request_sha,response_sha,backend_receipt,envelope_sha,bind_sha FROM consumed WHERE op=?',(slot,)).fetchone())
    emit(event(slot,'CONSUME_RETURNED',reply=result,row=row,in_transaction=db.in_transaction))
    if fault=='before-native-reply':halt(base,slot,fault,emit)
    return result


def validate_audit(events,wire,plan,slot,fault,namespace,final):
    need(fault=='normal' or fault in MODES)
    return storage.validate_audit(events,wire,plan,slot,'normal',namespace,final)


def validate_ack(events,slot,namespace,fault,audit,final,row=None,reply=None):
    need(fault=='normal' or fault in MODES)
    phases=['SEAL_ACK_RETURNED']+([] if fault=='after-seal-return' else ['CONSUME_RETURNED'])+([] if fault=='normal' else ['CRASH_INTENT'])
    need(type(events) is list and [x['phase'] for x in events]==phases)
    extra={'SEAL_ACK_RETURNED':{'archive'},'CONSUME_RETURNED':{'reply','row','in_transaction'},'CRASH_INTENT':{'boundary','pid','signal','snapshot'}}
    common={'op','phase','uid','namespace','at_ns'};last=audit[-1]['at_ns']
    for x in events:
        need(set(x)==common|extra[x['phase']] and x['op']==slot and type(x['uid']) is int and x['uid']==n.CUSTODY
            and x['namespace']==namespace and type(x['at_ns']) is int and x['at_ns']>=last);last=x['at_ns']
    need(audit[-1]['phase']=='SEAL_RETURN' and events[0]['archive'].get('local_fsync_completed') is True and events[0]['archive']==audit[-1]['archive'] and audit[-1]['snapshot']==final)
    if fault!='after-seal-return':
        x=events[1];need(x['in_transaction'] is False and n.canonical(x['row'])==n.canonical(row) and n.canonical(x['reply'])==n.canonical(reply))
    if fault!='normal':
        x=events[-1];need(x['boundary']==fault and type(x['pid']) is int and x['pid']>0 and type(x['signal']) is int and x['signal']==9 and x['snapshot']==final)
    return True
