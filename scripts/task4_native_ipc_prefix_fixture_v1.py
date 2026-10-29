"""Selected real Unix send prefixes after the original Custody handler returns.

The accepted native.sock alone is wrapped. No handler, serializer, client frame,
authority or replay response is replaced. sendall success is local acceptance,
not a claim of remote acknowledgement; the Runtime independently records bytes.
"""
import json
import os
from pathlib import Path
import socket
from scripts import task4_native_reply_ack_fixture_v1 as old
m,n,u,e,ingress,need=old.m,old.n,old.u,old.e,old.ingress,old.need
MODES=('one-byte','mid-json','without-newline')
snapshot=old.snapshot


def source_sha256():
    need(old.source_sha256()=='0ef9b1f25c7815ac193540e3c88da5fbcdb78c13fda84fa2f7f7e2b167a38a70')
    return e.sha(Path(__file__).read_bytes())


def selected(wire,fault):
    need(type(wire) is bytes and wire.endswith(b'\n') and b'\n' not in wire[:-1])
    reply=json.loads(wire);need(wire==n.canonical(reply)+b'\n' and reply['decision']=='ARCHIVED_NATIVE_RESPONSE')
    need(fault=='normal' or fault in MODES)
    count=len(wire) if fault=='normal' else 1 if fault=='one-byte' else len(wire)//2 if fault=='mid-json' else len(wire)-1
    need(0<count<=len(wire));return wire[:count]


def audit_seal(original,*args,fault,emit,ack_emit,**kwargs):
    need(fault=='normal' or fault in MODES)
    return old.audit_seal(original,*args,**kwargs,fault='normal',emit=emit,ack_emit=ack_emit)


def consume(original,*args,fault,emit):
    need(fault=='normal' or fault in MODES)
    return old.consume(original,*args,fault='normal',emit=emit)


def validate_audit(events,wire,plan,slot,fault,namespace,final):
    need(fault=='normal' or fault in MODES)
    return old.validate_audit(events,wire,plan,slot,'normal',namespace,final)


def send(conn,wire,base,fault,emit,ack_emit):
    n.kernel.role_identity(n.CUSTODY)
    prefix=selected(wire,fault);reply=json.loads(wire)
    slot=reply['archive']['statement']['operation_id']
    need(slot in [arm+str(i) for arm in 'AB' for i in range(4)])
    conn.sendall(prefix)  # Real selected bytes accepted by the actual Unix socket.
    emit(old.event(slot,'SEND_RETURNED',pid=os.getpid(),boundary=fault,full_bytes=len(wire),full_sha256=e.sha(wire),
        sent_bytes=len(prefix),sent_sha256=e.sha(prefix),sent_b64=n.encode(prefix),newline_sent=prefix.endswith(b'\n')))
    if fault!='normal':old.halt(base,slot,fault,ack_emit)


def install(base,fault,emit,ack_emit):
    """Keep the original server loop and SO_PEERCRED check; scope to native.sock."""
    need(fault=='normal' or fault in MODES);original=socket.socket
    class Connection:
        def __init__(self,conn):self.conn=conn
        def __getattr__(self,name):return getattr(self.conn,name)
        def __enter__(self):self.conn.__enter__();return self
        def __exit__(self,*args):return self.conn.__exit__(*args)
        def sendall(self,wire,*args,**kwargs):
            if json.loads(wire).get('decision')!='ARCHIVED_NATIVE_RESPONSE':return self.conn.sendall(wire,*args,**kwargs)
            need(not args and not kwargs)
            return send(self.conn,wire,base,fault,emit,ack_emit)
    class Observed(original):
        def accept(self):
            conn,address=super().accept()
            return (Connection(conn) if self.family==socket.AF_UNIX and self.getsockname()==str(base/'ipc/native.sock') else conn),address
    socket.socket=Observed
    return original


def validate_send(event,reply,slot,namespace,fault,after_ns):
    wire=n.canonical(reply)+b'\n';prefix=selected(wire,fault)
    need(set(event)=={'op','phase','uid','namespace','at_ns','pid','boundary','full_bytes','full_sha256','sent_bytes','sent_sha256','sent_b64','newline_sent'})
    need(event['op']==slot and event['phase']=='SEND_RETURNED' and type(event['uid']) is int and event['uid']==n.CUSTODY
        and event['namespace']==namespace and type(event['at_ns']) is int and event['at_ns']>=after_ns
        and type(event['pid']) is int and event['pid']>0 and event['boundary']==fault
        and type(event['full_bytes']) is int and event['full_bytes']==len(wire) and event['full_sha256']==e.sha(wire)
        and type(event['sent_bytes']) is int and event['sent_bytes']==len(prefix) and event['sent_sha256']==e.sha(prefix)
        and event['sent_b64']==n.encode(prefix) and event['newline_sent'] is (fault=='normal'))
    return prefix


def validate_ack(events,slot,namespace,fault,audit,final,row=None,reply=None):
    if fault=='normal':return old.validate_ack(events,slot,namespace,fault,audit,final,row,reply)
    need(fault in MODES and type(events) is list and len(events)==3)
    old.validate_ack(events[:2],slot,namespace,'normal',audit,final,row,reply)
    intent=events[-1]
    need(set(intent)=={'op','phase','uid','namespace','at_ns','boundary','pid','signal','snapshot'}
        and intent['op']==slot and intent['phase']=='CRASH_INTENT' and type(intent['uid']) is int and intent['uid']==n.CUSTODY
        and intent['namespace']==namespace and type(intent['at_ns']) is int and intent['at_ns']>=events[1]['at_ns']
        and intent['boundary']==fault and type(intent['pid']) is int and intent['pid']>0
        and type(intent['signal']) is int and intent['signal']==9 and intent['snapshot']==final)
    return True
