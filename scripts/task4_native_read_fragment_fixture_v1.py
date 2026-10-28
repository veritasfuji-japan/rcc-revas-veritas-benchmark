"""Explicit synthetic TLS application-write schedule; no collector replacement.

A TLS write is not assumed to equal a read universally. Full observed receive
fragments must match this schedule in the selected actual local TLS fixture.
"""
from pathlib import Path
import os
import ssl
import time
from scripts import task4_native_bounded_unix_egress_v1 as m
from scripts import task4_native_total_deadline_v1 as deadline
from scripts import task4_native_response_id_guard_v1 as guard
from scripts import task4_native_response_framing_guard_v1 as frame
n,u,e,ingress=m.n,m.u,m.e,m.ingress
need=m.need
MODES=('normal','complete-at-cap','prefix-at-cap')
COUNT=256


def source_sha256():return e.sha(Path(__file__).read_bytes())


def fragments(wire,mode):
    need(type(wire) is bytes and mode in MODES and len(wire)>COUNT and len(wire)<=ingress.raw.LIMIT)
    status,headers,_=ingress.raw.parse_wire(wire,'eof')
    need(status==200);guard.require_one_id(headers);frame.require_framing(wire)
    count=COUNT-1 if mode=='normal' else COUNT
    sent=wire[:COUNT] if mode=='prefix-at-cap' else wire
    return [sent[i*len(sent)//count:(i+1)*len(sent)//count] for i in range(count)]


def send_response(base,wire,channel,mode):
    n.kernel.role_identity(n.BACKEND)
    post=u.read_lines(base/'backend/raw-posts.jsonl')[-1];op=post['op']
    status,headers,body=ingress.raw.parse_wire(wire,'eof')
    row=next(x for x in u.effects(base) if x[0]==op)
    need(status==200 and guard.require_one_id(headers)['request_id']=='native-local-'+op
         and post['authorized'] is True and post['wire_sha256']==e.sha(wire) and post['wire_bytes']==len(wire)
         and post['response_sha256']==e.sha(body) and row==(op,post['request_sha256'],e.sha(body),n.digest(dict(operation_id=op,request_sha256=post['request_sha256'],response_sha256=e.sha(body)))))
    parts=fragments(wire,mode);sent=bytearray();sends=[];started=time.monotonic_ns()
    for part in parts:
        channel.sendall(part);sent.extend(part)
        sends.append(dict(part_b64=n.encode(part),finished_ns=time.monotonic_ns(),cumulative_bytes=len(sent)))
    terminal_started=time.monotonic_ns();channel.settimeout(5)
    if mode=='normal':
        try:
            plain=channel.unwrap();plain.close();result='UNWRAPPED'
        except (BrokenPipeError,ConnectionResetError,ssl.SSLEOFError) as error:result=type(error).__name__
        termination='TLS_CLOSE_NOTIFY'
    else:
        try:need(channel.recv(1)==b'');result='EOF'
        except (BrokenPipeError,ConnectionResetError,ssl.SSLEOFError) as error:result=type(error).__name__
        termination='HOLD_OPEN_UNTIL_CLIENT_CLOSE'
    finished=time.monotonic_ns()
    record=dict(op=op,mode=mode,uid=os.geteuid(),namespace=e.namespace(),wire_b64=n.encode(wire),
        wire_sha256=e.sha(wire),wire_bytes=len(wire),transmitted_b64=n.encode(bytes(sent)),
        transmitted_sha256=e.sha(bytes(sent)),transmitted_bytes=len(sent),writes=sends,
        started_ns=started,terminal_started_ns=terminal_started,terminal_finished_ns=finished,
        termination=termination,terminal_result=result,phase='COMMITTED_EFFECT_FRAGMENTED_TLS_RESPONSE')
    u.append(base/'backend/read-fragments.jsonl',record)
    return record


def validate_record(record,wire,mode,op,namespace):
    parts=fragments(wire,mode);sent=b''.join(parts)
    need(set(record)=={'op','mode','uid','namespace','wire_b64','wire_sha256','wire_bytes','transmitted_b64',
        'transmitted_sha256','transmitted_bytes','writes','started_ns','terminal_started_ns','terminal_finished_ns',
        'termination','terminal_result','phase'})
    need(record['op']==op and record['mode']==mode and record['uid']==n.BACKEND and record['namespace']==namespace
         and record['wire_b64']==n.encode(wire) and record['wire_sha256']==e.sha(wire) and record['wire_bytes']==len(wire)
         and record['transmitted_b64']==n.encode(sent) and record['transmitted_sha256']==e.sha(sent)
         and record['transmitted_bytes']==len(sent) and record['phase']=='COMMITTED_EFFECT_FRAGMENTED_TLS_RESPONSE')
    need(all(type(record[k]) is int and record[k]>0 for k in ('started_ns','terminal_started_ns','terminal_finished_ns'))
         and record['started_ns']<=record['terminal_started_ns']<=record['terminal_finished_ns'])
    expected='TLS_CLOSE_NOTIFY' if mode=='normal' else 'HOLD_OPEN_UNTIL_CLIENT_CLOSE'
    allowed={'UNWRAPPED','BrokenPipeError','ConnectionResetError','SSLEOFError'} if mode=='normal' else {'EOF','BrokenPipeError','ConnectionResetError','SSLEOFError'}
    need(record['termination']==expected and record['terminal_result'] in allowed and len(record['writes'])==len(parts))
    previous=record['started_ns'];total=0
    for item,part in zip(record['writes'],parts):
        total+=len(part)
        need(set(item)=={'part_b64','finished_ns','cumulative_bytes'} and item['part_b64']==n.encode(part)
             and type(item['finished_ns']) is int and previous<=item['finished_ns']<=record['terminal_started_ns']
             and type(item['cumulative_bytes']) is int and item['cumulative_bytes']==total)
        previous=item['finished_ns']
    return sent


def validate_collection(collection,wire,mode):
    need(deadline.MAX_READS==COUNT)
    parts=fragments(wire,mode);observed=b''.join(parts)
    completion,reason=('eof','eof') if mode=='normal' else ('limit','read-count-limit')
    deadline.validate_collection(collection,observed,completion,reason)
    reads=collection['reads'];need(len(reads)==COUNT and collection['finished_ns']<collection['deadline_ns'])
    data=reads[:-1] if mode=='normal' else reads
    need(len(data)==len(parts) and all(x['outcome']=='bytes' and n.decode(x['part_b64'])==part
         and x['after_ns']<collection['deadline_ns'] for x,part in zip(data,parts)))
    if mode=='normal':need(reads[-1]['outcome']=='eof' and reads[-1]['part_b64']=='')
    return observed
