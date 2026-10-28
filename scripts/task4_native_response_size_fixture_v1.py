"""Explicit local JSON-whitespace size fixture, never a Provider adapter.

The original scripted JSON is produced first; padding happens before the original
backend commits/hash-binds its body. No authority, collector or SDK is replaced.
"""
from pathlib import Path
import os
from scripts import task4_native_bounded_unix_egress_v1 as m
n,u,e,b,ingress=m.n,m.u,m.e,m.b,m.ingress
need=m.need
LIMIT=ingress.raw.LIMIT
TARGETS=(LIMIT-1,LIMIT,LIMIT+1,LIMIT+4096)
PHASE='SYNTHETIC_JSON_WHITESPACE_PADDED_BEFORE_EFFECT'


def source_sha256():return e.sha(Path(__file__).read_bytes())


def padded_body(original,op,target):
    need(type(original) is bytes and type(op) is str and op in {a+str(i) for a in 'AB' for i in range(4)}
         and type(target) is int and target in TARGETS)
    code,headers,body=ingress.raw.parse_wire(ingress.response_wire(original,op,'success'),'eof')
    need(code==200 and body==original and n.canonical(ingress.raw.strict(original))==original)
    count=target-len(ingress.response_wire(original,op,'success'))
    need(count>=0)
    for _ in range(8):
        padded=original+b' '*count
        size=len(ingress.response_wire(padded,op,'success'))
        if size==target:return padded
        count+=target-size;need(count>=0)
    raise ValueError('CLOSED_PADDING_SIZE_STOP')


def install_backend(base,target_for_op):
    original=b.scripted_response
    def scripted(source,request,op):
        body=original(source,request,op);target=target_for_op(op)
        padded=padded_body(body,op,target)
        u.append(base/'backend/size-fixture.jsonl',dict(op=op,uid=os.geteuid(),namespace=e.namespace(),
            original_body_b64=n.encode(body),original_body_sha256=e.sha(body),padded_body_sha256=e.sha(padded),
            target_wire_bytes=target,padded_body_bytes=len(padded),phase=PHASE))
        return padded
    b.scripted_response=scripted


def validate_padding(record,wire,op,target,namespace):
    original=n.decode(record['original_body_b64']);padded=padded_body(original,op,target)
    need(record==dict(op=op,uid=n.BACKEND,namespace=namespace,
        original_body_b64=n.encode(original),original_body_sha256=e.sha(original),padded_body_sha256=e.sha(padded),
        target_wire_bytes=target,padded_body_bytes=len(padded),phase=PHASE)
        and ingress.response_wire(padded,op,'success')==wire and len(wire)==target)
    return padded
