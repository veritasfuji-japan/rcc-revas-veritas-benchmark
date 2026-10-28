"""Closed Content-Length-only response framing policy, no I/O or permissions.

Not a universal HTTP parser. Keep original parse/JSON and occurrence-preserving
ID verification after durable archive; this guard grants no execution authority.
"""
import hashlib
from pathlib import Path
import re

PROFILE='task4.native-response-framing-guard.v1'
LIMIT=32768
NAME=re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+",re.ASCII)
DECIMAL=re.compile(rb'(?:0|[1-9][0-9]{0,4})',re.ASCII)

class AmbiguousFraming(ValueError):
    pass


def source_sha256():return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def require_framing(wire):
    """One canonical length, no transfer coding, exact EOF body length, no suffix."""
    def need(value):
        if not value:raise AmbiguousFraming('CLOSED_RESPONSE_FRAMING_STOP')
    need(type(wire) is bytes and 0<len(wire)<=LIMIT)
    head,separator,body=wire.partition(b'\r\n\r\n')
    need(separator==b'\r\n\r\n')
    rows=head.split(b'\r\n');need(rows[0]==b'HTTP/1.1 200 OK')
    lengths=[]
    for row in rows[1:]:
        name,colon,value=row.partition(b':')
        need(colon==b':' and NAME.fullmatch(name) is not None
             and all(32<=byte<=126 for byte in value))
        need(name.lower()!=b'transfer-encoding')
        if name.lower()==b'content-length':
            need(value.startswith(b' ') and DECIMAL.fullmatch(value[1:]) is not None)
            lengths.append(int(value[1:]))
    need(len(lengths)==1 and lengths[0]==len(body))
    return dict(length_field_count=1,content_length=lengths[0],body_bytes=len(body),transfer_encoding_present=False)
