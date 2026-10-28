"""Closed fixture response-ID guard; no transport, authority, retry or live profile."""
import hashlib
from pathlib import Path
import re

PROFILE='task4.native-response-id-guard.v1'
TOKEN=re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}',re.ASCII)


class AmbiguousResponseId(ValueError):
    """No unique bounded ASCII response-ID token is available."""


def source_sha256():return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def id_values(headers):
    """Preserve occurrences and values; never collapse headers into a dictionary."""
    if type(headers) not in (list,tuple):raise AmbiguousResponseId('RESPONSE_ID_HEADERS_SHAPE')
    values=[]
    for row in headers:
        if type(row) not in (list,tuple) or len(row)!=2 or not all(type(x) is str for x in row):
            raise AmbiguousResponseId('RESPONSE_ID_HEADERS_SHAPE')
        name,value=row
        if name.casefold()=='x-request-id':values.append(value)
    return values


def require_one_id(headers):
    """Require one header and one token without trimming, splitting or normalization."""
    values=id_values(headers)
    if len(values)!=1 or TOKEN.fullmatch(values[0]) is None:
        raise AmbiguousResponseId('ONE_BOUNDED_ASCII_RESPONSE_ID_REQUIRED')
    return dict(field_count=1,request_id=values[0])
