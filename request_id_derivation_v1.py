"""Deterministic request identity for a frozen canonical Decide request.

Offline proof primitive only. This does not alter /v1/decide, CDA, promotion,
or the historical result-bearing runner.
"""
from __future__ import annotations
import hashlib, json
from copy import deepcopy
from typing import Any, Mapping

PROFILE="veritas.rveval.request-id-derivation/v1"
PREFIX="rveval-request:v1:sha256:"

def _canonical(value: Any) -> bytes:
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False).encode("utf-8")

def freeze_decide_request_identity(*, request_context: Mapping[str,Any], alternatives: list[Mapping[str,Any]],
                                   min_evidence: int=1, memory_auto_put: bool=False,
                                   persona_evolve: bool=False) -> dict[str,Any]:
    if type(request_context) is not dict or set(request_context)!={"query","context"}:
        raise ValueError("REQUEST_CONTEXT_SHAPE")
    if type(request_context["query"]) is not str or not request_context["query"]:
        raise ValueError("REQUEST_QUERY_REQUIRED")
    if type(request_context["context"]) is not dict:
        raise ValueError("REQUEST_CONTEXT_REQUIRED")
    if type(alternatives) is not list or not alternatives:
        raise ValueError("REQUEST_ALTERNATIVES_REQUIRED")
    request={"query":request_context["query"],"context":deepcopy(request_context["context"]),
             "alternatives":deepcopy(alternatives),"min_evidence":min_evidence,
             "memory_auto_put":memory_auto_put,"persona_evolve":persona_evolve}
    preimage={"profile":PROFILE,"request":request}
    digest=hashlib.sha256(_canonical(preimage)).hexdigest()
    return {"profile":PROFILE,"request_id":PREFIX+digest,"request_sha256":digest,"request":request}

def verify_decide_request_identity(packet: Mapping[str,Any]) -> dict[str,Any]:
    if type(packet) is not dict or set(packet)!={"profile","request_id","request_sha256","request"}:
        raise ValueError("REQUEST_ID_PACKET_SHAPE")
    if packet["profile"]!=PROFILE:
        raise ValueError("REQUEST_ID_PROFILE")
    raw={"profile":PROFILE,"request":packet["request"]}
    digest=hashlib.sha256(_canonical(raw)).hexdigest()
    if packet["request_sha256"]!=digest or packet["request_id"]!=PREFIX+digest:
        raise ValueError("REQUEST_ID_MISMATCH")
    return deepcopy(packet)
