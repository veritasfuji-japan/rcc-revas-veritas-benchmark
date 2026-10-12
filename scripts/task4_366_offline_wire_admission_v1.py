"""Offline-only serialized JSON inspection for the Task4 local admission rehearsal."""
import hashlib
import json
from scripts.task4_365_oneuse_session_rehearsal_v1 import consume_before_dispatch,begin_arm,MODEL,CASE

KEYS={"model","messages","tools","tool_choice","temperature","max_completion_tokens"}

def strict_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key]=value
    return result

def measure(raw,encode):
    if not isinstance(raw,bytes):
        raise ValueError("raw bytes required")
    source=raw.decode("utf-8","strict")
    obj=json.loads(source,object_pairs_hook=strict_object)
    if not isinstance(obj,dict) or set(obj)!=KEYS:
        raise ValueError("unexpected request fields")
    if obj["model"]!=MODEL or obj["max_completion_tokens"]!=256:
        raise ValueError("model or completion cap mismatch")
    if not isinstance(obj["messages"],list) or not obj["messages"]:
        raise ValueError("missing messages")
    if not isinstance(obj["tools"],list) or not obj["tools"]:
        raise ValueError("missing tools")
    if obj["tool_choice"]!="auto" or obj["temperature"]!=0:
        raise ValueError("sampling mismatch")
    tokens=len(encode(source))
    if len(raw)>10000 or tokens>10000:
        raise ValueError("local wire gate")
    return {"wire_sha256":hashlib.sha256(raw).hexdigest(),
            "local_wire_bytes":len(raw),"local_bpe_tokens":tokens}

def request(arm,session,ordinal,prior,raw,encode):
    fields=measure(raw,encode)
    return {"arm":arm,"session_id":session,"case_id":CASE,
            "model":MODEL,"ordinal":ordinal,"prior_response_sha":prior,
            "max_completion_tokens":256,"real_provider_dispatch":False,**fields}

def start(con,arm,session,raw,encode):
    value=request(arm,session,1,None,raw,encode)
    begin_arm(con,arm,session,value)
    return value

def admit(con,arm,session,ordinal,prior,raw,encode):
    try:
        value=request(arm,session,ordinal,prior,raw,encode)
    except (ValueError,UnicodeError,TypeError,json.JSONDecodeError):
        poison={"arm":arm,"session_id":session,"ordinal":ordinal,
                "case_id":CASE,"model":MODEL,"prior_response_sha":prior,
                "max_completion_tokens":256,"real_provider_dispatch":False,
                "local_wire_bytes":10001,"local_bpe_tokens":10001}
        try:
            consume_before_dispatch(con,arm,poison)
        except ValueError:
            pass
        raise
    receipt=consume_before_dispatch(con,arm,value)
    return {**receipt,**{k:value[k] for k in ("wire_sha256","local_wire_bytes","local_bpe_tokens")}}
