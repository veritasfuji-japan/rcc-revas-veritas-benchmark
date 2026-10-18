"""#461: original SDK-wire bytes, one-use state and preparse storage edge (no sender)."""
import hashlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.task4_461_sdk_response_ingress_no_go_v1 import SDKResponseIngress, IngressRefused


def req(*, step=0, append=True, model=None, cap=256):
    messages = [
        {"role": "developer", "content": [{"type": "text", "text": "Task4 trusted date fixture 2031-07-08"}]},
        {"role": "user", "content": [{"type": "text", "text": "native banking request"}]},
    ]
    for i in range(step):
        messages.extend([{"role":"assistant", "content":f"read {i}"},
                         {"role":"tool", "content":f"tool result {i}"}])
    if not append and step:
        messages[-1] = {"role":"tool","content":"rewritten"}
    body = json.dumps({"model":model or "gpt-4.1-mini-2025-04-14",
                       "messages":messages,"tools":[{"type":"function","function":{"name":"get_iban"}}],
                       "max_completion_tokens":cap,"temperature":0,"tool_choice":"auto"}).encode()
    return SimpleNamespace(method="POST",url="https://api.openai.com/v1/chat/completions",content=body)


def response(request, *, n=0, status=200, raw=None):
    if raw is None:
        raw=json.dumps({"id":f"local-test-{n}","object":"chat.completion",
                        "model":"gpt-4.1-mini-2025-04-14", "choices":[{"index":0,
                        "message":{"role":"assistant","content":"test text"},
                        "finish_reason":"stop"}]}).encode()
    return SimpleNamespace(request=request,status_code=status,content=raw)


def claim(**kwargs):
    return {"decision":"LOCAL_CONSUMED_NO_SEND", "live_post":False,
            "receipt_sha": hashlib.sha256(json.dumps(kwargs,sort_keys=True).encode()).hexdigest()}


def seal(*, arm, ordinal, request, response, **kwargs):
    return {"arm":arm,"ordinal":ordinal,
            "request_sha256":hashlib.sha256(request.content).hexdigest(),
            "response_sha256":hashlib.sha256(response.content).hexdigest(),
            "local_fsync_completed":True,"external_provider_authenticated":False}


def new(): return SDKResponseIngress(arm="A", trial_id="a"*64)


def test_two_step_same_arm_sdk_object_and_unscored():
    s=new()
    for i in range(2):
        q=req(step=i)
        x=s.before_response(ordinal=i,request=q,claim=claim)
        assert x["provider_send_permission"] is False
        ans=response(q,n=i)
        assert s.after_response(response=ans,seal=seal) is ans
    out=s.report()
    assert out["request_attempts_reserved"]==2 and len(out["response_receipts"])==2
    assert out["genuine_model_utility"] is None and out["score_status"]=="UNSCORED"
    assert out["provider_authenticated"] is False and out["real_provider_dispatch"]=="DENY"


def test_five_distinct_responses_allowed_no_sixth():
    s=new()
    for i in range(5):
        q=req(step=i)
        s.before_response(ordinal=i,request=q,claim=claim)
        s.after_response(response=response(q,n=i),seal=seal)
    with pytest.raises(IngressRefused):s.before_response(ordinal=5,request=req(step=5),claim=claim)


def test_invalid_model_burns_attempt():
    s=new()
    with pytest.raises(IngressRefused):s.before_response(ordinal=0,request=req(model="wrong"),claim=claim)
    assert s.attempts==1 and s.poisoned
    with pytest.raises(IngressRefused):s.before_response(ordinal=1,request=req(step=1),claim=claim)


@pytest.mark.parametrize("bad", ["wrong_arm","wrong_trial","nonseq","double_begin","nonpost","http",
                                "path","oversized","bad_cap","bad_json","empty_tools","not_initial",
                                "wrong_claim","claim_exception"])
def test_reject_invalid_initial_request_or_claim(bad):
    if bad == "wrong_arm":
        with pytest.raises(IngressRefused):SDKResponseIngress(arm="Z",trial_id="a"*64)
        return
    if bad == "wrong_trial":
        with pytest.raises(IngressRefused):SDKResponseIngress(arm="A",trial_id="x")
        return
    s=new(); q=req(); cb=claim; step=0
    if bad == "nonseq": step=1
    if bad == "nonpost":q.method="GET"
    if bad == "http":q.url=q.url.replace("https:","http:")
    if bad == "path":q.url=q.url.replace("chat/completions","responses")
    if bad == "oversized":q.content += b" "*11000
    if bad == "bad_cap":q=req(cap=999)
    if bad == "bad_json":q.content=b"{bad"
    if bad == "empty_tools":
        b=json.loads(q.content);b["tools"]=[];q.content=json.dumps(b).encode()
    if bad == "not_initial":q=req(step=1)
    if bad == "wrong_claim":cb=lambda **_: {"decision":"SEND_PERMITTED","live_post":True,"receipt_sha":"a"*64}
    if bad == "claim_exception":cb=Mock(side_effect=RuntimeError("interrupted"))
    if bad == "double_begin":
        s.before_response(ordinal=0,request=q,claim=claim)
        with pytest.raises(IngressRefused):s.before_response(ordinal=1,request=req(step=1),claim=claim)
        return
    with pytest.raises((IngressRefused,RuntimeError)):
        s.before_response(ordinal=step,request=q,claim=cb)
    assert s.poisoned


@pytest.mark.parametrize("bad",["swapped_req","unsealed","wrong_digest","seal_mutates","non200",
                                "malformed","duplicate_json","wrong_model","wrong_object","wrong_role",
                                "wrong_choice","duplicate_id","nonfinite"])
def test_response_sealed_first_then_denied(bad):
    s=new();q=req();s.before_response(ordinal=0,request=q,claim=claim)
    ans=response(q)
    seen=[]
    def spy(**kw):
        seen.append(True)
        r=seal(**kw)
        if bad == "unsealed":r["local_fsync_completed"]=False
        if bad == "wrong_digest":r["response_sha256"]="0"*64
        if bad == "seal_mutates":kw["response"].content+=b"\n"
        return r
    if bad=="swapped_req":ans.request=req()
    if bad=="non200":ans.status_code=500
    if bad=="malformed":ans.content=b"{not JSON"
    if bad=="duplicate_json":ans.content=b'{"x":1,"x":2}'
    if bad=="wrong_model":
        b=json.loads(ans.content);b["model"]="wrong";ans.content=json.dumps(b).encode()
    if bad=="wrong_object":
        b=json.loads(ans.content);b["object"]="else";ans.content=json.dumps(b).encode()
    if bad=="wrong_role":
        b=json.loads(ans.content);b["choices"][0]["message"]["role"]="user";ans.content=json.dumps(b).encode()
    if bad=="wrong_choice":
        b=json.loads(ans.content);b["choices"]=[];ans.content=json.dumps(b).encode()
    if bad=="nonfinite":ans.content=b'{"x": NaN}'
    if bad=="duplicate_id":
        s.after_response(response=ans,seal=seal)
        q2=req(step=1);s.before_response(ordinal=1,request=q2,claim=claim)
        ans=response(q2)
    if bad=="swapped_req":
        # Identity mismatch is detected before seal; it must never be released.
        with pytest.raises(IngressRefused):s.after_response(response=ans,seal=spy)
        assert not seen
    else:
        with pytest.raises(IngressRefused):s.after_response(response=ans,seal=spy)
        assert seen
    assert s.poisoned
    with pytest.raises(IngressRefused):s.before_response(ordinal=s.attempts,request=req(step=s.attempts),claim=claim)


def test_unknown_is_permanent():
    s=new();q=req();s.before_response(ordinal=0,request=q,claim=claim)
    s.unknown()
    assert s.report()["poisoned"] is True
    with pytest.raises(IngressRefused):s.after_response(response=response(q),seal=seal)
    with pytest.raises(IngressRefused):s.before_response(ordinal=1,request=req(step=1),claim=claim)


def test_native_history_prefix_cannot_be_rewritten():
    s=new();q=req();s.before_response(ordinal=0,request=q,claim=claim)
    s.after_response(response=response(q),seal=seal)
    q2=req(step=1)
    b=json.loads(q2.content);b["messages"][0]["content"][0]["text"]="changed date";q2.content=json.dumps(b).encode()
    with pytest.raises(IngressRefused):s.before_response(ordinal=1,request=q2,claim=claim)
    assert s.poisoned


def test_module_has_no_sender_or_approval_switch():
    code=(Path(__file__).resolve().parents[1] / "scripts/task4_461_sdk_response_ingress_no_go_v1.py").read_text()
    for forbidden in ("import openai", "import httpx", "requests.post(", "socket.socket(",
                      "urllib.request", "OPENAI_API_KEY", "workflow_dispatch", "httpx.Client("):
        assert forbidden not in code


def test_real_httpx_request_response_preserved_as_same_object():
    httpx = pytest.importorskip("httpx")
    prototype = req()
    request = httpx.Request("POST", prototype.url, content=prototype.content)
    expected = response(request, n=1)
    actual = httpx.Response(200, content=expected.content, request=request)
    session = new()
    session.before_response(ordinal=0, request=request, claim=claim)
    result = session.after_response(response=actual, seal=seal)
    assert result is actual and result.content is actual.content
    assert session.report()["response_receipts"][0]["response_sha256"] == hashlib.sha256(actual.content).hexdigest()
