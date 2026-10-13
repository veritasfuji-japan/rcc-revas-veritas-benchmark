"""#382 real HTTPS POST adapter rehearsed ONLY against local fake connections.

No actual Provider credentials, no real network, no external tag, no score.
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
import socket
from pathlib import Path
import pytest

from scripts import final128_382_first_two_responses_once_transport_v1 as m
from scripts import final128_381_task1_real_responses_capture_contract_v1 as w
from scripts import final128_350_task1_responses_once_budget_v1 as b

RUN="38352812345"

@pytest.fixture(autouse=True)
def no_network_no_secrets(monkeypatch):
    def blocked(*args,**kwargs):pytest.fail("382_REAL_NETWORK_FORBIDDEN_IN_CI")
    monkeypatch.setattr(socket.socket,"connect",blocked)
    monkeypatch.setattr(socket.socket,"connect_ex",blocked)
    monkeypatch.setattr(socket,"create_connection",blocked)
    for key in ("OPENAI_API_KEY","TASK4_OPENAI_API_KEY","ANTHROPIC_API_KEY",
                "OPENAI_BASE_URL","GITHUB_TOKEN","GH_TOKEN"):
        monkeypatch.delenv(key,raising=False)

def response(arm="A",**changes):
    a={
       "id":f"resp_OFFLINE_382_{arm}_not_genuine",
       "object":"response","model":m.wire.MODEL,"status":"completed",
       "output":[{"type":"function_call","id":f"fc_OFFLINE_382_{arm}",
          "call_id":f"call_OFFLINE_382_{arm}_not_genuine",
          "name":m.wire.guard.TOOL,"arguments":'{"n":100}'}],
       "usage":{"input_tokens":130,"output_tokens":16,"total_tokens":146}
    }
    for key,val in changes.items():
        if key in ("id","object","model","status","output","usage"):a[key]=val
        elif key in a["output"][0]:a["output"][0][key]=val
        else:raise AssertionError("bad fixture")
    return a

class FakeHTTPResponse:
    def __init__(self,arm="A",status=200,header=None,body=None):
        self.status=status
        self.header=header if header is not None else f"req_OFFLINE_382_{arm}_not_genuine"
        self.body=body if body is not None else json.dumps(response(arm),sort_keys=True).encode("utf8")
        self.reads=0
    def getheader(self,key):
        assert key=="x-request-id"
        return self.header
    def read(self,count):
        assert count==m.MAX_RESPONSE_BYTES+1
        self.reads+=1
        return self.body

class FakeConn:
    def __init__(self,arm="A",response=None,fail_on=None):
        self.arm=arm
        self.response=response or FakeHTTPResponse(arm)
        self.fail_on=fail_on
        self.calls=[]
        self.closed=False
    def request(self,method,path,body,headers):
        if self.fail_on=="request":raise OSError("unknown_send_failure")
        assert self.closed is False
        assert method=="POST" and path=="/v1/responses"
        assert body==w.canonical(w.first_real_wire_packet())
        assert headers["Content-Type"]=="application/json"
        assert headers["X-Client-Request-Id"]==f"task1-382-{self.arm}-{RUN}"
        assert headers["User-Agent"]=="veritas-task1-first-two-presend-v1"
        assert headers["Authorization"].startswith("Bearer offline-not-valid-382")
        assert set(headers)=={
            "Content-Type","X-Client-Request-Id","User-Agent","Authorization"}
        self.calls.append((method,path,m.digest_bytes(body)))
    def getresponse(self):
        if self.fail_on=="getresponse":raise TimeoutError("unknown_result")
        assert len(self.calls)==1
        return self.response
    def close(self):
        self.closed=True

def test_exact_first_two_presend_manifest_but_no_permission():
    out=m.prepare_two_first_packets()
    assert out["arms"]["A"]["original_wire_sha256"]==out["arms"]["B"]["original_wire_sha256"]
    assert out["max_first_two_provider_attempts_proposed"]==2
    assert out["max_output_tokens"]==256
    assert out["live_dispatch_authorized"] is False
    assert out["protected_runner_installed"] is False
    assert out["consumed_protected_global_lease"] is False
    assert out["project_hard_spend_stop_verified"] is False
    assert out["local_budget_reserved_max_usd_for_2_calls"]=="0.0104192"

def test_actual_transport_function_two_independent_local_connections(tmp_path):
    made=[]
    def create(arm):
        c=FakeConn(arm);made.append(c);return c
    out=m.offline_two_arm_transport_rehearsal(
        conn_factory=create,run_id=RUN,folder=tmp_path)
    assert out["local_attempts_consumed_no_retry"]==2
    assert out["real_provider_calls_confirmed"]==0
    assert out["official_native_scorer_invocations"]==0
    assert out["official_utility_or_attack_scores"] is None
    assert out["real_provider_tls_origin_verified"] is False
    assert out["A_call_id_sha256"]!=out["B_call_id_sha256"]
    assert out["A_server_request_header_sha256"]!=out["B_server_request_header_sha256"]
    assert len(made)==2 and all(c.closed and len(c.calls)==1 for c in made)
    events=[json.loads(x) for x in
      (tmp_path/"final128-382-local-only-journal.jsonl").read_text().splitlines()]
    assert [e["phase"] for e in events]==[
        "OFFLINE_START","BEFORE_MOCK_POST_CONSUMED","MOCK_RESPONSE_CAPTURED",
        "BEFORE_MOCK_POST_CONSUMED","MOCK_RESPONSE_CAPTURED",
        "TWO_MOCK_CAPTURES_COMPLETE"]
    assert events[1]["arm"]=="A" and events[3]["arm"]=="B"
    assert "Bearer" not in str(events)
    assert "resp_OFFLINE" not in str(events)

def test_restart_same_journal_must_refuse_not_replay(tmp_path):
    created=[]
    def mk(arm):
        c=FakeConn(arm);created.append(c);return c
    m.offline_two_arm_transport_rehearsal(conn_factory=mk,run_id=RUN,folder=tmp_path)
    with pytest.raises(m.Blocked,match="EXISTING_LOCAL_JOURNAL"):
        m.offline_two_arm_transport_rehearsal(conn_factory=mk,run_id=RUN,folder=tmp_path)
    assert len(created)==2

@pytest.mark.parametrize("issue",[
   "status_401","status_500","no_header","wrong_header","bad_json",
   "too_large","bad_model","bad_tool","wrong_args","bad_call_id",
   "missing_usage","wrong_response_object","missing_call",
])
def test_unknown_or_invalid_A_response_fails_without_trying_B(tmp_path,issue):
    obj=response("A");status=200;header="req_OFFLINE_382_A_not_genuine"
    if issue=="status_401":status=401
    elif issue=="status_500":status=500
    elif issue=="no_header":header=""
    elif issue=="wrong_header":header="!!!"
    elif issue=="bad_json":raw=b"{"
    elif issue=="too_large":raw=b"!"*(m.MAX_RESPONSE_BYTES+1)
    elif issue=="bad_model":obj["model"]="wrong-model"
    elif issue=="bad_tool":obj["output"][0]["name"]="send_money"
    elif issue=="wrong_args":obj["output"][0]["arguments"]='{"n":99}'
    elif issue=="bad_call_id":obj["output"][0]["call_id"]="not_allowed"
    elif issue=="missing_usage":obj.pop("usage")
    elif issue=="wrong_response_object":obj["object"]="chat.completion"
    elif issue=="missing_call":obj["output"]=[]
    if issue not in ("bad_json","too_large"):
        raw=json.dumps(obj).encode()
    made=[]
    def mk(arm):
        c=FakeConn(arm,response=FakeHTTPResponse(arm,status=status,
                header=header,body=raw));made.append(c);return c
    with pytest.raises((m.Blocked,w.Refused)):
        m.offline_two_arm_transport_rehearsal(
            conn_factory=mk,run_id=RUN,folder=tmp_path)
    assert len(made)==1 and made[0].closed is True
    events=(tmp_path/"final128-382-local-only-journal.jsonl").read_text()
    assert "BEFORE_MOCK_POST_CONSUMED" in events
    assert "UNKNOWN_AFTER_POST_STOP" in events
    assert '"arm":"B"' not in events
    with pytest.raises(m.Blocked,match="EXISTING_LOCAL_JOURNAL"):
        m.offline_two_arm_transport_rehearsal(
            conn_factory=mk,run_id=RUN,folder=tmp_path)
    assert len(made)==1

@pytest.mark.parametrize("issue",["request","getresponse"])
def test_network_transport_uncertainty_stops_and_burns_local_attempt(tmp_path,issue):
    made=[]
    def mk(arm):
        c=FakeConn(arm,fail_on=issue);made.append(c);return c
    with pytest.raises((OSError,TimeoutError)):
        m.offline_two_arm_transport_rehearsal(
            conn_factory=mk,run_id=RUN,folder=tmp_path)
    assert len(made)==1 and made[0].closed is True
    assert "UNKNOWN_AFTER_POST_STOP" in (
        tmp_path/"final128-382-local-only-journal.jsonl").read_text()

def test_cross_arm_duplicate_response_ID_fails_after_second_and_no_replay(tmp_path):
    def mk(arm):
        obj=response("A") if arm=="B" else response("A")
        if arm=="B":
            # Keep unique Tool ID but counterfeit same response ID.
            obj["output"][0]["call_id"]="call_OFFLINE_382_B_not_genuine"
        raw=json.dumps(obj).encode()
        return FakeConn(arm,response=FakeHTTPResponse(arm,body=raw))
    with pytest.raises(m.Blocked,match="CROSS_ARM_RESPONSE_ID_REUSE"):
        m.offline_two_arm_transport_rehearsal(
            conn_factory=mk,run_id=RUN,folder=tmp_path)

def test_exact_wire_or_credentials_rejected_before_any_request():
    conn=FakeConn()
    request=w.first_real_wire_packet()
    variants=[
        dict(arm="A",request=request,api_key="bad",run_id=RUN),
        dict(arm="A",request={**request,"store":True},api_key="x"*24,run_id=RUN),
        dict(arm="C",request=request,api_key="x"*24,run_id=RUN),
        dict(arm="A",request=request,api_key="x"*24,run_id="bad"),
        dict(arm="A",request=request,api_key="",run_id=RUN),
    ]
    for v in variants:
        with pytest.raises(m.Blocked):
            m._request(**v,conn=conn)
    assert conn.calls==[]

def test_live_gate_never_authorized_by_forged_claims():
    for x in (None,True,{},{"grant":True},
              "I APPROVE TASK1 A/B ONE RUN UP TO USD 1"):
        with pytest.raises(m.Blocked,match="NO_FRESH_EXTERNAL_ISSUER"):
            m.protected_live_dispatch_gate(x)

def test_no_live_cli_or_workflow_dispatch_is_introduced():
    code=Path(m.__file__).read_text()
    assert 'if __name__=="__main__"' not in code
    assert "workflow_dispatch" in code # documentation only
    assert "http.client.HTTPSConnection(" not in code
    assert "OpenAI(" not in code

def test_local_evidence_redacted(tmp_path):
    out=m.offline_two_arm_transport_rehearsal(
        conn_factory=lambda a:FakeConn(a),run_id=RUN,folder=tmp_path)
    s=json.dumps(out)
    assert "OFFLINE_382_A_not_genuine" not in s
    assert "Bearer" not in s and "Authorization" not in s
    assert "function_call_output" not in s
    assert "bank_account" not in s
