"""#294 Provider first-two-call capture: zero live network in tests.

Run with TASK4_FROZEN_SOURCE_PACKET_PATH pointing at #292 immutable artifact
task4-two-first-request-packets.json; the artifact is SHA-pinned by CI.
"""
import copy
import json
import os
from pathlib import Path

import pytest
from scripts.task4_live_first_two_call_capture_oneuse_v1 import (
    RULE,CASE,MODEL,COMPLETE_REQUEST_SHA,APPROVAL_TEXT,Blocked,
    digest,read_verified_packets,send_exactly_once,execute,
)

@pytest.fixture(scope="module")
def source():
    p=os.environ["TASK4_FROZEN_SOURCE_PACKET_PATH"]
    return Path(p)

@pytest.fixture
def valid(source):
    return json.loads(source.read_text())

@pytest.fixture
def valid_req(source):
    return read_verified_packets(source)[0]["A"]

class FakeReply:
    status=200
    def __init__(self,body=None,status=200):
        self.status=status
        self.body=body if body is not None else {
            "id":"chatcmpl-test-not-authentic","object":"chat.completion",
            "model":MODEL,
            "choices":[{"index":0,"finish_reason":"tool_calls",
                         "message":{"role":"assistant","content":None,
                         "tool_calls":[{"id":"mock-0","type":"function",
                           "function":{"name":"get_iban","arguments":"{}"}}]}}],
            "usage":{"prompt_tokens":700,"completion_tokens":32,
                     "total_tokens":732},
        }
    def getheader(self,name):
        return "req-mocked-do-not-claim-real" if name=="x-request-id" else None
    def read(self,n):
        return json.dumps(self.body).encode()
class FakeTransport:
    def __init__(self,response=None):
        self.response=response or FakeReply()
        self.requests=[]
        self.closed=False
    def request(self,method,path,body,headers):
        self.requests.append((method,path,body,headers))
    def getresponse(self):
        return self.response
    def close(self):
        self.closed=True

def test_01_pinned_source_exact_2_owner_separated_request_bodies(source):
    requests,m=read_verified_packets(source)
    assert m["rule_of_one"]==RULE
    assert m["source_artifact"]=="11672698922"
    assert m["expected_provider_calls"]==2
    assert m["approved_proposed_max_usd"]==0.50
    assert m["provider_project_hard_cap_verified"] is False
    assert m["first_call_contains_malicious_native_tool_data"] is False
    assert requests["A"]==requests["B"]
    assert digest(requests["A"])==COMPLETE_REQUEST_SHA
    assert len(json.dumps(requests["A"]))<32768

def test_02_preflight_no_secret_network_or_provider(monkeypatch,source,tmp_path):
    for k in ("GITHUB_ACTIONS","GITHUB_EVENT_NAME","GITHUB_REF",
              "GITHUB_RUN_ATTEMPT","TASK4_CONSUMED_REF_CREATED",
              "TASK4_APPROVAL_PHRASE","TASK4_OPENAI_API_KEY"):
        monkeypatch.delenv(k,raising=False)
    output=tmp_path/"summary.json"
    from argparse import Namespace
    execute(Namespace(mode="preflight",source=str(source),output=str(output)))
    obj=json.loads(output.read_text())
    assert obj["expected_provider_calls"]==2
    assert obj["provider_project_hard_cap_verified"] is False

def test_03_fake_transport_only_never_real_network(valid_req):
    fake=FakeTransport()
    result=send_exactly_once(request=valid_req,key="fake-do-not-use",
         arm="A",request_id="task4-v1-A-local-unit",transport=lambda:fake)
    assert result["provider_response_id"]=="chatcmpl-test-not-authentic"
    assert result["native_tools_dispatched"]==0
    assert result["canonical_case_utility_scored"] is False
    assert result["estimated_cost_usd"]<0.25
    assert len(fake.requests)==1 and fake.closed
    method,path,body,headers=fake.requests[0]
    assert method=="POST" and path=="/v1/chat/completions"
    assert "fake-do-not-use" not in body.decode()
    assert headers["X-Client-Request-Id"]=="task4-v1-A-local-unit"

def test_04_manual_send_without_github_environment_refused(monkeypatch,source,tmp_path):
    from argparse import Namespace
    monkeypatch.setenv("TASK4_OPENAI_API_KEY","mock-key-for-offline-test-12345")
    monkeypatch.setenv("TASK4_APPROVAL_PHRASE",APPROVAL_TEXT)
    monkeypatch.setenv("TASK4_CONSUMED_REF_CREATED","0")
    monkeypatch.setenv("GITHUB_ACTIONS","true")
    monkeypatch.setenv("GITHUB_EVENT_NAME","workflow_dispatch")
    monkeypatch.setenv("GITHUB_REF","refs/heads/main")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT","1")
    with pytest.raises(Blocked,match="NO_MANUAL_OPERATOR"):
        execute(Namespace(mode="send",source=str(source),
                          output=str(tmp_path/"out.jsonl")))

@pytest.mark.parametrize("fault",[
 "case","status","count","source_alias","first_sha","complete_sha",
 "temperature","model","too_many_output_tokens","extra_history",
 "writer_tool_count","fake_sent_provider","wrong_tool_choice",
 "previous_reply","fake_approval","no_live_flag"
])
def test_05_sixteen_mutated_source_refusals(valid,fault,tmp_path):
    j=copy.deepcopy(valid)
    a,b=j["packets"]["A"],j["packets"]["B"]
    if fault=="case":j["case_id"]="banking:user_task_15"
    if fault=="status":j["entrypoint"]="EXECUTED"
    if fault=="count":j["approved_request_count"]=2
    if fault=="source_alias":b["synthetic_source_sha256"]=a["synthetic_source_sha256"]
    if fault=="first_sha":a["first_request_sha256"]="0"*64
    if fault=="complete_sha":a["complete_first_request_sha256"]="0"*64
    if fault=="temperature":a["complete_first_request"]["temperature"]=0.7
    if fault=="model":a["complete_first_request"]["model"]="some-other-model"
    if fault=="too_many_output_tokens":
        a["complete_first_request"]["max_completion_tokens"]=65536
    if fault=="extra_history":
        a["complete_first_request"]["messages"].append({"role":"assistant","content":"fake"})
    if fault=="writer_tool_count":a["complete_first_request"]["tools"].pop()
    if fault=="fake_sent_provider":b["request_sent_to_provider"]=True
    if fault=="wrong_tool_choice":a["complete_first_request"]["tool_choice"]="none"
    if fault=="previous_reply":b["provider_response_id"]="forged"
    if fault=="fake_approval":j["fresh_human_approval_present"]=True
    if fault=="no_live_flag":a["provider_use_authorized"]=True
    path=tmp_path/"tampered.json";path.write_text(json.dumps(j))
    with pytest.raises(Blocked):
        read_verified_packets(path)

@pytest.mark.parametrize("bad",[
 "http_429","wrong_model","inconsistent_usage","negative_usage",
 "output_too_large","missing_request_id","oversized_body",
])
def test_06_seven_response_errors_never_retried(valid_req,bad):
    resp=FakeReply()
    if bad=="http_429":resp.status=429
    if bad=="wrong_model":resp.body["model"]="gpt-4o"
    if bad=="inconsistent_usage":resp.body["usage"]["total_tokens"]=900
    if bad=="negative_usage":resp.body["usage"]["prompt_tokens"]=-10
    if bad=="output_too_large":
        resp.body["usage"]["completion_tokens"]=300
        resp.body["usage"]["total_tokens"]=1000
    if bad=="missing_request_id":
        resp.getheader=lambda n: None
    if bad=="oversized_body":
        resp.read=lambda n:b" "*262145
    fake=FakeTransport(resp)
    with pytest.raises(Blocked):
        send_exactly_once(request=valid_req,key="fake",
                          arm="A",request_id="task4-v1-A-local-test",
                          transport=lambda:fake)
    assert len(fake.requests)==1 and fake.closed
