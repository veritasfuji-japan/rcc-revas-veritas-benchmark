"""#297 fake-only tests for future Task4 SECOND two-POST sender.

No real Provider credential and no real provider transport may exist in PR
CI. The first used tag must stay consumed; creating a second tag/approval
is a separate future human operation.
"""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
from argparse import Namespace
import pytest

if os.getenv("TASK4_SECOND_TWO_SENDER_OFFLINE_TEST")!="1":
    pytest.skip("Dedicated offline fake transport only",allow_module_level=True)

from scripts.task4_live_second_two_call_capture_oneuse_v1 import (
    RULE,MODEL,CASE,SOURCES,SOURCE_JSON_SHA256,APPROVAL_PHRASE,NEW_USED_REF,
    FIRST_USED_REF,Denied,frozen_second_requests,once,execute,digest,canon
)

@pytest.fixture(scope="module")
def source():
    return Path(os.environ["TASK4_SECOND_TWO_SOURCE_FILE"])

@pytest.fixture(scope="module")
def original(source):
    return json.loads(source.read_text())

@pytest.fixture(scope="module")
def a(source):
    return frozen_second_requests(source)[0]["A"]

def test_01_exact_second_source_lineage_and_no_approval(source):
    reqs,manifest=frozen_second_requests(source)
    assert manifest["rule_of_one"]==RULE
    assert manifest["source_file_sha256"]==SOURCE_JSON_SHA256
    assert manifest["case_id"]==CASE
    assert manifest["source_artifact_id"]=="11674814494"
    assert manifest["new_oneuse_ref_required"]==NEW_USED_REF
    assert manifest["prior_approval_consumed_ref"]==FIRST_USED_REF
    assert manifest["current_new_call_authorization"]==0
    assert manifest["proposed_calls_not_yet_approved"]==2
    assert manifest["proposed_total_max_cost_usd"]==0.50
    for arm in ("A","B"):
        req=reqs[arm]
        assert digest(req)==SOURCES[arm]
        assert req["model"]==MODEL
        assert req["max_completion_tokens"]==256
        assert req["n"]==1 and req["stream"] is False and req["store"] is False
        assert [x["role"] for x in req["messages"]]==[
            "developer","user","assistant","tool"]
        assert req["messages"][3]["tool_call_id"]==(
            req["messages"][2]["tool_calls"][0]["id"])
        assert req["messages"][3]["content"]==[
            {"type":"text","text":"DE89370400440532013000"}]
    assert SOURCES["A"]!=SOURCES["B"]

def test_02_only_preflight_allowed_by_default(source,tmp_path,monkeypatch):
    for k in ("GITHUB_ACTIONS","GITHUB_RUN_ATTEMPT","GITHUB_REF",
              "GITHUB_EVENT_NAME","TASK4_SECOND_APPROVAL_PHRASE",
              "TASK4_SECOND_ONCE_REF_CREATED","TASK4_OPENAI_API_KEY"):
        monkeypatch.delenv(k,raising=False)
    out=tmp_path/"manifest.json"
    execute(Namespace(mode="preflight",source=str(source),output=str(out)))
    j=json.loads(out.read_text())
    assert j["live_provider_access_or_project_budget_verified"] is False
    with pytest.raises(Denied,match="MISSING_FRESH_SECOND"):
        execute(Namespace(mode="send",source=str(source),
                          output=str(tmp_path/"journal.jsonl")))

def test_03_cannot_use_prior_consumed_tag_as_authorization(source,tmp_path,monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS","true")
    monkeypatch.setenv("GITHUB_EVENT_NAME","workflow_dispatch")
    monkeypatch.setenv("GITHUB_REF","refs/heads/main")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT","1")
    monkeypatch.setenv("TASK4_SECOND_APPROVAL_PHRASE",APPROVAL_PHRASE)
    monkeypatch.setenv("TASK4_OPENAI_API_KEY","mock-unit-only-do-not-share-123456")
    monkeypatch.setenv("TASK4_SECOND_ONCE_REF_CREATED","0")
    with pytest.raises(Denied,match="MISSING_FRESH_SECOND"):
        execute(Namespace(mode="send",source=str(source),
             output=str(tmp_path/"must-not-exist.jsonl")))

class FakeResponse:
    def __init__(self):
        self.status=200
        self.body={
          "object":"chat.completion","model":MODEL,
          "id":"chatcmpl-synthetic-second-response",
          "choices":[{"index":0,"finish_reason":"tool_calls","message":{
             "role":"assistant","content":None,"tool_calls":[{
                "id":"mock-next-call","type":"function",
                "function":{"name":"get_most_recent_transactions",
                            "arguments":'{"n":10}'}}]}}],
          "usage":{"prompt_tokens":825,"completion_tokens":23,
                   "total_tokens":848}
        }
    def getheader(self,k):
        return "req-fake-no-provider-auth" if k=="x-request-id" else None
    def read(self,maxbytes):
        return json.dumps(self.body).encode("utf8")
class FakeTransport:
    def __init__(self,response=None):
        self.response=response if response is not None else FakeResponse()
        self.posts=[];self.closed=False
    def request(self,method,path,body,headers):
        self.posts.append((method,path,body,headers))
    def getresponse(self):
        return self.response
    def close(self):
        self.closed=True

def test_04_both_fake_two_arm_responses_captured_no_native_calls(source):
    reqs,_=frozen_second_requests(source)
    results=[]
    for arm in ("A","B"):
        fake=FakeTransport()
        result=once(request=reqs[arm],arm=arm,key="mock-key",
           client_request_id="task4-second-v1-"+arm+"-unit",
           transport=lambda:fake)
        assert result["request_sha256"]==SOURCES[arm]
        assert result["native_tool_dispatches"]==0
        assert result["provider_output_is_execution_authority"] is False
        assert result["native_attack_exposure_observed"] is False
        assert result["native_task4_utility_scored"] is False
        assert result["usage_based_estimated_cost_usd"]<0.25
        assert len(fake.posts)==1 and fake.closed
        assert fake.posts[0][0]=="POST"
        assert fake.posts[0][1]=="/v1/chat/completions"
        assert fake.posts[0][3]["X-Client-Request-Id"]=="task4-second-v1-"+arm+"-unit"
        assert b"mock-key" not in fake.posts[0][2]
        results.append(result)
    assert results[0]["arm"]=="A" and results[1]["arm"]=="B"

@pytest.mark.parametrize("fault",[
 "wrong_case","original_first_approval_reuse","new_approval_forged",
 "second_sent","source_rule_promoted","model_alias",
 "call_id_swapped","missing_native_result","different_native_result",
 "new_model_response_fake","source_sha_alias","native_write_claim",
 "overlong_first_history","model_output_limit_relaxed","disable_store",
 "different_original_first_response","source_zip_pretend_verified"
])
def test_05_seventeen_source_tamper_attempts_fail_closed(source,original,tmp_path,fault):
    val=copy.deepcopy(original); a=val["packets"]["A"]; b=val["packets"]["B"]
    if fault=="wrong_case":val["exact_case"]="banking:user_task_15:injection_task_0:direct"
    elif fault=="original_first_approval_reuse":val["first_two_real_calls_already_consumed"]=False
    elif fault=="new_approval_forged":val["second_model_requests_authorized"]=2
    elif fault=="second_sent":a["request_already_sent"]=True
    elif fault=="source_rule_promoted":val["rule_of_one"]="REAL_PROVIDER_MEASURED"
    elif fault=="model_alias":a["second_complete_request"]["model"]="gpt-4o"
    elif fault=="call_id_swapped":a["second_complete_request"]["messages"][3]["tool_call_id"]="forged"
    elif fault=="missing_native_result":a["second_complete_request"]["messages"].pop()
    elif fault=="different_native_result":b["second_complete_request"]["messages"][3]["content"][0]["text"]="attacker text"
    elif fault=="new_model_response_fake":b["next_real_model_response_received"]=True
    elif fault=="source_sha_alias":a["second_complete_request_sha256"]=SOURCES["B"]
    elif fault=="native_write_claim":b["native_bank_effect_authorized"]=True
    elif fault=="overlong_first_history":a["second_complete_request"]["messages"].append({"role":"assistant","content":"x"})
    elif fault=="model_output_limit_relaxed":a["second_complete_request"]["max_completion_tokens"]=500
    elif fault=="disable_store":a["second_complete_request"]["store"]=True
    elif fault=="different_original_first_response":a["original_real_first_model_response_sha256"]="0"*64
    elif fault=="source_zip_pretend_verified":val["frozen_source_zip_sha256"]="0"*64
    p=tmp_path/"tamper.json";p.write_text(json.dumps(val))
    with pytest.raises(Denied):
        frozen_second_requests(p)

@pytest.mark.parametrize("fault",[
 "status","request_id","model","total_usage","completion_limit",
 "negative_usage","server_id","response_length","response_object"
])
def test_06_nine_bad_http_responses_fail_no_retries(a,fault):
    response=FakeResponse()
    if fault=="status":response.status=429
    if fault=="model":response.body["model"]="gpt-4o"
    if fault=="total_usage":response.body["usage"]["total_tokens"]=1
    if fault=="completion_limit":response.body["usage"]["completion_tokens"]=257
    if fault=="negative_usage":response.body["usage"]["prompt_tokens"]=-1
    if fault=="server_id":response.getheader=lambda _:None
    if fault=="response_length":response.read=lambda _:b"x"*262145
    if fault=="response_object":response.body["object"]="other"
    client_id="task4-second-v1-A-test"
    if fault=="request_id":client_id="invalid"
    fake=FakeTransport(response)
    with pytest.raises(Denied):
        once(request=a,arm="A",key="fake",
             client_request_id=client_id,transport=lambda:fake)
    assert len(fake.posts)<=1 and fake.closed is (fault!="request_id")

def test_07_new_approval_phrase_is_distinct_from_consumed_first_one():
    assert APPROVAL_PHRASE != "APPROVE_TASK4_ONE_CASE_A_B_FIRST_2_CALLS_MAX_USD_0.50"
    assert NEW_USED_REF != FIRST_USED_REF
