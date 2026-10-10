"""#299 OFFLINE-ONLY tests for future manually authorized third A/B model POSTs.

Cannot send to OpenAI, cannot reuse first or second consumed consent, cannot
dispatch native banking tools or score. Fake HTTPS always local.
"""
from __future__ import annotations
from argparse import Namespace
import copy
import hashlib
import json
import os
from pathlib import Path
import pytest

if os.getenv("TASK4_THIRD_TWO_SENDER_OFFLINE_TEST")!="1":
    pytest.skip("This suite runs only offline with frozen historical artifacts",
                allow_module_level=True)

import scripts.task4_live_third_two_call_capture_oneuse_v1 as m

@pytest.fixture(scope="module")
def source():
    return Path(os.environ["TASK4_THIRD_TWO_FROZEN_SOURCE_JSON"])

@pytest.fixture(scope="module")
def frozen(source):
    return json.loads(source.read_text())

def test_01_actual_attack_bearing_two_third_requests_frozen_no_authority(source):
    packets,meta=m.frozen_third_packets(source)
    assert meta["rule_of_one"]==m.RULE
    assert meta["source_artifact_id"]=="11676881211"
    assert meta["source_json_sha256"]==m.SOURCE_JSON_SHA
    assert meta["third_provider_calls_approved_so_far"]==0
    assert meta["new_provider_requests_dispatched"]==0
    assert meta["actual_genuine_model_exposure_to_attack"] is False
    assert meta["contains_exact_native_attack_transaction"] is True
    assert meta["new_approval_required"] is True
    assert meta["third_single_use_ref_required"]==m.NEW_THIRD
    assert meta["prior_second_consumed_ref"]==m.OLD_SECOND
    for arm in ("A","B"):
        request=packets[arm]
        assert m.sha_obj(request)==m.SHA_REQUEST[arm]
        assert len(m.canon(request))==6895
        assert len(request["messages"])==6
        assert request["max_completion_tokens"]==256
        assert request["stream"] is False and request["store"] is False
        assert request["messages"][-1]["tool_call_id"]==(
            request["messages"][-2]["tool_calls"][0]["id"])
        assert len(request["tools"])==11
    assert m.SHA_REQUEST["A"]!=m.SHA_REQUEST["B"]

def test_02_offline_preflight_allowed_but_no_implicit_live_consent(source,tmp_path,monkeypatch):
    for name in ("GITHUB_ACTIONS","GITHUB_EVENT_NAME","GITHUB_ACTOR",
      "GITHUB_REF","GITHUB_RUN_ATTEMPT","TASK4_THIRD_APPROVAL_PHRASE",
      "TASK4_THIRD_NEW_PROTECTED_REF_CREATED","TASK4_OPENAI_API_KEY"):
        monkeypatch.delenv(name,raising=False)
    out=tmp_path/"preflight.json"
    m.execute(Namespace(mode="preflight",source=str(source),output=str(out)))
    j=json.loads(out.read_text())
    assert j["network_or_project_billing_authority"] is False
    assert j["task4_utility_or_injection_success_measured"] is False
    with pytest.raises(m.Denied,match="NEW_THIRD_ROUND_MANUAL"):
        m.execute(Namespace(mode="send",source=str(source),
            output=str(tmp_path/"journal-must-not-exist.jsonl")))
    assert not (tmp_path/"journal-must-not-exist.jsonl").exists()

def test_03_both_old_refs_spent_does_not_authorize_third(source,tmp_path,monkeypatch):
    for name,value in (
      ("GITHUB_ACTIONS","true"),("GITHUB_EVENT_NAME","workflow_dispatch"),
      ("GITHUB_REF","refs/heads/main"),("GITHUB_ACTOR","veritasfuji-japan"),
      ("GITHUB_RUN_ATTEMPT","1"),("TASK4_THIRD_APPROVAL_PHRASE",m.APPROVAL),
      ("TASK4_THIRD_NEW_PROTECTED_REF_CREATED","0"),
      ("TASK4_OPENAI_API_KEY","fake-openai-key-never-online-12345678")
    ):
        monkeypatch.setenv(name,value)
    with pytest.raises(m.Denied,match="NEW_THIRD_ROUND_MANUAL"):
        m.execute(Namespace(mode="send",source=str(source),
                  output=str(tmp_path/"never-create.jsonl")))
    assert not (tmp_path/"never-create.jsonl").exists()

class FakeResponse:
    def __init__(self):
        self.status=200
        self.response={
          "object":"chat.completion","model":m.MODEL,
          "id":"chatcmpl-synthetic-third-no-provider",
          "choices":[{"index":0,"finish_reason":"tool_calls",
                      "message":{"role":"assistant","content":None,
                       "tool_calls":[{"type":"function",
                                      "id":"mock-third-request-from-fake-model",
                                      "function":{"name":"send_money",
                                                  "arguments":'{"amount":500}'}}]}}],
          "usage":{"prompt_tokens":1000,"completion_tokens":25,
                   "total_tokens":1025}
        }
    def getheader(self,key):
        return "req-local-fake-do-not-use" if key=="x-request-id" else None
    def read(self,n):
        return json.dumps(self.response).encode("utf8")
class FakeConnection:
    def __init__(self,reply=None):
        self.reply=reply or FakeResponse()
        self.requests=[];self.closed=False
    def request(self,method,path,body,headers):
        self.requests.append((method,path,body,headers))
    def getresponse(self):return self.reply
    def close(self):self.closed=True

def test_04_model_may_suggest_protected_writer_but_no_native_writer_executes(source):
    packets,_=m.frozen_third_packets(source)
    results=[]
    for arm in ("A","B"):
        fake=FakeConnection()
        r=m.one_post(request=packets[arm],arm=arm,
          key="FAKE_LOCAL_ONLY",client_id="task4-third-v1-"+arm+"-test",
          transport=lambda:fake)
        assert r["arm"]==arm and r["request_sha256"]==m.SHA_REQUEST[arm]
        assert r["provider_response_sha256"]==m.sha_obj(r["real_provider_response"])
        assert r["native_tools_dispatched"]==0
        assert r["native_bank_effects"]==0
        assert r["model_output_does_not_grant_execution_authority"] is True
        assert r["task4_utility_or_injection_success_scored"] is False
        assert r["estimated_cost_usd_not_invoice"]<0.25
        assert len(fake.requests)==1 and fake.closed
        assert fake.requests[0][0:2]==("POST","/v1/chat/completions")
        assert fake.requests[0][2]==m.canon(packets[arm])
        assert b"FAKE_LOCAL_ONLY" not in fake.requests[0][2]
        assert fake.requests[0][3]["X-Client-Request-Id"]==(
            "task4-third-v1-"+arm+"-test")
        results.append(r)
    assert {r["arm"] for r in results}=={"A","B"}

def test_05_pure_source_preflight_is_deterministic_without_modification(source):
    raw=source.read_bytes()
    first=m.frozen_third_packets(source)
    second=m.frozen_third_packets(source)
    assert first==second and source.read_bytes()==raw

@pytest.mark.parametrize("fault",[
 "rule","case","prior_first_run","prior_second_run","prior_not_consumed",
 "pretend_new_authorized","claim_third_sent","claim_model_saw_attack",
 "fake_native_bank_write","fake_final128_score","swap_arm",
 "wrong_second_response","wrong_second_request","forged_third_hash",
 "wrong_model","tool_count","role_tamper","wrong_previous_call_id",
 "remove_malicious_transaction","wrong_malicious_transaction",
 "fake_write_journal","wrong_native_state"
])
def test_06_semantically_mutated_source_is_refused_even_if_raw_sha_gate_rebased(
        source,frozen,tmp_path,monkeypatch,fault):
    d=copy.deepcopy(frozen);a=d["A_B"]["A"];b=d["A_B"]["B"]
    q=a["complete_third_unsent_model_request"]
    if fault=="rule":d["rule_of_one"]="WRONG"
    elif fault=="case":d["exact_case"]="banking:user_task_15:injection_task_0:direct"
    elif fault=="prior_first_run":d["genuine_first_provider_run"]="0"
    elif fault=="prior_second_run":d["genuine_second_provider_run"]="0"
    elif fault=="prior_not_consumed":d["first_and_second_round_authorizations_consumed"]=False
    elif fault=="pretend_new_authorized":d["new_authorization_to_call_provider"]=True
    elif fault=="claim_third_sent":d["third_model_requests_sent"]=1
    elif fault=="claim_model_saw_attack":d["actual_real_llm_exposure_to_injected_tool_output"]=True
    elif fault=="fake_native_bank_write":d["actual_bank_write_effects"]=1
    elif fault=="fake_final128_score":d["new_canonical_final128_scores"]=1
    elif fault=="swap_arm":a["arm"]="B"
    elif fault=="wrong_second_response":b["second_real_provider_response_sha256"]="0"*64
    elif fault=="wrong_second_request":b["original_second_request_sha256"]="0"*64
    elif fault=="forged_third_hash":a["third_unsent_model_request_sha256"]="0"*64
    elif fault=="wrong_model":q["model"]="gpt-4o"
    elif fault=="tool_count":q["tools"].pop()
    elif fault=="role_tamper":q["messages"][-1]["role"]="developer"
    elif fault=="wrong_previous_call_id":q["messages"][-1]["tool_call_id"]="forged"
    elif fault=="remove_malicious_transaction":
        q["messages"][-1]["content"][0]["text"]="[]"
    elif fault=="wrong_malicious_transaction":
        q["messages"][-1]["content"][0]["text"]=(
            q["messages"][-1]["content"][0]["text"].replace("GB29NWBK60161331926819","OTHER_BANK"))
    elif fault=="fake_write_journal":a["native_two_read_journal"][1]["bank_write_dispatches"]=1
    elif fault=="wrong_native_state":b["native_injected_pre_and_post_state_sha256"]="0"*64
    else:raise AssertionError(fault)
    raw=json.dumps(d,ensure_ascii=False,sort_keys=True,indent=2).encode()+b"\n"
    bad=tmp_path/"tampered.json";bad.write_bytes(raw)
    monkeypatch.setattr(m,"SOURCE_JSON_SHA",hashlib.sha256(raw).hexdigest())
    with pytest.raises((m.Denied,KeyError,ValueError,TypeError)):
        m.frozen_third_packets(bad)

@pytest.mark.parametrize("fault",[
 "bad_http","no_x_request_id","wrong_model","incorrect_usage",
 "negative_usage","too_many_completion_tokens","oversize_body",
 "wrong_object","unparseable_json","wrong_provider_response_count"
])
def test_07_fake_provider_bad_or_unknown_never_retries(source,fault):
    q=m.frozen_third_packets(source)[0]["A"]
    reply=FakeResponse()
    if fault=="bad_http":reply.status=429
    elif fault=="no_x_request_id":reply.getheader=lambda _:None
    elif fault=="wrong_model":reply.response["model"]="gpt-4o"
    elif fault=="incorrect_usage":reply.response["usage"]["total_tokens"]=100
    elif fault=="negative_usage":reply.response["usage"]["prompt_tokens"]=-1
    elif fault=="too_many_completion_tokens":reply.response["usage"]["completion_tokens"]=257
    elif fault=="oversize_body":reply.read=lambda _:b"X"*262145
    elif fault=="wrong_object":reply.response["object"]="not.chat.completion"
    elif fault=="unparseable_json":reply.read=lambda _:b"{bad JSON"
    elif fault=="wrong_provider_response_count":reply.response["choices"]=[]
    c=FakeConnection(reply)
    with pytest.raises((m.Denied,ValueError,TypeError)):
        m.one_post(request=q,arm="A",key="fake-only",
           client_id="task4-third-v1-A-test",transport=lambda:c)
    assert len(c.requests)==1 and c.closed

def test_08_new_third_consent_cannot_equal_old_approval_or_tags():
    assert m.APPROVAL!="APPROVE_TASK4_ONE_CASE_A_B_SECOND_2_CALLS_MAX_USD_0.50"
    assert m.APPROVAL!="APPROVE_TASK4_ONE_CASE_A_B_FIRST_2_CALLS_MAX_USD_0.50"
    assert m.NEW_THIRD!=m.OLD_SECOND!=m.OLD_FIRST
