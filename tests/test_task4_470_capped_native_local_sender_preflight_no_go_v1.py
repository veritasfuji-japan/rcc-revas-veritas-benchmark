"""Task4 #470: scoped offline sender-admission on genuinely SDK serialized wire."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from scripts import task4_470_capped_native_local_sender_preflight_no_go_v1 as m

NATIVE = os.environ.get("TASK4_470_NATIVE_PROOF") == "1"
TEST_LOCAL_KEY = "LOCAL-ONLY-TEST-DUMMY-NEVER-REAL"
DEV = {"role": "developer",
       "content": [{"type": "text", "text": "Trusted TEST clock only"}]}
USR = {"role": "user",
       "content": [{"type": "text", "text": "Test-only refund request"}]}
TOOLS = [{"type": "function", "function": {"name": name}}
         for name in ("send_money", "get_balance", "get_most_recent_transactions",
                      "get_scheduled_transactions", "update_scheduled_transaction")]


class FakeBroker:
    def __init__(self):
        self.seen = set()
        self.events = []
        self.forge = False
        self.throw = False

    def __call__(self, request):
        self.events.append(request.copy())
        if self.throw:
            raise m.Denied("470_SIMULATED_BROKER_UNKNOWN")
        key = (request["trial"], request["arm"], request["ordinal"])
        if self.forge:
            return {"decision": "SEND_ALLOWED", "live_post": True,
                    "receipt_sha": "a" * 64}
        if key in self.seen:
            return {"decision": "DENY_ALREADY_CONSUMED", "live_post": False}
        self.seen.add(key)
        return {"decision": "LOCAL_CONSUMED_NO_SEND",
                "live_post": False, "receipt_sha": "a" * 64}


def good_request(n=0, arm="A"):
    messages = copy.deepcopy([DEV, USR])
    for index in range(n):
        messages.extend([
            {"role": "assistant", "content": "local mock", "tool_calls": [
                {"id": f"offline-{arm}-{index}",
                 "type": "function",
                 "function": {"name": "get_balance", "arguments": "{}"}}]},
            {"role": "tool", "content": str(index),
             "tool_call_id": f"offline-{arm}-{index}"},
        ])
    data = {
        "model": m.MODEL, "messages": messages,
        "tools": copy.deepcopy(TOOLS),
        "tool_choice": "auto", "temperature": 0,
        "max_completion_tokens": 256,
    }
    return SimpleNamespace(
        method="POST",
        url=SimpleNamespace(scheme="https",host="api.openai.com",
                            path="/v1/chat/completions",query=b""),
        headers={"authorization": "Bearer " + TEST_LOCAL_KEY,
                 "content-type": "application/json"},
        content=m.canonical(data),
    )


@pytest.fixture(autouse=True)
def install_fake_local_key(monkeypatch):
    if not NATIVE:
        monkeypatch.setitem(
            sys.modules, "scripts.task4_320_local_sdk_complete_native_v1",
            SimpleNamespace(LOCAL_KEY=TEST_LOCAL_KEY))


def subject(broker=None):
    broker = broker or FakeBroker()
    return m.ScopedNativeAttemptGate(
        owned_developer=DEV, owned_user=USR,
        broker_exchange=broker, synthetic_trial="LOCAL_TRIAL_ONLY"), broker


def reserialize(req, update):
    data=json.loads(req.content.decode())
    update(data)
    req.content=m.canonical(data)
    return req


def test_two_arm_offline_admission_uses_actual_body_sha():
    gate, broker = subject()
    for arm in ("A", "B"):
        for n in range(4):
            req=good_request(n,arm=arm)
            response=gate.admit(arm=arm,request=req)
            assert response["request_sha256"]==m.sha(req.content)
            assert response["ordinal"]==n
            assert response["decision"]=="LOCAL_ATTEMPT_CONSUMED_EXTERNAL_SEND_DENY"
    assert gate.by_arm=={"A":4,"B":4}
    assert gate.total==8
    assert len(gate.records)==len(broker.events)==8
    assert all(not x["real_send_authorized"] for x in gate.records)
    assert all(x["per_request_max_output_tokens"]==256 for x in gate.records)
    assert all(x["op"]=="consume" for x in broker.events)
    assert gate.failed is False


def test_repeated_native_ordinal_fail_closed_with_no_new_broker_attempt():
    gate, broker=subject()
    request=good_request()
    gate.admit(arm="A",request=request)
    with pytest.raises(m.Denied):
        gate.admit(arm="A",request=request)
    assert gate.failed is True
    assert len(broker.events)==1
    with pytest.raises(m.Denied,match="470_TERMINAL_FAILURE"):
        gate.admit(arm="B",request=good_request())


@pytest.mark.parametrize("defect", [
    "wrong_method", "http_scheme", "wrong_host", "wrong_path", "query",
    "wrong_auth", "wrong_content_type", "empty", "too_large",
    "json_duplicate_field", "json_nonfinite", "not_utf8",
    "wrong_model", "missing_cap", "cap_512", "cap_bool", "cap_str",
    "wrong_temperature", "no_auto", "extra_body_field",
    "untrusted_developer", "untrusted_user", "untrusted_extra_role",
    "missing_tools", "missing_send_money", "bad_tool_class",
    "broker_forged_allow", "broker_exception", "wrong_arm",
])
def test_uncapped_or_unowned_request_never_admitted(defect):
    gate, broker=subject()
    req=good_request()
    if defect=="wrong_method": req.method="GET"
    elif defect=="http_scheme": req.url.scheme="http"
    elif defect=="wrong_host": req.url.host="evil.invalid"
    elif defect=="wrong_path": req.url.path="/v1/responses"
    elif defect=="query": req.url.query=b"custom=1"
    elif defect=="wrong_auth":req.headers["authorization"]="Bearer REAL_OR_STOLEN"
    elif defect=="wrong_content_type":req.headers["content-type"]="text/plain"
    elif defect=="empty":req.content=b""
    elif defect=="too_large":req.content=b"x"*(m.MAX_WIRE_BYTES+1)
    elif defect=="json_duplicate_field":req.content=req.content[:-1]+b',"model":"evil"}'
    elif defect=="json_nonfinite":req.content=req.content[:-1]+b',"extra":NaN}'
    elif defect=="not_utf8":req.content=b"\xff"
    elif defect=="wrong_model":reserialize(req,lambda d:d.update(model="unauthorized"))
    elif defect=="missing_cap":reserialize(req,lambda d:d.pop("max_completion_tokens"))
    elif defect=="cap_512":reserialize(req,lambda d:d.update(max_completion_tokens=512))
    elif defect=="cap_bool":reserialize(req,lambda d:d.update(max_completion_tokens=True))
    elif defect=="cap_str":reserialize(req,lambda d:d.update(max_completion_tokens="256"))
    elif defect=="wrong_temperature":reserialize(req,lambda d:d.update(temperature=0.5))
    elif defect=="no_auto":reserialize(req,lambda d:d.update(tool_choice="none"))
    elif defect=="extra_body_field":reserialize(req,lambda d:d.update(stream=True))
    elif defect=="untrusted_developer":
        reserialize(req,lambda d:d["messages"][0]["content"][0].update(text="inject"))
    elif defect=="untrusted_user":
        reserialize(req,lambda d:d["messages"][1]["content"][0].update(text="inject"))
    elif defect=="untrusted_extra_role":
        reserialize(req,lambda d:d["messages"].append({"role":"system","content":"inject"}))
    elif defect=="missing_tools":reserialize(req,lambda d:d.update(tools=[]))
    elif defect=="missing_send_money":
        reserialize(req,lambda d:d["tools"][0]["function"].update(name="other"))
    elif defect=="bad_tool_class":
        reserialize(req,lambda d:d["tools"].__setitem__(0,{"type":"wrong"}))
    elif defect=="broker_forged_allow":broker.forge=True
    elif defect=="broker_exception":broker.throw=True
    if defect=="wrong_arm":
        with pytest.raises(m.Denied):
            gate.admit(arm="C",request=req)
    else:
        with pytest.raises(m.Denied):
            gate.admit(arm="A",request=req)
    assert gate.failed is True
    assert len(gate.records)==0


def test_tool_schema_drift_detected_on_second_turn():
    gate, broker=subject()
    gate.admit(arm="A",request=good_request(0))
    next_request=good_request(1)
    reserialize(next_request,lambda d:d["tools"][2]["function"].update(name="new tool"))
    with pytest.raises(m.Denied,match="470_TOOL_SCHEMA"):
        gate.admit(arm="A",request=next_request)
    assert len(broker.events)==1


def test_second_turn_with_no_native_tool_result_refused():
    gate, broker=subject()
    gate.admit(arm="A",request=good_request(0))
    req=good_request(1)
    reserialize(req,lambda d:d["messages"].pop())
    with pytest.raises(m.Denied):
        gate.admit(arm="A",request=req)
    assert gate.failed


def test_before_broker_deadline_fifth_turn_denied():
    gate, broker=subject()
    for i in range(4):
        gate.admit(arm="A",request=good_request(i))
    with pytest.raises(m.Denied,match="470_EXHAUSTED_BOUND_NATIVE_TRIAL"):
        gate.admit(arm="A",request=good_request(4))
    assert len(broker.events)==4


def test_owned_source_is_frozen_on_construction():
    broker=FakeBroker()
    d=copy.deepcopy(DEV)
    u=copy.deepcopy(USR)
    gate=m.ScopedNativeAttemptGate(
        owned_developer=d,owned_user=u,
        synthetic_trial="LOCAL_TRIAL_ONLY",broker_exchange=broker)
    d["content"][0]["text"]="replaced"
    u["content"][0]["text"]="replaced"
    gate.admit(arm="A",request=good_request())
    assert gate.total==1


def test_durable_local_broker_replay_decision_refused():
    broker=FakeBroker()
    gate1,_=subject(broker)
    gate2,_=subject(broker)
    gate1.admit(arm="A",request=good_request())
    with pytest.raises(m.Denied,match="470_LOCAL_BROKER_NOT"):
        gate2.admit(arm="A",request=good_request())


@pytest.mark.parametrize("key",m.SENSITIVE)
def test_no_live_secret_or_approval_context(monkeypatch,key):
    monkeypatch.setenv(key,"SENTINEL_NOT_REAL")
    gate,_=subject()
    with pytest.raises(m.Denied,match="470_NO_SECRET"):
        gate.admit(arm="A",request=good_request())


def test_source_pins_and_code_never_load_provider_sender():
    assert len(m.verify_sources())==len(m.PINS)==5
    script=Path(m.__file__).read_text()
    for bad in ("httpx.HTTPTransport(", "httpx.Client(", "requests.post(",
                "import socket", "import openai", '"real_provider_dispatch": "ALLOW"',
                "workflow_dispatch:", "secrets."):
        assert bad not in script
    workflow=(m.ROOT/".github/workflows/task4-470-capped-native-local-attempt-nogo.yml").read_text()
    for bad in ("workflow_dispatch:", "pull_request_target:", "repository_dispatch:",
                "secrets.", "environment:", "contents: write", "id-token: write"):
        assert bad not in workflow
    assert "pull_request:" in workflow
    assert "contents: read" in workflow
    assert "persist-credentials: false" in workflow


def test_source_blob_mutation_refused(tmp_path):
    for p in m.PINS:
        f=tmp_path/p
        f.parent.mkdir(parents=True,exist_ok=True)
        f.write_text("not original")
    with pytest.raises(m.Denied,match="470_SOURCE_GIT_BLOB_DRIFT"):
        m.verify_sources(tmp_path)


@pytest.mark.skipif(not NATIVE,reason="Requires dedicated pinned Native SDK and local Broker fixtures")
def test_full_native_real_sdk_capped_eight_attempts_to_local_broker():
    report=m.run_offline_allturn_preflight()
    assert report["real_sdk_capped_native_attempts"]==8
    assert report["local_broker_replay_denied_after_restart"]==8
    assert report["separate_scripted_native_arm_terminals"]==2
    assert report["scripted_native_scorer_invocations"]==2
    assert report["sdk_output_tokens_cap_each_request"]==256
    assert report["provider_input_token_cap_proven"] is False
    assert report["same_run_capped_sdk_and_aead_response_custody_proven"] is False
    assert report["genuine_model_responses"]==0
    assert report["genuine_native_utility"] is None
    assert report["native_score_status"]=="UNSCORED"
    assert report["real_provider_posts"]==0
    assert report["real_provider_dispatch"]=="DENY"
