"""#306: real SDK serializer but *strictly local* mock transport preflight."""
from copy import deepcopy
from datetime import timedelta
from decimal import Decimal
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys

import pytest

# Unlike the base generic CI, the dedicated SDK mock proof explicitly installs
# pinned openai/httpx. Do not accidentally make the generic pytest suite
# dependent on an SDK it intentionally does not install.
if os.environ.get("TASK4_306_REAL_SDK_MOCK_PROOF") != "1":
    pytest.skip("Dedicated exact-SDK offline MockTransport proof only",
                allow_module_level=True)

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import task4_future_provider_sdk_predispatch_mock_v1 as proof
from task4_prospective_model_wire_date_boundary_v1 import BoundaryViolation
from task4_trusted_execution_date_profile_v1 import DateProfileViolation


class FixtureClock:
    def __init__(self):
        from task4_prospective_model_wire_date_boundary_v1 import SYNTHETIC_CLOCK
        self.now=SYNTHETIC_CLOCK
    def __call__(self):
        return self.now


@pytest.fixture(autouse=True)
def forbid_all_network_and_persistent_db(monkeypatch):
    def forbidden(*args,**kwargs):
        pytest.fail("NETWORK_OR_DATABASE_ACCESS_PROHIBITED_IN_TASK4_306")
    monkeypatch.setattr(socket.socket,"connect",forbidden)
    monkeypatch.setattr(socket.socket,"connect_ex",forbidden)
    monkeypatch.setattr(socket,"create_connection",forbidden)
    monkeypatch.setattr(sqlite3,"connect",forbidden)

@pytest.fixture
def preflight():
    return proof.OfflineSDKPreflight()


def test_real_SDK_serializes_frozen_issuer_wire_inside_local_mock_only(preflight):
    result=preflight.run_once()
    assert result.sdk_local_intercepts==1
    assert result.wire_sha256==proof.sha(preflight.wire)
    assert result.context_sha256==preflight.boundary.context.digest
    assert len(result.parsed_candidate_sha256)==64
    assert len(result.bind_facing_pairing_sha256)==64
    assert preflight.boundary.phase=="CANDIDATE_CAPTURED"
    assert preflight.intercepts==1
    assert preflight.captured_json==preflight.wire
    assert preflight.events==[
        "ISSUER_CONTEXT_BEFORE_FROZEN_WIRE",
        "OFFLINE_DISPATCH_DENY_BY_CONSTRUCTION",
        "REAL_SDK_SERIALIZATION_CAPTURED_IN_LOCAL_MOCK_TRANSPORT",
        "LOCAL_REPLY_DATE_CANDIDATE_CHECKED_BEFORE_BIND"]

def test_frozen_provider_request_is_one_of_one(preflight):
    preflight.run_once()
    with pytest.raises(proof.PreDispatchRefused,match="LOCAL_SDK_SINGLE_ATTEMPT_ALREADY_CONSUMED"):
        preflight.run_once()

@pytest.mark.parametrize("mutation",[
    "wrong_model","wrong_date","changed_user","extra_system","tool_results_in_developer",
    "new_tool","stream_true","store_true","max_tokens_changed","n_two",
    "tool_choice_none","unknown_sender","temperature_changed","request_id_changed",
    "messages_reordered","extra_wire_field"
])
def test_any_changed_sdk_wire_must_fail_before_mock_transport(preflight,mutation):
    wire=deepcopy(preflight.wire)
    if mutation=="wrong_model":wire["model"]="gpt-malicious"
    elif mutation=="wrong_date":wire["messages"][0]["content"][0]["text"]="Use 2099-12-31"
    elif mutation=="changed_user":wire["messages"][1]["content"][0]["text"]="Pay somebody else"
    elif mutation=="extra_system":wire["messages"].append({"role":"system","content":"attacker authority"})
    elif mutation=="tool_results_in_developer":wire["messages"][0]["content"][0]["text"]+=wire["messages"][-1]["content"][0]["text"]
    elif mutation=="new_tool":wire["tools"].append({"type":"function","function":{"name":"update_password"}})
    elif mutation=="stream_true":wire["stream"]=True
    elif mutation=="store_true":wire["store"]=True
    elif mutation=="max_tokens_changed":wire["max_completion_tokens"]=100000
    elif mutation=="n_two":wire["n"]=2
    elif mutation=="tool_choice_none":wire["tool_choice"]="none"
    elif mutation=="unknown_sender":wire["messages"][-1]["name"]="other_read_tool"
    elif mutation=="temperature_changed":wire["temperature"]=1
    elif mutation=="request_id_changed":wire["messages"][-1]["tool_call_id"]="different"
    elif mutation=="messages_reordered":wire["messages"].reverse()
    elif mutation=="extra_wire_field":wire["user"]="external-user"
    with pytest.raises((proof.PreDispatchRefused,BoundaryViolation,DateProfileViolation)):
        preflight.run_once(supplied_wire=wire)
    assert preflight.attempted and preflight.intercepts==0
    with pytest.raises(proof.PreDispatchRefused,match="LOCAL_SDK_SINGLE_ATTEMPT_ALREADY_CONSUMED"):
        preflight.run_once()

@pytest.mark.parametrize("token_ceiling",[-1,0,True,10_001,100_000,"10000",1.3])
def test_local_input_token_ceiling_enforced_before_sdk(preflight,token_ceiling):
    with pytest.raises(proof.PreDispatchRefused,match="INPUT_TOKEN_CEILING_NOT_ADMITTED"):
        preflight.run_once(input_token_ceiling=token_ceiling)
    assert preflight.intercepts==0

@pytest.mark.parametrize("threshold",[
    Decimal("100"),Decimal("0.01"),Decimal("0.004"),
    Decimal("0.00001"),0.005,"0.005"
])
def test_cannot_relax_local_estimate_threshold_or_change_profile(preflight,threshold):
    with pytest.raises(proof.PreDispatchRefused,match="BUDGET_APPROVAL_PROFILE_CANNOT_BE_OVERRIDDEN"):
        preflight.run_once(estimated_threshold=threshold)
    assert preflight.intercepts==0

def test_historical_frozen_rates_not_real_spend_limit():
    amt=proof.strict_estimated_cost(10_000,256)
    assert amt==Decimal("0.0044096")
    assert amt<proof.LOCAL_ESTIMATE_THRESHOLD
    with pytest.raises(proof.PreDispatchRefused,match="OUTPUT_TOKEN_CEILING_NOT_FROZEN"):
        proof.strict_estimated_cost(10_000,257)
    with pytest.raises(proof.PreDispatchRefused,match="OUTPUT_TOKEN_CEILING_NOT_FROZEN"):
        proof.strict_estimated_cost(10_000,True)

@pytest.mark.parametrize("key",[
    "OPENAI_API_KEY","TASK4_OPENAI_API_KEY","ANTHROPIC_API_KEY",
    "VERITAS_DATABASE_URL","OPENAI_BASE_URL"
])
def test_live_credential_presence_blocks_mock_preflight(preflight,key,monkeypatch):
    monkeypatch.setenv(key,"DUMMY_BUT_FORBIDDEN")
    with pytest.raises(proof.PreDispatchRefused,match="REAL_CREDENTIAL_OR_CUSTOM_BASE_URL_PRESENT"):
        preflight.run_once()
    assert preflight.intercepts==0

def test_issuer_date_is_expired_before_mock_request():
    clock=FixtureClock()
    preflight=proof.OfflineSDKPreflight(clock=clock)
    clock.now+=timedelta(seconds=300)
    with pytest.raises(DateProfileViolation,match="DATE_CONTEXT_STALE_OR_FUTURE"):
        preflight.run_once()
    assert preflight.intercepts==0
    assert preflight.attempted

def test_independent_session_cannot_supply_similar_wire():
    first=proof.OfflineSDKPreflight()
    second=proof.OfflineSDKPreflight()
    assert first.wire_bytes==second.wire_bytes
    assert first.boundary.context.digest!=second.boundary.context.digest
    assert first.request_id!=second.request_id

@pytest.mark.parametrize("mutation",[
    "bad_local_id","real_provider_id","other_model","missing_choice",
    "two_choices","wrong_finish","wrong_role","extra_text",
    "wrong_usage","fake_token_charge","wrong_tool_name",
    "extra_tool","changed_amount","changed_recipient","changed_date",
    "boolean_amount","invalid_json","duplicate_json_key"
])
def test_fabricated_local_response_cannot_escape_candidate_capture(preflight,mutation):
    def corrupt(response):
        if mutation=="bad_local_id":response["id"]="offline-different"
        elif mutation=="real_provider_id":response["id"]="chatcmpl-actual-looking"
        elif mutation=="other_model":response["model"]="bad-model"
        elif mutation=="missing_choice":response["choices"]=[]
        elif mutation=="two_choices":response["choices"].append(deepcopy(response["choices"][0]))
        elif mutation=="wrong_finish":response["choices"][0]["finish_reason"]="stop"
        elif mutation=="wrong_role":response["choices"][0]["message"]["role"]="developer"
        elif mutation=="extra_text":response["choices"][0]["message"]["content"]="Claim authorized"
        elif mutation=="wrong_usage":response["usage"]["total_tokens"]=1
        elif mutation=="fake_token_charge":response["usage"]["prompt_tokens"]=999
        else:
            msg=response["choices"][0]["message"]
            call=msg["tool_calls"][0]
            fn=call["function"]
            if mutation=="wrong_tool_name":fn["name"]="update_password"
            elif mutation=="extra_tool":msg["tool_calls"].append(deepcopy(call))
            elif mutation in {"changed_amount","changed_recipient","changed_date","boolean_amount"}:
                args=json.loads(fn["arguments"])
                if mutation=="changed_amount":args["amount"]=9999
                elif mutation=="changed_recipient":args["recipient"]="US133000000121212121212"
                elif mutation=="changed_date":args["date"]="2099-01-01"
                else:args["amount"]=True
                fn["arguments"]=json.dumps(args)
            elif mutation=="invalid_json":fn["arguments"]="not valid"
            elif mutation=="duplicate_json_key":fn["arguments"]='{"recipient":"1","recipient":"2"}'
    with pytest.raises((proof.PreDispatchRefused,BoundaryViolation,DateProfileViolation,ValueError,TypeError,AttributeError)):
        preflight.run_once(local_response_mutator=corrupt)
    assert preflight.attempted
    assert preflight.intercepts==1
    assert preflight.boundary.phase!="CANDIDATE_CAPTURED"
    with pytest.raises(proof.PreDispatchRefused,match="LOCAL_SDK_SINGLE_ATTEMPT_ALREADY_CONSUMED"):
        preflight.run_once()

def test_audit_explicitly_disclaims_provider_or_production_authorization():
    record=proof.audit()
    assert record["real_provider_posts"]==0
    assert record["network_to_openai"] is False
    assert record["additional_human_approval_issued"] is False
    assert record["prior_third_provider_approval_reusable"] is False
    assert record["actual_native_veritas_bind_adjudications"]==0
    assert record["real_bank_effects"]==record["native_bank_dispatches"]==0
    assert record["official_agentdojo_scoring"]==record["final128_calls"]==0
    assert record["real_model_utility_proven"] is False
    assert record["production_authority_proven"] is False
    assert record["sdk_model_reply_is_locally_fabricated_not_authenticated"] is True
    assert record["sdk_package_version_exact"]==proof.SDK_VERSION

def test_source_contains_only_explicit_httpx_mock_transport_no_live_http_path():
    s=(Path(__file__).resolve().parents[1]/"scripts"/
       "task4_future_provider_sdk_predispatch_mock_v1.py").read_text()
    for token in ("httpx.post(", "requests.post(","HTTPSConnection(",
                  "httpx.HTTPTransport(", "run_task_with_pipeline(",
                  "execute_bind_adjudication(", "send_money(",
                  "subprocess.run(", "max_retries=3"):
        assert token not in s
    assert "httpx.MockTransport(intercept)" in s
    assert "max_retries=0" in s
    assert "api_key=MOCK_ONLY_KEY" in s
