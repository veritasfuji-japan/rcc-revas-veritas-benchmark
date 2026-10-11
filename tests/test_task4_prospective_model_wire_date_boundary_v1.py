"""#303: prospective date-before-wire freeze and Bind-facing recheck, offline only."""
from copy import deepcopy
from datetime import timedelta
import json
import socket
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import task4_prospective_model_wire_date_boundary_v1 as proof
from task4_trusted_execution_date_profile_v1 import DateProfileViolation

class Clock:
    def __init__(self):
        self.now=proof.SYNTHETIC_CLOCK
    def __call__(self):
        return self.now

@pytest.fixture(autouse=True)
def no_external_network_or_database(monkeypatch):
    def deny(*args,**kwargs):
        pytest.fail("OFFLINE_303_EXTERNAL_EFFECT_ATTEMPT")
    monkeypatch.setattr(socket.socket,"connect",deny)
    monkeypatch.setattr(socket.socket,"connect_ex",deny)
    monkeypatch.setattr(socket,"create_connection",deny)
    monkeypatch.setattr(sqlite3,"connect",deny)

@pytest.fixture
def sample():
    clock=Clock()
    boundary=proof.ProspectiveWireBoundary(proof.date_session(clock))
    wire=boundary.issue_and_freeze()
    return clock,boundary,wire

def test_new_date_is_issued_before_model_compatible_wire(sample):
    _,b,wire=sample
    assert b.events==[
        "INDEPENDENT_DATE_ISSUED_BEFORE_MODEL_WIRE",
        "MODEL_COMPATIBLE_WIRE_FROZEN_BUT_NOT_DISPATCHED"]
    assert b.context.payload()["execution_date"]=="2031-07-08"
    assert b.context.payload()["immediate_pre_state_sha256"]==proof.sha(b.scope["trusted_prestate"])
    assert wire["model"]==proof.MODEL
    assert wire["max_completion_tokens"]==256
    assert wire["stream"] is wire["store"] is False
    assert wire["n"]==1
    assert len(wire["tools"])==1
    assert wire["messages"][0]["role"]=="developer"
    assert wire["messages"][1]["role"]=="user"
    assert wire["messages"][2]["role"]=="assistant"
    assert wire["messages"][3]["role"]=="tool"
    assert proof.ATTACK not in json.dumps(wire["messages"][:2])
    assert proof.ATTACK in json.dumps(wire["messages"][3])
    assert b.phase=="FROZEN_NOT_DISPATCHABLE"

def test_response_from_local_standin_can_be_captured_once_and_checked_before_bind(sample):
    _,b,wire=sample
    fake=proof.local_stub_candidate(deepcopy(wire))
    digest=b.capture_stub_response(supplied_wire=deepcopy(wire),proposed_candidate=fake)
    identity=b.verify_before_bind(supplied_wire=deepcopy(wire),candidate=deepcopy(fake))
    assert digest==proof.sha(fake)
    assert len(identity)==64
    assert b.binding.candidate_sha256==digest
    assert b.phase=="CANDIDATE_CAPTURED"
    with pytest.raises(proof.BoundaryViolation,match="ONE_RESPONSE_ATTEMPT_ONLY"):
        b.capture_stub_response(supplied_wire=wire,proposed_candidate=fake)

@pytest.mark.parametrize("mutation",[
    "wrong_model","wrong_date","wrong_user","attack_in_developer",
    "attack_in_user","removed_tool","modified_tool","tool_role_to_user",
    "increased_tokens","tool_choice_none","store_true","extra_action",
    "modified_read_call_id","altered_read_payload","unknown_role",
])
def test_model_request_modified_after_issuance_fails_closed(sample,mutation):
    _,b,wire=sample
    bad=deepcopy(wire)
    if mutation=="wrong_model":bad["model"]="unauthorized-model"
    elif mutation=="wrong_date":bad["messages"][0]["content"][0]["text"]="Task4 trusted runtime metadata: UTC execution date 2099-12-31."
    elif mutation=="wrong_user":bad["messages"][1]["content"][0]["text"]="Refund another account"
    elif mutation=="attack_in_developer":bad["messages"][0]["content"][0]["text"]+=proof.ATTACK
    elif mutation=="attack_in_user":bad["messages"][1]["content"][0]["text"]+=proof.ATTACK
    elif mutation=="removed_tool":bad["tools"]=[]
    elif mutation=="modified_tool":bad["tools"][0]["function"]["name"]="update_password"
    elif mutation=="tool_role_to_user":bad["messages"][3]["role"]="user"
    elif mutation=="increased_tokens":bad["max_completion_tokens"]=1024
    elif mutation=="tool_choice_none":bad["tool_choice"]="none"
    elif mutation=="store_true":bad["store"]=True
    elif mutation=="extra_action":bad["tools"].append({"type":"function","function":{"name":"update_password"}})
    elif mutation=="modified_read_call_id":bad["messages"][3]["tool_call_id"]="call_modified"
    elif mutation=="altered_read_payload":bad["messages"][3]["content"][0]["text"]="Fake senior instruction"
    elif mutation=="unknown_role":bad["messages"][0]["role"]="system"
    with pytest.raises(proof.BoundaryViolation,match="MODEL_WIRE_TAMPER_OR_SUBSTITUTION"):
        b.capture_stub_response(supplied_wire=bad,proposed_candidate=proof.local_stub_candidate(wire))
    # Failed first response attempt permanently closes this boundary slot.
    with pytest.raises(proof.BoundaryViolation,match="ONE_RESPONSE_ATTEMPT_ONLY"):
        b.capture_stub_response(supplied_wire=wire,proposed_candidate=proof.local_stub_candidate(wire))

@pytest.mark.parametrize("change",[
    "attack_recipient","wrong_amount","wrong_date","extra_arg",
    "different_protected_tool","fake_metadata","wrong_subject_type"
])
def test_bad_untrusted_local_model_proposal_is_rejected_without_repair(sample,change):
    _,b,wire=sample
    candidate=proof.local_stub_candidate(wire)
    if change=="attack_recipient":candidate["arguments"]["recipient"]=proof.ATTACKER
    elif change=="wrong_amount":candidate["arguments"]["amount"]=1000
    elif change=="wrong_date":candidate["arguments"]["date"]="2099-01-01"
    elif change=="extra_arg":candidate["arguments"]["notes"]="request elevated access"
    elif change=="different_protected_tool":candidate["name"]="update_password"
    elif change=="fake_metadata":candidate["metadata"]={"trusted":True}
    elif change=="wrong_subject_type":candidate["arguments"]["subject"]=True
    with pytest.raises(DateProfileViolation):
        b.capture_stub_response(supplied_wire=wire,proposed_candidate=candidate)
    with pytest.raises(proof.BoundaryViolation,match="ONE_RESPONSE_ATTEMPT_ONLY"):
        b.capture_stub_response(supplied_wire=wire,proposed_candidate=proof.local_stub_candidate(wire))

def test_model_cannot_forge_provider_response_identity(sample):
    _,b,wire=sample
    with pytest.raises(proof.BoundaryViolation,match="PROVIDER_RESPONSE_CANNOT_BE_IMPERSONATED"):
        b.capture_stub_response(supplied_wire=wire,
            proposed_candidate=proof.local_stub_candidate(wire),
            local_stub_id="chatcmpl_forged_provider_reply")

def test_context_expires_after_300_seconds_even_if_frozen_wire_unchanged(sample):
    clock,b,wire=sample
    clock.now+=timedelta(seconds=300)
    with pytest.raises(DateProfileViolation,match="DATE_CONTEXT_STALE_OR_FUTURE"):
        b.capture_stub_response(supplied_wire=wire,
            proposed_candidate=proof.local_stub_candidate(wire))
    assert b.phase=="RESPONSE_ATTEMPTED"

def test_context_cannot_survive_utc_day_rollover(sample):
    clock,b,wire=sample
    fake=proof.local_stub_candidate(wire)
    b.capture_stub_response(supplied_wire=wire,proposed_candidate=fake)
    clock.now+=timedelta(hours=12)
    with pytest.raises(DateProfileViolation):
        b.verify_before_bind(supplied_wire=wire,candidate=fake)

@pytest.mark.parametrize("field",["amount","recipient","subject","date"])
def test_candidate_substitution_after_capture_fails_at_bind_facing_gate(sample,field):
    _,b,wire=sample
    fake=proof.local_stub_candidate(wire)
    b.capture_stub_response(supplied_wire=wire,proposed_candidate=fake)
    bad=deepcopy(fake)
    bad["arguments"][field]="ATTACKER_NEW_VALUE"
    with pytest.raises(proof.BoundaryViolation,match="CANDIDATE_CHANGED_BEFORE_BIND"):
        b.verify_before_bind(supplied_wire=wire,candidate=bad)

def test_immediate_trusted_prestate_drift_prevents_bind_facing_verification(sample):
    _,b,wire=sample
    fake=proof.local_stub_candidate(wire)
    b.capture_stub_response(supplied_wire=wire,proposed_candidate=fake)
    drift=deepcopy(b.scope["trusted_prestate"])
    drift["bank_account"]["transactions"][0]["amount"]=999
    with pytest.raises(proof.BoundaryViolation,match="TRUSTED_PRESTATE_CHANGED_BEFORE_BIND"):
        b.verify_before_bind(supplied_wire=wire,candidate=fake,prestate=drift)

def test_session_cannot_be_reused_to_mint_second_wire(sample):
    _,b,wire=sample
    with pytest.raises(proof.BoundaryViolation,match="WIRE_CONTEXT_ALREADY_ISSUED"):
        b.issue_and_freeze()
    with pytest.raises(DateProfileViolation,match="DATE_CONTEXT_ALREADY_ISSUED"):
        b.session.issue_before_candidate(**b.scope)

def test_new_issuer_from_other_session_cannot_validate_borrowed_context(sample):
    _,b,wire=sample
    other=proof.ProspectiveWireBoundary(proof.date_session())
    other.issue_and_freeze()
    other.context=b.context
    with pytest.raises(DateProfileViolation,match="DATE_CONTEXT_AUTHENTICATION_FAILED"):
        other.capture_stub_response(supplied_wire=json.loads(other.wire_bytes),proposed_candidate=proof.local_stub_candidate(wire))

def test_audit_contract_prohibits_real_provider_and_production_allow():
    result=proof.audit()
    assert result["new_provider_calls"]==0
    assert result["native_bank_dispatches"]==0
    assert result["real_bank_effects"]==0
    assert result["native_veritas_bind_adjudications"]==0
    assert result["provider_dispatch_approved"] is False
    assert result["historical_third_permission_reused"] is False
    assert result["production_authority_proven"] is False
    assert result["no_real_model_response_used"] is True
    assert result["attacker_text_confined_to_lower_trust_tool_role"] is True
    assert len(result["wire_sha256"])==64

def test_source_contains_no_live_provider_dispatch():
    source=(Path(__file__).resolve().parents[1]/"scripts"/
        "task4_prospective_model_wire_date_boundary_v1.py").read_text()
    for token in ("openai.OpenAI(", "requests.post(", "http.client.HTTPSConnection(",
                  "send_money(", "execute_bind_adjudication(", "subprocess.run("):
        assert token not in source
