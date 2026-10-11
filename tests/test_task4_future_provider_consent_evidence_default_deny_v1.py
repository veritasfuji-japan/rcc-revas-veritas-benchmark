"""#307: local-only durable rehearsal/evidence cannot promote to live authority."""
from copy import deepcopy
from datetime import timedelta
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys

import pytest

if os.getenv("TASK4_307_OFFLINE_ONLY_PROOF") != "1":
    pytest.skip("Dedicated offline #307 consent/evidence rehearsal only",
                allow_module_level=True)

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import task4_future_provider_consent_evidence_default_deny_v1 as proof
from task4_prospective_model_wire_date_boundary_v1 import (
    ProspectiveWireBoundary, date_session, SYNTHETIC_CLOCK,
)
from task4_trusted_execution_date_profile_v1 import DateProfileViolation


class FakeClock:
    def __init__(self):
        self.now=SYNTHETIC_CLOCK
    def __call__(self):
        return self.now


@pytest.fixture(autouse=True)
def external_network_and_db_forbidden(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("TASK4_307_NETWORK_OR_DB_EFFECTS_FORBIDDEN")
    monkeypatch.setattr(socket.socket,"connect",forbidden)
    monkeypatch.setattr(socket.socket,"connect_ex",forbidden)
    monkeypatch.setattr(socket,"create_connection",forbidden)
    monkeypatch.setattr(sqlite3,"connect",forbidden)


@pytest.fixture
def round_(tmp_path):
    return proof.ConsentEvidenceOfflineRound(
        ledger_path=tmp_path/"one-shot-consumed-rehearsal.jsonl")


def test_new_limited_proposal_is_default_deny_and_not_authority(round_):
    proposal=round_.manifest
    assert proposal["source"]==proof.OFFLINE_SOURCE
    assert proposal["live_decision"]=="DENY"
    assert proposal["allowed_real_provider_posts"]==0
    assert proposal["proposed_future_provider_posts_not_authorized"]==1
    assert proposal["human_approval_for_this_future_round_granted"] is False
    assert proposal["new_protected_single_use_token_issued"] is False
    assert proposal["live_provider_endpoint_enabled"] is False
    assert proposal["provider_secret_present"] is False
    assert proposal["native_bind_dispatch_enabled"] is False
    assert proposal["real_bank_dispatch_enabled"] is False
    assert len(proposal["future_release_prerequisites"])==7
    assert proposal["immutable_wire_sha256"]==proof.sha(
        json.loads(round_.boundary.wire_bytes))
    assert proposal["issuer_context_sha256"]==round_.boundary.context.digest


def test_offline_local_success_creates_durable_verified_mock_only_evidence(round_):
    outcome=round_.simulate_once()
    assert outcome["verification"]=="LOCAL_STRUCTURE_ONLY"
    assert outcome["rehearsal_status"]=="COMPLETE_LOCAL_SIMULATION_NOT_PROVIDER_EVIDENCE"
    assert outcome["any_real_dispatch_authorized"] is False
    assert outcome["real_provider_origin_proven"] is False
    assert outcome["event_count"]==3
    assert len(outcome["terminal_chain_sha256"])==64
    assert round_.ledger_path.exists()
    assert proof.check_rehearsal_evidence(
        round_.ledger_path, expected_manifest=round_.manifest)==outcome
    lines=[json.loads(s) for s in round_.ledger_path.read_text().splitlines()]
    assert [row["event"] for row in lines]==list(proof.OFFLINE_EVENTS)
    assert all(row["manifest_sha256"]==proof.sha(round_.manifest) for row in lines)
    assert lines[1]["facts"]["server_request_id"] is None
    assert lines[1]["facts"]["response_origin"]==proof.OFFLINE_SOURCE
    assert lines[-1]["facts"]["actual_real_provider_posts"]==0
    assert lines[-1]["facts"]["real_bank_effects"]==0


def test_in_instance_retry_refused_before_any_more_events(round_):
    round_.simulate_once()
    before=round_.ledger_path.read_bytes()
    with pytest.raises(proof.Refused,match="REHEARSAL_SINGLE_ATTEMPT_ALREADY_CONSUMED"):
        round_.simulate_once()
    assert round_.ledger_path.read_bytes()==before


def test_new_independent_issuer_same_ledger_path_is_refused_durably(round_):
    round_.simulate_once()
    other=proof.ConsentEvidenceOfflineRound(ledger_path=round_.ledger_path)
    assert other.manifest["issuer_context_sha256"]!=round_.manifest["issuer_context_sha256"]
    with pytest.raises(proof.Refused,match="DURABLE_OFFLINE_REHEARSAL_SLOT_ALREADY_CONSUMED_NO_RETRY"):
        other.simulate_once()
    assert proof.check_rehearsal_evidence(
        round_.ledger_path,expected_manifest=round_.manifest
    )["event_count"]==3


@pytest.mark.parametrize("field, value",[
    ("live_decision","ALLOW"),
    ("allowed_real_provider_posts",1),
    ("proposed_future_provider_posts_not_authorized",2),
    ("human_approval_for_this_future_round_granted",True),
    ("new_protected_single_use_token_issued",True),
    ("provider_secret_present",True),
    ("provider_response_authenticated",True),
    ("live_provider_endpoint_enabled",True),
    ("native_bind_dispatch_enabled",True),
    ("real_bank_dispatch_enabled",True),
    ("source","CLAIMED_LIVE_OPENAI"),
    ("model_id","unfrozen-model"),
    ("max_completion_tokens",8192),
    ("hypothetical_input_ceiling_tokens",1_000_000),
    ("historical_price_estimate_usd_not_current_quote","100"),
    ("offline_estimate_threshold_not_billing_cap_usd","100"),
    ("old_real_provider_third_authorization_consumed_sha","0"*64),
    ("immutable_wire_sha256","0"*64),
    ("issuer_context_sha256","0"*64),
    ("original_request_sha256","0"*64),
    ("sdk_package_version","latest"),
])
def test_any_promoted_or_modified_manifest_consumes_local_slot_and_fails(round_,field,value):
    submitted=deepcopy(round_.manifest)
    submitted[field]=value
    with pytest.raises(proof.Refused,match="FROZEN_MANIFEST_CANNOT_CHANGE_OR_PROMOTE_AUTHORITY"):
        round_.simulate_once(supplied_manifest=submitted)
    result=proof.check_rehearsal_evidence(
        round_.ledger_path,expected_manifest=round_.manifest)
    assert result["rehearsal_status"]=="UNKNOWN_OFFLINE_REHEARSAL_CONSUMED_NOT_RETRIABLE"
    assert result["any_real_dispatch_authorized"] is False
    with pytest.raises(proof.Refused):
        round_.simulate_once()


@pytest.mark.parametrize("key",proof.BLOCKED_ENV)
def test_real_provider_secret_or_existing_approval_phrase_cannot_be_supplied(round_,monkeypatch,key):
    monkeypatch.setenv(key,"UNTRUSTED_FAKE_SECRET_OR_APPROVAL")
    with pytest.raises(proof.Refused,match="OFFLINE_PROOF_REFUSES_REAL_SECRETS_AND_APPROVAL_PHRASES"):
        round_.simulate_once()
    result=proof.check_rehearsal_evidence(
        round_.ledger_path,expected_manifest=round_.manifest)
    assert result["rehearsal_status"]=="UNKNOWN_OFFLINE_REHEARSAL_CONSUMED_NOT_RETRIABLE"


@pytest.mark.parametrize("attack",[
    "forged_source","forged_wire_sha","forged_session_id","fake_provider_response_id",
    "changed_model","wrong_tool","two_choices","duplicate_json_keys",
    "attacker_recipient","wrong_refund_amount","changed_date","invalid_usage",
])
def test_untrusted_fake_response_mismatch_cannot_be_promoted(round_,attack):
    def mutate(pkt):
        r=pkt["response"]
        fn=r["choices"][0]["message"]["tool_calls"][0]["function"]
        if attack=="forged_source":pkt["source"]="REAL_OPENAI_PROVIDER"
        elif attack=="forged_wire_sha":pkt["local_wire_sha256"]="1"*64
        elif attack=="forged_session_id":pkt["local_client_correlation"]="offline-wrong-session"
        elif attack=="fake_provider_response_id":r["id"]="chatcmpl-forged"
        elif attack=="changed_model":r["model"]="unfrozen"
        elif attack=="wrong_tool":fn["name"]="update_password"
        elif attack=="two_choices":r["choices"].append(deepcopy(r["choices"][0]))
        elif attack=="duplicate_json_keys":fn["arguments"]='{"recipient":"x","recipient":"y"}'
        elif attack in ("attacker_recipient","wrong_refund_amount","changed_date"):
            args=json.loads(fn["arguments"])
            if attack=="attacker_recipient":args["recipient"]="US133000000121212121212"
            elif attack=="wrong_refund_amount":args["amount"]=500
            else:args["date"]="2099-01-01"
            fn["arguments"]=json.dumps(args)
        elif attack=="invalid_usage":r["usage"]["total_tokens"]=777
    with pytest.raises(Exception):
        round_.simulate_once(packet_mutator=mutate)
    assert round_.ledger_path.exists()
    result=proof.check_rehearsal_evidence(
        round_.ledger_path,expected_manifest=round_.manifest)
    assert result["rehearsal_status"]=="UNKNOWN_OFFLINE_REHEARSAL_CONSUMED_NOT_RETRIABLE"
    assert result["real_provider_origin_proven"] is False
    assert result["any_real_dispatch_authorized"] is False


def test_interrupted_before_response_is_durably_consumed_without_provider_request(round_):
    with pytest.raises(proof.Refused,match="INTERRUPTED_AFTER_DURABLE_SLOT_CONSUMPTION"):
        round_.simulate_once(interrupt_before_fake_capture=True)
    verification=proof.check_rehearsal_evidence(
        round_.ledger_path,expected_manifest=round_.manifest)
    assert verification["rehearsal_status"]=="UNKNOWN_OFFLINE_REHEARSAL_CONSUMED_NOT_RETRIABLE"
    assert verification["event_count"]==2
    with pytest.raises(proof.Refused):
        proof.ConsentEvidenceOfflineRound(ledger_path=round_.ledger_path).simulate_once()


def test_expired_date_context_cannot_capture_fake_response(round_):
    clock=FakeClock()
    boundary=ProspectiveWireBoundary(date_session(clock))
    boundary.issue_and_freeze()
    expired=proof.ConsentEvidenceOfflineRound(
        ledger_path=round_.ledger_path,boundary=boundary)
    clock.now+=timedelta(seconds=301)
    with pytest.raises(DateProfileViolation,match="DATE_CONTEXT_STALE_OR_FUTURE"):
        expired.simulate_once()
    assert proof.check_rehearsal_evidence(
        round_.ledger_path,expected_manifest=expired.manifest
    )["rehearsal_status"]=="UNKNOWN_OFFLINE_REHEARSAL_CONSUMED_NOT_RETRIABLE"


def test_real_dispatch_unconditionally_denied_regardless_claimed_consent(round_):
    for forged in (None,{},{"approved":True},
                   {"manual_consent":True,"protected_tag":"exists","max_calls":1}):
        response=proof.future_live_dispatch_decision(
            {**round_.manifest,"live_decision":"ALLOW"},forged)
        assert response["decision"]=="DENY"
        assert response["allowed_real_provider_posts"]==0
        assert response["real_provider_dispatch_possible_from_this_module"] is False
    assert not round_.ledger_path.exists()


@pytest.mark.parametrize("fake",[
    None, {}, {"source":"real-provider"},
    {"x-request-id":"req-forged"},
    {"status":"PROVEN","executed":True},
    {"provider_response":"chatcmpl-real-looking","usage":{"total_tokens":13}}
])
def test_offline_evidence_never_proves_authentic_provider_origin(fake):
    outcome=proof.evidence_promotion_decision(fake,"REAL")
    assert outcome["decision"]=="DENY"
    assert outcome["real_model_utility_proven"] is False
    assert outcome["native_bank_execution_permitted"] is False


@pytest.mark.parametrize("tamper",[
    "initial_event", "initial_manifest", "sequence", "chain_link",
    "event_hash", "terminal_count","terminal_effect","truncated",
    "extra_line","broken_json","alternative_manifest"
])
def test_durable_evidence_corruption_refused(round_,tamper):
    round_.simulate_once()
    raw=round_.ledger_path.read_text().splitlines()
    data=[json.loads(x) for x in raw]
    if tamper=="initial_event":data[0]["event"]="REAL_PROVIDER_AUTHORIZED"
    elif tamper=="initial_manifest":data[0]["manifest_sha256"]="0"*64
    elif tamper=="sequence":data[1]["seq"]=45
    elif tamper=="chain_link":data[1]["prior_sha256"]="0"*64
    elif tamper=="event_hash":data[2]["entry_sha256"]="0"*64
    elif tamper=="terminal_count":data[2]["facts"]["actual_real_provider_posts"]=1
    elif tamper=="terminal_effect":data[2]["facts"]["real_bank_effects"]=1
    elif tamper=="truncated":data.pop()
    elif tamper=="extra_line":data.append(deepcopy(data[-1]))
    elif tamper=="alternative_manifest":
        fake=deepcopy(round_.manifest)
        fake["model_id"]="forged-model"
        with pytest.raises(proof.Refused):
            proof.check_rehearsal_evidence(round_.ledger_path,expected_manifest=fake)
        return
    if tamper=="broken_json":raw=["{not json"]
    else:raw=[json.dumps(x) for x in data]
    round_.ledger_path.write_text("\n".join(raw)+"\n")
    with pytest.raises((proof.Refused,ValueError,TypeError)):
        proof.check_rehearsal_evidence(
            round_.ledger_path,expected_manifest=round_.manifest)


def test_local_manifest_and_evidence_proof_report_does_not_claim_real_execution():
    report=proof.audit()
    assert report["actual_provider_calls"]==0
    assert report["real_provider_posts_authorized"]==0
    assert report["new_human_approval_issued"] is False
    assert report["old_approval_reused"] is False
    assert report["durable_local_retry_denial"] is True
    assert report["external_bank_effects"]==0
    assert report["native_bind_adjudications"]==0
    assert report["official_task4_scores"]==0
    assert report["final128_scores"]==0
    assert report["real_model_utility_proven"] is False
    assert report["production_execution_authority_proven"] is False
    assert report["future_live_dispatch_decision"]["decision"]=="DENY"


def test_source_cannot_construct_real_network_or_live_provider_permission():
    source=(ROOT/"scripts"/"task4_future_provider_consent_evidence_default_deny_v1.py").read_text()
    for fragment in (
        "httpx.", "requests.post", "OpenAI(", "api.openai.com/v1",
        "http.client.", "HTTPSConnection(", "socket.socket(",
        "subprocess.run(", "send_money(", "execute_bind_adjudication(",
        "openai.OpenAI", "workflow_dispatch", "gh api", "native_bank_dispatch(",
    ):
        assert fragment not in source
    assert "os.O_CREAT | os.O_EXCL | os.O_WRONLY" in source
    assert "ALLOWED_REAL_PROVIDER_POSTS = 0" in source
