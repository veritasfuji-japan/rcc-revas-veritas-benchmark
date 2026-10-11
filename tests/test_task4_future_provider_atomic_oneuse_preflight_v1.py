"""#308: one atomic local rehearsal slot, exactly scoped, no real approval."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import timedelta
import json
import os
from pathlib import Path
import socket
import sys

import pytest

if os.getenv("TASK4_308_OFFLINE_PROOF")!="1":
    pytest.skip("Dedicated #308 local-only SQLite atomic-consumption test",
                allow_module_level=True)
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import task4_future_provider_atomic_oneuse_preflight_v1 as proof
from task4_prospective_model_wire_date_boundary_v1 import (
    ProspectiveWireBoundary,date_session,SYNTHETIC_CLOCK, MODEL,
)
from task4_trusted_execution_date_profile_v1 import DateProfileViolation


class FixtureClock:
    def __init__(self): self.now=SYNTHETIC_CLOCK
    def __call__(self): return self.now

@pytest.fixture(autouse=True)
def disallow_external_network(monkeypatch):
    def stop(*args,**kwargs):
        pytest.fail("NO_EXTERNAL_NETWORK_ALLOWED_FOR_TASK4_308")
    monkeypatch.setattr(socket.socket,"connect",stop)
    monkeypatch.setattr(socket.socket,"connect_ex",stop)
    monkeypatch.setattr(socket,"create_connection",stop)

@pytest.fixture
def round_(tmp_path):
    return proof.OfflineSingleUseAdmission(db_path=tmp_path/"local-consume.sqlite3")


def test_exact_proposal_bound_to_issuer_frozen_wire_cost_and_old_consumption(round_):
    p=round_.plan
    assert p["source"]==proof.SOURCE
    assert p["issuer_context_sha256"]==round_.boundary.context.digest
    assert p["immutable_wire_sha256"]==proof.sha(
        json.loads(round_.boundary.wire_bytes))
    assert p["model"]==MODEL
    assert p["proposed_call_count_not_allowed"]==1
    assert p["live_provider_posts_authorized"]==0
    assert p["new_human_consent_issued"] is False
    assert p["production_grant_issued"] is False
    assert p["native_bind_authorized"] is False
    assert p["bank_action_authorized"] is False
    assert p["old_provider_consent_consumed_sha"]==proof.HISTORICAL_THIRD_CONSUMED
    assert p["estimated_spend_usd_historical_not_invoice"]=="0.0044096"
    assert p["local_estimate_threshold_usd_not_billing_cap"]=="0.005"
    assert p["output_token_ceiling"]==256
    assert round_.ack["kind"]==proof.OFFLINE_ACK_KIND
    assert round_.ack["real_execution_authorized"] is False
    assert round_.ack["server_request_id"] is None


def test_first_local_attempt_consumes_atomically_but_never_posts(round_):
    result=round_.attempt_once()
    assert result["local_state"]=="OFFLINE_VALIDATED_REAL_DISPATCH_STILL_DENIED"
    assert result["sqlite_atomic_consumption"] is True
    assert result["live_api_dispatch"]=="DENY"
    assert result["provider_calls"]==0
    assert result["bank_effects"]==result["native_bind_calls"]==0
    assert result["globally_durable_single_use_proven"] is False
    assert len(result["local_receipt_digest"])==64
    assert result==round_.inspect()


def test_in_process_repeat_refused_before_any_db_change(round_):
    before=round_.attempt_once()
    with pytest.raises(proof.Rejected,match="IN_PROCESS_SIMULATION_ALREADY_ATTEMPTED"):
        round_.attempt_once()
    assert round_.inspect()==before


def test_restart_with_same_issuer_consumed_slot_is_refused(round_):
    before=round_.attempt_once()
    restarted=proof.OfflineSingleUseAdmission(
        db_path=round_.db_path,boundary=round_.boundary)
    assert restarted.slot==round_.slot
    with pytest.raises(proof.Rejected,match="ALREADY_CONSUMED_ATOMIC_LOCAL_SLOT_NO_RETRY"):
        restarted.attempt_once()
    assert restarted.inspect()==before


def test_concurrent_independent_consumers_same_local_slot_only_one_wins(round_):
    copies=[proof.OfflineSingleUseAdmission(
                db_path=round_.db_path,boundary=round_.boundary)
            for _ in range(10)]
    def try_one(obj):
        try:
            return ("success",obj.attempt_once()["local_state"])
        except proof.Rejected as e:
            return ("refused",str(e))
    with ThreadPoolExecutor(max_workers=10) as pool:
        results=list(pool.map(try_one,copies))
    assert sum(x[0]=="success" for x in results)==1,results
    assert sum(x[0]=="refused" for x in results)==9,results
    assert all(x[1]=="ALREADY_CONSUMED_ATOMIC_LOCAL_SLOT_NO_RETRY"
               for x in results if x[0]=="refused")
    assert round_.inspect()["live_api_dispatch"]=="DENY"


@pytest.mark.parametrize("key,value",[
    ("source","REAL_OPENAI_AUTHORITY"),
    ("schema","forged-schema"),
    ("model","other-model"),
    ("original_request_sha256","0"*64),
    ("issuer_context_sha256","0"*64),
    ("immutable_wire_sha256","0"*64),
    ("previous_plan_sha256","0"*64),
    ("old_provider_consent_consumed_sha","0"*64),
    ("sdk_version_not_loaded","future-latest"),
    ("benchmark_scope","banking:user_task_2:other"),
    ("proposed_call_count_not_allowed",2),
    ("output_token_ceiling",10000),
    ("hypothetical_input_token_ceiling",1000000),
    ("local_estimate_threshold_usd_not_billing_cap","100.00"),
    ("estimated_spend_usd_historical_not_invoice","100.00"),
    ("live_provider_posts_authorized",1),
    ("new_human_consent_issued",True),
    ("production_grant_issued",True),
    ("production_secret_exposed",True),
    ("real_provider_response_authenticated",True),
    ("native_bind_authorized",True),
    ("bank_action_authorized",True),
    ("mock_only",False),
])
def test_every_offer_scope_tamper_consumes_local_slot_then_fails(round_,key,value):
    p=deepcopy(round_.plan);p[key]=value
    with pytest.raises(proof.Rejected,match="EXACT_PROPOSED_SCOPE_OR_BUDGET_DRIFT"):
        round_.attempt_once(offered_plan=p)
    result=round_.inspect()
    assert result["local_state"]=="UNKNOWN_CONSUMED_NO_RETRY"
    assert result["provider_calls"]==0
    with pytest.raises(proof.Rejected):
        proof.OfflineSingleUseAdmission(
            db_path=round_.db_path,boundary=round_.boundary).attempt_once()


@pytest.mark.parametrize("field,value",[
    ("kind","REAL_PROVIDER_PERMISSION_GRANTED"),
    ("proposal_sha256","0"*64),
    ("issued_context_sha256","0"*64),
    ("wire_sha256","0"*64),
    ("model","unfrozen"),
    ("case_id","banking:user_task_1"),
    ("proposed_call_count_not_allowed",3),
    ("historical_estimate_not_billing_cap","$100"),
    ("real_execution_authorized",True),
    ("server_request_id","req-forged-real-looking"),
])
def test_fake_operator_ack_never_promotes_to_actual_consent(round_,field,value):
    forged=deepcopy(round_.ack)
    forged[field]=value
    with pytest.raises(proof.Rejected,match="FORGED_MOCK_CONSENT_CANNOT_BECOME_REAL_APPROVAL"):
        round_.attempt_once(offered_ack=forged)
    assert round_.inspect()["local_state"]=="UNKNOWN_CONSUMED_NO_RETRY"


@pytest.mark.parametrize("env",(
    "OPENAI_API_KEY","TASK4_OPENAI_API_KEY","ANTHROPIC_API_KEY",
    "OPENAI_BASE_URL","VERITAS_DATABASE_URL",
    "TASK4_THIRD_APPROVAL_PHRASE","TASK4_307_APPROVAL_PHRASE",
))
def test_secret_presence_refuses_after_consuming_offline_slot(round_,monkeypatch,env):
    monkeypatch.setenv(env,"nonempty-forbidden")
    with pytest.raises(proof.Rejected,match="OFFLINE_PROOF_REFUSES_REAL_SECRETS_AND_APPROVAL_PHRASES"):
        round_.attempt_once()
    assert round_.inspect()["local_state"]=="UNKNOWN_CONSUMED_NO_RETRY"


@pytest.mark.parametrize("error",("fail_after_consume","before_terminal_failure"))
def test_interrupted_or_unknown_outcome_stays_consumed_and_nonretry(round_,error):
    with pytest.raises(proof.Rejected,match="SYNTHETIC_UNKNOWN"):
        round_.attempt_once(**{error:True})
    evidence=round_.inspect()
    assert evidence["local_state"]=="UNKNOWN_CONSUMED_NO_RETRY"
    assert evidence["record_sha256"] is not None
    assert evidence["live_api_dispatch"]=="DENY"
    with pytest.raises(proof.Rejected,match="ALREADY_CONSUMED_ATOMIC_LOCAL_SLOT_NO_RETRY"):
        proof.OfflineSingleUseAdmission(
            db_path=round_.db_path,boundary=round_.boundary).attempt_once()


def test_expired_issuer_context_consumes_then_fails_before_any_effect(tmp_path):
    clk=FixtureClock()
    boundary=ProspectiveWireBoundary(date_session(clk))
    boundary.issue_and_freeze()
    obj=proof.OfflineSingleUseAdmission(
        db_path=tmp_path/"expired.sqlite3",boundary=boundary)
    clk.now+=timedelta(seconds=310)
    with pytest.raises(DateProfileViolation,match="DATE_CONTEXT_STALE_OR_FUTURE"):
        obj.attempt_once()
    assert obj.inspect()["local_state"]=="UNKNOWN_CONSUMED_NO_RETRY"
    assert obj.inspect()["provider_calls"]==0


def test_even_claimed_real_permission_has_unconditional_default_deny(round_):
    for claim in (None,{},{"APPROVED":True},
                  {"source":"REAL","max_cost":"100","calls":1}):
        answer=proof.always_deny_real_api(round_.plan,claim,{"origin":"real"})
        assert answer["decision"]=="DENY"
        assert answer["authorized_real_calls"]==0
        assert answer["provider_posts_possible_through_308"] is False


def test_local_sqlite_digest_corruption_is_detected_but_not_tamper_proof(round_):
    round_.attempt_once()
    import sqlite3
    with sqlite3.connect(round_.db_path) as c:
        c.execute("UPDATE local_rehearsals SET record_sha256=? WHERE slot_id=?",
                  ("0"*64,round_.slot))
    with pytest.raises(proof.Rejected,match="LOCAL_SIMULATION_RECORD_INTEGRITY"):
        round_.inspect()


def test_audit_reports_bounded_success_without_claiming_live_readiness():
    report=proof.audit()
    assert report["determination"]=="LOCAL_SQLITE_ATOMIC_SINGLE_USE_PREFLIGHT_PASS_REAL_DISPATCH_DEFAULT_DENY"
    assert report["new_human_approval_issued"] is False
    assert report["mock_ack_is_real_human_consent"] is False
    assert report["no_live_Provider_client_constructed"] is True
    assert report["local_restart_replay_refused"] is True
    assert report["live_api_post_count"]==0
    assert report["real_bank_effect_count"]==0
    assert report["actual_native_bind_adjudications"]==0
    assert report["official_task4_scorer_calls"]==0
    assert report["final128_calls"]==0
    assert report["global_protected_consumption_proven"] is False
    assert report["tamper_evident_external_evidence_proven"] is False
    assert report["production_authority_proven"] is False
    assert report["future_live_execution"]["decision"]=="DENY"


def test_no_real_provider_sdk_transport_or_bank_executor_in_source():
    source=(ROOT/"scripts"/"task4_future_provider_atomic_oneuse_preflight_v1.py").read_text()
    for disallowed in ("OpenAI(","openai.OpenAI","httpx.","requests.post(",
                       "http.client.","HTTPSConnection(","socket.socket(",
                       "subprocess.run(","run_task_with_pipeline(",
                       "send_money(","execute_bind_adjudication(",
                       "workflow_dispatch"):
        assert disallowed not in source
    assert "BEGIN IMMEDIATE" in source
    assert "PRIMARY KEY" in source
    assert "REAL_DISPATCH_DENIED" in source
