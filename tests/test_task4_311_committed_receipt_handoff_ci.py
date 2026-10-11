"""#311: PostgreSQL committed fixture receipt vs uncommitted state. No real API."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from decimal import Decimal
import os
from pathlib import Path
import socket
import sys
import uuid
import pytest

if os.getenv("TASK4_311_CI_ONLY")!="1":
    pytest.skip("Run only in isolated Task4 #311 PostgreSQL CI",
                allow_module_level=True)

import psycopg  # dedicated CI installs this; ordinary CI skips above

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import task4_311_committed_receipt_handoff_ci as bridge

@pytest.fixture(autouse=True)
def only_pg_loopback(monkeypatch):
    original=socket.socket.connect
    def local_only(sock, address):
        assert isinstance(address,tuple) and address[0] in ("127.0.0.1","localhost") \
            and address[1]==5432,"NO_PROVIDER_OR_REMOTE_NETWORK"
        return original(sock,address)
    monkeypatch.setattr(socket.socket,"connect",local_only)

@pytest.fixture
def scope():
    s=bridge.fresh_scope()
    bridge.seed_fixture(s)
    return s

def new_attempt():
    return "attempt-311-ci-"+uuid.uuid4().hex

def test_permissions_and_old_unreceipted_path_rejected():
    right=bridge.proof_scope_roles()
    assert right["parent_old_consume_disabled"] is True
    assert right["new_consumer_consume"] is True
    assert right["handoff_verify"] is True
    assert right["new_consumer_verify"] is False
    assert right["handoff_consume"] is False
    assert right["issuer_consume"] is False
    assert all(v for k,v in right.items() if "_no_" in k)

def test_committed_receipt_visible_in_fresh_handoff_session(scope):
    attempt=new_attempt()
    assert bridge.verify_committed_in_separate_session(scope,attempt) is False
    assert bridge.consume_fixture(scope,attempt_id=attempt)==(True,attempt)
    assert bridge.verify_committed_in_separate_session(scope,attempt) is True
    receipt=bridge.admin_receipt(scope["grant_id"])
    grant=bridge.admin_record(scope["grant_id"])
    assert receipt["attempt_id"]==attempt
    assert receipt["db_consumed_at"]==grant["consumed_at"]
    assert receipt["state"]=="CONSUMED_FIXTURE_ONLY"
    assert len(receipt["receipt_sha256"])==64

def test_uncommitted_success_return_is_not_cross_session_receipt(scope):
    attempt=new_attempt()
    with bridge.db("consumer") as c:
        with c.transaction():
            assert c.execute(
                bridge.CONSUME_SQL,bridge.scope_params(scope,attempt)
            ).fetchone()[0] is True
            # Separate PostgreSQL session cannot see pending row or receipt.
            assert bridge.verify_committed_in_separate_session(scope,attempt) is False
            assert bridge.admin_receipt(scope["grant_id"]) is None
        # explicit commit has completed here
    assert bridge.verify_committed_in_separate_session(scope,attempt) is True

def test_rollback_after_successful_function_return_leaves_no_receipt(scope):
    class SimulatedCrash(Exception):pass
    attempt=new_attempt()
    with pytest.raises(SimulatedCrash):
        with bridge.db("consumer") as c:
            with c.transaction():
                assert c.execute(
                    bridge.CONSUME_SQL,bridge.scope_params(scope,attempt)
                ).fetchone()[0] is True
                assert bridge.verify_committed_in_separate_session(scope,attempt) is False
                raise SimulatedCrash()
    assert bridge.verify_committed_in_separate_session(scope,attempt) is False
    assert bridge.admin_receipt(scope["grant_id"]) is None
    assert bridge.admin_record(scope["grant_id"])["state"]=="ISSUED_FIXTURE_ONLY"
    # This is ONLY a DB rollback simulation, not permission to retry a
    # remotely ambiguous real Provider POST.
    other=new_attempt()
    assert bridge.consume_fixture(scope,attempt_id=other)[0] is True
    assert bridge.verify_committed_in_separate_session(scope,other) is True
    assert bridge.no_live_send_authority()["decision"]=="DENY"

def test_lost_client_ack_after_commit_can_be_reconciled_without_new_consume(scope):
    attempt=new_attempt()
    bridge.consume_fixture(scope,attempt_id=attempt) # pretend caller lost ACK
    assert bridge.verify_committed_in_separate_session(scope,attempt) is True
    assert bridge.consume_fixture(scope,attempt_id=new_attempt())[0] is False
    assert bridge.no_live_send_authority()["real_provider_posts_authorized"]==0

def test_parallel_twelve_consumers_only_winner_receipt_visible(scope):
    with ThreadPoolExecutor(max_workers=12) as pool:
        results=list(pool.map(lambda _:bridge.consume_fixture(scope),range(12)))
    wins=[a for b,a in results if b]
    assert len(wins)==1
    assert len([a for b,a in results if not b])==11
    assert bridge.verify_committed_in_separate_session(scope,wins[0])
    for was_accepted,attempt in results:
        assert bridge.verify_committed_in_separate_session(scope,attempt) is was_accepted
    assert bridge.consume_fixture(scope)[0] is False

@pytest.mark.parametrize("field,value",[
    ("grant_id","fake-not-issued"),
    ("case_id","banking:user_task_1"),
    ("context","0"*64),
    ("wire","0"*64),
    ("model","different-model"),
    ("estimated_cost",Decimal("0.005")),
])
def test_mismatched_consume_scope_cannot_create_receipt(scope,field,value):
    offered=dict(scope);offered[field]=value
    accepted,attempt=bridge.consume_fixture(scope,alter={field:value})
    assert accepted is False
    assert bridge.verify_committed_in_separate_session(scope,attempt) is False
    assert bridge.admin_receipt(scope["grant_id"]) is None
    assert bridge.consume_fixture(scope)[0] is True

@pytest.mark.parametrize("field,value",[
    ("grant_id","another-grant"),
    ("case_id","banking:user_task_14"),
    ("context","0"*64),
    ("wire","0"*64),
    ("model","wrong-model"),
    ("estimated_cost",Decimal("0.005")),
])
def test_modified_expected_receipt_fields_are_rejected(scope,field,value):
    accepted,attempt=bridge.consume_fixture(scope)
    assert accepted
    assert bridge.verify_committed_in_separate_session(
        scope,attempt,alter={field:value}) is False
    assert bridge.verify_committed_in_separate_session(scope,attempt) is True

@pytest.mark.parametrize("attempt_id",["","short", "incorrect-1"])
def test_forged_or_missing_attempt_cannot_verify(scope,attempt_id):
    good=new_attempt()
    assert bridge.consume_fixture(scope,attempt_id=good)[0] is True
    assert bridge.verify_committed_in_separate_session(scope,attempt_id) is False
    assert bridge.verify_committed_in_separate_session(scope,good) is True

@pytest.mark.parametrize("attempt_id",["x","short",""])
def test_inadequate_attempt_length_is_never_consumed(scope,attempt_id):
    accepted,_=bridge.consume_fixture(scope,attempt_id=attempt_id)
    assert accepted is False
    assert bridge.admin_receipt(scope["grant_id"]) is None
    assert bridge.consume_fixture(scope,attempt_id=new_attempt())[0] is True

def test_db_expiry_prevents_receipt_generation():
    scope=bridge.fresh_scope()
    bridge.seed_fixture(scope,expiry_seconds=-30)
    accepted,attempt=bridge.consume_fixture(scope)
    assert accepted is False
    assert bridge.admin_receipt(scope["grant_id"]) is None
    assert bridge.verify_committed_in_separate_session(scope,attempt) is False

def test_parent_consumption_without_receipt_refused_to_former_fixture_role(scope):
    from task4_310_postgres_single_use_ci import db as old_db,CALL_SQL
    with old_db("consumer") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(CALL_SQL,bridge.scope_params(scope,new_attempt()))
    assert bridge.admin_record(scope["grant_id"])["state"]=="ISSUED_FIXTURE_ONLY"

@pytest.mark.parametrize("role,query",[
    ("consumer","SELECT * FROM task4_311.offline_committed_receipts"),
    ("consumer","DELETE FROM task4_311.offline_committed_receipts"),
    ("consumer","UPDATE task4_311.offline_committed_receipts SET attempt_id='forged'"),
    ("handoff","SELECT * FROM task4_311.offline_committed_receipts"),
    ("handoff","DELETE FROM task4_311.offline_committed_receipts"),
    ("handoff","UPDATE task4_311.offline_committed_receipts SET attempt_id='forged'"),
])
def test_no_direct_receipt_table_access_from_consumer_or_handoff(role,query):
    with bridge.db(role) as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(query)

def test_consumer_cannot_invoke_handoff_verify(scope):
    with bridge.db("consumer") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(bridge.VERIFY_SQL,bridge.scope_params(scope,new_attempt()))

def test_handoff_cannot_issue_or_consume(scope):
    with bridge.db("handoff") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(bridge.CONSUME_SQL,bridge.scope_params(scope,new_attempt()))
    assert bridge.admin_receipt(scope["grant_id"]) is None

def test_privileged_admin_can_tamper_receipt_digest_so_local_integrity_fails(scope):
    _,a=bridge.consume_fixture(scope)
    assert bridge.verify_committed_in_separate_session(scope,a)
    with bridge.parent_db("admin") as c:
        c.execute("""UPDATE task4_311.offline_committed_receipts
                     SET receipt_sha256=%s WHERE grant_id=%s""",
                  ("0"*64,scope["grant_id"]))
    assert bridge.verify_committed_in_separate_session(scope,a) is False
    # Receipt is unkeyed; privileged administrator CAN forge a new hash.
    # Therefore this is NOT protected/tamper-proof production evidence.

def test_compromised_admin_can_consume_old_parent_grant_without_receipt(scope):
    # Explicit demonstration of remaining privileged bypass. Never claim
    # global impossible bypass while admin privileges exist.
    with bridge.parent_db("admin") as c:
        assert c.execute(
            "SELECT task4_310.consume_offline_fixture_once(%s,%s,%s,%s,%s,%s,%s)",
            bridge.scope_params(scope,new_attempt())).fetchone()[0] is True
    assert bridge.admin_record(scope["grant_id"])["state"]=="CONSUMED_FIXTURE_ONLY"
    assert bridge.admin_receipt(scope["grant_id"]) is None
    assert bridge.verify_committed_in_separate_session(scope,new_attempt()) is False

@pytest.mark.parametrize("which",["TASK4_311_CONSUMER_DSN","TASK4_311_HANDOFF_DSN"])
def test_remote_db_dsn_is_forbidden(monkeypatch,which):
    monkeypatch.setenv(which,"postgresql://user:pass@production.example:5432/postgres")
    with pytest.raises(bridge.BoundaryDenied,match="ONLY_EPHEMERAL_LOOPBACK"):
        bridge.check_ci()

def test_ci_only_gate_fails_without_explicit_env(monkeypatch):
    monkeypatch.delenv("TASK4_311_CI_ONLY")
    with pytest.raises(bridge.BoundaryDenied,match="EXPLICIT_CI_ONLY"):
        bridge.check_ci()

def test_new_real_Provider_approval_never_issued_even_with_receipt(scope):
    _,a=bridge.consume_fixture(scope)
    assert bridge.verify_committed_in_separate_session(scope,a)
    for forged in (None,True,{"human_approval":True},
                   {"receipt":"real-looking","signed":True}):
        reply=bridge.no_live_send_authority(forged)
        assert reply["decision"]=="DENY"
        assert reply["real_provider_posts_authorized"]==0
        assert reply["production_sender_present"] is False

def test_audit_report_is_internally_consistent_and_explicitly_bounded():
    result=bridge.audit()
    assert result["parallel_independent_consumer_connections"]==12
    assert result["fixture_successful_consumptions"]==1
    assert result["conflicting_consumption_refusals"]==11
    assert result["separate_handoff_session_verified_exact_winner"] is True
    assert result["loser_attempts_unverified"]==11
    assert result["separate_session_replay_refused"] is True
    assert result["new_real_human_consent_issued"] is False
    assert result["real_provider_posts"]==0
    assert result["real_bank_effects"]==0
    assert result["global_protected_single_use_proven"] is False
    assert result["production_handoff_proven"] is False
    assert result["future_live_provider_decision"]["decision"]=="DENY"

def test_source_and_workflow_never_offer_real_api_sender_or_keys():
    code=(ROOT/"scripts/task4_311_committed_receipt_handoff_ci.py").read_text()
    for forbidden in ("openai.OpenAI", "OpenAI(", "requests.post(", "httpx.Client(",
                      "HTTPSConnection(", "send_money("):
        assert forbidden not in code
    y=(ROOT/".github/workflows/task4-committed-receipt-handoff-ci-v1.yml").read_text()
    assert "postgres:16.6" in y
    assert "OPENAI_API_KEY: \"\"" in y
    assert "TASK4_OPENAI_API_KEY: \"\"" in y
    assert "persist-credentials: false" in y
    assert "permissions:\n  contents: read\n  actions: read" in y
    assert "workflow_dispatch:" not in y
    assert "pull_request_target:" not in y
    assert "secrets." not in y
