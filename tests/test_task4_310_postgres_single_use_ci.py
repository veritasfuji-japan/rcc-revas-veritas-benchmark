"""#310 ephemeral PostgreSQL 16 role-separated consume-only tests. NO Provider calls."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timedelta,timezone
from decimal import Decimal
from pathlib import Path
import os
import socket
import sys
import uuid
import pytest

if os.getenv("TASK4_310_CI_ONLY")!="1":
    pytest.skip("Dedicated isolated PostgreSQL service proof only",
                allow_module_level=True)
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import task4_310_postgres_single_use_ci as proof
import psycopg

@pytest.fixture(autouse=True)
def guard_egress(monkeypatch):
    real_socket_connect=socket.socket.connect
    def restrict(self,address):
        assert type(address) is tuple and address[0] in (
            "127.0.0.1","localhost") and address[1]==5432, (
            "NEVER_ALLOW_PROVIDER_NETWORK_IN_TASK4_310_CI")
        return real_socket_connect(self,address)
    monkeypatch.setattr(socket.socket,"connect",restrict)

@pytest.fixture
def grant():
    scope=proof.fresh_scope()
    proof.seed_fixture(scope)
    return scope

def test_exact_fixture_only_sql_scope_and_permissions():
    m=proof.role_permission_report()
    assert m["issuer_insert"] is True
    assert m["consumer_execute_fn"] is True
    assert all(m[key] is False for key in (
      "issuer_select","issuer_update","issuer_delete",
      "consumer_insert","consumer_select","consumer_update",
      "consumer_delete","issuer_execute_fn","public_execute_fn"))
    assert "SECURITY DEFINER" in proof.SQL_FILE.read_text()
    assert "SET search_path = pg_catalog" in proof.SQL_FILE.read_text()
    assert "REVOKE ALL ON FUNCTION" in proof.SQL_FILE.read_text()
    assert "GRANT INSERT" in proof.SQL_FILE.read_text()

def test_atomic_first_consumption_is_committed_before_ack(grant):
    assert proof.simulated_consume(grant) is True
    r=proof.admin_record(grant["grant_id"])
    assert r["state"]=="CONSUMED_FIXTURE_ONLY"
    assert r["consumed_at"] is not None
    assert r["attempt"].startswith("attempt-310-ci-")
    assert r["wire"]==grant["wire"]
    assert r["context"]==grant["context"]
    assert r["model"]==grant["model"]
    assert r["estimated_cost"]==Decimal("0.00440960")
    assert r["max_calls"]==1

def test_cross_session_restart_retry_refused(grant):
    assert proof.simulated_consume(grant) is True
    for _ in range(4):
        assert proof.simulated_consume(grant) is False
    assert proof.admin_record(grant["grant_id"])["state"]=="CONSUMED_FIXTURE_ONLY"

def test_sixteen_distinct_connections_can_consume_same_scope_only_once(grant):
    with ThreadPoolExecutor(max_workers=16) as pool:
        results=list(pool.map(lambda _:proof.simulated_consume(grant),range(16)))
    assert results.count(True)==1
    assert results.count(False)==15
    assert proof.admin_record(grant["grant_id"])["state"]=="CONSUMED_FIXTURE_ONLY"
    assert proof.simulated_consume(grant) is False

@pytest.mark.parametrize("field,value",[
    ("case_id","banking:user_task_11:attacker"),
    ("context","0"*64),
    ("wire","0"*64),
    ("model","unfrozen-provider-model"),
    ("estimated_cost",Decimal("0.005")),
    ("grant_id","task4-310-ci-wrong-id"),
])
def test_forged_authorization_fields_rejected_without_consuming_real_slot(grant,field,value):
    assert proof.simulated_consume(grant,mutate={field:value}) is False
    assert proof.admin_record(grant["grant_id"])["state"]=="ISSUED_FIXTURE_ONLY"
    assert proof.simulated_consume(grant) is True

@pytest.mark.parametrize("attempt_id",["","x","short"])
def test_invalid_attempt_id_refused_before_consumption(grant,attempt_id):
    # explicit nonempty short ids must not be accepted; default generated ids
    # are used when None (but the empty-string API defaults to generated).
    if attempt_id=="":
        assert proof.simulated_consume(grant,attempt_id="short") is False
    else:
        assert proof.simulated_consume(grant,attempt_id=attempt_id) is False
    assert proof.admin_record(grant["grant_id"])["state"]=="ISSUED_FIXTURE_ONLY"
    assert proof.simulated_consume(grant) is True

def test_expired_postgres_clock_prevents_consume():
    scope=proof.fresh_scope()
    proof.seed_fixture(scope,expiry_seconds=-30)
    assert proof.simulated_consume(scope) is False
    assert proof.admin_record(scope["grant_id"])["state"]=="ISSUED_FIXTURE_ONLY"

def test_two_unrelated_issuances_are_independent():
    a,b=proof.fresh_scope(),proof.fresh_scope()
    proof.seed_fixture(a);proof.seed_fixture(b)
    assert proof.simulated_consume(a) is True
    assert proof.simulated_consume(b) is True
    assert proof.simulated_consume(a) is False
    assert proof.simulated_consume(b) is False

def test_uncommitted_test_transaction_has_no_durable_consumption(grant):
    # Architectural danger demonstration: a PL/pgSQL function cannot force
    # the *caller* to commit; only a separate commit-ack may precede egress.
    class StopAfterSimulatedConsume(Exception):pass
    with pytest.raises(StopAfterSimulatedConsume):
        with proof.db("consumer") as c:
            with c.transaction():
                x=c.execute(proof.CALL_SQL,(
                  grant["grant_id"],grant["case_id"],grant["context"],
                  grant["wire"],grant["model"],grant["estimated_cost"],
                  "attempt-310-test-rollback")).fetchone()[0]
                assert x is True
                raise StopAfterSimulatedConsume()
    assert proof.admin_record(grant["grant_id"])["state"]=="ISSUED_FIXTURE_ONLY"
    assert proof.simulated_consume(grant) is True

@pytest.mark.parametrize("role,query",[
    ("consumer","SELECT * FROM task4_310.offline_fixture_grants"),
    ("consumer","DELETE FROM task4_310.offline_fixture_grants"),
    ("consumer","UPDATE task4_310.offline_fixture_grants SET state='ISSUED_FIXTURE_ONLY'"),
    ("issuer","SELECT * FROM task4_310.offline_fixture_grants"),
    ("issuer","DELETE FROM task4_310.offline_fixture_grants"),
    ("issuer","UPDATE task4_310.offline_fixture_grants SET state='ISSUED_FIXTURE_ONLY'"),
])
def test_separate_db_role_cannot_query_or_mutate_protected_rows(role,query):
    with proof.db(role) as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(query)

def test_issuer_cannot_consume_without_consumer_role(grant):
    with proof.db("issuer") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(proof.CALL_SQL,(
               grant["grant_id"],grant["case_id"],grant["context"],
               grant["wire"],grant["model"],grant["estimated_cost"],
               "attempt-310-unauthorized"))
    assert proof.admin_record(grant["grant_id"])["state"]=="ISSUED_FIXTURE_ONLY"

def test_consumer_cannot_issue_new_test_grant(grant):
    with proof.db("consumer") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("""INSERT INTO task4_310.offline_fixture_grants(
                grant_id,case_id,issuer_context_sha256,frozen_wire_sha256,
                model_id,expected_cost_usd,max_calls,expires_at)
                VALUES (%s,%s,%s,%s,%s,%s,1,%s)""",(
                "task4-310-ci-"+uuid.uuid4().hex,
                grant["case_id"],grant["context"],grant["wire"],
                grant["model"],grant["estimated_cost"],
                datetime.now(timezone.utc)+timedelta(minutes=4)))

@pytest.mark.parametrize("env",proof.REAL_ENVS)
def test_api_secret_or_old_consumed_consent_env_always_refused(env,monkeypatch):
    monkeypatch.setenv(env,"untrusted-live-looking-env")
    with pytest.raises(proof.Refused,match="LIVE_PROVIDER_OR_PRODUCTION_CREDENTIAL_PRESENT"):
        proof.check_ci()

@pytest.mark.parametrize("env",("TASK4_310_ADMIN_DSN","TASK4_310_ISSUER_DSN",
                                 "TASK4_310_CONSUMER_DSN"))
def test_prod_db_dsn_or_remote_network_never_accepted(env,monkeypatch):
    monkeypatch.setenv(env,"postgresql://postgres:secret@production.example:5432/postgres")
    with pytest.raises(proof.Refused,match="ONLY_EPHEMERAL_LOOPBACK_POSTGRES_CI"):
        proof.check_ci()

def test_test_only_runner_rejects_if_flag_absent(monkeypatch):
    monkeypatch.delenv("TASK4_310_CI_ONLY")
    with pytest.raises(proof.Refused,match="CI_ONLY_EXPLICIT_OPT_IN_REQUIRED"):
        proof.check_ci()

def test_audit_report_never_claims_live_permission():
    report=proof.audit()
    assert report["atomic_fixture_consumes"]==1
    assert report["atomic_fixture_conflict_rejections"]==15
    assert report["independent_session_replay_refused"] is True
    assert report["persistent_ci_terminal_state"]=="CONSUMED_FIXTURE_ONLY"
    assert report["new_human_approval_issued"] is False
    assert report["real_provider_calls"]==0
    assert report["actual_provider_response_received"] is False
    assert report["real_bank_effects"]==0
    assert report["native_bind_adjudications"]==0
    assert report["globally_protected_single_use_proven"] is False
    assert report["production_deployment_proven"] is False
    assert report["future_live_dispatch_decision"]=="DENY"

def test_workflow_contains_isolated_postgres_service_without_provider_sdk():
    y=(ROOT/".github/workflows/task4-postgres-role-separated-consumption-v1.yml").read_text()
    assert "postgres:16.6" in y
    assert "pull_request_target:" not in y
    assert "workflow_dispatch:" not in y
    assert "permissions:\n  contents: read\n  actions: read" in y
    assert "persist-credentials: false" in y
    assert "TASK4_310_CI_ONLY: \"1\"" in y
    assert "OPENAI_API_KEY: \"\"" in y
    assert "TASK4_OPENAI_API_KEY: \"\"" in y
    assert "secrets." not in y
    assert "openai==" not in y

def test_prototype_uses_only_db_connections_not_provider_network():
    script=(ROOT/"scripts/task4_310_postgres_single_use_ci.py").read_text()
    for bad in ("openai.OpenAI", "OpenAI(", "api.openai.com",
                "https://api.", "httpx.Client(", "requests.post(",
                "http.client.", "HTTPSConnection(", "send_money("):
        assert bad not in script
    assert "autocommit=True" in script
    assert "127.0.0.1" in script
    assert "REAL_ENVS" in script
