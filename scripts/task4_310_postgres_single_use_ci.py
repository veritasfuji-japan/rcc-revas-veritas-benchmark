#!/usr/bin/env python3
"""#310: isolated PostgreSQL 16 single-use grant consumption CI proof.

Creates ONLY fake Task4 grants in an EPHEMERAL LOOPBACK CI database.
The issuer and consumer each have distinct limited DB roles.
This script has no provider client, real human consent, real token, bank,
native Bind, spend authorization or external network dispatch.
The DB boolean is not a permission to call any API.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timedelta,timezone
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit,unquote
import uuid

ROOT=Path(__file__).resolve().parents[1]
for p in (ROOT,ROOT/"scripts"):
    if str(p) not in sys.path:sys.path.insert(0,str(p))
from task4_prospective_model_wire_date_boundary_v1 import (
    ProspectiveWireBoundary,date_session,sha,CASE,MODEL,
)

RULE="TASK4_POSTGRES_ROLE_SEPARATED_CONSUMPTION_CI_V1"
MAIN_PARENT="cdcb5672e82f1c2109adff3bd9ae5404451d5359"
SOURCE="LOCAL_CI_POSTGRES_EPHEMERAL_FIXTURE_NOT_REAL_APPROVAL"
OLD_CONSUMED="95ff6be8c5875ed3827a00fe71fb54bd9de48130"
SQL_FILE=ROOT/"sql"/"task4_310_offline_postgres_consume_v1.sql"
CALL_SQL="SELECT task4_310.consume_offline_fixture_once(%s,%s,%s,%s,%s,%s,%s)"
CI_ENV={
    "admin":("TASK4_310_ADMIN_DSN","postgres"),
    "issuer":("TASK4_310_ISSUER_DSN","task4_310_fixture_issuer"),
    "consumer":("TASK4_310_CONSUMER_DSN","task4_310_fixture_consumer"),
}
REAL_ENVS=("OPENAI_API_KEY","TASK4_OPENAI_API_KEY","ANTHROPIC_API_KEY",
           "OPENAI_BASE_URL","VERITAS_DATABASE_URL","TASK4_THIRD_APPROVAL_PHRASE",
           "TASK4_307_APPROVAL_PHRASE","TASK4_308_APPROVAL_PHRASE")

class Refused(ValueError):pass

def require(ok,code):
    if not ok:raise Refused(code)

def check_ci():
    require(os.getenv("TASK4_310_CI_ONLY")=="1","CI_ONLY_EXPLICIT_OPT_IN_REQUIRED")
    require(not any(os.getenv(n) for n in REAL_ENVS),
            "LIVE_PROVIDER_OR_PRODUCTION_CREDENTIAL_PRESENT")
    for key,(name,role) in CI_ENV.items():
        raw=os.getenv(name,"")
        uri=urlsplit(raw)
        require(uri.scheme in ("postgres","postgresql") and
                uri.hostname in ("127.0.0.1","localhost") and
                uri.port==5432 and uri.path=="/postgres" and
                unquote(uri.username or "")==role and
                uri.password is not None,
                "ONLY_EPHEMERAL_LOOPBACK_POSTGRES_CI_"+key.upper())
    return True

def db(role):
    check_ci()
    import psycopg
    return psycopg.connect(os.environ[CI_ENV[role][0]],autocommit=True,
                           connect_timeout=5)

def create_schema():
    check_ci()
    sql=SQL_FILE.read_text(encoding="utf8")
    require("SECURITY DEFINER" in sql and
            "SET search_path = pg_catalog" in sql and
            "REVOKE ALL ON FUNCTION" in sql and
            "BEGIN" in sql,
            "PROTECTED_FUNCTION_SCHEMA_UNEXPECTED")
    with db("admin") as conn:
        conn.execute(sql,prepare=False)
    return {"setup":"CI_EPHEMERAL_POSTGRES_ROLES_READY",
            "source":"STATIC_SQL_PROTOTYPE_NOT_DEPLOYED_PRODUCTION",
            "parent_main":MAIN_PARENT,"real_provider_authorization_issued":False}

def fresh_scope():
    # Real #303 issuer algorithm but an isolated synthetic test environment.
    b=ProspectiveWireBoundary(date_session())
    b.issue_and_freeze()
    return {
       "case_id":CASE,
       "context":b.context.digest,
       "wire":sha(json.loads(b.wire_bytes)),
       "model":MODEL,
       "estimated_cost":Decimal("0.00440960"), # historical, not billing cap
       "max_calls":1,
       "grant_id":"task4-310-ci-"+uuid.uuid4().hex,
    }

def seed_fixture(scope,*,expiry_seconds=180):
    check_ci()
    require(type(scope) is dict and
            scope["case_id"]==CASE and scope["model"]==MODEL and
            scope["max_calls"]==1 and
            scope["estimated_cost"]==Decimal("0.00440960"),
            "EXACT_TEST_ONLY_ISSUER_SCOPE_REQUIRED")
    expiry=datetime.now(timezone.utc)+timedelta(seconds=expiry_seconds)
    with db("issuer") as conn:
        conn.execute("""INSERT INTO task4_310.offline_fixture_grants(
             grant_id,case_id,issuer_context_sha256,frozen_wire_sha256,
             model_id,expected_cost_usd,max_calls,expires_at)
             VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",(
          scope["grant_id"],scope["case_id"],scope["context"],
          scope["wire"],scope["model"],scope["estimated_cost"],
          scope["max_calls"],expiry))
    return scope["grant_id"]

def simulated_consume(scope,*,attempt_id=None,mutate=None):
    """Autocommit connection: one committed fixture update before any receipt."""
    check_ci()
    s=dict(scope)
    if mutate is not None:s.update(mutate)
    attempt_id=attempt_id or "attempt-310-ci-"+uuid.uuid4().hex
    with db("consumer") as conn:
        result=conn.execute(CALL_SQL,(
          s["grant_id"],s["case_id"],s["context"],s["wire"],
          s["model"],s["estimated_cost"],attempt_id)).fetchone()
    require(type(result) is tuple and type(result[0]) is bool,
            "UNEXPECTED_DB_ATOMIC_CONSUME_RESULT")
    return result[0]

def admin_record(grant_id):
    with db("admin") as conn:
        r=conn.execute("""SELECT grant_id,case_id,issuer_context_sha256,
             frozen_wire_sha256,model_id,expected_cost_usd,max_calls,state,
             attempt_id,consumed_at,expires_at
             FROM task4_310.offline_fixture_grants WHERE grant_id=%s""",
             (grant_id,)).fetchone()
    require(r is not None,"GRANT_ROW_REQUIRED")
    return dict(zip(("grant_id","case_id","context","wire","model",
                     "estimated_cost","max_calls","state","attempt",
                     "consumed_at","expires_at"),r))

def role_permission_report():
    """Admin introspection: role grants, not production IAM evidence."""
    with db("admin") as conn:
        def permitted(role,action):
            return bool(conn.execute(
              "SELECT has_table_privilege(%s,%s,%s)",
              (role,"task4_310.offline_fixture_grants",action)).fetchone()[0])
        consumer="task4_310_fixture_consumer"
        issuer="task4_310_fixture_issuer"
        can_consume=bool(conn.execute("""SELECT has_function_privilege(
             %s,'task4_310.consume_offline_fixture_once(text,text,text,text,text,numeric,text)','EXECUTE')""",
             (consumer,)).fetchone()[0])
        issuer_can_consume=bool(conn.execute("""SELECT has_function_privilege(
             %s,'task4_310.consume_offline_fixture_once(text,text,text,text,text,numeric,text)','EXECUTE')""",
             (issuer,)).fetchone()[0])
        public_can_consume=bool(conn.execute("""SELECT has_function_privilege(
            'PUBLIC','task4_310.consume_offline_fixture_once(text,text,text,text,text,numeric,text)','EXECUTE')""").fetchone()[0])
    result={
       "issuer_can_insert_fixture":permitted(issuer,"INSERT") if False else None
    }
    # Execute privilege introspection inside fresh admin connection, not the
    # previous connection (permitted closure captures connection).
    with db("admin") as conn:
        def yes(role,priv):
            return bool(conn.execute("SELECT has_table_privilege(%s,%s,%s)",
                      (role,"task4_310.offline_fixture_grants",priv)).fetchone()[0])
        result={
          "issuer_insert":yes(issuer,"INSERT"),
          "issuer_select":yes(issuer,"SELECT"),
          "issuer_update":yes(issuer,"UPDATE"),
          "issuer_delete":yes(issuer,"DELETE"),
          "consumer_insert":yes(consumer,"INSERT"),
          "consumer_select":yes(consumer,"SELECT"),
          "consumer_update":yes(consumer,"UPDATE"),
          "consumer_delete":yes(consumer,"DELETE"),
          "consumer_execute_fn":can_consume,
          "issuer_execute_fn":issuer_can_consume,
          "public_execute_fn":public_can_consume,
        }
    require(result=={
        "issuer_insert":True,"issuer_select":False,"issuer_update":False,
        "issuer_delete":False,"consumer_insert":False,
        "consumer_select":False,"consumer_update":False,
        "consumer_delete":False,"consumer_execute_fn":True,
        "issuer_execute_fn":False,"public_execute_fn":False,
    },"CI_POSTGRES_ROLE_BOUNDARY_PERMISSION_DRIFT")
    return result

def audit():
    check_ci()
    permissions=role_permission_report()
    scope=fresh_scope()
    seed_fixture(scope)
    contenders=16
    def each(_):
        return simulated_consume(scope)
    with ThreadPoolExecutor(max_workers=contenders) as pool:
        outcome=list(pool.map(each,range(contenders)))
    require(sum(x is True for x in outcome)==1 and
            sum(x is False for x in outcome)==contenders-1,
            "CI_POSTGRES_CONCURRENT_DOUBLE_SPEND_OR_MISCOUNT")
    first=admin_record(scope["grant_id"])
    require(first["state"]=="CONSUMED_FIXTURE_ONLY" and
            first["attempt"] is not None and
            first["consumed_at"] is not None and
            first["case_id"]==scope["case_id"] and
            first["context"]==scope["context"] and
            first["wire"]==scope["wire"] and
            first["model"]==scope["model"],
            "PERSISTED_CI_CONSUMPTION_INTEGRITY_FAILURE")
    # Different DB connection after all contenders completed.
    need_again=simulated_consume(scope)
    require(need_again is False,"CROSS_SESSION_RETRY_MUST_DENY")
    return {
      "rule_of_one":RULE,
      "determination":"EPHEMERAL_POSTGRES_ROLE_SEPARATION_AND_SINGLE_ROW_CAS_PROVEN_IN_CI_ONLY",
      "main_parent_sha":MAIN_PARENT,
      "previous_third_live_approval_tag_consumed_sha":OLD_CONSUMED,
      "ci_backend":"PostgreSQL 16 service container, independent TCP client sessions",
      "fixture_source":SOURCE,
      "role_permission_matrix":permissions,
      "parallel_consumers":contenders,
      "atomic_fixture_consumes":sum(outcome),
      "atomic_fixture_conflict_rejections":outcome.count(False),
      "independent_session_replay_refused":not need_again,
      "issuer_context_sha256":scope["context"],
      "frozen_wire_sha256":scope["wire"],
      "ephemeral_grant_sha256":hashlib.sha256(scope["grant_id"].encode()).hexdigest(),
      "persistent_ci_terminal_state":first["state"],
      "historical_price_assumption_not_account_cap_usd":str(scope["estimated_cost"]),
      "new_human_approval_issued":False,
      "real_provider_calls":0,
      "production_provider_credential_loaded":False,
      "actual_provider_response_received":False,
      "real_bank_effects":0,
      "native_bind_adjudications":0,
      "official_task4_or_final128_scores":0,
      "globally_protected_single_use_proven":False,
      "production_deployment_proven":False,
      "production_egress_enforcement_proven":False,
      "account_billing_cap_proven":False,
      "future_live_dispatch_decision":"DENY",
      "remaining_real_prerequisites":["independently administered live grant issuer",
        "protected durable Postgres deployment with backups/role policy",
        "approved egress and credential isolation",
        "fresh real pricing and account spend enforcement",
        "durable commit receipt handed off before any send",
        "new explicit human consent and Provider response provenance",
        "native production Bind and effects reconciliation"],
      "limitations":"Fixture grants are simulated by test-only DB roles. Shared atomic DB consumption tested inside one ephemeral CI container, NOT a protected production issuer, production IAM, network trust, hard billing cap, distributed deployment or safe real API sender.",
    }

def main():
    parser=argparse.ArgumentParser()
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--setup",action="store_true")
    group.add_argument("--report",type=Path)
    a=parser.parse_args()
    if a.setup:
        print(json.dumps(create_schema(),sort_keys=True))
    else:
        outcome=audit()
        a.report.parent.mkdir(parents=True,exist_ok=True)
        a.report.write_text(json.dumps(outcome,sort_keys=True,indent=2)+"\n")
        print("TASK4_310_POSTGRES_ROLE_SEPARATED_CONSUME_CI_PASS_ZERO_REAL_PROVIDER_CALLS")

if __name__=="__main__":
    main()
