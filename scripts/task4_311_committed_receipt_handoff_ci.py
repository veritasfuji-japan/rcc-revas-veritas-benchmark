#!/usr/bin/env python3
"""#311: CI-only committed PostgreSQL receipt + independent-session handoff.

ALL fixture roles, credentials, tokens and grants are disposable test-only.
No real Provider API client, no protected production grant, no paid API call,
no banking effect or actual native Bind. A successful committed receipt is
NOT live dispatch authority. This module always returns REAL_POST_DENIED.

#310 parent provides the pinned Task4 issuer/wire fixture, restricted loopback
PostgreSQL connection and issuer INSERT role. PostgreSQL transaction atomicity
does not, by itself, create an external protected trust boundary.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit, unquote
import uuid

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT/"scripts") not in sys.path:
    sys.path.insert(0,str(ROOT/"scripts"))
from task4_310_postgres_single_use_ci import (
    check_ci as parent_check, db as parent_db, fresh_scope, seed_fixture,
    admin_record, OLD_CONSUMED,
)

RULE="TASK4_COMMITTED_CONSUMPTION_RECEIPT_FAIL_CLOSED_HANDOFF_CI_V1"
PARENT_MAIN="5d49b4a7c7e28ec9fd497a1e3f0b2ddaa5f82617"
ONLY_OFFLINE="EPHEMERAL_POSTGRES_FIXTURE_COMMITTED_RECEIPT_NOT_LIVE_AUTHORITY"
SQL_PATH=ROOT/"sql"/"task4_311_committed_receipt_handoff_ci_v1.sql"
CONSUME_SQL="SELECT task4_311.consume_and_record_fixture_once(%s,%s,%s,%s,%s,%s,%s)"
VERIFY_SQL="SELECT task4_311.verify_committed_fixture_receipt(%s,%s,%s,%s,%s,%s,%s)"
ROLE_DSN={
  "consumer":("TASK4_311_CONSUMER_DSN","task4_311_fixture_consumer"),
  "handoff":("TASK4_311_HANDOFF_DSN","task4_311_fixture_handoff"),
}

class BoundaryDenied(ValueError): pass

def need(ok,reason):
    if not ok: raise BoundaryDenied(reason)

def check_ci():
    parent_check()
    need(os.getenv("TASK4_311_CI_ONLY")=="1","TASK4_311_EXPLICIT_CI_ONLY_REQUIRED")
    for which,(key,role) in ROLE_DSN.items():
        raw=os.environ.get(key,"")
        uri=urlsplit(raw)
        need(uri.scheme in ("postgres","postgresql")
             and uri.hostname=="127.0.0.1" and uri.port==5432
             and uri.path=="/postgres"
             and unquote(uri.username or "")==role
             and uri.password is not None,
             "TASK4_311_ONLY_EPHEMERAL_LOOPBACK_DB_"+which.upper())
    return True

def db(role):
    check_ci()
    import psycopg
    return psycopg.connect(os.environ[ROLE_DSN[role][0]],autocommit=True,
                           connect_timeout=5)

def setup():
    check_ci()
    raw=SQL_PATH.read_text(encoding="utf8")
    need("SECURITY DEFINER" in raw and "SET search_path = pg_catalog" in raw
         and "REVOKE EXECUTE ON FUNCTION task4_310.consume_offline_fixture_once" in raw
         and "REFERENCES task4_310.offline_fixture_grants" in raw,
         "EXPECTED_OFFLINE_ATOMIC_DB_SCHEMA_NOT_PRESENT")
    with parent_db("admin") as c:
        c.execute(raw,prepare=False)
    return {"setup":"POSTGRES_EPHEMERAL_CONSUME_AND_RECEIPT_READY",
            "source":ONLY_OFFLINE,
            "future_real_provider_permission_created":False}

def scope_params(scope,attempt_id):
    need(type(scope) is dict and type(attempt_id) is str,
         "EXACT_FIXTURE_SCOPE_AND_ATTEMPT_REQUIRED")
    return (scope["grant_id"],scope["case_id"],scope["context"],
            scope["wire"],scope["model"],scope["estimated_cost"],attempt_id)

def consume_fixture(scope,*,attempt_id=None,alter=None):
    check_ci()
    attempt=attempt_id if attempt_id is not None else (
        "task4-311-attempt-"+uuid.uuid4().hex)
    effective=dict(scope)
    if alter is not None:
        effective.update(alter)
    with db("consumer") as c:
        accepted=c.execute(CONSUME_SQL,scope_params(effective,attempt)).fetchone()[0]
    need(type(accepted) is bool,"PG_CONSUME_FUNCTION_BOOL_REQUIRED")
    return accepted,attempt

def verify_committed_in_separate_session(scope,attempt_id,*,alter=None):
    """Independent DB session; no caller-controlled 'committed' flag."""
    check_ci()
    effective=dict(scope)
    if alter is not None:
        effective.update(alter)
    with db("handoff") as c:
        seen=c.execute(VERIFY_SQL,scope_params(effective,attempt_id)).fetchone()[0]
    need(type(seen) is bool,"PG_RECEIPT_VERIFICATION_BOOL_REQUIRED")
    return seen

def admin_receipt(grant_id):
    check_ci()
    with parent_db("admin") as c:
        rows=c.execute("""SELECT grant_id,attempt_id,case_id,
            issuer_context_sha256,frozen_wire_sha256,model_id,
            estimated_cost_usd,committed_state,db_consumed_at,receipt_sha256
            FROM task4_311.offline_committed_receipts WHERE grant_id=%s""",
            (grant_id,)).fetchall()
    need(len(rows) <= 1,"DUPLICATE_LOCAL_RECEIPT_SHOULD_BE_IMPOSSIBLE")
    if not rows:return None
    return dict(zip(("grant_id","attempt_id","case_id","context","wire",
                     "model","estimated_cost","state","db_consumed_at",
                     "receipt_sha256"),rows[0]))

def proof_scope_roles():
    check_ci()
    with parent_db("admin") as c:
        fn_consume="task4_311.consume_and_record_fixture_once(text,text,text,text,text,numeric,text)"
        fn_verify="task4_311.verify_committed_fixture_receipt(text,text,text,text,text,numeric,text)"
        issuer="task4_310_fixture_issuer"
        consumer="task4_311_fixture_consumer"
        handoff="task4_311_fixture_handoff"
        former="task4_310_fixture_consumer"
        def executable(role,fn):
            return bool(c.execute("SELECT has_function_privilege(%s,%s,'EXECUTE')",
                                  (role,fn)).fetchone()[0])
        def rowpriv(role,priv,table):
            return bool(c.execute("SELECT has_table_privilege(%s,%s,%s)",
                                  (role,table,priv)).fetchone()[0])
        rights={
            "new_consumer_consume":executable(consumer,fn_consume),
            "new_consumer_verify":executable(consumer,fn_verify),
            "handoff_verify":executable(handoff,fn_verify),
            "handoff_consume":executable(handoff,fn_consume),
            "issuer_consume":executable(issuer,fn_consume),
            "issuer_verify":executable(issuer,fn_verify),
            "parent_old_consume_disabled":not executable(
                former,"task4_310.consume_offline_fixture_once(text,text,text,text,text,numeric,text)"),
            "issuer_seeds_310_table":rowpriv(
                issuer,"INSERT","task4_310.offline_fixture_grants"),
        }
        for role in (issuer,consumer,handoff):
            for table in ("task4_310.offline_fixture_grants",
                          "task4_311.offline_committed_receipts"):
                for p in ("SELECT","UPDATE","DELETE"):
                    rights[role+"_"+table+"_no_"+p.lower()] = (
                        not rowpriv(role,p,table))
                if role!=issuer:
                    rights[role+"_"+table+"_no_insert"] = (
                        not rowpriv(role,"INSERT",table))
    need(rights["new_consumer_consume"]
         and not rights["new_consumer_verify"]
         and rights["handoff_verify"]
         and not rights["handoff_consume"]
         and not rights["issuer_consume"]
         and not rights["issuer_verify"]
         and rights["parent_old_consume_disabled"]
         and rights["issuer_seeds_310_table"]
         and all(val for k,val in rights.items() if "_no_" in k),
         "POSTGRES_LEAST_PRIVILEGE_HISTORICAL_BYPASS_NOT_CLOSED")
    return rights

def no_live_send_authority(_anything=None):
    return {"decision":"DENY",
            "reason":"CI_COMMITTED_FIXTURE_RECEIPT_NOT_REAL_HUMAN_AUTHORIZATION",
            "real_provider_posts_authorized":0,
            "bank_actions_authorized":False,
            "production_sender_present":False}

def audit():
    check_ci()
    rights=proof_scope_roles()
    scope=fresh_scope()
    seed_fixture(scope)
    def contender(_):
        # Each contender uses its OWN postgres connection and attempt id.
        return consume_fixture(scope)
    with ThreadPoolExecutor(max_workers=12) as p:
        results=list(p.map(contender,range(12)))
    wins=[attempt for won,attempt in results if won]
    need(len(wins)==1 and sum(not won for won,_ in results)==11,
         "POSTGRES_RECEIPT_DOUBLE_CONSUME_OR_CONCURRENT_LOSS")
    attempt=wins[0]
    need(verify_committed_in_separate_session(scope,attempt),
         "CROSS_SESSION_COMMITTED_RECEIPT_NOT_OBSERVED")
    need(all(not verify_committed_in_separate_session(scope,wrong)
             for won,wrong in results if not won),
         "LOSER_ATTEMPT_SPOOFED_COMMITTED_RECEIPT")
    persisted=admin_receipt(scope["grant_id"])
    grant=admin_record(scope["grant_id"])
    need(persisted is not None
         and persisted["attempt_id"]==attempt
         and persisted["state"]==grant["state"]=="CONSUMED_FIXTURE_ONLY"
         and persisted["db_consumed_at"]==grant["consumed_at"]
         and persisted["wire"]==scope["wire"]
         and persisted["context"]==scope["context"]
         and len(persisted["receipt_sha256"])==64,
         "ATOMIC_GRANT_RECEIPT_PAIR_NOT_PERSISTED")
    need(not consume_fixture(scope)[0],"GRANT_REPLAY_AFTER_COMMIT_NOT_REFUSED")
    return {
        "rule_of_one":RULE,
        "determination":"POSTGRES_ISOLATED_CI_ATOMIC_COMMITTED_RECEIPT_AND_SEPARATE_HANDOFF_VERIFIED",
        "main_parent_sha":PARENT_MAIN,"source":ONLY_OFFLINE,
        "prior_real_provider_approval_consumed_sha":OLD_CONSUMED,
        "parallel_independent_consumer_connections":12,
        "fixture_successful_consumptions":1,
        "conflicting_consumption_refusals":11,
        "separate_handoff_session_verified_exact_winner":True,
        "loser_attempts_unverified":11,
        "separate_session_replay_refused":True,
        "single_atomic_grant_receipt_pair":True,
        "receipt_sha256_local_integrity_not_authentication":persisted["receipt_sha256"],
        "receipt_sha256_format":"plain unkeyed SHA256, NOT an authenticated external signed record",
        "synthetic_issuer_context_sha256":scope["context"],
        "synthetic_wire_sha256":scope["wire"],
        "db_role_separation":rights,
        "new_real_human_consent_issued":False,
        "real_provider_posts":0,
        "actual_native_bind_calls":0,
        "real_bank_effects":0,
        "official_task4_or_final128_scores":0,
        "global_protected_single_use_proven":False,
        "production_handoff_proven":False,
        "production_commit_to_network_coupling_proven":False,
        "production_credential_or_egress_controls_proven":False,
        "real_spend_cap_proven":False,
        "real_provider_response_proven":False,
        "future_live_provider_decision":no_live_send_authority(),
        "limitations":"CI ephemeral local PostgreSQL, public fixture roles, privileged DB admin, no protected issuer/real approval/Provider sender. Separate-session visibility is necessary but not sufficient for production exactly-once effects. No live Provider POST even when local receipt verifies.",
    }

def main():
    p=argparse.ArgumentParser()
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument("--setup",action="store_true")
    group.add_argument("--report",type=Path)
    a=p.parse_args()
    if a.setup:
        print(json.dumps(setup(),sort_keys=True))
    else:
        result=audit()
        a.report.parent.mkdir(parents=True,exist_ok=True)
        a.report.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
        print("TASK4_311_COMMITTED_LOCAL_RECEIPT_VERIFIED_NO_REAL_PROVIDER_SEND")

if __name__=="__main__":
    main()
