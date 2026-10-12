#!/usr/bin/env python3
"""Task13 #334: fail-closed pre-Bind approval/CAS HANDOFF simulation.

Existing #333 origin signatures -> independent scoped approval -> re-read exact
prestate -> atomic consume in a local SQLite test ledger -> re-read exact
prestate. There is *no* protected bank tool callback or Bind entrypoint.
Even a successful local CAS returns dispatch_allowed=False and
execution_authorized=False. Signing keys in tests have no external IAM status.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import threading
from datetime import timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts import task13_333_dual_issuer_provenance_preflight_v1 as source

RULE="TASK13_THREE_ROLE_SOURCE_APPROVAL_EXACT_PREBIND_CAS_TEST_ONLY_V1"
STATUS="TEST_ONLY_SINGLE_USE_PREBIND_SEAM_NO_EXTERNAL_ISSUER_NO_DISPATCH"
SCHEMA="veritas.utility.task13.prebind-test-only.v1"
APPROVAL_SCHEMA="veritas.task13.test-only-scoped-approval.v1"
APPROVAL_DOMAIN=b"VERITAS-TASK13-TEST-ONLY-APPROVAL-V1\x00"
PARENT="5c38fa43006b4fb735639ca94563fb38f85cd3d9"
ROOT=Path(__file__).resolve().parents[1]
CONTRACT=ROOT/"contracts/TASK13_334_TEST_ONLY_PREBIND_SINGLE_USE_V1.json"
SOURCE_BLOBS={
    "scripts/task13_333_dual_issuer_provenance_preflight_v1.py":
        "a3c5d5598c77864ee18ab898c071ef859f4012d2",
    "scripts/task13_330_same_candidate_native_bind_local_v1.py":
        "89da7794ee62bf092a1a7547e1d603c8a92fcbb8",
    "sql/task4_310_offline_postgres_consume_v1.sql":
        "0b891930f50fc17747a9854666450c9438ef7945",
}
GRANT_PATTERN=re.compile(r"^task13-334-ci-[a-f0-9]{32}$")
ATTEMPT_PATTERN=re.compile(r"^[a-f0-9]{32}$")

class GateDenied(ValueError):
    pass

def require(condition, code):
    if not condition:
        raise GateDenied(code)

def result(status, *, case_id, source_status="NOT_VERIFIED",
           local_fixture_consumed=False, attempt=None, reason=None):
    return {
        "schema":SCHEMA,
        "rule_of_one":RULE,
        "status":status,
        "case_id":case_id,
        "source_provenance":source_status,
        "test_ledger_cas_committed":local_fixture_consumed,
        "test_attempt_id":attempt if local_fixture_consumed else None,
        "denial_reason":reason,
        "execution_authorized":False,
        "dispatch_allowed":False,
        "real_issuer_trust_verified":False,
        "external_IAM_verified":False,
        "protected_ledger_verified":False,
        "veritas_bind_called":False,
        "native_mutation_count":0,
        "real_provider_calls":0,
        "new_utility_scores":0,
        "new_injection_success_measurements":0,
        "mode":"LOCAL_TEST_ONLY",
    }

def validate_approval(*,approval_receipt,approval_root,
                      source_roots,source_preflight,
                      request_receipt,file_receipt,trusted_time):
    """Exact signed, short-lived approval bound to both #333 roles.

    It cannot prove that its public key was independently enrolled by an IAM
    service. Domain-separated signature prevents repurposing source receipts.
    """
    require(source_preflight.get("status")==
            "CRYPTO_RECEIPTS_VALID_ONLY_NO_EXECUTION_AUTHORITY",
            "ORIGINAL_REQUEST_AND_FILE_PROVENANCE_REQUIRED")
    need=source.need
    # Request/file signers and approval signer must have different keys/IDs.
    req,rpk=source.root_key("request",source_roots)
    file,fpk=source.root_key("file",source_roots)
    require(type(approval_root) is dict
            and set(approval_root)=={"issuer_id","key_id","public_key_b64"},
            "NO_SEPARATELY_PROVISIONED_APPROVAL_KEY")
    require(source.check_str(approval_root["issuer_id"])
            and source.check_str(approval_root["key_id"]),
            "APPROVAL_ID_INVALID")
    approval_pk=source.b64_exact(approval_root["public_key_b64"],32)
    require(len({req["issuer_id"],file["issuer_id"],approval_root["issuer_id"]})==3
            and len({req["key_id"],file["key_id"],approval_root["key_id"]})==3
            and len({rpk,fpk,approval_pk})==3,
            "ISSUER_ROLE_COLLUSION_OR_DUPLICATE_KEY")
    require(type(approval_receipt) is dict
            and set(approval_receipt)=={"signed_payload","signature_b64"},
            "APPROVAL_RECEIPT_ENVELOPE_SHAPE")
    p=approval_receipt["signed_payload"]
    required={
        "schema","issuer_id","key_id","purpose","mode","case_id",
        "session_id","original_request_sha256","file_content_sha256",
        "immediate_pre_state_sha256","candidate_sha256",
        "request_receipt_sha256","file_receipt_sha256",
        "scope","allowed_tool","allowed_fields",
        "grant_id","issued_at","expires_at","max_uses",
    }
    require(type(p) is dict and set(p)==required,"APPROVAL_EXACT_FIELDS_REQUIRED")
    require(p["schema"]==APPROVAL_SCHEMA and
            p["issuer_id"]==approval_root["issuer_id"] and
            p["key_id"]==approval_root["key_id"] and
            p["purpose"]=="LOCAL_TEST_APPROVAL_PROOF_NOT_NATIVE_AUTHORITY" and
            p["mode"]=="CI_LOCAL_ONLY_NO_PRODUCTION_GRANT" and
            p["scope"]==source.SCOPE and
            p["allowed_tool"]==source.ACTION and
            p["allowed_fields"]==["street","city"] and
            type(p["max_uses"]) is int and p["max_uses"]==1,
            "APPROVAL_SCOPE_MODE_OR_ISSUER_INVALID")
    require(type(p["grant_id"]) is str
            and GRANT_PATTERN.fullmatch(p["grant_id"]) is not None,
            "APPROVAL_TEST_GRANT_ID_INVALID")
    session=request_receipt["signed_payload"]["session_id"]
    require(session==file_receipt["signed_payload"]["session_id"]
            and p["session_id"]==session,
            "ORIGINAL_SIGNED_SESSION_NOT_BOUND")
    exact={
        "case_id":source_preflight["case_id"],
        "original_request_sha256":source_preflight["original_request_sha256"],
        "file_content_sha256":source_preflight["file_content_sha256"],
        "immediate_pre_state_sha256":source_preflight["prestate_sha256"],
        "candidate_sha256":source_preflight["rcc_candidate_sha256"],
        "request_receipt_sha256":source_preflight["signed_receipt_digests"][0],
        "file_receipt_sha256":source_preflight["signed_receipt_digests"][1],
    }
    for field,value in exact.items():
        require(p.get(field)==value,"APPROVAL_"+field.upper()+"_NOT_EXACT")
    now=source.parse_utc(trusted_time)
    issued=source.parse_utc(p["issued_at"])
    expiry=source.parse_utc(p["expires_at"])
    req_expiry=source.parse_utc(request_receipt["signed_payload"]["expires_at"])
    file_expiry=source.parse_utc(file_receipt["signed_payload"]["expires_at"])
    require(issued<=now<=expiry
            and timedelta(0)<expiry-issued<=timedelta(minutes=5)
            and expiry<=req_expiry and expiry<=file_expiry,
            "APPROVAL_NOT_FRESH_OR_EXCEEDS_SOURCE_RECEIPTS")
    try:
        Ed25519PublicKey.from_public_bytes(approval_pk).verify(
            source.b64_exact(approval_receipt["signature_b64"],64),
            APPROVAL_DOMAIN+source.canonical(p)
        )
    except (InvalidSignature,ValueError) as e:
        raise GateDenied("APPROVAL_CRYPTOGRAPHIC_SIGNATURE_INVALID") from e
    return p

class TestOnlySqliteLedger:
    """Ephemeral local fixture, NOT a protected CAS/production grant ledger.

    This API intentionally cannot issue externally trusted grants. It may only
    be constructed in a temporary directory for a CI/test file. Its single
    update is atomic across SQLite connections, then independently re-read.
    """
    def __init__(self,path):
        p=Path(path).resolve()
        temp=Path(tempfile.gettempdir()).resolve()
        require(p.is_relative_to(temp) and p.suffix==".sqlite3",
                "LEDGER_MUST_BE_EPHEMERAL_LOCAL_TEST_PATH")
        require(not p.exists(),"TEST_LEDGER_MUST_BEGIN_FRESH")
        self.path=p
        with self._connect() as db:
            db.execute("""CREATE TABLE grants(
              grant_id TEXT PRIMARY KEY, case_id TEXT NOT NULL,
              approval_sha256 TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              state TEXT NOT NULL CHECK(state IN ('ISSUED_LOCAL','CONSUMED_LOCAL')),
              attempt_id TEXT UNIQUE,
              CHECK((state='ISSUED_LOCAL' AND attempt_id IS NULL)
                   OR (state='CONSUMED_LOCAL' AND attempt_id IS NOT NULL))
            )""")
    def _connect(self):
        db=sqlite3.connect(str(self.path),timeout=5,isolation_level=None)
        db.execute("PRAGMA busy_timeout=5000")
        return db
    def seed_fixture(self,approval):
        require(type(approval) is dict
                and approval.get("schema")==APPROVAL_SCHEMA
                and approval.get("mode")=="CI_LOCAL_ONLY_NO_PRODUCTION_GRANT"
                and approval.get("purpose")==
                "LOCAL_TEST_APPROVAL_PROOF_NOT_NATIVE_AUTHORITY",
                "NO_EXTERNAL_GRANT_ISSUANCE_IN_THIS_LEDGER")
        with self._connect() as db:
            db.execute(
                "INSERT INTO grants VALUES(?,?,?,?,?,NULL)",
                (approval["grant_id"],approval["case_id"],
                 source.digest(approval),approval["expires_at"],"ISSUED_LOCAL"))
    def consume_once(self,approval,attempt_id,trusted_time):
        require(type(attempt_id) is str
                and ATTEMPT_PATTERN.fullmatch(attempt_id) is not None,
                "ATTEMPT_ID_INVALID")
        require(source.parse_utc(trusted_time)<=
                source.parse_utc(approval["expires_at"]),
                "APPROVAL_ALREADY_EXPIRED")
        with self._connect() as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                updated=db.execute(
                    """UPDATE grants SET state='CONSUMED_LOCAL',
                       attempt_id=? WHERE grant_id=? AND case_id=?
                       AND approval_sha256=? AND expires_at>=?
                       AND state='ISSUED_LOCAL' AND attempt_id IS NULL""",
                    (attempt_id,approval["grant_id"],approval["case_id"],
                     source.digest(approval),trusted_time)
                ).rowcount
                db.execute("COMMIT")
            except sqlite3.Error:
                db.execute("ROLLBACK")
                raise
        if updated!=1:
            return False
        # Separate connection proves that the update was COMMITTED, not just
        # successful in a transaction that might yet be rolled back.
        with self._connect() as verify:
            row=verify.execute(
                "SELECT state,attempt_id,approval_sha256 FROM grants WHERE grant_id=?",
                (approval["grant_id"],)
            ).fetchone()
        return row==("CONSUMED_LOCAL",attempt_id,source.digest(approval))

def evaluate(*,case_id,original_request,prestate,candidate,trusted_time,
             source_roots,request_receipt,file_receipt,
             approval_root,approval_receipt,
             fresh_snapshot_reader,ledger,attempt_id):
    """Local gate simulation. No Bind or native effect even when checks PASS."""
    src="NOT_VERIFIED"
    try:
        require(type(case_id) is str,"CASE_ID_REQUIRED")
        require(callable(fresh_snapshot_reader),"PROTECTED_SNAPSHOT_READER_MISSING")
        require(isinstance(ledger,TestOnlySqliteLedger),
                "TEST_LEDGER_REQUIRED_NO_PRODUCTION_CONSUMPTION")
        require(type(trusted_time) is str,
                "INDEPENDENT_VERIFIER_TIME_UNAVAILABLE")
        first=deepcopy(prestate)
        frozen=deepcopy(candidate)
        origin=source.preflight(
            case_id=case_id,original_request=original_request,
            prestate=prestate,candidate=candidate,
            trusted_time=trusted_time,trust_roots=source_roots,
            request_receipt=request_receipt,file_receipt=file_receipt
        )
        src=origin["status"]
        require(src=="CRYPTO_RECEIPTS_VALID_ONLY_NO_EXECUTION_AUTHORITY",
                "SOURCE_PROVENANCE_NOT_CRYPTOGRAPHICALLY_VERIFIED")
        approval=validate_approval(
            approval_receipt=approval_receipt,
            approval_root=approval_root,source_roots=source_roots,
            source_preflight=origin,
            request_receipt=request_receipt,
            file_receipt=file_receipt,
            trusted_time=trusted_time
        )
        require(source.digest(fresh_snapshot_reader())==
                origin["prestate_sha256"],"LIVE_PREBIND_STATE_DRIFT_BEFORE_CONSUME")
        require(first==prestate and frozen==candidate,
                "CANDIDATE_OR_SOURCE_CHANGED_BEFORE_CONSUME")
        consumed=ledger.consume_once(approval,attempt_id,trusted_time)
        require(consumed is True,"LOCAL_TEST_GRANT_MISSING_SPENT_OR_EXPIRED")
        require(source.digest(fresh_snapshot_reader())==
                origin["prestate_sha256"],"LIVE_PREBIND_STATE_DRIFT_AFTER_CONSUME")
        require(first==prestate and frozen==candidate,
                "CANDIDATE_OR_SOURCE_CHANGED_AFTER_CONSUME")
        return result("TEST_LEDGER_CONSUMED_BOUND_CANDIDATE_NO_DISPATCH",
                      case_id=case_id,source_status=src,
                      local_fixture_consumed=True,attempt=attempt_id)
    except (GateDenied,source.PreflightDenied,sqlite3.Error,KeyError,TypeError,
            ValueError) as exc:
        # Failure from any validation point must not release an operation.
        return result("DENY_PREBIND_SEAM",case_id=case_id,
                      source_status=src,reason=type(exc).__name__+":"+str(exc))
    except Exception:
        # An unexpected snapshot/backend failure must be a denial, not bypass.
        return result("DENY_UNEXPECTED_FAIL_CLOSED",case_id=case_id,
                      source_status=src,reason="UNEXPECTED_BACKEND_ERROR")

def verify_contract(manifest):
    require(type(manifest) is dict and set(manifest)=={
        "schema","rule_of_one","parent_main","source_blobs",
        "provenance","handoff_invariants","claim_boundary"
    },"CONTRACT_EXACT_KEYS_REQUIRED")
    require(manifest["schema"]==SCHEMA and
            manifest["rule_of_one"]==RULE and
            manifest["parent_main"]==PARENT and
            manifest["source_blobs"]==SOURCE_BLOBS,
            "PINNED_BASE_OR_SCOPE_DRIFT")
    for path,pin in SOURCE_BLOBS.items():
        require(source.old.blob(ROOT/path)==pin,
                "FROZEN_GIT_BLOB_DRIFT_"+path)
    require(manifest["provenance"]=={
        "prior_task13_333_preflight_real_dispatch":False,
        "previous_V13_original_signed_request_and_file_receipts":0,
        "original_model_traces_not_reexecuted":True,
        "test_signers_are_not_external_issuers":True,
    },"ARCHIVED_PROVENANCE_PROMOTION")
    require(manifest["handoff_invariants"]=={
        "signed_request_and_read_file_evidence":True,
        "third_distinct_scoped_approval_signature":True,
        "exact_original_prestate_and_candidate_hash":True,
        "external_trusted_time_argument_required":True,
        "max_approval_lifetime_seconds":300,
        "source_receipt_expiry_binds_approval":True,
        "immediate_pre_and_post_consume_snapshot":True,
        "atomic_consume_and_committed_receipt_test_only":True,
        "duplicate_and_concurrent_consume_rejected":True,
        "production_issuer_and_ledger_verified":False,
        "production_prebind_handoff_permitted":False,
    },"TEST_ONLY_HANDOFF_CONTRACT_DRIFT")
    require(manifest["claim_boundary"]=={
        "test_ledger_type":"EPHEMERAL_SQLITE_CI_FIXTURE_ONLY",
        "external_root_ownership_attested":False,
        "external_IAM_enforced":False,
        "credential_egress_bypass_rejected":False,
        "production_single_use_receipt_verified":False,
        "execution_authorized":False,
        "dispatch_allowed":False,
        "native_bind_calls":0,
        "native_bank_effects":0,
        "real_provider_calls":0,
        "new_authentic_utility_recoveries":0,
        "new_injection_success_measurements":0,
        "final128_remeasured":False,
        "status":STATUS,
    },"TEST_PROOF_PROMOTED_TO_PRODUCTION")
    return manifest

def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args(argv)
    for name in ("OPENAI_API_KEY","TASK4_OPENAI_API_KEY","ANTHROPIC_API_KEY",
                 "VERITAS_DATABASE_URL"):
        require(not os.environ.get(name),"LIVE_CREDENTIAL_PRESENT")
    dest=args.output.resolve()
    require(dest.parent==(ROOT/"results").resolve()
            and dest.name=="task13-334-test-only-prebind.json"
            and not dest.exists(),"ONLY_FRESH_SCOPED_REPORT")
    manifest=verify_contract(json.loads(CONTRACT.read_text("utf-8")))
    # The actual historical archive has no original signed issuer evidence;
    # even the public Task13 candidate is denied with an unsigned source.
    archived=result("DENY_HISTORICAL_V13_UNSIGNED_SOURCE",
                    case_id=source.CASE_IDS[0],
                    reason="MISSING_USER_REQUEST_FILE_AND_APPROVAL_ISSUERS")
    report={
        "rule_of_one":RULE,"classification":STATUS,
        "contract_sha256":source.digest(manifest),
        "archived_task13_actual_signed_receipts":0,
        "historical_execution_allowed":False,
        "historical_sample":archived,
        "production_issuer_proven":False,
        "test_sqlite_cas_ran_in_unit_tests_only":True,
        "new_provider_requests":0,"new_bank_effects":0,
        "new_utility_scores":0,"new_injection_success_measurements":0,
        "live_dispatch":"DENY",
    }
    report["report_sha256"]=source.digest(report)
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("TASK13_334_TEST_ONLY_PREBIND_AUTHORIZATION_CHAIN_NO_PRODUCTION_DISPATCH")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
