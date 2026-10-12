#!/usr/bin/env python3
"""Task13 #333: read-only dual-issuer signed-source preflight.

Two distinct externally provisioned issuers must attest user-request authority
and *tool read* provenance respectively, against the exact captured action and
native prestate. Cryptographic verification is NOT executable authority:
this module NEVER calls any mutation, Bind, Provider or native scorer, and
NEVER mints grants. V13 archives contain no such independently signed receipts.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import sys
from collections.abc import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0,str(ROOT))

from scripts import task13_332_v13_four_case_native_counterfactual_v1 as v13
from scripts import task13_330_same_candidate_native_bind_local_v1 as old
from scripts.task13_source_bound_native_city_projection_diagnostic_v1 import inspect_existing_candidate

RULE="TASK13_TWO_INDEPENDENT_SIGNED_ISSUERS_REQUEST_AND_READ_RECEIPT_PREFLIGHT_V1"
STATUS="CRYPTO_VERIFIER_AND_ARCHIVED_NEGATIVE_ONLY_NO_DISPATCH"
CONTRACT=ROOT/"contracts/TASK13_333_SIGNED_REQUEST_AND_READ_ORIGIN_PREFLIGHT_V1.json"
CASE_IDS=v13.CASE_IDS
FILE_PATH="address-change.txt"
USER_REQUEST=old.EXPECTED
ACTION="update_user_info"
SCOPE="banking:user_task_13:update_user_info:address_only"
REQUEST_SCHEMA="veritas.task13.signed-user-request-origin.v1"
FILE_SCHEMA="veritas.task13.signed-tool-read-origin.v1"
REQ_DOMAIN=b"VERITAS-TASK13-REQUEST-ORIGIN-V1\x00"
FILE_DOMAIN=b"VERITAS-TASK13-FILE-READ-ORIGIN-V1\x00"
HEX64=re.compile(r"^[a-f0-9]{64}$")
HEX32=re.compile(r"^[a-f0-9]{32}$")
UTC_FORMAT="%Y-%m-%dT%H:%M:%SZ"
SOURCE_PINS={
    "scripts/task13_332_v13_four_case_native_counterfactual_v1.py":
        "55a2c7f6527ecd74577b9a533591221435875b7b",
    "scripts/task13_330_same_candidate_native_bind_local_v1.py":
        "89da7794ee62bf092a1a7547e1d603c8a92fcbb8",
    "scripts/task13_source_bound_native_city_projection_diagnostic_v1.py":
        "8bffce16daecb90f03e7e272ec9e524bba8d5b6f",
    "agentdojo_constraint_resolver_v0_1.py":
        "edbf513e67efa8719de3a1193a5f3ba937afdf52",
}
CONTRACT_SOURCE_SHA="9a26e6e364d7cc2a00e9c318e1aba059414b29c4"

class PreflightDenied(ValueError):
    pass

def need(cond,why):
    if not cond:
        raise PreflightDenied(why)

def canonical(value):
    # JSON only, exact types, no floats/nonfinite/NaN and no unserializable
    def enforce(obj,depth=0):
        need(depth<=30,"JSON_TOO_DEEP")
        if obj is None or type(obj) in (str,bool,int):
            return
        # The pinned RCC canonical JSON profile permits finite float values.
        # Original AgentDojo banking prestates include native monetary floats;
        # NaN/Infinity remain forbidden for stable SHA-256 source binding.
        if type(obj) is float:
            need(math.isfinite(obj),"NONFINITE_JSON_NUMBER")
            return
        if type(obj) is list:
            for x in obj:
                enforce(x,depth+1)
            return
        if type(obj) is dict:
            need(all(type(k) is str for k in obj),"NONSTRING_JSON_KEY")
            for x in obj.values():
                enforce(x,depth+1)
            return
        raise PreflightDenied("NON_CANONICAL_JSON_VALUE")
    enforce(value)
    return json.dumps(value,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode("utf-8")

def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()

def hash_text(text):
    need(type(text) is str,"UNEXPECTED_TEXT_TYPE")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def check_str(s):
    return type(s) is str and bool(s) and len(s)<=256

def b64_exact(s,expected_length):
    need(type(s) is str and bool(s),"BASE64_VALUE_MISSING")
    try:
        raw=base64.b64decode(s,validate=True)
    except (binascii.Error,ValueError) as e:
        raise PreflightDenied("NON_CANONICAL_BASE64") from e
    need(len(raw)==expected_length and base64.b64encode(raw).decode("ascii")==s,
         "BASE64_BYTES_OR_ENCODING_INCORRECT")
    return raw

def parse_utc(value):
    need(type(value) is str
         and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ",value) is not None,
         "TIMESTAMP_NOT_CANONICAL_UTC")
    try:
        return datetime.strptime(value,UTC_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise PreflightDenied("TIMESTAMP_INVALID") from exc

def root_key(role,trust_roots):
    need(type(trust_roots) is dict and set(trust_roots)=={"request","file"},
         "TWO_EXPLICIT_TRUST_ROOTS_REQUIRED")
    key=trust_roots[role]
    need(type(key) is dict
         and set(key)=={"issuer_id","key_id","public_key_b64"},
         "EXTERNAL_TRUST_ROOT_SHAPE")
    need(check_str(key["issuer_id"]) and check_str(key["key_id"]),
         "EXTERNAL_TRUST_ROOT_ID_INVALID")
    return key,b64_exact(key["public_key_b64"],32)

def role_payload(role,body):
    common={
       "schema","issuer_id","key_id","case_id","session_id",
       "original_request_sha256","immediate_pre_state_sha256",
       "candidate_sha256","issued_at","expires_at","purpose",
    }
    extras={
       "request":{"scope","allowed_tool","allowed_fields","referenced_file_path"},
       "file":{"tool_name","tool_arguments","file_path",
               "file_content_sha256","read_result_sha256"},
    }
    need(type(body) is dict and set(body)==common|extras[role],
         "SIGNED_"+role.upper()+"_ENVELOPE_SHAPE_DRIFT")
    for f in ("schema","issuer_id","key_id","case_id","session_id",
              "original_request_sha256","immediate_pre_state_sha256",
              "candidate_sha256","issued_at","expires_at","purpose"):
        need(type(body[f]) is str and bool(body[f]),
             "SIGNED_"+role.upper()+"_REQUIRED_FIELD_MISSING")
    need(HEX32.fullmatch(body["session_id"]) is not None,
         "INVALID_SESSION_ID")
    for k in ("original_request_sha256","immediate_pre_state_sha256","candidate_sha256"):
        need(HEX64.fullmatch(body[k]) is not None,"INVALID_SIGNED_DIGEST")
    expected_schema=REQUEST_SCHEMA if role=="request" else FILE_SCHEMA
    need(body["schema"]==expected_schema,"SIGNED_SCHEMA_WRONG_ROLE")
    if role=="request":
        need(body["purpose"]=="ATTEST_ORIGINAL_USER_INTENT_ONLY"
             and body["scope"]==SCOPE
             and body["allowed_tool"]==ACTION
             and body["allowed_fields"]==["street","city"]
             and body["referenced_file_path"]==FILE_PATH,
             "SIGNED_REQUEST_SCOPE_BROADENED")
    else:
        need(body["purpose"]=="ATTEST_READ_FILE_BYTES_ONLY_NOT_EXECUTION_AUTHORITY"
             and body["tool_name"]=="read_file"
             and body["tool_arguments"]=={"file_path":FILE_PATH}
             and body["file_path"]==FILE_PATH
             and type(body["file_content_sha256"]) is str
             and type(body["read_result_sha256"]) is str
             and HEX64.fullmatch(body["file_content_sha256"]) is not None
             and HEX64.fullmatch(body["read_result_sha256"]) is not None,
             "SIGNED_FILE_READ_SCOPE_BROADENED")

def _verified_envelope(*,role,receipt,root,now,expected):
    need(type(receipt) is dict
         and set(receipt)=={"signed_payload","signature_b64"},
         "SIGNED_RECEIPT_ENVELOPE_SHAPE")
    body=receipt["signed_payload"]
    role_payload(role,body)
    need(body["issuer_id"]==root["issuer_id"]
         and body["key_id"]==root["key_id"],"SIGNED_ISSUER_NOT_ENROLLED")
    for key,value in expected.items():
        need(body.get(key)==value,"SIGNED_"+role.upper()+"_"+key.upper()+"_MISMATCH")
    beginning=parse_utc(body["issued_at"])
    expiry=parse_utc(body["expires_at"])
    need(beginning<=now<=expiry and
         timedelta(0)<=expiry-beginning<=timedelta(minutes=5),
         "SIGNED_RECEIPT_NOT_FRESH")
    raw=b64_exact(receipt["signature_b64"],64)
    prefix=REQ_DOMAIN if role=="request" else FILE_DOMAIN
    try:
        Ed25519PublicKey.from_public_bytes(
            b64_exact(root["public_key_b64"],32)
        ).verify(raw,prefix+canonical(body))
    except (InvalidSignature,ValueError) as exc:
        raise PreflightDenied("SIGNED_"+role.upper()+"_CRYPTO_INVALID") from exc
    return digest(body)

def _source_inputs(*,case_id,original_request,prestate,candidate):
    need(case_id in CASE_IDS,"UNENROLLED_CASE_ID")
    need(original_request==USER_REQUEST and type(original_request) is str,
         "ORIGINAL_USER_REQUEST_NOT_EXPECTED")
    need(type(prestate) is dict and type(candidate) is dict,
         "ORIGINAL_IMMUTABLE_SNAPSHOT_NOT_MAPPING")
    need(candidate==old.CANDIDATE,
         "ORIGINAL_MODEL_CANDIDATE_NOT_EXACTLY_BOUND")
    files=prestate.get("filesystem",{}).get("files",{})
    need(type(files) is dict and type(files.get(FILE_PATH)) is str,
         "NATIVE_READ_FILE_BYTES_UNAVAILABLE")
    text=files[FILE_PATH]
    need(bool(text),"READ_FILE_CONTENT_EMPTY")
    projection=inspect_existing_candidate(
        trusted_prestate=prestate,arguments=candidate
    )
    need(projection["structurally_compatible"] is True,
         "STRICT_NATIVE_CITY_PROJECTION_MISMATCH")
    action={"kind":"tool_call","name":ACTION,"arguments":deepcopy(candidate),
            "content":None,"metadata":{}}
    return {
        "case_id":case_id,
        "original_request_sha256":hash_text(original_request),
        "immediate_pre_state_sha256":digest(prestate),
        "candidate_sha256":digest(action),
        "file_content_sha256":hash_text(text),
        "read_result_sha256":hash_text(text)
    }

def preflight(*,case_id,original_request,prestate,candidate,
              trusted_time=None,trust_roots=None,
              request_receipt=None,file_receipt=None):
    """Verify separately issued cryptographic evidence ONLY; never execute.

    trust_roots must be supplied by a protected caller; this function cannot
    attest their provisioning/ownership. Success never gives native authority.
    The archived V13 case has no issuer receipts, and is always DENY.
    """
    captured=deepcopy(prestate)
    frozen_args=deepcopy(candidate)
    bound=_source_inputs(case_id=case_id,original_request=original_request,
                         prestate=prestate,candidate=candidate)
    missing=[]
    if not isinstance(trust_roots,dict):
        missing.append("MISSING_EXTERNAL_DUAL_ISSUER_TRUST_ROOT")
    if request_receipt is None:
        missing.append("MISSING_SEPARATE_ORIGINAL_REQUEST_ISSUER_RECEIPT")
    if file_receipt is None:
        missing.append("MISSING_SEPARATE_NATIVE_FILE_READ_RECEIPT")
    common={
       "case_id":case_id,
       "original_request_sha256":bound["original_request_sha256"],
       "prestate_sha256":bound["immediate_pre_state_sha256"],
       "rcc_candidate_sha256":bound["candidate_sha256"],
       "file_content_sha256":bound["file_content_sha256"],
       "native_tool_name":ACTION,
       "native_tool_effect_count":0,
       "native_bind_called":False,
       "model_provider_calls":0,
       "native_scorer_calls":0,
       "execution_authorized":False,
       "dispatch_allowed":False,
       "production_issuer_independently_attested":False,
       "issuer_source_controls_verified":False,
       "durable_one_use_consumption_verified":False,
       "origin_of_trust_roots_unverifiable_in_this_repo":True,
       "classification":STATUS,
    }
    if missing:
        need(prestate==captured and candidate==frozen_args,
             "PREFLIGHT_CHANGED_CAPTURED_SOURCE")
        return {**common,"status":"DENY_MISSING_INDEPENDENT_ISSUERS",
                "reasons":missing,"signed_receipt_digests":[]}
    rroot,rpk=root_key("request",trust_roots)
    froot,fpk=root_key("file",trust_roots)
    need(rroot["issuer_id"]!=froot["issuer_id"]
         and rroot["key_id"]!=froot["key_id"]
         and not hmac.compare_digest(rpk,fpk),
         "REQUEST_AND_FILE_ISSUERS_NOT_INDEPENDENT")
    need(trusted_time is not None,"TRUSTED_EXTERNAL_TIME_REQUIRED")
    now=parse_utc(trusted_time)
    need(request_receipt is not None and file_receipt is not None,
         "TWO_RECEIPTS_REQUIRED")
    req=deepcopy(request_receipt.get("signed_payload",{})) if type(request_receipt) is dict else {}
    read=deepcopy(file_receipt.get("signed_payload",{})) if type(file_receipt) is dict else {}
    need(req.get("session_id")==read.get("session_id"),
         "TWO_SIGNERS_DIFFERENT_SESSION_OR_REQUEST")
    expected={
       "case_id":case_id,
       "original_request_sha256":bound["original_request_sha256"],
       "immediate_pre_state_sha256":bound["immediate_pre_state_sha256"],
       "candidate_sha256":bound["candidate_sha256"],
    }
    req_dig=_verified_envelope(
        role="request",receipt=request_receipt,root=rroot,now=now,
        expected=expected
    )
    read_dig=_verified_envelope(
        role="file",receipt=file_receipt,root=froot,now=now,
        expected={**expected,
                  "file_content_sha256":bound["file_content_sha256"],
                  "read_result_sha256":bound["read_result_sha256"]}
    )
    need(prestate==captured and candidate==frozen_args,
         "PREFLIGHT_CHANGED_CAPTURED_SOURCE")
    return {
        **common,
        "status":"CRYPTO_RECEIPTS_VALID_ONLY_NO_EXECUTION_AUTHORITY",
        "reasons":["TRUST_ROOT_ORIGIN_NOT_INDEPENDENTLY_ATTESTED",
                   "DURABLE_SINGLE_USE_AND_EXECUTION_AUTHORITY_NOT_VERIFIED"],
        "signed_receipt_digests":[req_dig,read_dig],
        "cryptographic_role_separation_passed":True,
        "request_and_file_receipts_bound_to_same_candidate_and_prestate":True
    }

def verify_contract(manifest):
    need(type(manifest) is dict and set(manifest)=={
        "schema","rule_of_one","base_main","source_blobs","archived",
        "required_issuer_separation","claim_boundary"
    },"CONTRACT_EXACT_KEYS_REQUIRED")
    need(manifest["schema"]=="veritas.utility.task13.dual-issuer-source-preflight.v1"
         and manifest["rule_of_one"]==RULE
         and manifest["base_main"]==CONTRACT_SOURCE_SHA
         and manifest["source_blobs"]==SOURCE_PINS,
         "PINNED_CONTRACT_DRIFT")
    for path,gitsha in SOURCE_PINS.items():
        need(old.blob(ROOT/path)==gitsha,"SOURCE_GIT_BLOB_DRIFT_"+path)
    need(manifest["archived"]=={
        "v13_artifact_id":11466539107,
        "v13_zip_sha256":v13.V13_ZIP_SHA,
        "replay_artifact_id":11472402060,
        "replay_zip_sha256":v13.REPLAY_ZIP_SHA,
        "case_ids":list(CASE_IDS),
        "original_signed_request_receipts":0,
        "original_signed_file_read_receipts":0
    },"FROZEN_ARCHIVAL_INPUT_DRIFT")
    need(manifest["required_issuer_separation"]=={
        "request_authority_role":"USER_REQUEST_AUTHORITY_ORIGIN",
        "file_read_origin_role":"TRUSTED_FILE_READ_RECEIPT",
        "same_issuer_disallowed":True,
        "same_key_disallowed":True,
        "max_receipt_lifetime_seconds":300,
        "issuers_must_be_external_to_repo_ci_agent_and_candidate":True,
        "no_issuer_private_keys_in_repository_or_ci":True,
        "benchmark_authority_fixture_is_not_independent_issuer":True,
        "signed_file_data_alone_grants_execution_authority":False,
        "protected_one_use_ledger_and_runtime_Bind_still_required":True,
    },"ROLE_SEPARATION_CONTRACT_DRIFT")
    need(manifest["claim_boundary"]=={
        "signed_v13_request_receipts_available":False,
        "signed_v13_tool_read_receipts_available":False,
        "historic_task13_four_case_b_native_execution_admitted":False,
        "real_external_issuer_connected":False,
        "external_trust_root_origin_verified":False,
        "production_signed_approval_proven":False,
        "credential_and_egress_bypass_rejection_proven":False,
        "fresh_real_provider_calls":0,
        "native_bank_effects":0,
        "native_bind_calls":0,
        "native_attack_scorer_calls":0,
        "new_authentic_utility_recoveries":0,
        "new_injection_success_measurements":0,
        "final128_remeasured":False,
        "live_authorization":False,
        "provider_dispatch":"DENY",
        "classification":STATUS,
    },"CLAIM_PROMOTION_NOT_PROVEN")
    return manifest

def inspect_v13_archive(*,v13_zip,replay_zip,agentdojo_root,rcc_root,veritas_root):
    """Real archived source input; no synthetic issuer fallback, always DENY."""
    from agentdojo.task_suite.load_suites import get_suite
    v13.local.verify_inputs(agentdojo_root=agentdojo_root,rcc_root=rcc_root,
                            veritas_root=veritas_root)
    manifest=verify_contract(json.loads(CONTRACT.read_text(encoding="utf-8")))
    records,scores,paired=v13.load_historic(v13_zip=v13_zip,replay_zip=replay_zip)
    suite=get_suite("v1.2.2","banking")
    rows=[]
    for case in CASE_IDS:
        pre,candidate,action,hist,b_args,old_a,old_b=v13.open_source(
             case,records,scores,paired,suite)
        result=preflight(
            case_id=case,original_request=old.EXPECTED,
            prestate=pre,candidate=candidate,
            trust_roots=None,request_receipt=None,file_receipt=None,
            trusted_time=None
        )
        need(result["status"]=="DENY_MISSING_INDEPENDENT_ISSUERS"
             and len(result["reasons"])==3
             and result["execution_authorized"] is False
             and result["dispatch_allowed"] is False
             and result["native_tool_effect_count"]==0,
             "ARCHIVED_INPUT_MUST_BE_DENIED_NOT_ENROLLED")
        rows.append({
            "case_id":case,
            "source_provenance":"ORIGINAL_V13_A_PROPOSAL_AND_ATTACKED_PRESTATE",
            "source_v13_original_model_candidate_from_archive":True,
            "original_utility_scores_unchanged":hist,
            "preflight":result,
            "historical_A_B_independent_continuation_not_replayed":True
        })
    report={
        "schema":"veritas.utility.task13.dual-issuer-source-preflight-report.v1",
        "rule_of_one":RULE,
        "classification":STATUS,
        "manifest_sha256":digest(manifest),
        "archived_v13_case_count":4,
        "archived_v13_missing_issuer_denials":4,
        "archived_v13_admissions":0,
        "independently_issued_signed_request_receipts_found":0,
        "independently_issued_signed_file_read_receipts_found":0,
        "native_tool_effects":0,
        "native_Bind_calls":0,
        "new_model_utility_scores":0,
        "new_injection_success_measurements":0,
        "provider_calls":0,
        "remote_bank_effects":0,
        "external_origin_proven":False,
        "live_authority_issued":False,
        "provider_dispatch":"DENY",
        "rows":rows
    }
    report["report_sha256"]=digest(report)
    return report

def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("--v13-zip",type=Path,required=True)
    p.add_argument("--replay-zip",type=Path,required=True)
    p.add_argument("--agentdojo-root",type=Path,required=True)
    p.add_argument("--rcc-root",type=Path,required=True)
    p.add_argument("--veritas-root",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    arg=p.parse_args(argv)
    for name in ("OPENAI_API_KEY","ANTHROPIC_API_KEY","TASK4_OPENAI_API_KEY",
                 "VERITAS_DATABASE_URL"):
        need(not os.environ.get(name),"NO_MODEL_OR_BANK_SECRETS_ALLOWED")
    dest=arg.output.resolve()
    need(dest.parent==(ROOT/"results").resolve()
         and dest.name=="task13-333-dual-issuer-provenance-preflight.json"
         and not dest.exists(),"FRESH_FIXED_READONLY_REPORT_REQUIRED")
    report=inspect_v13_archive(
        v13_zip=arg.v13_zip,replay_zip=arg.replay_zip,
        agentdojo_root=arg.agentdojo_root,rcc_root=arg.rcc_root,
        veritas_root=arg.veritas_root
    )
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("TASK13_333_FROZEN_V13_FOUR_CASES_DENIED_WITHOUT_TWO_INDEPENDENT_SIGNED_ISSUERS")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
