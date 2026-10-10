"""Task15 ONE-SHOT live OpenAI-model capture boundary; CI is offline only.

This module *can* make an actual model-only Chat Completions HTTPS call, but
ONLY after a separately signed, exact-source, short-lived operator approval,
credential availability, and a durable SQLite claim. No default approval,
no retry after UNKNOWN, and absolutely no bank/tool execution capability.

A signed test consent from this project's test harness is NOT production
operator onboarding. Live trust-root custody and approval must be established
independently by the operator before the first billable call. CI NEVER does it.
"""
from __future__ import annotations
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
from datetime import datetime,timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

RULE="TASK15_ONE_SHOT_OPENAI_MODEL_CAPTURE_GATE_V1"
PREDECESSOR_MAIN="aee25a92d105183aafd07fecc63f1c614b5ab8f4"
MODEL="gpt-4.1-mini-2025-04-14"
CASE="banking:user_task_15:injection_task_0:direct"
ARM="A"
SOURCE_SHA="a09c777b94e6e86edc274983fac8e447343749d7312e88397b39941741899d19"
MAX_OUTPUT_TOKENS=256
PROPOSED_MAX_MICRO_USD=250000
MAX_REQUEST_BYTES=32768
HOST="api.openai.com"
API_PATH="/v1/chat/completions"
APPROVAL_PROFILE="task15-one-exact-openai-chat-call-human-signed-v1"

class OneShotDenied(ValueError):pass

def need(check,why):
    if not check:raise OneShotDenied(why)

def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False)

def digest(obj):
    return hashlib.sha256(canonical(obj).encode()).hexdigest()

def is_hex(s,n=64):
    return type(s) is str and len(s)==n and all(x in "0123456789abcdef" for x in s)

def input_from_exact_archived_evidence(manifest,quarantine):
    need(type(manifest) is dict and type(quarantine) is dict,
         "EXACT_PR275_AND_ARCHIVED_NATIVE_WIRE_REQUIRED")
    need(manifest.get("rule_of_one")==
            "TASK15_REAL_PROVIDER_FIRST_CALL_PREFLIGHT_DEFAULT_DENY_V1"
         and manifest.get("kind")=="NON_EXECUTABLE_ONE_CALL_SOURCE_PREFLIGHT"
         and manifest.get("first_case_id")==CASE
         and manifest.get("first_arm")==ARM
         and manifest.get("exact_model_snapshot")==MODEL
         and manifest.get("source_request_sha256")==SOURCE_SHA
         and manifest.get("requested_model_call_limit")==1
         and manifest.get("proposed_max_output_tokens")==MAX_OUTPUT_TOKENS
         and manifest.get("proposed_cost_ceiling_micro_usd")==PROPOSED_MAX_MICRO_USD
         and manifest.get("cost_ceiling_authorizes_spend") is False
         and manifest.get("operator_approval_attested") is False
         and manifest.get("provider_transport_present") is False
         and manifest.get("live_provider_execution_authority_issued") is False,
         "EXACT_CLOSED_PR275_MODEL_SOURCE_PROPOSAL_REQUIRED")
    need(type(quarantine.get("client_calls")) is dict
         and type(quarantine.get("proof")) is dict
         and quarantine["proof"].get("rule_of_one")==
            "TASK15_OFFLINE_POSTREAD_RCC_QUARANTINE_V1",
         "EXACT_OFFLINE_NATIVE_WIRE_SOURCE_REQUIRED")
    calls=quarantine["client_calls"].get(CASE,{})
    need(type(calls) is dict and set(calls)=={"A","B"}
         and type(calls[ARM]) is list and len(calls[ARM])==1,
         "EXACT_ONE_A_ARM_NATIVE_MODEL_CALL_REQUIRED")
    row=calls[ARM][0]
    need(type(row) is dict and
         set(row)=={"model","messages","tools","tool_choice","temperature"}
         and row["model"]==MODEL
         and row["tool_choice"]=="auto"
         and type(row["temperature"]) is float
         and row["temperature"]==0.0
         and type(row["messages"]) is list
         and len(row["messages"])==4
         and type(row["tools"]) is list and len(row["tools"])==2,
         "UNEXPECTED_NATIVE_MODEL_CALL_ENVELOPE")
    wire={"messages":row["messages"],"tools":row["tools"]}
    need(digest(wire)==SOURCE_SHA,
         "NATIVE_MESSAGES_AND_TOOLS_DO_NOT_MATCH_FROZEN_SHA")
    # Pin source tool schemas exactly, do not materialize a writable execution
    # adapter. Function definitions are mere strings in a model request.
    request={
        "model":MODEL,"messages":copy.deepcopy(row["messages"]),
        "tools":copy.deepcopy(row["tools"]),"tool_choice":"auto",
        "temperature":0.0,"max_completion_tokens":MAX_OUTPUT_TOKENS,
        "n":1,"stream":False,"store":False,
    }
    size=len(canonical(request).encode("utf-8"))
    need(size<=MAX_REQUEST_BYTES,"FIRST_CALL_PAYLOAD_BYTE_CAP_EXCEEDED")
    return request

def validate_fresh_approval(approval,public_key,request,*,now_utc):
    need(type(public_key) is bytes and len(public_key)==32,
         "EXTERNAL_OPERATOR_PUBLIC_ROOT_MUST_BE_PRE_ENROLLED")
    need(type(approval) is dict and
         set(approval)=={"statement","signature_hex"},
         "EXACT_SEPARATE_OPERATOR_SIGNATURE_REQUIRED")
    s=approval["statement"];hex_sig=approval["signature_hex"]
    need(type(s) is dict and set(s)=={
        "profile","case_id","arm","model","wire_source_sha256",
        "request_sha256","max_calls","max_output_tokens",
        "max_total_spend_micro_usd","no_native_effects",
        "operator_public_key_sha256","issued_at","expires_at","nonce"},
        "OPERATOR_APPROVAL_SCOPE_FIELDS_MUST_BE_EXACT")
    need(s["profile"]==APPROVAL_PROFILE
         and s["case_id"]==CASE and s["arm"]==ARM
         and s["model"]==MODEL
         and s["wire_source_sha256"]==SOURCE_SHA
         and s["request_sha256"]==digest(request)
         and type(s["max_calls"]) is int and s["max_calls"]==1
         and type(s["max_output_tokens"]) is int
         and s["max_output_tokens"]==MAX_OUTPUT_TOKENS
         and type(s["max_total_spend_micro_usd"]) is int
         and s["max_total_spend_micro_usd"]==PROPOSED_MAX_MICRO_USD
         and s["no_native_effects"] is True
         and s["operator_public_key_sha256"]==hashlib.sha256(public_key).hexdigest()
         and is_hex(s["nonce"])
         and is_hex(hex_sig,128),
         "OPERATOR_SIGNATURE_REQUEST_OR_BUDGET_DRIFT")
    need(type(now_utc) is datetime and now_utc.tzinfo is not None
         and now_utc.utcoffset().total_seconds()==0,
         "TRUSTED_UTC_CLOCK_IS_EXTERNAL_OPERATOR_PRECONDITION")
    try:
        issued=datetime.fromisoformat(s["issued_at"])
        expiry=datetime.fromisoformat(s["expires_at"])
    except (ValueError,KeyError,TypeError) as exc:
        raise OneShotDenied("MALFORMED_OPERATOR_APPROVAL_TIMES") from exc
    need(issued.tzinfo is not None and expiry.tzinfo is not None
         and issued.utcoffset().total_seconds()==0
         and expiry.utcoffset().total_seconds()==0
         and issued<=now_utc<expiry
         and 0<(expiry-issued).total_seconds()<=600,
         "OPERATOR_APPROVAL_EXPIRED_OR_NOT_YET_VALID")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(hex_sig),canonical(s).encode())
    except (InvalidSignature,ValueError) as exc:
        raise OneShotDenied("OPERATOR_SIGNATURE_VERIFICATION_FAILED") from exc
    return digest(approval)

class DirectOpenAIHTTPSOnce:
    """No retry, no SDK, no redirects, no external tool calls; TLS only."""
    def __init__(self,api_key):
        need(type(api_key) is str and api_key.startswith("sk-")
             and len(api_key)>12,
             "ACTUAL_API_KEY_MUST_BE_SUPPLIED_AT_EXPLICIT_LOCAL_LIVE_EXECUTION")
        self._key=api_key
        self._spent=False

    def send(self,request):
        need(not self._spent,"NO_HTTP_RETRY_EVER")
        self._spent=True
        connection=http.client.HTTPSConnection(
            HOST,443,timeout=20,context=ssl.create_default_context())
        try:
            # Native TLS verifies the public API host; this is not a
            # provider-signed, third-party-verified execution receipt.
            connection.request("POST",API_PATH,
                body=canonical(request).encode(),
                headers={
                    "Authorization":"Bearer "+self._key,
                    "Content-Type":"application/json",
                    "Accept":"application/json",
                })
            response=connection.getresponse()
            body=response.read(1048577)
            need(len(body)<=1048576,"OPENAI_RESPONSE_BODY_TOO_LARGE")
            need(response.status==200,
                 "OPENAI_HTTP_FAILURE_OUTCOME_UNKNOWN_"+str(response.status))
            return json.loads(body)
        finally:connection.close()

class DurableOneShotModelCapture:
    """Disk-atomic claim BEFORE provider, UNKNOWN on all ambiguous outcomes.

    Approval is verified on each invocation. Caller MUST establish operator
    trust root independently; passing any attacker-owned root is outside proof.
    """
    def __init__(self,path,manifest,quarantine,approval,public_key,*,
                 preflight_evidence,now_utc,create):
        need(type(preflight_evidence) is dict
             and preflight_evidence.get("rule_of_one")==
                 "TASK15_REAL_PROVIDER_FIRST_CALL_PREFLIGHT_DEFAULT_DENY_V1"
             and preflight_evidence.get("determination")==
                 "EXACT_ONE_SOURCE_SEALED_NO_LIVE_PROVIDER_AUTHORITY"
             and type(preflight_evidence.get("manifest")) is dict
             and canonical(manifest)==canonical(preflight_evidence["manifest"])
             and preflight_evidence.get("actual_real_provider_calls")==0
             and preflight_evidence.get("actual_real_provider_spend_usd")==0
             and preflight_evidence.get("fresh_operator_approval_issued") is False,
             "UNVERIFIED_PR275_PREFLIGHT_EVIDENCE_OR_MANIFEST_SUBSTITUTION")
        self.path=Path(path)
        self.request=input_from_exact_archived_evidence(manifest,quarantine)
        self.approval_sha=validate_fresh_approval(
            approval,public_key,self.request,now_utc=now_utc)
        self.request_sha=digest(self.request)
        self.frozen_manifest_sha=digest(manifest)
        if create:
            need(not self.path.exists() and self.path.parent.is_dir(),
                 "FRESH_ONE_TIME_LIVE_CAPTURE_LEDGER_REQUIRED")
            db=self._db(create=True)
            try:
                db.executescript("""
                  CREATE TABLE capture(
                    request_sha TEXT PRIMARY KEY,
                    manifest_sha TEXT NOT NULL,
                    approval_sha TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN (
                      'PREPARED','DISPATCH_UNKNOWN','MOCK_RECORDED',
                      'LIVE_RESPONSE_RECORDED')),
                    claim_count INTEGER NOT NULL CHECK(claim_count IN (0,1)),
                    response_sha TEXT,
                    raw_response_json TEXT,
                    CHECK((state IN ('PREPARED','DISPATCH_UNKNOWN')
                           AND response_sha IS NULL
                           AND raw_response_json IS NULL)
                         OR state IN ('MOCK_RECORDED','LIVE_RESPONSE_RECORDED'))
                  );
                  CREATE TABLE audit(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,event TEXT NOT NULL
                  );
                """)
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO capture VALUES (?,?,?,'PREPARED',0,NULL,NULL)",
                    (self.request_sha,self.frozen_manifest_sha,self.approval_sha))
                db.execute("INSERT INTO audit(event) VALUES"
                           "('SIGNED_OPERATOR_APPROVAL_PINNED_NO_PROVIDER_SEND')")
                db.execute("COMMIT")
            finally:db.close()
        else:
            need(self.path.is_file(),"DURABLE_SINGLE_CALL_LEDGER_REQUIRED")
            self.status()

    def _db(self,create=False):
        db=sqlite3.connect(self.path,timeout=20,isolation_level=None)
        db.execute("PRAGMA busy_timeout=20000")
        if create:db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def status(self):
        db=self._db()
        try:
            rows=db.execute("SELECT * FROM capture").fetchall()
            events=[x[0] for x in db.execute("SELECT event FROM audit ORDER BY seq")]
        finally:db.close()
        need(len(rows)==1 and rows[0][0:3]==(
            self.request_sha,self.frozen_manifest_sha,self.approval_sha),
            "CAPTURE_SOURCE_OR_OPERATOR_APPROVAL_SUBSTITUTED")
        row=rows[0]
        need((row[3]=="PREPARED" and row[4]==0 and len(events)==1)
             or (row[3]=="DISPATCH_UNKNOWN" and row[4]==1 and len(events)==2)
             or (row[3] in ("MOCK_RECORDED","LIVE_RESPONSE_RECORDED")
                 and row[4]==1 and len(events)==3),
             "SINGLE_CALL_LEDGER_INVALID_STATE_SEQUENCE")
        if row[5] is not None:
            need(type(row[6]) is str
                 and digest(json.loads(row[6]))==row[5],
                 "CAPTURED_RESPONSE_HASH_MISMATCH")
        return {"state":row[3],"claims":row[4],
                "request_sha256":self.request_sha,
                "approval_sha256":self.approval_sha,
                "response_sha256":row[5],
                "journal":events}

    def _claim(self):
        db=self._db()
        try:
            db.execute("BEGIN IMMEDIATE")
            updated=db.execute(
                "UPDATE capture SET state='DISPATCH_UNKNOWN',claim_count=1"
                " WHERE request_sha=? AND state='PREPARED' AND claim_count=0",
                (self.request_sha,))
            if updated.rowcount!=1:
                db.execute("ROLLBACK")
                raise OneShotDenied("SINGLE_CALL_CLAIM_ALREADY_USED_OR_UNKNOWN")
            db.execute("INSERT INTO audit(event) VALUES"
                       "('CLAIMED_BEFORE_ANY_POSSIBLE_MODEL_SEND')")
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:db.execute("ROLLBACK")
            raise
        finally:db.close()

    def capture(self,transport,*,live=False):
        # Mock simulations are always marked MOCK, never live authenticity.
        need(type(live) is bool,"EXPLICIT_EXECUTION_MODE_REQUIRED")
        if live:
            need(type(transport) is DirectOpenAIHTTPSOnce,
                 "REAL_PROVIDER_MUST_USE_FIXED_NO_RETRY_TLS_TRANSPORT")
        else:
            need(type(transport) is not DirectOpenAIHTTPSOnce,
                 "REAL_PROVIDER_TRANSPORT_FORBIDDEN_IN_SIMULATION")
        self._claim()
        # From this instant a network timeout/crash leaves UNKNOWN permanently.
        try:
            response=transport.send(copy.deepcopy(self.request))
            need(type(response) is dict
                 and type(response.get("id")) is str and response["id"]
                 and response.get("model")==MODEL
                 and type(response.get("usage")) is dict
                 and type(response["usage"].get("prompt_tokens")) is int
                 and type(response["usage"].get("completion_tokens")) is int
                 and type(response.get("choices")) is list
                 and len(response["choices"])==1,
                 "MODEL_RESPONSE_NOT_EXACT_OR_UNVERIFIED")
            # Bill is a post-hoc estimate using published base rates, not an
            # actual independent billing invoice or hard provider cap.
            u=response["usage"]
            need(u["prompt_tokens"]>=0
                 and 0<=u["completion_tokens"]<=MAX_OUTPUT_TOKENS,
                 "MODEL_USAGE_EXCEEDS_PROPOSED_OUTPUT_LIMIT")
            estimated_micro_usd=(u["prompt_tokens"]*0.40
                                 +u["completion_tokens"]*1.60)
            need(estimated_micro_usd<=PROPOSED_MAX_MICRO_USD,
                 "POST_HOC_USAGE_ESTIMATE_OVER_OPERATOR_BUDGET")
            raw=canonical(response)
            db=self._db()
            try:
                db.execute("BEGIN IMMEDIATE")
                updated=db.execute(
                    "UPDATE capture SET state=?,response_sha=?,raw_response_json=?"
                    " WHERE request_sha=? AND state='DISPATCH_UNKNOWN'"
                    " AND claim_count=1",
                    ("LIVE_RESPONSE_RECORDED" if live else "MOCK_RECORDED",
                     digest(response),raw,self.request_sha))
                if updated.rowcount!=1:
                    db.execute("ROLLBACK")
                    raise OneShotDenied("ATOMIC_RESPONSE_COMMIT_FAILED")
                db.execute("INSERT INTO audit(event) VALUES (?)",
                    ("LIVE_RESPONSE_SAVED_NEVER_TOOL_EXECUTED" if live else
                     "MOCK_RESPONSE_SAVED_NEVER_TOOL_EXECUTED",))
                db.execute("COMMIT")
            finally:db.close()
        except BaseException:
            # No retries, no silent NO_EFFECT even on HTTP failure.
            raise
        return self.status()

    def read_response(self):
        s=self.status()
        need(s["state"] in ("MOCK_RECORDED","LIVE_RESPONSE_RECORDED"),
             "NO_AUTHENTICATED_RESPONSE_FOR_UNRESOLVED_CALL")
        db=self._db()
        try:
            body=db.execute("SELECT raw_response_json FROM capture").fetchone()[0]
        finally:db.close()
        return json.loads(body)
