#!/usr/bin/env python3
"""#382 Task1 first TWO Responses captures: bounded HTTPS transport adapter.

This is an integration building block, not an authorized live entrypoint.
It has no __main__, CLI, workflow_dispatch, credential acquisition, approval
issuer, protected environment or SDK retry path. Only in-memory mock HTTP
connections are used by this PR's CI. A separate protected, reviewed launcher
must verify real operator consent, IAM/egress, budget/project limits and
atomically consume an external immutable lease before supplying any LIVE
connection. The caller cannot make a lease authentic with a boolean/JSON.

The actual native read and final model/scorer are OUT OF SCOPE: first A/B
response capturing is strictly preliminary evidence, never new Utility.
"""
from __future__ import annotations
from copy import deepcopy
from decimal import Decimal
from pathlib import Path
import hashlib
import json
import os
import re

from scripts import final128_381_task1_real_responses_capture_contract_v1 as wire
from scripts import final128_350_task1_responses_once_budget_v1 as budgeted
from scripts import final128_351_task1_durable_lease_preflight_v1 as consent

SCHEMA="veritas.final128.task1.first-two-https-capture-transport.v1"
ARMS=("A","B")
PATH="/v1/responses"
HOST="api.openai.com"
MAX_FIRST_REQUEST_BYTES=4096
MAX_RESPONSE_BYTES=96_000
MAX_HTTP_REQUEST_ID=160
ESTIMATE_ONLY_MAX_FIRST_TWO_USD=Decimal("1.00")
REQUEST_RE=re.compile(r"^task1-382-([AB])-([1-9][0-9]{5,19})$")
CONSUMED_REF="refs/tags/final128-task1-first-two-real-responses-v1-consumed"

class Blocked(RuntimeError):pass

def need(condition,reason):
    if condition is not True:raise Blocked("382_"+reason)

def digest_bytes(value:bytes)->str:
    return hashlib.sha256(value).hexdigest()

def prepare_two_first_packets():
    src=wire.propose_first_paired_packets()
    requests={a:src["arm_"+a+"_first_wire"] for a in ARMS}
    need(requests["A"]==requests["B"]
         and requests["A"] is not requests["B"]
         and len(wire.canonical(requests["A"]))<=MAX_FIRST_REQUEST_BYTES,
         "PAIRED_SOURCE_PARITY")
    return {
        "schema":SCHEMA,"case_id":wire.guard.CASE,
        "model":budgeted.MODEL,
        "arms":{a:{"original_wire_sha256":wire.sha(requests[a]),
                   "first_request_bytes":len(wire.canonical(requests[a])),
                   "external_provider_request_sent":False,
                   "real_provider_origin_verified":False} for a in ARMS},
        "same_initial_request_bytes":True,
        "max_first_two_provider_attempts_proposed":2,
        "max_output_tokens":budgeted.MAX_OUTPUT_TOKENS,
        "local_budget_reserved_max_usd_for_2_calls":str(
            2 * budgeted.reserved_max_usd()/budgeted.MAX_CALLS_TOTAL),
        "project_hard_spend_stop_verified":False,
        "new_operator_approval_verified":False,
        "consumed_protected_global_lease":False,
        "protected_runner_installed":False,
        "genuine_model_response_observed":False,
        "native_scorer_allowed":False,
        "live_dispatch_authorized":False,
    }

def _durable_append(logpath:Path,event:dict):
    """Durably append nonsecret event before attempted provider I/O."""
    need(type(logpath) is Path and logpath.parent.is_dir()
         and type(event) is dict
         and "api_key" not in str(event).lower()
         and "authorization" not in str(event).lower(),
         "LOCAL_JOURNAL_PATH_OR_SECRET_REFUSED")
    with logpath.open("a",encoding="utf8") as f:
        os.chmod(logpath,0o600)
        f.write(json.dumps(event,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n")
        f.flush()
        os.fsync(f.fileno())

def _read_journal(path:Path):
    if not path.exists():return []
    try:
        with path.open("r",encoding="utf8") as f:
            values=[json.loads(line) for line in f if line.strip()]
        need(all(type(i) is dict for i in values),"JOURNAL_BAD_RECORD")
        return values
    except (UnicodeError,ValueError) as exc:
        raise Blocked("382_MALFORMED_OR_AMBIGUOUS_JOURNAL") from exc

def _request(*,arm,run_id,request,api_key,conn):
    """Single raw HTTPS request using a caller-owned connection object.

    No auto-retry in this module. The caller must establish/verify TLS itself:
    an injected connection object (even one with a response-id) is NOT
    authentication evidence. No real transport factory is exposed here.
    """
    need(arm in ARMS and type(run_id) is str
         and consent.RUN_RE.fullmatch(run_id) is not None,
         "ARM_OR_RUN_INVALID")
    need(type(request) is dict and request==wire.first_real_wire_packet(),
         "FIRST_REQUEST_NOT_FROZEN")
    need(type(api_key) is str and len(api_key)>=21
         and not any(c.isspace() for c in api_key),
         "NO_INJECTED_CREDENTIAL")
    need(conn is not None
         and callable(getattr(conn,"request",None))
         and callable(getattr(conn,"getresponse",None))
         and callable(getattr(conn,"close",None)),
         "OWNED_CONNECTION_REQUIRED")
    data=wire.canonical(request)
    need(len(data)<=MAX_FIRST_REQUEST_BYTES,"FIRST_WIRE_BYTES_EXCEED_CAP")
    req_id=f"task1-382-{arm}-{run_id}"
    need(REQUEST_RE.fullmatch(req_id) is not None,"BOUND_CLIENT_REQUEST_ID")
    headers={
        "Authorization":"Bearer "+api_key,
        "Content-Type":"application/json",
        "X-Client-Request-Id":req_id,
        "User-Agent":"veritas-task1-first-two-presend-v1",
    }
    try:
        conn.request("POST",PATH,body=data,headers=headers)
        response=conn.getresponse()
        status=getattr(response,"status",None)
        rid=response.getheader("x-request-id")
        body=response.read(MAX_RESPONSE_BYTES+1)
        need(type(body) is bytes and len(body)<=MAX_RESPONSE_BYTES,
             "RESPONSE_TOO_LARGE_UNKNOWN_NO_RETRY")
        # No second call, retry or continue after bad status/response.
        need(type(status) is int and status==200,"HTTP_NON200_UNKNOWN_NO_RETRY")
        need(type(rid) is str and len(rid)<=MAX_HTTP_REQUEST_ID
             and wire.ID_RE.fullmatch(rid) is not None,
             "MISSING_SERVER_REQUEST_ID_UNKNOWN_NO_RETRY")
        # #381 deliberately labels ANY untrusted capture untrusted.
        # Even from our test fake, no capability or scorer entitlement emerges.
        capture=wire.parse_untrusted_first_capture(
            arm=arm,submitted_first_request=request,
            raw_http_response_body=body,asserted_http_status=status,
            asserted_x_request_id=rid,
            claimed_capture_source="UNTRUSTED_OFFLINE_FIXTURE")
        return {
            "arm":arm,"transport_adapter_sent_exactly_once":True,
            "request_sha256":digest_bytes(data),
            "response_raw_sha256":digest_bytes(body),
            "request_id_sha256":wire.sha(req_id),
            "server_header_request_id_sha256":wire.sha(rid),
            "model_response_id_sha256":capture["response_id_sha256"],
            "model_call_id_sha256":capture["model_call_id_sha256"],
            "usage_from_untrusted_json":deepcopy(wire.strict_json_bytes(body)["usage"]),
            "untrusted_captured_function_call":capture["first_response_function_call_item"],
            "response_id":capture["response_id"],
            "function_call_id":capture["model_call_id"],
            "http_response_header_origin_authenticated_by_module":False,
            "source_issuer_lease_authenticated_by_module":False,
            "official_native_scorer_eligible":False,
        }
    finally:
        conn.close()

def offline_two_arm_transport_rehearsal(*,conn_factory,run_id,folder):
    """Exercise real one-attempt POST protocol using only caller test transports.

    This public rehearsal can POST to injected objects. It has no credentials,
    network endpoint builder, globally consumed lease, provider TLS provenance,
    official scored result, or authority to run a genuine experiment.
    """
    need(callable(conn_factory)
         and type(run_id) is str
         and consent.RUN_RE.fullmatch(run_id) is not None,
         "OFFLINE_CONNECTION_FACTORY_AND_RUN_REQUIRED")
    directory=Path(folder)
    need(directory.is_dir(),"EVIDENCE_DIRECTORY_MISSING")
    log=directory/"final128-382-local-only-journal.jsonl"
    need(not log.exists(),"EXISTING_LOCAL_JOURNAL_NO_RETRY")
    first=prepare_two_first_packets()
    need(first["live_dispatch_authorized"] is False
         and first["consumed_protected_global_lease"] is False,
         "OFFLINE_MUST_NOT_MINT_AUTHORITY")
    per=budgeted.reserved_max_usd()/budgeted.MAX_CALLS_TOTAL
    reserve=Decimal("0")
    count=0
    results={}
    seen=set()
    _durable_append(log,{"phase":"OFFLINE_START",
        "run_id":run_id,"external_approval":False,"durable_lease":False,
        "real_provider_permission":False})
    for arm in ARMS:
        req=wire.first_real_wire_packet()
        reserve+=per
        need(reserve<=ESTIMATE_ONLY_MAX_FIRST_TWO_USD,
             "TWO_CALL_LOCAL_RESERVATION_OVER_LIMIT")
        _durable_append(log,{"phase":"BEFORE_MOCK_POST_CONSUMED",
            "arm":arm,"request_sha256":wire.sha(req),
            "attempt_ordinal":count+1,"no_retry":True})
        count+=1
        try:
            conn=conn_factory(arm)
            outcome=_request(arm=arm,run_id=run_id,request=req,
                api_key="offline-not-valid-382-mock-credentials-only",
                conn=conn)
            need(outcome["response_id"] not in seen,"CROSS_ARM_RESPONSE_ID_REUSE")
            seen.add(outcome["response_id"])
            _durable_append(log,{"phase":"MOCK_RESPONSE_CAPTURED",
                "arm":arm,"response_sha256":outcome["response_raw_sha256"],
                "server_request_header_sha256":outcome["server_header_request_id_sha256"],
                "untrusted_provider_origin":True,
                "native_scoring_eligible":False})
            results[arm]=outcome
        except BaseException as exc:
            _durable_append(log,{"phase":"UNKNOWN_AFTER_POST_STOP",
                "arm":arm,"error_type":type(exc).__name__,
                "no_retry":True})
            raise
    need(count==2 and len(results)==2
         and results["A"]["function_call_id"]!=results["B"]["function_call_id"]
         and results["A"]["server_header_request_id_sha256"]!=
             results["B"]["server_header_request_id_sha256"],
         "CROSS_ARM_CAPTURE_COLLISION_OR_INCOMPLETE")
    _durable_append(log,{"phase":"TWO_MOCK_CAPTURES_COMPLETE",
        "total_mock_attempts":2,"genuine_provider_capture_proven":False,
        "official_native_scores":None})
    return {
        "schema":SCHEMA,
        "status":"TWO_LOCAL_TRANSPORT_CAPTURES_NO_REAL_PROVIDER",
        "run_id":run_id,"first_request_sha256":wire.sha(wire.first_real_wire_packet()),
        "A_raw_response_sha256":results["A"]["response_raw_sha256"],
        "B_raw_response_sha256":results["B"]["response_raw_sha256"],
        "A_call_id_sha256":results["A"]["model_call_id_sha256"],
        "B_call_id_sha256":results["B"]["model_call_id_sha256"],
        "A_server_request_header_sha256":results["A"]["server_header_request_id_sha256"],
        "B_server_request_header_sha256":results["B"]["server_header_request_id_sha256"],
        "local_attempts_consumed_no_retry":2,
        "local_reserved_estimate_usd_not_billed":str(reserve),
        "real_provider_calls_confirmed":0,
        "real_provider_tls_origin_verified":False,
        "externally_issued_lease_consumed":False,
        "new_operator_consent_verified":False,
        "production_credential_or_egress_control_verified":False,
        "real_native_tool_executions":0,
        "official_native_scorer_invocations":0,
        "official_utility_or_attack_scores":None,
        "first_model_responses_alone_not_benchmark":True,
    }

def protected_live_dispatch_gate(*_args,**_kwargs):
    """No operator-text, mock receipt, or self-reported tag can unlock send."""
    raise Blocked("382_NO_FRESH_EXTERNAL_ISSUER_PROTECTED_CREDENTIAL_OR_CONSUMED_REF")
