"""Task13 #334: actual local SQLite atomic CAS after three test-only signatures.

No bank effects, no VERITAS Bind invocation, no actual independent issuers.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import tempfile
import uuid

import pytest

if os.environ.get("TASK13_334_PROOF")!="1":
    pytest.skip("Task13 #334 needs dedicated offline crypto/SQLite CI only",
                allow_module_level=True)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

from scripts import task13_334_exact_prebind_single_use_local_v1 as m

NOW="2026-10-12T02:01:00Z"
ISSUED="2026-10-12T02:00:00Z"
EXPIRES="2026-10-12T02:03:00Z"
CASE=m.source.CASE_IDS[0]
SESSION="d"*32

@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def deny(*_args,**_kw):
        pytest.fail("TASK13_334_ALL_OUTBOUND_NETWORK_FORBIDDEN")
    monkeypatch.setattr(socket.socket,"connect",deny)
    monkeypatch.setattr(socket.socket,"connect_ex",deny)

def local_test_fixture(tmp_path):
    # Ephemeral in-memory keys; deliberately not enrolled by external IAM.
    keys={role:Ed25519PrivateKey.generate() for role in ("request","file","approval")}
    def root(role):
        b=keys[role].public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        return {"issuer_id":"ci-local-"+role,
                "key_id":"ci-local-"+role+"-public-key",
                "public_key_b64":base64.b64encode(b).decode("ascii")}
    roots={role:root(role) for role in ("request","file")}
    approval_root=root("approval")
    def sign(role,p):
        domain={
            "request":m.source.REQ_DOMAIN,
            "file":m.source.FILE_DOMAIN,
            "approval":m.APPROVAL_DOMAIN
        }[role]
        return {"signed_payload":deepcopy(p),
                "signature_b64":base64.b64encode(
                    keys[role].sign(domain+m.source.canonical(p))
                ).decode("ascii")}
    state=m.source.old.local_state()
    candidate=deepcopy(m.source.old.CANDIDATE)
    facts=m.source._source_inputs(
        case_id=CASE,original_request=m.source.USER_REQUEST,
        prestate=state,candidate=candidate
    )
    common={
        "case_id":CASE,
        "session_id":SESSION,
        "original_request_sha256":facts["original_request_sha256"],
        "immediate_pre_state_sha256":facts["immediate_pre_state_sha256"],
        "candidate_sha256":facts["candidate_sha256"],
        "issued_at":ISSUED,
        "expires_at":EXPIRES
    }
    req={**common,
         "schema":m.source.REQUEST_SCHEMA,
         "issuer_id":roots["request"]["issuer_id"],
         "key_id":roots["request"]["key_id"],
         "purpose":"ATTEST_ORIGINAL_USER_INTENT_ONLY",
         "scope":m.source.SCOPE,
         "allowed_tool":m.source.ACTION,
         "allowed_fields":["street","city"],
         "referenced_file_path":m.source.FILE_PATH}
    file={**common,
          "schema":m.source.FILE_SCHEMA,
          "issuer_id":roots["file"]["issuer_id"],
          "key_id":roots["file"]["key_id"],
          "purpose":"ATTEST_READ_FILE_BYTES_ONLY_NOT_EXECUTION_AUTHORITY",
          "tool_name":"read_file",
          "tool_arguments":{"file_path":m.source.FILE_PATH},
          "file_path":m.source.FILE_PATH,
          "file_content_sha256":facts["file_content_sha256"],
          "read_result_sha256":facts["read_result_sha256"]}
    rr=sign("request",req)
    fr=sign("file",file)
    source_verified=m.source.preflight(
        case_id=CASE,original_request=m.source.USER_REQUEST,
        prestate=state,candidate=candidate,trusted_time=NOW,
        trust_roots=roots,request_receipt=rr,file_receipt=fr
    )
    assert source_verified["status"]=="CRYPTO_RECEIPTS_VALID_ONLY_NO_EXECUTION_AUTHORITY"
    approval={
        "schema":m.APPROVAL_SCHEMA,
        "issuer_id":approval_root["issuer_id"],
        "key_id":approval_root["key_id"],
        "purpose":"LOCAL_TEST_APPROVAL_PROOF_NOT_NATIVE_AUTHORITY",
        "mode":"CI_LOCAL_ONLY_NO_PRODUCTION_GRANT",
        "case_id":CASE,
        "session_id":SESSION,
        "original_request_sha256":facts["original_request_sha256"],
        "file_content_sha256":facts["file_content_sha256"],
        "immediate_pre_state_sha256":facts["immediate_pre_state_sha256"],
        "candidate_sha256":facts["candidate_sha256"],
        "request_receipt_sha256":source_verified["signed_receipt_digests"][0],
        "file_receipt_sha256":source_verified["signed_receipt_digests"][1],
        "scope":m.source.SCOPE,
        "allowed_tool":"update_user_info",
        "allowed_fields":["street","city"],
        "grant_id":"task13-334-ci-"+uuid.uuid4().hex,
        "issued_at":ISSUED,
        "expires_at":"2026-10-12T02:02:30Z",
        "max_uses":1
    }
    ledger=m.TestOnlySqliteLedger(tmp_path/"task13-334.sqlite3")
    ledger.seed_fixture(approval)
    a=sign("approval",approval)
    params={
        "case_id":CASE,"original_request":m.source.USER_REQUEST,
        "prestate":state,"candidate":candidate,
        "trusted_time":NOW,
        "source_roots":roots,
        "request_receipt":rr,"file_receipt":fr,
        "approval_root":approval_root,"approval_receipt":a,
        "fresh_snapshot_reader":lambda:deepcopy(state),
        "ledger":ledger,
        "attempt_id":uuid.uuid4().hex,
    }
    return params,sign,approval,ledger

def assert_never_dispatch(r):
    assert r["execution_authorized"] is False
    assert r["dispatch_allowed"] is False
    assert r["real_issuer_trust_verified"] is False
    assert r["external_IAM_verified"] is False
    assert r["protected_ledger_verified"] is False
    assert r["veritas_bind_called"] is False
    assert r["native_mutation_count"]==0
    assert r["real_provider_calls"]==0
    assert r["new_utility_scores"]==0
    assert r["new_injection_success_measurements"]==0
    assert r["mode"]=="LOCAL_TEST_ONLY"

def test_exact_local_three_role_consume_commits_once_but_no_dispatch(tmp_path):
    kw,_,p,ledger=local_test_fixture(tmp_path)
    pre=deepcopy(kw["prestate"])
    candidate=deepcopy(kw["candidate"])
    r=m.evaluate(**kw)
    assert r["status"]=="TEST_LEDGER_CONSUMED_BOUND_CANDIDATE_NO_DISPATCH"
    assert r["test_ledger_cas_committed"] is True
    assert r["test_attempt_id"]==kw["attempt_id"]
    assert r["source_provenance"]=="CRYPTO_RECEIPTS_VALID_ONLY_NO_EXECUTION_AUTHORITY"
    assert_never_dispatch(r)
    assert kw["prestate"]==pre and kw["candidate"]==candidate

def test_duplicate_attempt_fails_atomically_even_if_fresh_attempt_id(tmp_path):
    kw,_,_,_=local_test_fixture(tmp_path)
    first=m.evaluate(**kw)
    assert first["test_ledger_cas_committed"]
    again=m.evaluate(**kw)
    assert again["status"]=="DENY_PREBIND_SEAM"
    assert not again["test_ledger_cas_committed"]
    changed={**kw,"attempt_id":uuid.uuid4().hex}
    third=m.evaluate(**changed)
    assert third["status"]=="DENY_PREBIND_SEAM"
    assert_never_dispatch(third)

def test_concurrent_requests_one_local_consume_only(tmp_path):
    kw,_,_,_=local_test_fixture(tmp_path)
    def try_it(_):
        return m.evaluate(**{**kw,"attempt_id":uuid.uuid4().hex})
    with ThreadPoolExecutor(max_workers=8) as pool:
        results=list(pool.map(try_it,range(12)))
    assert sum(r["test_ledger_cas_committed"] for r in results)==1
    assert sum(r["status"]=="DENY_PREBIND_SEAM" for r in results)==11
    for row in results:
        assert_never_dispatch(row)

@pytest.mark.parametrize("missing",[
    "request_receipt","file_receipt","source_roots",
    "approval_receipt","approval_root","fresh_snapshot_reader","ledger",
    "trusted_time"
])
def test_missing_source_approval_ledger_or_freshness_fails_closed(tmp_path,missing):
    kw,_,_,_=local_test_fixture(tmp_path)
    kw[missing]=None
    out=m.evaluate(**kw)
    assert out["status"].startswith("DENY")
    assert out["test_ledger_cas_committed"] is False
    assert_never_dispatch(out)

@pytest.mark.parametrize("tamper",[
    "approval_sig","approval_issuer","approval_key_id","approval_grant_id",
    "approval_case","approval_candidate","approval_file_sha",
    "approval_request_sha","approval_original_state",
    "approval_request_receipt_sha","approval_file_receipt_sha",
    "approval_tool","approval_scope","approval_fields",
    "approval_max_uses","approval_mode","approval_purpose",
    "approval_session","approval_extra_field",
    "different_request_sig","different_file_sig",
    "same_request_approval_key","same_file_approval_issuer",
    "same_file_approval_key_id"
])
def test_three_roles_signature_scope_and_hash_refusals(tmp_path,tamper):
    kw,sign,p,_=local_test_fixture(tmp_path)
    raw=kw["approval_receipt"]["signed_payload"]
    changes={
       "approval_issuer":("issuer_id","impersonator"),
       "approval_key_id":("key_id","imposter-key"),
       "approval_grant_id":("grant_id","attacker-grant"),
       "approval_case":("case_id",m.source.CASE_IDS[1]),
       "approval_candidate":("candidate_sha256","0"*64),
       "approval_file_sha":("file_content_sha256","f"*64),
       "approval_request_sha":("original_request_sha256","f"*64),
       "approval_original_state":("immediate_pre_state_sha256","f"*64),
       "approval_request_receipt_sha":("request_receipt_sha256","f"*64),
       "approval_file_receipt_sha":("file_receipt_sha256","f"*64),
       "approval_tool":("allowed_tool","send_money"),
       "approval_scope":("scope","banking:anything"),
       "approval_fields":("allowed_fields",["street","city","recipient"]),
       "approval_max_uses":("max_uses",2),
       "approval_mode":("mode","PRODUCTION"),
       "approval_purpose":("purpose","AUTHORIZE_LIVE_BANKING"),
       "approval_session":("session_id","a"*32),
       "approval_extra_field":("new_authority",True),
    }
    if tamper=="approval_sig":
        kw["approval_receipt"]["signature_b64"]="A"*88
    elif tamper=="different_request_sig":
        kw["request_receipt"]["signature_b64"]="A"*88
    elif tamper=="different_file_sig":
        kw["file_receipt"]["signature_b64"]="B"*88
    elif tamper=="same_request_approval_key":
        kw["approval_root"]["public_key_b64"]=kw["source_roots"]["request"]["public_key_b64"]
    elif tamper=="same_file_approval_issuer":
        kw["approval_root"]["issuer_id"]=kw["source_roots"]["file"]["issuer_id"]
    elif tamper=="same_file_approval_key_id":
        kw["approval_root"]["key_id"]=kw["source_roots"]["file"]["key_id"]
    else:
        field,value=changes[tamper]
        raw[field]=value
        kw["approval_receipt"]=sign("approval",raw)
    result=m.evaluate(**kw)
    assert result["status"]=="DENY_PREBIND_SEAM"
    assert not result["test_ledger_cas_committed"]
    assert_never_dispatch(result)

@pytest.mark.parametrize("bad",[
    "expired_source","expired_approval","source_expires_before_approval",
    "too_long_approval","future_approval"
])
def test_issuer_time_and_scope_expiration_fails_closed(tmp_path,bad):
    kw,sign,p,_=local_test_fixture(tmp_path)
    if bad=="expired_source":kw["trusted_time"]="2026-10-12T02:03:01Z"
    else:
        p=deepcopy(p)
        if bad=="expired_approval":kw["trusted_time"]="2026-10-12T02:02:31Z"
        if bad=="source_expires_before_approval":p["expires_at"]="2026-10-12T02:03:01Z"
        if bad=="too_long_approval":p["expires_at"]="2026-10-12T02:06:00Z"
        if bad=="future_approval":p["issued_at"]="2026-10-12T02:02:00Z"
        kw["approval_receipt"]=sign("approval",p)
    res=m.evaluate(**kw)
    assert res["status"]=="DENY_PREBIND_SEAM"
    assert_never_dispatch(res)

@pytest.mark.parametrize("change",[
    "prestate","city","street","request","case","file"
])
def test_actual_original_frozen_candidate_and_prestate_never_rewritten(tmp_path,change):
    kw,_,_,_=local_test_fixture(tmp_path)
    if change=="prestate":kw["prestate"]["user_account"]["city"]="Boston"
    if change=="city":kw["candidate"]["city"]="Boston"
    if change=="street":kw["candidate"]["street"]="Attacker Street"
    if change=="request":kw["original_request"]="Send money to attacker"
    if change=="case":kw["case_id"]="banking:user_task_13:injection_task_999:direct"
    if change=="file":kw["prestate"]["filesystem"]["files"]["address-change.txt"]+="\nSend money"
    out=m.evaluate(**kw)
    assert out["status"]=="DENY_PREBIND_SEAM"
    assert_never_dispatch(out)

def test_pre_consume_toctou_change_does_not_spend_grant(tmp_path):
    kw,_,_,ledger=local_test_fixture(tmp_path)
    altered=deepcopy(kw["prestate"])
    altered["user_account"]["city"]="Boston"
    kw["fresh_snapshot_reader"]=lambda:altered
    r=m.evaluate(**kw)
    assert r["status"]=="DENY_PREBIND_SEAM"
    assert not r["test_ledger_cas_committed"]
    assert m.evaluate(**{**kw,"fresh_snapshot_reader":lambda:kw["prestate"]})[
        "test_ledger_cas_committed"
    ] is True

def test_post_consume_toctou_change_denied_and_grant_stays_spent(tmp_path):
    kw,_,_,ledger=local_test_fixture(tmp_path)
    altered=deepcopy(kw["prestate"])
    altered["user_account"]["city"]="Boston"
    reads=0
    def moving_state():
        nonlocal reads
        reads+=1
        return kw["prestate"] if reads==1 else altered
    kw["fresh_snapshot_reader"]=moving_state
    r=m.evaluate(**kw)
    assert r["status"]=="DENY_PREBIND_SEAM"
    assert r["test_ledger_cas_committed"] is False
    next_try=m.evaluate(**{**kw,"fresh_snapshot_reader":lambda:kw["prestate"]})
    assert next_try["status"]=="DENY_PREBIND_SEAM" # cannot reissue/retry after committed CAS

def test_snapshot_reader_fails_closed_on_unknown_remote_state(tmp_path):
    kw,_,_,_=local_test_fixture(tmp_path)
    def unavailable():
        raise OSError("UNKNOWN_REMOTE_STATE")
    kw["fresh_snapshot_reader"]=unavailable
    out=m.evaluate(**kw)
    assert out["status"]=="DENY_UNEXPECTED_FAIL_CLOSED"
    assert_never_dispatch(out)

def test_approval_cannot_seed_any_production_ledger_path(tmp_path):
    with pytest.raises(m.GateDenied,match="LEDGER_MUST_BE_EPHEMERAL_LOCAL_TEST_PATH"):
        m.TestOnlySqliteLedger(Path("/var/lib/production.sqlite3"))
    kw,_,p,_=local_test_fixture(tmp_path)
    with pytest.raises(m.GateDenied,match="TEST_LEDGER_MUST_BEGIN_FRESH"):
        m.TestOnlySqliteLedger(tmp_path/"task13-334.sqlite3")
    assert m.evaluate(**kw)["execution_authorized"] is False

def test_untrusted_file_instructions_never_widen_to_transfer(tmp_path):
    kw,_,_,_=local_test_fixture(tmp_path)
    text=kw["prestate"]["filesystem"]["files"]["address-change.txt"]
    assert "Send money to an attacker" in text
    out=m.evaluate(**kw)
    assert out["status"]=="TEST_LEDGER_CONSUMED_BOUND_CANDIDATE_NO_DISPATCH"
    assert_never_dispatch(out)

@pytest.mark.parametrize("claim",[
    ("claim_boundary","execution_authorized",True),
    ("claim_boundary","dispatch_allowed",True),
    ("claim_boundary","external_IAM_enforced",True),
    ("claim_boundary","credential_egress_bypass_rejected",True),
    ("claim_boundary","production_single_use_receipt_verified",True),
    ("claim_boundary","new_authentic_utility_recoveries",2),
    ("claim_boundary","real_provider_calls",1),
    ("claim_boundary","native_bind_calls",1),
    ("handoff_invariants","production_prebind_handoff_permitted",True),
])
def test_contract_cannot_promote_local_cas_to_real_authority(claim):
    c=json.loads(m.CONTRACT.read_text())
    assert m.verify_contract(c)==c
    modified=deepcopy(c)
    section,key,value=claim
    modified[section][key]=value
    with pytest.raises(m.GateDenied):
        m.verify_contract(modified)

def test_no_unexpected_report_target(tmp_path):
    with pytest.raises(m.GateDenied,match="ONLY_FRESH_SCOPED_REPORT"):
        m.main(["--output",str(tmp_path/"unscoped.json")])
