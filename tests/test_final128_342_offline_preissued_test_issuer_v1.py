"""#342 offline issuer verifier tests: pinned root, no in-run signature creation."""
from __future__ import annotations
import base64
from copy import deepcopy
from datetime import datetime,UTC,timedelta
import hashlib,json,os,socket
from pathlib import Path
import pytest
from scripts import final128_342_offline_preissued_test_issuer_verifier_v1 as m

@pytest.fixture(autouse=True)
def deny_external_network_and_credentials(monkeypatch):
    def fail(*args,**kwargs):pytest.fail("342_EXTERNAL_NETWORK_FORBIDDEN")
    monkeypatch.setattr(socket.socket,"connect",fail)
    monkeypatch.setattr(socket.socket,"connect_ex",fail)
    for name in m.r337.BANNED_KEYS:monkeypatch.delenv(name,raising=False)

@pytest.fixture
def c():
    return m.contract_check(m.unique_json(m.CONTRACT))

@pytest.fixture
def voucher():
    return m.unique_json(m.VOUCHER)

@pytest.fixture(scope="module")
def proof():
    rcc=os.environ.get("FINAL128_342_RCC_ROOT")
    osroot=os.environ.get("FINAL128_342_VERITAS_ROOT")
    if not rcc or not osroot:
        pytest.skip("dedicated exact-source CI is required for integrated proof")
    m.r339.verify_os(Path(osroot),
        m.r339.contract_check(m.r338.read_json(m.r339.CONTRACT_PATH)))
    m.r337.verify_source(Path(rcc),
        m.r337.validate_contract(m.r337.load_json(m.r337.CONTRACT)))
    report=m.unique_json(m.OUT/"report.json")
    assert m.verify_report(report)
    return report

def test_offline_issuer_public_key_pinned_and_key_not_embedded(c,voucher):
    assert c["issuer_key_private_in_repo"] is False
    assert len(m.decoded(c["trust_anchor_public_key_b64"]))==32
    assert hashlib.sha256(m.decoded(c["trust_anchor_public_key_b64"])).hexdigest()==m.PUBLIC_SHA
    assert set(voucher)=={"payload","signature_b64","signature_algorithm","issuer_key_id"}
    assert not any("private" in k or "secret" in k for k in voucher)
    assert m.hash_json(voucher)==m.VOUCHER_SHA

def test_preissued_signature_succeeds_from_pinned_root(c,voucher):
    result=m.verify_voucher(voucher,c)
    assert result["signature_verified"] is True
    assert result["trust_anchor_pinned"] is True
    assert result["issuer_private_key_loaded"] is False
    assert result["voucher_sha256"]==m.VOUCHER_SHA

@pytest.mark.parametrize("key,value",[
    ("trust_anchor_public_key_b64","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
    ("trust_anchor_public_key_sha256","0"*64),
    ("issuer_id","attacker-controlled-issuer"),
    ("frozen_signature_sha256","0"*64),
    ("frozen_voucher_sha256","0"*64),
    ("case_id","fixture:other"),
    ("issuer_key_private_in_repo",True),
    ("base_main_sha","0"*40),
])
def test_contract_and_trust_anchor_cannot_be_replaced(c,key,value):
    mutated=deepcopy(c);mutated[key]=value
    with pytest.raises(m.Refused,match="342_TRUST_ANCHOR_OR_SCOPE_CHANGED"):
        m.contract_check(mutated)

@pytest.mark.parametrize("field,value",[
    ("real_world_authority",True),
    ("test_only",False),
    ("independent_legal_issuer",True),
    ("allow_voucher_reissue_in_ci",True),
    ("never_accept_embedded_candidate_public_keys",False),
])
def test_no_claim_or_reissuer_override(c,field,value):
    mutated=deepcopy(c);mutated["guardrails"][field]=value
    with pytest.raises(m.Refused):
        m.contract_check(mutated)

@pytest.mark.parametrize("field,value",[
    ("production_authority_proven",True),
    ("real_enterprise_issuer_proven",True),
    ("human_approval_receipts",1),
    ("native_v2_authorizations",1),
    ("real_external_effects",1),
])
def test_unproven_execution_claims_fail_closed(c,field,value):
    mutated=deepcopy(c);mutated["nonclaims"][field]=value
    with pytest.raises(m.Refused):
        m.contract_check(mutated)

def test_payload_change_fails_signature_even_if_frozen_digest_guard_disabled(c,voucher):
    forged=deepcopy(voucher)
    forged["payload"]["case_id"]="fixture:forged-elsewhere"
    key=m.decoded(c["trust_anchor_public_key_b64"])
    with pytest.raises(m.Refused,match="342_OFFLINE_ISSUER_SIGNATURE_INVALID"):
        m.signature_only_verify(forged,key)

def test_signature_tamper_fails_even_without_digest_guard(c,voucher):
    forged=deepcopy(voucher)
    sig=bytearray(m.decoded(forged["signature_b64"]))
    sig[0] ^= 1
    forged["signature_b64"]=base64.b64encode(sig).decode()
    with pytest.raises(m.Refused,match="342_OFFLINE_ISSUER_SIGNATURE_INVALID"):
        m.signature_only_verify(forged,m.decoded(c["trust_anchor_public_key_b64"]))

@pytest.mark.parametrize("change",[
    ("issuer_id","attacker"),("issuer_key_id","another-issuer"),
    ("audience","other-service"),("case_id","fixture:other"),
    ("purpose","production-permit"),("expires_at","2035-01-01T00:00:00Z"),
])
def test_substituted_voucher_identity_rejected(c,voucher,change):
    key,value=change
    mutated=deepcopy(voucher)
    mutated["payload"][key]=value
    with pytest.raises(m.Refused,match="342_VOUCHER_ISSUER_OR_ACTION_SCOPE_MISMATCH"):
        m.verify_voucher(mutated,c)

def test_embedded_candidate_key_or_extra_evidence_rejected(c,voucher):
    modified=deepcopy(voucher)
    modified["candidate_supplied_trusted_public_key"]="AAAAAAAA"
    with pytest.raises(m.Refused,match="342_VOUCHER_EXTRA_OR_MISSING_KEYS"):
        m.verify_voucher(modified,c)

def test_changed_action_and_scope_not_accepted(c,voucher):
    for field,val in [("target_resource","user:attacker"),
                      ("canonical_action","delete_audit_log"),
                      ("requested_scope",["role:superuser"])]:
        mutated=deepcopy(voucher)
        mutated["payload"]["mandate"][field]=val
        with pytest.raises(m.Refused):
            m.verify_voucher(mutated,c)

def test_expired_and_future_vouchers_refused(c,voucher):
    before=m.when(voucher["payload"]["not_before"])-timedelta(seconds=1)
    after=m.when(voucher["payload"]["expires_at"])
    for at in (before,after):
        with pytest.raises(m.Refused,match="342_VOUCHER_NOT_YET_VALID_OR_EXPIRED"):
            m.verify_voucher(voucher,c,at=at)

def test_offline_invalid_signature_with_changed_key(c,voucher):
    wrong=b"\\x00"*32
    with pytest.raises(m.Refused,match="342_OFFLINE_ISSUER_SIGNATURE_INVALID"):
        m.signature_only_verify(voucher,wrong)

def test_real_rcc_case_bound_to_signer_source_not_other_case(proof,c,voucher):
    raw=m.unique_json(m.OUT/"original-rcc-request.json")
    source=raw["context"]["rcc_revas"]["candidate"]
    assert source["candidate_id"]=="candidate:"+m.EXPECTED_CASE
    assert proof["case_id"]==m.EXPECTED_CASE
    assert m.verify_voucher(voucher,c,source)["signature_verified"]
    forged=deepcopy(source)
    forged["candidate_id"]="candidate:another-released-case"
    with pytest.raises(m.Refused,match="342_VOUCHER_SOURCE_CANDIDATE_ID_MISMATCH"):
        m.verify_voucher(voucher,c,forged)

def test_actual_native_candidate_source_and_signed_fixture_match(proof):
    x=proof["observation"]
    raw=m.unique_json(m.OUT/"original-rcc-request.json")
    assert m.hash_json(raw)==x["origin_request_sha256"]
    assert m.hash_json(raw["context"]["rcc_revas"]["candidate"])==x["original_rcc_candidate_sha256"]
    assert x["rcc_candidate_semantic_hash"]==raw["context"]["rcc_revas"]["candidate_semantic_hash"]
    assert x["original_action_identity_preserved"] is True
    assert x["native_schema_candidate_promotable_for_test"] is True
    assert len(x["native_candidate_sha256"])==64
    assert x["untrusted_without_voucher_refused"] is True

def test_no_native_authorization_or_effect_claimed(proof):
    x=proof["observation"]
    assert x["actual_cda_created_in_this_pr"] is False
    assert x["actual_execution_intent_created_in_this_pr"] is False
    assert x["real_issuer_authentication_proven"] is False
    assert x["native_bind_invoked"] is False
    assert x["human_approval_requirement_not_receipt"] is True
    assert proof["nonclaims"]["live_provider_calls"]==0
    assert proof["nonclaims"]["real_external_effects"]==0

@pytest.mark.parametrize("field,value",[
    ("signature_verified",False),("trust_anchor_pinned",False),
    ("issuer_private_key_loaded",True),
    ("native_schema_candidate_promotable_for_test",False),
    ("actual_cda_created_in_this_pr",True),
    ("real_external_effects",1),
])
def test_false_evidence_does_not_pass(proof,field,value):
    modified=deepcopy(proof)
    modified["observation"][field]=value
    with pytest.raises(m.Refused,match="342_OFFLINE_ISSUER_TRUST_OR_SCOPE_PROOF_MISSING"):
        m.verify_report(modified)

def test_report_digest_and_source_count(proof):
    p=deepcopy(proof)
    recorded=p.pop("report_sha256")
    assert recorded==m.hash_json(p)
    assert proof["case_counts"]["registered"]==36
    assert proof["case_counts"]["prepared"]+proof["case_counts"]["withheld"]==36
