"""#343: actual native CDA + EI packet from pinned offline issuer and original RCC."""
from __future__ import annotations
from copy import deepcopy
from datetime import timedelta
import os
from pathlib import Path
import socket
import pytest

from scripts import final128_343_offline_voucher_native_cda_promotion_v1 as m

@pytest.fixture(autouse=True)
def no_paid_api_or_external_network(monkeypatch):
    def denied(*args,**kwargs):
        pytest.fail("343_EXTERNAL_NETWORK_OR_PROVIDER_ACCESS_FORBIDDEN")
    monkeypatch.setattr(socket.socket,"connect",denied)
    monkeypatch.setattr(socket.socket,"connect_ex",denied)
    for key in m.r337.BANNED_KEYS:
        monkeypatch.delenv(key,raising=False)

@pytest.fixture
def contract():
    return m.contract_check(m.read(m.CONTRACT))

@pytest.fixture(scope="module")
def proof():
    upstream=os.environ.get("FINAL128_343_RCC_ROOT")
    osroot=os.environ.get("FINAL128_343_VERITAS_ROOT")
    if not upstream or not osroot:
        pytest.skip("dedicated exact pin source verifier CI required")
    m.r339.verify_os(Path(osroot),
        m.r339.contract_check(m.r338.read_json(m.r339.CONTRACT_PATH)))
    m.r337.verify_source(Path(upstream),
        m.r337.validate_contract(m.r337.load_json(m.r337.CONTRACT)))
    r=m.read(m.OUT/"report.json")
    assert m.verify_report(r)
    return r

def test_parent_pins_and_no_runtime_issuer_key(contract):
    assert contract["base_main_sha"]==m.MAIN
    assert contract["rcc_sha"]==m.r339.PIN_RCC
    assert contract["veritas_sha"]==m.r339.PIN_VERITAS
    assert contract["offline_voucher_sha256"]==m.r342.VOUCHER_SHA
    assert contract["offline_public_key_sha256"]==m.r342.PUBLIC_SHA
    assert contract["issuer_private_key_generated_in_ci"] is False
    assert contract["issuer_signature_generated_in_ci"] is False
    source=Path(m.__file__).read_text(encoding="utf-8")
    assert "Ed25519PrivateKey.generate(" not in source
    assert "sign_test_mandate(" not in source

@pytest.mark.parametrize("key,value",[
   ("base_main_sha","0"*40),
   ("rcc_sha","0"*40),
   ("veritas_sha","0"*40),
   ("source_case_id","fixture:other"),
   ("offline_voucher_sha256","0"*64),
   ("offline_public_key_sha256","0"*64),
   ("issuer_private_key_generated_in_ci",True),
   ("issuer_signature_generated_in_ci",True),
   ("controlled_model_transcript_only",False),
   ("never_treat_required_human_approval_as_granted",False),
])
def test_contract_source_and_issuer_mutations_fail(contract,key,value):
    altered=deepcopy(contract)
    altered[key]=value
    with pytest.raises(m.Refused,match="343_OFFLINE_TRUST_CONTRACT_OR_NONCLAIMS_DRIFT"):
        m.contract_check(altered)

@pytest.mark.parametrize("key,value",[
   ("real_external_provider_calls",1),
   ("real_external_effects",1),
   ("native_v2_authorizations_issued",1),
   ("native_v2_bind_calls",1),
   ("native_authorization_consumptions",1),
   ("real_human_approval_receipts",1),
   ("actual_production_authority",True),
   ("independent_business_issuer_verified",True),
   ("independent_model_choice_verified",True),
   ("official_final128_scores_recomputed",True),
])
def test_operational_authority_fabrication_forbidden(contract,key,value):
    altered=deepcopy(contract)
    altered["limits"][key]=value
    with pytest.raises(m.Refused,match="343_OFFLINE_TRUST_CONTRACT_OR_NONCLAIMS_DRIFT"):
        m.contract_check(altered)

def test_preissued_signature_is_verified_only_against_pinned_root(contract):
    c342=m.r342.contract_check(m.r342.unique_json(m.r342.CONTRACT))
    voucher=m.r342.unique_json(m.r342.VOUCHER)
    checked=m.r342.verify_voucher(voucher,c342)
    assert checked["signature_verified"] is True
    assert checked["issuer_private_key_loaded"] is False
    assert checked["voucher_sha256"]==contract["offline_voucher_sha256"]

def test_untrusted_candidate_cannot_supply_its_own_issuer_key(contract):
    altered=m.r342.unique_json(m.r342.VOUCHER)
    altered["trusted_public_key_from_rcc"]="attacker-key"
    with pytest.raises(m.r342.Refused,match="342_VOUCHER_EXTRA_OR_MISSING_KEYS"):
        m.r342.verify_voucher(altered,m.r342.unique_json(m.r342.CONTRACT))

def test_offline_expiry_is_hard_block(contract):
    c342=m.r342.unique_json(m.r342.CONTRACT)
    voucher=m.r342.unique_json(m.r342.VOUCHER)
    at=m.r342.when(voucher["payload"]["expires_at"])
    with pytest.raises(m.r342.Refused,match="342_VOUCHER_NOT_YET_VALID_OR_EXPIRED"):
        m.r342.verify_voucher(voucher,c342,at=at)

def test_actual_rcc_source_and_offline_voucher_are_same_action(proof,contract):
    req=m.read(m.OUT/"original-rcc-request.json")
    source=req["context"]["rcc_revas"]["candidate"]
    assert proof["case_id"]==contract["source_case_id"]
    assert m.digest(req)==proof["observed"]["original_request_sha256"]
    assert m.digest(source)==proof["observed"]["source_candidate_sha256"]
    assert m.digest(source["typed_action"])==proof["observed"]["source_typed_action_sha256"]
    assert m.r341.verify_declared_action(
        source,m.r342.unique_json(m.r342.CONTRACT)["mandate"]
    )==source["typed_action"]
    assert m.verified_voucher_for_source(source)["signature_verified"] is True

@pytest.mark.parametrize("field,value",[
    ("target_resource","user:attacker"),
    ("actor_identity","unknown-administrator"),
    ("canonical_action","delete_audit_logs"),
    ("requested_scope",["role:owner"]),
])
def test_origin_action_substitution_cannot_pass_offline_voucher(proof,field,value):
    req=m.read(m.OUT/"original-rcc-request.json")
    source=deepcopy(req["context"]["rcc_revas"]["candidate"])
    source["typed_action"][field]=value
    with pytest.raises(m.r341.Refused,match="341_RCC_ACTION_NOT_PREDECLARED_TRUST_SCOPE"):
        m.verified_voucher_for_source(source)

def test_offline_issuer_selected_real_route_and_ei_evidence(proof):
    x=proof["observed"]
    assert x["local_native_http_route_executed"]
    assert x["local_native_kernel_executed"]
    assert x["native_cda_verified"]
    assert x["native_cda_selected_action_verified"]
    assert x["native_execution_intent_schema_promotion"]
    assert x["native_execution_intent_decision_lineage_exact"]
    assert x["native_verified_promotion_packet"]
    assert x["native_candidate_hash"]==x["native_selected_action_candidate_hash"]
    assert x["native_candidate_hash"]==x["native_verified_promotion_candidate_hash"]
    assert x["native_cda_decision_hash"]
    assert x["native_verified_promotion_packet_hash"]
    assert x["synthetic_kms_sign_calls"]>0
    assert x["synthetic_worm_put_calls"]>0

def test_no_issuer_mint_or_external_effect_and_approval_not_granted(proof):
    x=proof["observed"]
    assert x["offline_signature_verified"]
    assert x["offline_issuer_private_key_used"] is False
    assert x["offline_issuer_signature_minted_at_runtime"] is False
    assert x["native_required_human_approval_not_granted"]
    assert x["untrusted_rcc_post_cda_refused"]
    assert x["tampered_native_candidate_post_cda_refused"]
    assert x["live_operator_authorization_proven"] is False
    assert x["real_external_effects"]==0
    assert proof["nonclaims"]["native_v2_authorizations_issued"]==0
    assert proof["nonclaims"]["native_v2_bind_calls"]==0

@pytest.mark.parametrize("field,value",[
   ("offline_signature_verified",False),
   ("offline_issuer_private_key_used",True),
   ("offline_issuer_signature_minted_at_runtime",True),
   ("native_cda_verified",False),
   ("native_cda_selected_action_verified",False),
   ("native_execution_intent_schema_promotion",False),
   ("native_verified_promotion_packet",False),
   ("untrusted_rcc_post_cda_refused",False),
   ("tampered_native_candidate_post_cda_refused",False),
   ("live_operator_authorization_proven",True),
   ("real_external_effects",1),
   ("native_candidate_hash","0"*64),
])
def test_forged_native_evidence_fails_closed(proof,field,value):
    altered=deepcopy(proof)
    altered["observed"][field]=value
    with pytest.raises(m.Refused,match="343_OFFLINE_RCCR_NATIVE_CDA_PROMOTION_PROOF_FAIL_CLOSED"):
        m.verify_report(altered)

def test_report_pin_sha256_and_case_accounting(proof):
    r=deepcopy(proof)
    expected=r.pop("report_sha256")
    assert expected==m.digest(r)
    assert proof["case_counts"]["registered"]==36
    assert proof["case_counts"]["prepared"]+proof["case_counts"]["withheld"]==36
    assert proof["issuer_trust_boundary"]=="PREISSUED_OFFLINE_AUTHOR_CONTROLLED_SYNTHETIC_FIXTURE_NOT_ENTERPRISE_AUTHORITY"
