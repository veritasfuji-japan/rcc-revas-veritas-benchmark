"""#341: exact source, isolated separately signed synthetic trust, CDA/EI no-effect proof."""
import copy,os,socket,hashlib,json
from pathlib import Path
import pytest
from scripts import final128_341_rcc_signed_test_mandate_native_promotion_v1 as m

@pytest.fixture(autouse=True)
def exclude_network_and_credentials(monkeypatch):
    def no(*args,**kwargs):pytest.fail("341_EXTERNAL_NETWORK_FORBIDDEN")
    monkeypatch.setattr(socket.socket,"connect",no)
    monkeypatch.setattr(socket.socket,"connect_ex",no)
    for name in m.r337.BANNED_KEYS:monkeypatch.delenv(name,raising=False)

@pytest.fixture(scope="module")
def proof():
    rcc=os.environ.get("FINAL128_341_RCC_ROOT")
    osroot=os.environ.get("FINAL128_341_VERITAS_ROOT")
    if not rcc or not osroot:
        pytest.skip("run only under exact-source dedicated CI")
    m.r339.verify_os(Path(osroot),
        m.r339.contract_check(m.r338.read_json(m.r339.CONTRACT_PATH)))
    m.r337.verify_source(Path(rcc),
        m.r337.validate_contract(m.r337.load_json(m.r337.CONTRACT)))
    result=m.read(m.OUT/"report.json")
    assert m.validate_report(result)
    return result

def test_static_trusted_test_mandate_cannot_auto_grant_real_world_authority():
    c=m.contract_check(m.read(m.CONTRACT))
    assert c["trusted_authority_in_real_deployment"] is False
    assert c["signed_mandate_test_only"] is True
    assert c["predeclared_test_mandate"]["source"]=="PREDECLARED_TEST_FIXTURE_NOT_RCC"
    assert c["predeclared_test_mandate"]["required_human_approval"] is True
    assert c["nonclaims"]["human_approval_receipt_issued"]==0

@pytest.mark.parametrize("field,value",[
 ("trusted_authority_in_real_deployment",True),
 ("signed_mandate_test_only",False),
 ("native_promotion_packet_must_verify",False),
 ("base_main_sha","substitution"),
])
def test_contract_pin_tamper_is_refused(field,value):
    c=m.read(m.CONTRACT);c[field]=value
    with pytest.raises(m.Refused,match="341_SOURCE_OR_TRUST_POLICY_DRIFT"):
        m.contract_check(c)

@pytest.mark.parametrize("field,value",[
 ("live_provider_calls",1),
 ("external_effects",1),
 ("bind_invocations",1),
 ("native_v2_authorization_issued",1),
 ("native_authorization_consumed",1),
 ("human_approval_receipt_issued",1),
 ("production_authority_proven",True),
 ("real_world_trust_proven",True),
 ("independent_model_choice_proven",True),
 ("new_final128_scores",128),
])
def test_unproven_operational_claims_rejected(field,value):
    c=m.read(m.CONTRACT);c["nonclaims"][field]=value
    with pytest.raises(m.Refused,match="341_SOURCE_OR_TRUST_POLICY_DRIFT"):
        m.contract_check(c)

def test_pinned_source_case_is_predeclared_and_not_synthesized(proof):
    source=m.read(m.OUT/"original-rcc-request.json")
    candidate=source["context"]["rcc_revas"]["candidate"]
    action=m.verify_declared_action(candidate,m.read(m.CONTRACT)["predeclared_test_mandate"])
    assert set(action)==set(m.ACTION_KEYS)
    assert proof["observed"]["source_typed_action_sha256"]==m.digest(action)
    assert proof["observed"]["source_original_candidate_sha256"]==m.digest(candidate)
    assert proof["case_id"]
    assert proof["case_counts"]["registered"]==36
    assert proof["case_counts"]["prepared"]+proof["case_counts"]["withheld"]==36

def test_native_observations_are_actual_route_and_exact_lineage(proof):
    x=proof["observed"]
    assert x["native_http_route_observed"] is True
    assert x["native_kernel_observed"] is True
    assert x["native_cda_verified"] is True
    assert x["native_cda_selected_action_matches_candidate"] is True
    assert x["native_candidate_hash"]==x["native_cda_selected_action_hash"]
    assert x["native_policy_snapshot_evidence_present"] is True
    assert x["native_intent_decision_lineage_exact"] is True
    assert x["native_intent_schema_promotion"] is True
    assert x["native_exact_promotion_packet_verified"] is True

def test_signed_test_mandate_not_operational_authority(proof):
    x=proof["observed"]
    assert x["test_mandate_signature_verified"] is True
    assert x["tamper_test_mandate_rejected"] is True
    assert x["tamper_rcc_action_rejected"] is True
    assert x["untrusted_candidate_fail_closed"] is True
    assert x["untrusted_rcc_post_cda_promotion_refused"] is True
    assert x["human_approval_required_not_granted"] is True
    assert x["operational_execution_authority_proven"] is False
    assert x["external_effects"]==0
    assert proof["scope"]["native_v2_authorization_issued"]==0
    assert proof["scope"]["bind_invocations"]==0

@pytest.mark.parametrize("key,value",[
 ("native_cda_verified",False),
 ("native_exact_promotion_packet_verified",False),
 ("native_cda_selected_action_matches_candidate",False),
 ("test_mandate_signature_verified",False),
 ("untrusted_candidate_fail_closed",False),
 ("human_approval_required_not_granted",False),
 ("operational_execution_authority_proven",True),
 ("external_effects",1),
])
def test_forged_proof_never_verifies(proof,key,value):
    r=copy.deepcopy(proof)
    r["observed"][key]=value
    with pytest.raises(m.Refused,match="341_SYNTHETIC_TEST_CDA_OR_NATIVE_PROMOTION_PROOF_INVALID"):
        m.validate_report(r)

def test_source_tamper_refused_at_trusted_mapping_boundary(proof):
    req=m.read(m.OUT/"original-rcc-request.json")
    cand=req["context"]["rcc_revas"]["candidate"]
    altered=copy.deepcopy(cand)
    altered["typed_action"]["canonical_action"]="inject_admin_access"
    with pytest.raises(m.Refused,match="341_RCC_ACTION_NOT_PREDECLARED_TRUST_SCOPE"):
        m.verify_declared_action(altered,m.read(m.CONTRACT)["predeclared_test_mandate"])

def test_missing_action_or_extra_metadata_refused(proof):
    req=m.read(m.OUT/"original-rcc-request.json")
    raw=req["context"]["rcc_revas"]["candidate"]
    altered=copy.deepcopy(raw)
    altered["typed_action"]["unauthorized"]="x"
    with pytest.raises(m.Refused,match="341_ACTION_EXTRA_OR_MISSING_FIELDS"):
        m.action_from_source(altered)

def test_report_digest_and_no_paid_api(proof):
    p=copy.deepcopy(proof)
    recorded=p.pop("report_sha256")
    assert recorded==m.digest(p)
    assert p["scope"]["live_provider_calls"]==0
    assert p["scope"]["external_effects"]==0
    assert p["trusted_environment_kind"]=="SYNTHETIC_EPHEMERAL_SIGNED_TEST_FIXTURE_NOT_REAL_WORLD_AUTHORITY"
