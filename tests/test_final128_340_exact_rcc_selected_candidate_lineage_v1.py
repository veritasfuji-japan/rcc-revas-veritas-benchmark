"""#340 strict RCC exact option selection, native CDA, and no authority claims."""
from copy import deepcopy
import os
import socket
from pathlib import Path
import pytest
from scripts import final128_340_exact_rcc_selected_candidate_lineage_v1 as m

@pytest.fixture(autouse=True)
def no_external_network_or_credentials(monkeypatch):
    def reject(*args,**kwargs):pytest.fail("340_EXTERNAL_NETWORK_NOT_PERMITTED")
    monkeypatch.setattr(socket.socket,"connect",reject)
    monkeypatch.setattr(socket.socket,"connect_ex",reject)
    for key in m.r337.BANNED_KEYS:monkeypatch.delenv(key,raising=False)

@pytest.fixture(scope="module")
def proof():
    source=os.environ.get("FINAL128_340_UPSTREAM_ROOT")
    osroot=os.environ.get("FINAL128_340_VERITAS_ROOT")
    if not source or not osroot:
        pytest.skip("dedicated frozen RCC+VERITAS source CI required")
    c=m.contract_check(m.read(m.CONTRACT))
    m.r339.verify_os(Path(osroot),
       m.r339.contract_check(m.r338.read_json(m.r339.CONTRACT_PATH)))
    m.r337.verify_source(Path(source),
       m.r337.validate_contract(m.r337.load_json(m.r337.CONTRACT)))
    r=m.read(m.OUT/"report.json")
    assert m.verify_report(r)
    return r

def test_pinned_source_contract_and_historical_boundary():
    c=m.contract_check(m.read(m.CONTRACT))
    assert c["parent_main_sha"]==m.BEN
    assert c["source_upstream_rcc_sha"]==m.r339.PIN_RCC
    assert c["source_veritas_os_sha"]==m.r339.PIN_VERITAS
    assert not c["origin_candidate_mutation"]
    assert not c["nonclaims"]["actual_native_execution_intent_proven"]
    assert c["historical_v13"]=={"arm_a_utility":93,"arm_b_utility":64,
                                 "arm_b_injection_success":0}

@pytest.mark.parametrize("key,value",[
    ("real_model_calls",1),("native_bind_invocations",1),
    ("native_authorization_issuance",1),("native_authorization_consumption",1),
    ("actual_native_execution_intent_proven",True),
    ("independent_model_selection_proven",True),
    ("production_authority",True),
])
def test_scope_cannot_claim_unsanctioned_authority(key,value):
    c=m.read(m.CONTRACT)
    c["nonclaims"][key]=value
    with pytest.raises(m.Refused,match="340_CONTRACT_AUTHORITY_CLAIM_DRIFT"):
        m.contract_check(c)

def test_transcript_exact_source_only(proof):
    request=m.read(m.OUT/"exact-rcc-request.json")
    t=m.build_control_transcript(request)
    body=t["response"]["content"]
    assert request["alternatives"][0]["id"] in body
    assert "required_authority" not in body
    assert m.sha(t)==proof["selected"]["controlled_provider_transcript_hash"]

def test_transcript_rejects_spoofed_source_candidate(proof):
    request=m.read(m.OUT/"exact-rcc-request.json")
    spoof=deepcopy(request)
    spoof["context"]["rcc_revas"]["candidate"]["candidate_type"]="INJECTED"
    with pytest.raises(m.Refused,match="340_CONTROL_TRANSCRIPT_UNBOUND_TO_ORIGINAL"):
        m.build_control_transcript(spoof)

def test_no_option_swap_or_candidate_mutation(proof):
    request=m.read(m.OUT/"exact-rcc-request.json")
    rows=m.r337.read_jsonl(m.OUT/"prepared/veritas_decide_requests.jsonl")
    original=next(row for row in rows if row["case_id"]==proof["case_id"])
    assert request==original["request"]
    assert m.sha(request)==proof["original_request_sha256"]
    assert request["context"]["rcc_revas"]["candidate_semantic_hash"]==proof["rcc_candidate_semantic_hash"]

def test_actual_native_cda_selected_exact_candidate(proof):
    selected=proof["selected"]
    assert selected["native_cda_verified"]
    assert selected["actual_http_route_exercised"]
    assert selected["selected_id_exact"]
    assert selected["selected_canonical_description_exact"]
    assert selected["source_candidate_semantic_hash"]==proof["rcc_candidate_semantic_hash"]
    assert selected["native_cda_chosen_hash"]
    assert selected["real_kernel_observed"]
    assert selected["synthetic_kms_sign_calls"]>0
    assert selected["synthetic_worm_put_calls"]>0

def test_native_promotion_unavailable_without_trusted_authority(proof):
    assert proof["selected"]["native_promotion_result"]=="REFUSED_NO_EXECUTION_INTENT"
    assert not proof["trusted_authority_issued"]
    assert not proof["native_bind_invoked"]
    assert proof["native_verified_execution_intent"] is None
    assert proof["real_external_effects"]==0
    assert proof["scope"]["real_model_calls"]==0
    assert not proof["scope"]["independent_model_selection_proven"]

@pytest.mark.parametrize("field,value",[
    ("selected_id_exact",False),
    ("selected_canonical_description_exact",False),
    ("native_cda_verified",False),
    ("actual_http_route_exercised",False),
    ("native_promotion_result","PROMOTED"),
])
def test_forged_selected_evidence_fails_closed(proof,field,value):
    r=deepcopy(proof)
    r["selected"][field]=value
    with pytest.raises(m.Refused,match="340_SELECTED_CANDIDATE_CONTINUITY"):
        m.verify_report(r)

def test_tamper_can_never_mint_authorization(proof):
    r=deepcopy(proof)
    r["trusted_authority_issued"]=True
    with pytest.raises(m.Refused):
        m.verify_report(r)

def test_report_digest_and_case_accounting(proof):
    c=deepcopy(proof)
    digest=c.pop("report_sha256")
    assert digest==m.sha(c)
    assert c["cases"]["registered"]==36
    assert c["cases"]["prepared"]+c["cases"]["withheld"]==36
    assert c["selection_model"]=="CONTROLLED_TEST_TRANSCRIPT_NOT_INDEPENDENT_MODEL"
