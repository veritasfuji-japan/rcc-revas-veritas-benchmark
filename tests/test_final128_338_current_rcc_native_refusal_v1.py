"""#338 boundaries. Dedicated job invokes real upstream + real VERITAS source."""
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import sys

import pytest

from scripts import final128_338_current_rcc_native_refusal_v1 as m

@pytest.fixture(autouse=True)
def forbid_external_transport(monkeypatch):
    def forbidden(*a,**kw):
        pytest.fail("338_NETWORK_DISPATCH_FORBIDDEN")
    monkeypatch.setattr(socket.socket,"connect",forbidden)
    monkeypatch.setattr(socket.socket,"connect_ex",forbidden)
    for key in m.upstream338.BANNED_KEYS:
        monkeypatch.delenv(key,raising=False)

@pytest.fixture(scope="module")
def evidence():
    source=os.environ.get("FINAL128_338_UPSTREAM_ROOT")
    veritas=os.environ.get("FINAL128_338_VERITAS_ROOT")
    if not source or not veritas:
        pytest.skip("338 requires dedicated current RCC and pinned VERITAS source checkouts")
    root=m.ROOT/"results/final128-338-current-rcc-native-refusal"
    report=m.read_json(root/"report.json")
    # The source-pinned dedicated job must execute; the global CI does not
    # attempt provider/network operations or claim the integrated proof.
    m.upstream338.verify_source(Path(source),
        m.upstream338.validate_contract(m.upstream338.load_json(m.upstream338.CONTRACT)))
    m.verify_veritas(Path(veritas),m.contract_check(m.read_json(m.CONTRACT)))
    assert m.validate_report(report)
    return report,root

def test_contract_pins_and_scope():
    c=m.contract_check(m.read_json(m.CONTRACT))
    assert c["veritas_commit"]==m.PIN_VERITAS
    assert c["upstream_commit"]==m.PIN_RCC
    assert c["scope"]["current_rcc_to_actual_native_effect_continuity"]=="NOT_PROVEN"
    assert c["scope"]["independent_cda_provided"] is False

@pytest.mark.parametrize("path,value",[
    ("native_bind_authorization_issued",True),
    ("native_bind_authorization_consumed",True),
    ("external_effects",1),
    ("http_decide_requests",1),
    ("provider_calls",1),
    ("official_agentdojo_scores",1),
    ("current_rcc_to_actual_native_effect_continuity","PROVEN"),
])
def test_contract_authority_promotion_refused(path,value):
    c=m.read_json(m.CONTRACT)
    c["scope"][path]=value
    with pytest.raises(m.Rejected,match="338_SCOPE_OR_AUTHORITY_CHANGED"):
        m.contract_check(c)

def test_contract_drift_rejected():
    c=m.read_json(m.CONTRACT)
    c["veritas_commit"]="0"*40
    with pytest.raises(m.Rejected):
        m.contract_check(c)

def test_single_real_case_refused(evidence):
    report,root=evidence
    observed=report["observed"]
    assert len(observed["rcc_semantic_candidate_hash"])==64
    assert observed["candidate_reflected_without_mutation"] is True
    assert observed["native_cda_verifier"]=="REJECTED_RCC_LOCK_NOT_CDA"
    assert observed["native_cda_promotion"]=="REFUSED_NO_EXECUTION_INTENT"
    assert observed["verified_native_execution_intent_created"] is False
    assert observed["native_candidate_validation"]["fail_closed"] is True
    assert "DECISION_CANDIDATE_AUTHORITY_UNSPECIFIED" in observed["native_candidate_validation"]["reason_codes"]
    assert observed["native_bind_probe"]["final_outcome"]=="BLOCKED"
    assert observed["native_bind_probe"]["apply_count"]==0
    assert observed["native_bind_probe"]["state_before_after"]=={"writes":0}
    assert report["rcc_case_accounting"]["registered"]==36
    assert report["rcc_case_accounting"]["errors"]==0
    assert report["rcc_case_accounting"]["prepared"]+report["rcc_case_accounting"]["withheld"]==36
    assert not report["native_http_route_exercised"]
    assert not report["native_authorization_consumption_exercised"]

def test_real_report_hash_matches(evidence):
    report,root=evidence
    copy=deepcopy(report)
    expected=copy.pop("report_sha256")
    assert m.sha_json(copy)==expected

@pytest.mark.parametrize("path,value",[
    ("native_bind_authorization_issued",True),
    ("external_effects",1),
    ("provider_calls",1),
    ("current_rcc_to_actual_native_effect_continuity","PROVEN"),
])
def test_evidence_claim_fabrication_rejected(evidence,path,value):
    report,root=evidence
    forged=deepcopy(report)
    forged["scope"][path]=value
    with pytest.raises(m.Rejected):
        m.validate_report(forged)

def test_mutated_candidate_must_fail_before_native_promotion(evidence):
    report,root=evidence
    selected=report["observed"]["rcc_case_id"]
    rows=m.upstream338.read_jsonl(root/"prepared/veritas_decide_requests.jsonl")
    handoffs={h["rcc_revas"]["audit"]["case_id"]:h for h in
        m.upstream338.read_jsonl(root/"rcc-run/handoff_results.jsonl")}
    row=next(r for r in rows if r["case_id"]==selected)
    forged=deepcopy(row)
    forged["request"]["context"]["rcc_revas"]["candidate"]={"typed_action":"DROP"}
    c=m.upstream338.validate_contract(m.upstream338.load_json(m.upstream338.CONTRACT))
    upstream=Path(os.environ["FINAL128_338_UPSTREAM_ROOT"])
    sys.path.insert(0,str(upstream/c["upstream_release_root"]))
    from rcc_revas_eval import native_veritas as native
    with pytest.raises(m.upstream338.Refused):
        m.upstream338.verify_one_prepared(forged,handoffs[selected],root/"rcc-run",native)

def test_rcc_lock_cannot_be_minted_as_cda(evidence):
    report,root=evidence
    selected=report["observed"]["rcc_case_id"]
    handoffs={h["rcc_revas"]["audit"]["case_id"]:h for h in
        m.upstream338.read_jsonl(root/"rcc-run/handoff_results.jsonl")}
    sys.path.insert(0,os.environ["FINAL128_338_VERITAS_ROOT"])
    from veritas_os.governance.canonical_decision_artifact import verify_canonical_decision_artifact
    from veritas_os.policy.decision_candidate import (
        DecisionCandidate, try_promote_verified_canonical_decision_candidate_to_execution_intent)
    spoof=handoffs[selected]["rcc_revas"]["decision_lock"]
    native_cda=verify_canonical_decision_artifact(spoof)
    assert not native_cda.is_valid
    proposal=DecisionCandidate(
        evidence_refs=["rcc-candidate-v1:"+report["observed"]["rcc_semantic_candidate_hash"]],
        required_authority=[],required_human_approval=None)
    promotion=try_promote_verified_canonical_decision_candidate_to_execution_intent(
        proposal,canonical_decision_artifact=spoof)
    assert promotion.execution_intent is None
    assert promotion.promoted is False
    assert "CANONICAL_DECISION_ARTIFACT_INVALID" in promotion.refusal_reason_codes

def test_no_unsanctioned_native_scope(evidence):
    report,root=evidence
    assert report["scope"]["selected_candidate_count"]==1
    assert report["scope"]["native_bind_authorization_issued"] is False
    assert report["scope"]["native_bind_authorization_consumed"] is False
    assert report["scope"]["external_effects"]==0
    assert report["scope"]["provider_calls"]==0
    assert report["historical_v13_reference_only"]=={
        "arm_a_utility":93,"arm_b_utility":64,"arm_b_injection_success":0}
