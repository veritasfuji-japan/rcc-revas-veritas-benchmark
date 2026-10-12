"""#339 source-pinned actual route and native CDA compatibility checks."""
from copy import deepcopy
import os
from pathlib import Path
import socket
import pytest

from scripts import final128_339_current_rcc_real_decide_compatibility_v1 as m

@pytest.fixture(autouse=True)
def no_network_no_creds(monkeypatch):
    def blocked(*args,**kwargs):
        pytest.fail("339_ANY_EXTERNAL_NETWORK_DISPATCH_FORBIDDEN")
    monkeypatch.setattr(socket.socket,"connect",blocked)
    monkeypatch.setattr(socket.socket,"connect_ex",blocked)
    for name in m.upstream.BANNED_KEYS:
        monkeypatch.delenv(name,raising=False)

@pytest.fixture(scope="module")
def report():
    if not os.environ.get("FINAL128_339_UPSTREAM_ROOT") or not os.environ.get("FINAL128_339_VERITAS_ROOT"):
        pytest.skip("339 only reports source-executed evidence under dedicated checkout CI")
    c=m.contract_check(m.prev.read_json(m.CONTRACT_PATH))
    m.verify_os(Path(os.environ["FINAL128_339_VERITAS_ROOT"]),c)
    m.upstream.verify_source(Path(os.environ["FINAL128_339_UPSTREAM_ROOT"]),
        m.upstream.validate_contract(m.upstream.load_json(m.upstream.CONTRACT)))
    r=m.prev.read_json(m.FIXED_OUT/"report.json")
    assert m.validate_report(r)
    return r

def test_contract_requires_exact_pins():
    c=m.contract_check(m.prev.read_json(m.CONTRACT_PATH))
    assert c["selected_case_count"]==1
    assert c["request_mutation_allowed"] is False
    assert c["upstream_veritas_sha"]==m.PIN_VERITAS

@pytest.mark.parametrize("path,value",[
    ("native_authorization_issued",True),
    ("native_bind_executed",True),
    ("live_model_provider_calls",1),
    ("official_final128_rescored",True),
    ("end_to_end_same_candidate_proven",True),
])
def test_scope_must_not_promote_unproven_claims(path,value):
    c=m.prev.read_json(m.CONTRACT_PATH)
    c["nonclaims"][path]=value
    with pytest.raises(m.Refused,match="339_SCOPE_DRIFT"):
        m.contract_check(c)

def test_observed_real_route_and_native_cda(report):
    assert report["route"]["real_api_route_called"] is True
    assert report["route"]["real_decide_kernel_observed"] is True
    assert report["route"]["native_cda_verified"] is True
    assert report["route"]["request_payload_exact"] is True
    assert len(report["route"]["native_decision_hash"])==64
    assert report["route"]["synthetic_kms_sign_calls"]>0
    assert report["route"]["synthetic_worm_put_calls"]>0

def test_same_original_rcc_candidate_honesty(report):
    request=m.prev.read_json(m.FIXED_OUT/"real-request.json")
    native=m.prev.read_json(m.FIXED_OUT/"native-decision.json")
    identity=report["linkage"]
    assert identity["request_description_exact_bytes_bound"] is True
    assert identity["original_candidate_semantic_hash"]==report["rcc_selected_semantic_hash"]
    assert native["request_exact_json_sha256"]==m.json_digest(request)
    assert native["linkage"]==identity
    assert request["alternatives"][0]["id"]=="rcc-candidate:"+report["rcc_selected_semantic_hash"]
    if not identity["response_exact_native_candidate_selection_proven"]:
        assert not report["rcc_to_native_execution_intent_proven"]
        assert report["verified_rcc_execution_intent"] is None

def test_real_request_identical_to_generated_rcc_evidence(report):
    selected=report["selected_case_id"]
    rows=m.upstream.read_jsonl(m.FIXED_OUT/"prepared/veritas_decide_requests.jsonl")
    match=next(row for row in rows if row["case_id"]==selected)
    request=m.prev.read_json(m.FIXED_OUT/"real-request.json")
    assert request==match["request"]
    c=m.upstream.validate_contract(m.upstream.load_json(m.upstream.CONTRACT))
    release=Path(os.environ["FINAL128_339_UPSTREAM_ROOT"])/c["upstream_release_root"]
    import sys
    sys.path.insert(0,str(release))
    from rcc_revas_eval import native_veritas
    handoffs={h["rcc_revas"]["audit"]["case_id"]:h for h in m.upstream.read_jsonl(
        m.FIXED_OUT/"rcc-run/handoff_results.jsonl")}
    m.upstream.verify_one_prepared(match,handoffs[selected],m.FIXED_OUT/"rcc-run",native_veritas)

def test_exact_candidate_mismatch_is_visible(report):
    request=m.prev.read_json(m.FIXED_OUT/"real-request.json")
    altered=deepcopy(request)
    altered["context"]["rcc_revas"]["candidate"]["candidate_type"]="ATTACK"
    original_hash=m.json_digest(request)
    assert m.json_digest(altered)!=original_hash

@pytest.mark.parametrize("field,value",[
    ("native_bind_invoked",True),
    ("actual_execution_effects",1),
    ("rcc_to_native_execution_intent_proven",True),
])
def test_forged_evidence_cannot_pass_when_unbound(report,field,value):
    modified=deepcopy(report)
    modified[field]=value
    if field=="rcc_to_native_execution_intent_proven" and report["linkage"]["response_exact_native_candidate_selection_proven"]:
        pytest.skip("Positive identity state requires separate EI status test")
    with pytest.raises(m.Refused):
        m.validate_report(modified)

def test_digest_and_no_paid_calls(report):
    copy=deepcopy(report)
    digest=copy.pop("report_sha256")
    assert digest==m.json_digest(copy)
    assert report["scope"]["live_model_provider_calls"]==0
    assert report["scope"]["native_authorization_issued"] is False
    assert report["scope"]["native_bind_executed"] is False
    assert report["actual_execution_effects"]==0
