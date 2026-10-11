"""#313 OFFLINE selection and independently attested control readiness."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

if os.environ.get("TASK4_313_OFFLINE_PREFLIGHT") != "1":
    pytest.skip("#313 isolated offline readiness test suite only",
                allow_module_level=True)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import task4_313_external_control_readiness_preflight_v1 as proof

def sample():
    return proof.load_spec()

def must_deny(spec, reason):
    with pytest.raises(proof.Denied, match=reason):
        proof.validate_spec(spec)

def test_parent_and_reference_controls_reconciled():
    result = proof.audit()
    parent = json.loads(
        (ROOT / "contracts/TASK4_PROTECTED_ISSUER_CREDENTIAL_EGRESS_ARCHITECTURE_V1.json")
        .read_text(encoding="utf-8")
    )
    assert {g["id"] for g in parent["pre_send_evidence_requirements"]} == proof.GATES
    assert proof.verify_parent_pins() == proof.PINS
    assert result["parent_merged_main"] == proof.PARENT
    assert len(result["unattested_external_pre_send_gates"]) == 12
    assert len(result["unresolved_infrastructure_dimensions"]) == 8
    assert result["external_attestation_count"] == 0
    assert result["remaining_db_superuser_bypass"] is True
    assert result["final_live_decision"] == "DENY"

@pytest.mark.parametrize("key", sorted(proof.GATES))
def test_missing_external_gate_fails(key):
    spec = sample()
    spec["pre_send_controls"] = [
        gate for gate in spec["pre_send_controls"] if gate["id"] != key
    ]
    must_deny(spec, "UNATTESTED_GATE")

@pytest.mark.parametrize("new_status", ["ATTESTED", "PASSED", "PROVEN", "ALLOW", None, True])
def test_fake_gate_completion_is_rejected(new_status):
    spec = sample()
    spec["pre_send_controls"][0]["status"] = new_status
    must_deny(spec, "UNATTESTED_GATE")

@pytest.mark.parametrize("claim", [
    {"independent_evidence_uri": "https://example.invalid/fake"},
    {"attestor_identity": "CI-self-attests"},
    {"extra": "approved"},
])
def test_fake_attestation_details_rejected(claim):
    spec = sample()
    spec["pre_send_controls"][0].update(claim)
    must_deny(spec, "UNATTESTED_GATE")

@pytest.mark.parametrize("dimension", sorted(proof.DIMENSIONS))
def test_selection_must_remain_unresolved_without_owner_decision(dimension):
    spec = sample()
    spec["decision_dimensions"] = [
        d for d in spec["decision_dimensions"] if d["id"] != dimension
    ]
    must_deny(spec, "UNVERIFIED_INFRA_SELECTION")

@pytest.mark.parametrize("field,value", [
    ("chosen_service", "unreviewed_cloud_product"),
    ("account_or_tenant", "user-controlled-project"),
    ("independent_control_owner", "repo-author"),
    ("externally_verified_evidence", "fake-evidence-hash"),
])
def test_fake_provider_or_security_admin_is_not_a_selection(field, value):
    spec = sample()
    spec["decision_dimensions"][0][field] = value
    must_deny(spec, "UNVERIFIED_INFRA_SELECTION")

@pytest.mark.parametrize("key,value", [
    ("infrastructure_selection", "CHOSEN"),
    ("administrative_separation", "ESTABLISHED"),
    ("remaining_privileged_bypass", "RESOLVED"),
    ("scope", "PRODUCTION_DEPLOYED"),
    ("result", "READY_TO_SEND"),
])
def test_offline_check_cannot_claim_production_status(key, value):
    spec = sample(); spec[key] = value
    must_deny(spec, "OWNER_INFRA_DECISION")

@pytest.mark.parametrize("key", [
    "external_cloud_iam_inspected",
    "actual_vault_permissions_inspected",
    "actual_egress_enforcement_inspected",
    "provider_billing_controls_inspected",
    "production_deployment_created",
    "new_human_provider_authorization",
])
def test_fake_external_proof_or_new_consent_fails(key):
    spec = sample(); spec[key] = True
    must_deny(spec, "FALSE_EXTERNAL_EVIDENCE")

@pytest.mark.parametrize("key", [
    "real_provider_posts", "real_bank_effects", "official_final128_scores",
])
@pytest.mark.parametrize("value", [1, True])
def test_fake_real_effects_or_final128_results_fail(key, value):
    spec = sample(); spec[key] = value
    must_deny(spec, "LIVE_EFFECT_OR_SCORE_FALSIFIED")

@pytest.mark.parametrize("key,value", [
    ("live_dispatch_decision", "ALLOW"),
    ("live_dispatch_decision", True),
])
def test_no_dispatch_ever_authorized(key, value):
    spec = sample(); spec[key] = value
    must_deny(spec, "LIVE_PROVIDER_DISPATCH_MUST_REMAIN_DENY")

@pytest.mark.parametrize("field,value", [
    ("parent_merged_main", "0" * 40),
    ("parent_blobs", {}),
    ("consumed_tag_target", "f" * 40),
    ("historical_real_provider_approval", "RENEWABLE"),
])
def test_parent_source_or_consent_cannot_be_swapped(field, value):
    spec = sample(); spec[field] = value
    must_deny(spec, "PARENT_312_OR_CONSUMED_AUTHORIZATION")

@pytest.mark.parametrize("extra", [
    {"attestation": "PROVEN"},
    {"approval": {"signed": True}},
    {"provider_credential": "SECRET"},
])
def test_extra_unreviewed_fields_fail_closed(extra):
    spec = sample(); spec.update(extra)
    must_deny(spec, "EXTRA_OR_MISSING_CONTRACT_FIELDS")

@pytest.mark.parametrize("name", proof.SENSITIVE_ENVS)
def test_secret_context_refuses_offline_test(name, monkeypatch):
    monkeypatch.setenv(name, "pretend-key")
    with pytest.raises(proof.Denied, match="CANNOT_RUN_WITH_PROVIDER_SECRETS"):
        proof.audit()

@pytest.mark.parametrize("claim", [
    {"human_approved": True},
    {"network_egress": "protected"},
    {"billing_cap_usd": 0.001},
    {"sender_deployed": True, "provider_result": "ok"},
    {"db_superuser_bypass": "fixed"},
])
def test_self_reported_claims_never_elevate_permission(claim):
    report = proof.audit(untrusted_claim=claim)
    assert report == proof.audit()
    assert report["final_live_decision"] == "DENY"
    assert report["forged_user_claims_used"] is False
    assert report["real_provider_calls"] == 0
    assert report["new_provider_authorizations"] == 0

def test_report_reproducible_and_sha_correct():
    x = proof.audit()
    assert x == proof.audit()
    expected = dict(x)
    expected.pop("report_sha256")
    assert x["report_sha256"] == hashlib.sha256(
        proof.canonical(expected)).hexdigest()
    assert x["proof_scope"] == "STATIC_MANIFEST_AND_PIN_AUDIT_ONLY_NOT_DEPLOYED_SECURITY"

def test_no_live_sender_or_secret_in_offline_source_and_workflow():
    src = (ROOT / "scripts/task4_313_external_control_readiness_preflight_v1.py").read_text()
    wf = (ROOT / ".github/workflows/task4-313-external-control-readiness-preflight-v1.yml").read_text()
    for forbidden in (
        "openai.OpenAI(", "OpenAI(", "requests.post(", "httpx.Client(",
        "socket.socket(", "subprocess.run(", "send_money(",
    ):
        assert forbidden not in src
    assert "permissions:\n  contents: read\n  actions: read" in wf
    assert "persist-credentials: false" in wf
    assert "workflow_dispatch:" not in wf
    assert "pull_request_target:" not in wf
    assert "repository_dispatch:" not in wf
    assert "secrets." not in wf
    assert 'OPENAI_API_KEY: ""' in wf
    assert 'TASK4_313_OFFLINE_PREFLIGHT: "1"' in wf
