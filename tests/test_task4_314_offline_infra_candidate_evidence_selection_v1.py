"""#314 candidate comparison is never a Provider execution authority."""
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import sys

import pytest

if os.environ.get("TASK4_314_OFFLINE_MATRIX_AUDIT") != "1":
    pytest.skip("#314 isolated offline candidate matrix only",
                allow_module_level=True)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import task4_314_offline_infra_candidate_evidence_selection_v1 as p

def baseline():
    return p.load()

def denied(spec, expected):
    with pytest.raises(p.OfflineDenied, match=expected):
        p.check(spec)

def test_reference_matrix_and_exact_313_pins():
    r = p.audit()
    assert p.verify_parent() == p.PINS
    assert r["candidate_count"] == 4
    assert r["independent_owner_roles_unassigned"] == 8
    assert r["external_gates_unattested"] == 12
    assert r["final_live_decision"] == "DENY"
    assert r["privileged_admin_bypass_unresolved"] is True
    assert r["production_selection"] is None

@pytest.mark.parametrize("id_", sorted(p.CANDIDATES))
def test_missing_candidate_is_rejected(id_):
    x = baseline()
    x["candidates"] = [c for c in x["candidates"] if c["id"] != id_]
    denied(x, "CANDIDATE_MATRIX")

@pytest.mark.parametrize("id_", sorted(p.CANDIDATES))
def test_duplicate_candidate_is_rejected(id_):
    x = baseline()
    x["candidates"][0]["id"] = id_
    if id_ == x["candidates"][0]["id"] and id_ == x["candidates"][1]["id"]:
        pass
    x["candidates"].append(deepcopy(x["candidates"][0]))
    denied(x, "CANDIDATE_MATRIX")

@pytest.mark.parametrize("field", sorted(p.FALSE_CANDIDATE_FIELDS))
def test_unverified_candidate_property_cannot_be_claimed(field):
    x = baseline(); x["candidates"][0][field] = True
    denied(x, "CANDIDATE_FALSE_PRODUCTION")

@pytest.mark.parametrize("field,value", [
    ("cost_quote_usd_month", 0),
    ("cost_quote_usd_month", 1),
    ("status", "DEPLOYED"),
    ("fit", "PRODUCTION_READY"),
    ("documentation_source", "fake-source"),
])
def test_unsupported_price_or_service_claim_fails(field, value):
    x = baseline(); x["candidates"][-1][field] = value
    denied(x, "CANDIDATE_FALSE_PRODUCTION")

@pytest.mark.parametrize("id_", sorted(p.ROLES))
def test_independent_admin_role_cannot_be_omitted(id_):
    x = baseline()
    x["owner_roles"] = [r for r in x["owner_roles"] if r["id"] != id_]
    denied(x, "ROLE_ACCOUNTABILITY_TOPOLOGY")

@pytest.mark.parametrize("field,value", [
    ("assigned_independent_person", "repo_owner"),
    ("assigned_independent_person", "unverified_third_party"),
    ("admin_tenancy", "shared_root_admin_account"),
    ("verified_separation", True),
])
def test_self_declared_admin_is_not_independence(field, value):
    x = baseline(); x["owner_roles"][0][field] = value
    denied(x, "SINGLE_OPERATOR_OR_SELF_DECLARED_INDEPENDENCE")

@pytest.mark.parametrize("id_", sorted(p.GATE_OWNER))
def test_all_12_external_evidence_gates_mandatory(id_):
    x = baseline()
    x["gate_plan"] = [g for g in x["gate_plan"] if g["id"] != id_]
    denied(x, "EXTERNAL_EVIDENCE_PLAN")

@pytest.mark.parametrize("field,value", [
    ("status", "ATTESTED"),
    ("status", "PROVEN"),
    ("evidence", "https://example.invalid/fake-proof"),
    ("required_owner_role", "repo_owner"),
    ("independent_proof_needed", "passed"),
])
def test_no_fabricated_evidence_or_wrong_owner(field, value):
    x = baseline(); x["gate_plan"][0][field] = value
    denied(x, "FAKE_EXTERNAL_EVIDENCE_OR_OWNER")

@pytest.mark.parametrize("field", sorted(p.FALSE_ROOT_FIELDS))
def test_cannot_promote_cloud_or_network_assertion(field):
    x = baseline(); x[field] = True
    denied(x, "EXTERNAL_SECURITY_NOT_INSPECTED")

@pytest.mark.parametrize("field", sorted(p.ZERO_ROOT_FIELDS))
@pytest.mark.parametrize("value", [1, True])
def test_provisioning_call_grant_and_score_must_be_zero(field, value):
    x = baseline(); x[field] = value
    denied(x, "NO_BILLING_PROVISIONING_OR_PROVIDER_EFFECT")

@pytest.mark.parametrize("field,value", [
    ("selected_candidate", "AWS_MANAGED_SEPARATION"),
    ("selected_candidate", "LOCAL_OFFLINE_FIXTURE"),
    ("current_budget_approval", "$10"),
    ("cost_and_pricing_validation", "PRICES_VERIFIED"),
    ("next_gate", "SEND_NOW"),
])
def test_no_implicit_selection_or_budget_spend(field, value):
    x = baseline(); x[field] = value
    denied(x, "UNAUTHORIZED_COST_OR_INFRA_SELECTION")

@pytest.mark.parametrize("field,value", [
    ("parent_merged_main", "0" * 40),
    ("parent_git_blobs", {}),
    ("previous_real_provider_consent", "REUSABLE"),
])
def test_exact_parent_and_consumed_consent_mandatory(field, value):
    x = baseline(); x[field] = value
    denied(x, "PARENT_PIN_OR_CONSENT_INVALID")

def test_explicit_provider_approval_cannot_be_added():
    x = baseline(); x["new_approval"] = "issued"
    denied(x, "MODEL_EXTRA_OR_MISSING_FIELDS")

def test_dispatch_must_always_be_denied():
    x = baseline(); x["decision"] = "ALLOW"
    denied(x, "NEVER_AUTHORIZE_PROVIDER_WITH_COMPARISON")

@pytest.mark.parametrize("claim", [
    {"cloud_provisioned": True},
    {"billing_hard_stop": True},
    {"trusted_reviewer": "myself"},
    {"grant_issued": True, "provider_sent": True},
    {"secret": "fake-secret"},
])
def test_untrusted_self_report_cannot_change_result(claim):
    assert p.audit(untrusted_claim=claim) == p.audit()
    assert p.audit()["final_live_decision"] == "DENY"

@pytest.mark.parametrize("name", p.SENSITIVE_ENV)
def test_real_secret_context_aborts_audit(name, monkeypatch):
    monkeypatch.setenv(name, "pretend-key")
    with pytest.raises(p.OfflineDenied, match="NO_LIVE_CREDENTIAL"):
        p.audit()

def test_report_stable_and_sha_matches():
    a = p.audit()
    b = dict(a); b.pop("report_sha256")
    assert a["report_sha256"] == hashlib.sha256(p.canon(b)).hexdigest()
    assert a["live_provider_calls"] == 0
    assert a["cloud_resources_created"] == 0
    assert a["official_final128_scores"] == 0
    assert a["untrusted_claims_used_as_evidence"] is False

def test_no_live_sender_or_secret_workflow():
    src = (ROOT / "scripts/task4_314_offline_infra_candidate_evidence_selection_v1.py").read_text()
    wf = (ROOT / ".github/workflows/task4-314-offline-infra-candidate-evidence-selection-v1.yml").read_text()
    for forbidden in ("openai.OpenAI(", "requests.post(", "httpx.Client(",
                      "socket.socket(", "subprocess.run(", "send_money("):
        assert forbidden not in src
    assert "permissions:\n  contents: read\n  actions: read" in wf
    assert "persist-credentials: false" in wf
    assert "pull_request_target:" not in wf
    assert "workflow_dispatch:" not in wf
    assert "repository_dispatch:" not in wf
    assert "secrets." not in wf
    assert 'OPENAI_API_KEY: ""' in wf
    assert 'TASK4_314_OFFLINE_MATRIX_AUDIT: "1"' in wf
