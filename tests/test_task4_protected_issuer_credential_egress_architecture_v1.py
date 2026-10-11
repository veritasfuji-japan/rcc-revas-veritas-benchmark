"""#312: inspect NON-DEPLOYED issuer/secret/egress graph; reject false ALLOW."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

if os.environ.get("TASK4_312_OFFLINE_ARCH_AUDIT")!="1":
    pytest.skip("Task4 #312 isolated offline capability graph audit only",
                allow_module_level=True)
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import task4_protected_issuer_credential_egress_architecture_v1 as proof

def baseline():
    return proof.load_contract()

def test_reference_graph_has_no_untrusted_to_protected_path():
    report=proof.audit()
    graph=report["reference_design"]
    assert graph["node_count"]==19
    assert graph["design_edge_count"]==19
    assert graph["protected_count"]==11
    assert graph["untrusted_count"]==5
    assert graph["all_untrusted_paths_excluded_in_declared_reference_graph"] is True
    assert graph["pr_author_and_regular_CI_lack_live_provider_paths_in_declared_graph"] is True
    assert all(v==[] for v in graph["untrusted_to_protected_paths"].values())
    assert graph["privileged_db_admin_not_externally_controlled"] is True
    assert graph["actual_production_network_and_iam_not_inspected"] is True

@pytest.mark.parametrize("edge",[
    ["agent","issuer_svc","forge_approval"],
    ["agent","provider_api","egress_direct"],
    ["agent","provider_vault","steal_secret"],
    ["pr_runner","protected_sender","assume_runner_identity"],
    ["regular_ci","egress_proxy","route_to_provider"],
    ["repo_writer","db_breakglass_admin","assume_admin"],
    ["public_submitter","grant_ledger","mint_grant"],
    ["mock_executor","provider_api","hidden_transport"],
    ["read_only_repo","issuer_svc","poison_build"],
    ["pr_runner","human_approver","self_approval"],
])
def test_untrusted_bypass_paths_are_refused(edge):
    graph=baseline()
    graph["reference_edges"].append(edge)
    with pytest.raises(proof.AuditDenied,match="UNTRUSTED_TO_PROTECTED"):
        proof.audit(contract_override=graph)

@pytest.mark.parametrize("edge",[
    ["issuer_svc","provider_vault","read_secret"],
    ["issuer_svc","egress_proxy","send_without_consumer"],
    ["protected_sender","issuer_svc","self_issue"],
    ["receipt_verifier","egress_proxy","send"],
    ["db_breakglass_admin","provider_vault","read_secret"],
    ["human_approver","provider_api","send_from_human"],
    ["protected_sender","grant_ledger","issue_scoped_grant"],
])
def test_privileged_confused_deputy_or_unreviewed_edge_is_refused(edge):
    spec=baseline();spec["reference_edges"].append(edge)
    with pytest.raises(proof.AuditDenied,match="UNREVIEWED_GRAPH_CAPABILITY_EDGE"):
        proof.check_reference_policy(spec)

@pytest.mark.parametrize("actor",sorted(proof.UNTRUSTED))
def test_no_untrusted_identity_may_be_omitted(actor):
    spec=baseline();spec["untrusted_sources"].remove(actor)
    with pytest.raises(proof.AuditDenied,match="UNTRUSTED_ACTOR_OMITTED"):
        proof.check_reference_policy(spec)

@pytest.mark.parametrize("target",sorted(proof.PROTECTED))
def test_every_sensitive_target_must_remain_in_attack_model(target):
    spec=baseline();spec["protected_targets"].remove(target)
    with pytest.raises(proof.AuditDenied,match="PROTECTED_TARGET_OMITTED"):
        proof.check_reference_policy(spec)

@pytest.mark.parametrize("edge",[
    ["protected_sender","provider_vault","exchange_ephemeral_token"],
    ["human_approver","issuer_svc","approve_fresh_out_of_band"],
    ["db_breakglass_admin","grant_ledger",
     "admin_maintenance_requires_out_of_band_audit"],
])
def test_hiding_privileged_dependency_is_not_accepted(edge):
    spec=baseline();spec["reference_edges"].remove(edge)
    with pytest.raises(proof.AuditDenied,match="UNREVIEWED_GRAPH_CAPABILITY_EDGE"):
        proof.check_reference_policy(spec)

@pytest.mark.parametrize("id_",sorted(proof.REQUIRED_PRE_SEND))
def test_missing_production_control_requirement_rejected(id_):
    spec=baseline()
    spec["pre_send_evidence_requirements"]=[
        g for g in spec["pre_send_evidence_requirements"] if g["id"]!=id_]
    with pytest.raises(proof.AuditDenied,match="PRODUCTION_EVIDENCE_P0_REQUIREMENT_MISSING"):
        proof.check_reference_policy(spec)

@pytest.mark.parametrize("id_",sorted(proof.REQUIRED_POST_SEND))
def test_required_after_send_evidence_cannot_be_omitted(id_):
    spec=baseline()
    spec["after_live_evidence_requirements"].remove(id_)
    with pytest.raises(proof.AuditDenied,match="POST_SEND_OBSERVATION_REQUIREMENT_MISSING"):
        proof.check_reference_policy(spec)

@pytest.mark.parametrize("key,value",[
    ("new_human_approval_issued",True),
    ("real_provider_posts",1),
    ("real_bank_effects",1),
    ("live_dispatch_decision","ALLOW"),
    ("external_live_evidence_status","PROVEN"),
    ("runtime_permission_model","DEPLOYED_AND_VETTED"),
    ("actual_native_bind_calls",1),
    ("official_final128_scores",128),
])
def test_contract_cannot_promote_offline_graph_to_live_authority(key,value):
    spec=baseline();spec[key]=value
    with pytest.raises(proof.AuditDenied,match="CANNOT_PROMOTE_ARCHITECTURE"):
        proof.check_reference_policy(spec)

@pytest.mark.parametrize("field,value",[
    ("issuer_may_read_provider_key",True),
    ("issuer_may_submit_provider_request",True),
    ("handoff_verifier_may_send",True),
    ("sender_may_issue_or_reissue_grant",True),
    ("ordinary_ci_may_assume_sender_or_issuer",True),
    ("db_admin_without_independent_controls_is_a_remaining_privileged_bypass",False),
    ("CI_grant_receipt_as_live_permission",True),
    ("human_approval_alone_as_consume_receipt",True),
    ("permitted_real_provider_posts_in_this_PR",1),
])
def test_invariant_tamper_never_passes(field,value):
    spec=baseline()
    spec["design_separation_invariants"][field]=value
    with pytest.raises(proof.AuditDenied,match="REFERENCE_BOUNDARY_INVARIANT_TAMPERED"):
        proof.check_reference_policy(spec)

@pytest.mark.parametrize("claim",[
    None,{},True,False,"AUTHORIZED",
    {"human_approval":{"signed":True,"budget_usd":1000}},
    {"ledger":{"globally_consumed":True,"receipt":"forged"}},
    {"network":{"egress_denied":True}},
    {"environment_protection":{"reviewers":2}},
    {"provider_key":"sk-example-forgery"},
    {"billing_limit":"hard $0.005"},
    {"actual_Provider_response":{"request_id":"req_forged"}},
    {"all_proofs_passed":True,"compliance":"SOC2"},
])
def test_user_claims_and_fake_attestations_never_enable_live_provider(claim):
    r=proof.audit(claim=claim)
    assert r["readiness"]==proof.BLOCKED
    assert r["final_live_decision"]["decision"]=="DENY"
    assert r["untrusted_or_user_claims_can_issue_grant"] is False
    assert r["externally_verified_real_enforcements"]==0
    assert r["real_provider_calls"]==0
    assert r["new_human_authorization_issued"] is False
    assert len(r["pre_send_requirements"])==12
    assert all(c["status"]=="NOT_ATTESTED" for c in r["pre_send_requirements"])

@pytest.mark.parametrize("name",proof.SENSITIVE_ENVS)
def test_real_credential_context_refuses_offline_audit(name,monkeypatch):
    monkeypatch.setenv(name,"pretend-live-secret")
    with pytest.raises(proof.AuditDenied,match="REFUSES_REAL_CREDENTIAL_CONTEXT"):
        proof.audit()

@pytest.mark.parametrize("file_",sorted(proof.EXPECTED_PINS))
def test_frozen_parent_source_change_denied(tmp_path,file_):
    for rel in proof.EXPECTED_PINS:
        target=tmp_path/rel
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes((ROOT/rel).read_bytes())
    target=tmp_path/file_
    target.write_bytes(target.read_bytes()+b"\n# modified parent\n")
    with pytest.raises(proof.AuditDenied,match="FROZEN_PARENT_GIT_BLOB_DRIFT"):
        proof.source_pins(tmp_path)

def test_parent_source_evidence_matches_exact_git_blob_sha():
    frozen=proof.source_pins()
    assert len(frozen)==5
    for name,pin in proof.EXPECTED_PINS.items():
        assert frozen[name]["git_blob_sha1"]==pin
        assert frozen[name]["content_sha256"]==hashlib.sha256(
            (ROOT/name).read_bytes()).hexdigest()
        assert frozen[name]["proof_scope"]=="SOURCE_PIN_ONLY_NOT_PRODUCTION_IDENTITY"

def test_no_fake_deployed_production_proofs_or_final128_scores():
    r=proof.audit()
    assert r["production_issuer_verified"] is False
    assert r["production_db_admin_bypass_blocked"] is False
    assert r["production_egress_restriction_verified"] is False
    assert r["production_secret_boundary_verified"] is False
    assert r["actual_provider_billing_cap_verified"] is False
    assert r["real_provider_calls"]==0
    assert r["native_bind_real_effects"]==0
    assert r["official_final128_scores"]==0
    assert r["final_live_decision"]["new_live_provider_posts_authorized"]==0
    assert r["final_live_decision"]["credential_access_created"] is False
    assert len(r["post_send_requirements"])==3
    assert all(g["status"]=="CANNOT_CHECK_BEFORE_REAL_CALL"
               for g in r["post_send_requirements"])

def test_architecture_audit_output_repeatable_nonsecret():
    a=proof.audit()
    b=proof.audit(claim={"approved":"anybody can say approved"})
    assert a==b
    encoded=json.dumps(a,sort_keys=True)
    assert "sk-test" not in encoded
    assert a["report_sha256"]==hashlib.sha256(proof.canonical({
        k:v for k,v in a.items() if k!="report_sha256"
    })).hexdigest()
    assert a["old_real_provider_approval_consumed_sha"]==proof.CONSUMED_TAG_SHA

def test_no_sender_or_credentials_in_architecture_audit_code_and_workflow():
    script=(ROOT/"scripts"/
        "task4_protected_issuer_credential_egress_architecture_v1.py").read_text()
    for forbidden in ("openai.OpenAI(","OpenAI(","httpx.Client(",
                      "requests.post(","http.client.","socket.socket(",
                      "subprocess.run(","send_money("):
        assert forbidden not in script
    wf=(ROOT/".github/workflows/"
        "task4-protected-issuer-credential-egress-architecture-v1.yml").read_text()
    assert "permissions:\n  contents: read\n  actions: read" in wf
    assert "persist-credentials: false" in wf
    assert "workflow_dispatch:" not in wf
    assert "pull_request_target:" not in wf
    assert "repository_dispatch:" not in wf
    assert "secrets." not in wf
    assert "OPENAI_API_KEY: \"\"" in wf
    assert "TASK4_312_OFFLINE_ARCH_AUDIT: \"1\"" in wf
