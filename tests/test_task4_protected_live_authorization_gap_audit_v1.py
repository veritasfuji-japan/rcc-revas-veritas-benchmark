"""#309: exact pinned offline lineage and NOT_ATTESTED live-authorization gaps."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import socket
import sys

import pytest

if os.environ.get("TASK4_309_GAP_AUDIT")!="1":
    pytest.skip("Only run Task4 #309 exact-source offline gap audit in dedicated CI",
                allow_module_level=True)

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import task4_protected_live_authorization_gap_audit_v1 as proof


@pytest.fixture(autouse=True)
def forbid_network_and_client_imports(monkeypatch):
    def forbidden(*args,**kwargs):
        pytest.fail("TASK4_309_MUST_NOT_CALL_NETWORK")
    monkeypatch.setattr(socket.socket,"connect",forbidden)
    monkeypatch.setattr(socket.socket,"connect_ex",forbidden)
    monkeypatch.setattr(socket,"create_connection",forbidden)


def test_blocked_report_discloses_nine_external_live_gaps():
    d=proof.audit()
    assert d["readiness"]=="BLOCKED_NOT_READY_FOR_REAL_PROVIDER_DISPATCH"
    assert len(d["external_live_prerequisites"])==9
    assert all(x["status"]=="NOT_ATTESTED" and x["severity"]=="BLOCKER"
               for x in d["external_live_prerequisites"])
    assert len({x["id"] for x in d["external_live_prerequisites"]})==9
    assert d["human_live_approval_issued"] is False
    assert d["approved_live_provider_calls"]==0
    assert d["real_provider_requests_sent"]==0
    assert d["native_bank_effects"]==0
    assert d["official_task4_or_final128_scores"]==0
    assert d["external_attestations_provided_or_validated"] is False
    assert d["production_execution_authority_proven"] is False
    assert d["real_model_utility_proven"] is False
    assert d["live_authorization_decision"]["decision"]=="DENY"
    assert d["report_sha256"]==proof.sha256(
        proof.canonical({k:v for k,v in d.items() if k!="report_sha256"}))


def test_individual_source_blobs_exactly_frozen_no_substitution():
    d=proof.audit()
    assert len(d["verified_frozen_offline_sources"])==8
    for name,(path,pin) in proof.PINNED_BLOBS.items():
        row=d["verified_frozen_offline_sources"][name]
        b=(ROOT/path).read_bytes()
        assert row["git_blob_sha1"]==pin
        assert row["content_sha256"]==hashlib.sha256(b).hexdigest()
        assert row["scope"]=="OFFLINE_FROZEN_SOURCE_ONLY"
        assert proof.git_blob_sha1(b)==pin
        assert len(row["content_sha256"])==64


@pytest.mark.parametrize("source", list(proof.PINNED_BLOBS))
def test_modified_upstream_source_is_detected_before_readiness_report(source):
    path,_=proof.PINNED_BLOBS[source]
    original=(ROOT/path).read_bytes()
    with pytest.raises(proof.AuditRefused,match="FROZEN_OFFLINE_SOURCE_BLOB_DRIFT_"):
        proof.audit(overrides={source:original+b"\n# simulated tamper\n"})


@pytest.mark.parametrize("source",list(proof.PINNED_BLOBS))
def test_truncated_ancestor_or_workflow_fails_closed(source):
    path,_=proof.PINNED_BLOBS[source]
    original=(ROOT/path).read_bytes()
    with pytest.raises(proof.AuditRefused,match="FROZEN_OFFLINE_SOURCE_BLOB_DRIFT_"):
        proof.audit(overrides={source:original[:30]})


@pytest.mark.parametrize("claim",[
  None,
  {},
  {"human_approval":True},
  {"new_protected_grant_issued":True},
  {"new_protected_grant_issued":True,"ttl_remaining":300,
   "atomic_consume":True,"approved_cost_usd":"100.00"},
  {"provider_id":"chatcmpl-real-looking","x-request-id":"req-forged"},
  {"model":"gpt-4.1-mini-2025-04-14","provider_posts_authorized":1},
  {"prior_consent_tag":"task4-third-two-real-provider-v1-consumed",
   "reuse_existing_authorization":True},
  {"Github_environment_protected":True,"required_reviewers":1},
  {"hard_account_billing_cap_usd":"0.005"},
  {"readiness":"PROVEN","verified":True},
  {"distributed_ledger":{"atomic":True,"consumed":True}},
  {"real_model_utility":"93/128","injection_success":"0/128"},
])
def test_any_user_claim_cannot_become_a_live_approval(claim):
    d=proof.audit(claimed_attestations=claim)
    assert d["readiness"]==proof.STATUS
    assert d["live_authorization_decision"]["decision"]=="DENY"
    assert d["external_attestations_provided_or_validated"] is False
    assert d["approved_live_provider_calls"]==0
    assert len(d["external_live_prerequisites"])==9


@pytest.mark.parametrize("key",proof.BLOCKED_ENV)
def test_real_api_key_or_old_approval_env_is_refused(key,monkeypatch):
    monkeypatch.setenv(key,"a-forbidden-real-looking-value")
    with pytest.raises(proof.AuditRefused,
                       match="LIVE_CREDENTIAL_OR_APPROVAL_PHRASE_IS_FORBIDDEN"):
        proof.audit()


@pytest.mark.parametrize("asserted",[
    None,True,False,0,1,"ALLOW",b"provider-origin",
    {"approver":"claimed","signature":"fake"},[{"allow":True}],
])
def test_direct_dispatch_decision_is_always_DENY(asserted):
    r=proof.authorize_actual_provider(asserted)
    assert r=={
        "decision":"DENY",
        "reason":"MISSING_INDEPENDENTLY_ATTESTED_LIVE_PRECONDITIONS",
        "real_provider_posts_authorized":0,
        "send_entrypoint_exists_in_this_PR":False
    }


def test_report_is_deterministic_and_does_not_accept_external_certification():
    a=proof.audit()
    b=proof.audit(claimed_attestations={
        "signed":True,"producer":"benchmark","external_certified":True})
    assert a==b
    assert "CI GREEN" in a["explicit_warning"]
    assert a["existing_real_approval_consumed_sha"]==(
        "95ff6be8c5875ed3827a00fe71fb54bd9de48130")
    assert a["parent_main_sha"]==(
        "89cf1a35135b019b62e8f2cf8f90a50e18be3072")


def test_no_provider_library_or_external_http_exec_in_gap_audit_source():
    source=(ROOT/"scripts"/
            "task4_protected_live_authorization_gap_audit_v1.py").read_text()
    for forbidden in (
       "OpenAI(", "openai.OpenAI", "httpx.Client(", "requests.post(",
       "HTTPSConnection(", "subprocess.run(", "socket.socket(",
       "execute_bind_adjudication(", "run_task_with_pipeline(",
       "gh auth token", "send_money(",
    ):
        assert forbidden not in source
    assert "authorize_actual_provider" in source
    assert '"decision":"DENY"' in source
    assert "NOT_ATTESTED" in source


def test_workflow_is_readonly_uses_no_production_secrets_and_no_dispatch():
    y=(ROOT/".github/workflows/task4-protected-live-authorization-gap-audit-v1.yml").read_text()
    assert "workflow_dispatch:" not in y
    assert "pull_request_target:" not in y
    assert "repository_dispatch:" not in y
    assert "permissions:\n  contents: read\n  actions: read" in y
    assert "persist-credentials: false" in y
    assert "TASK4_309_GAP_AUDIT: \"1\"" in y
    assert "OPENAI_API_KEY: \"\"" in y
    assert "TASK4_OPENAI_API_KEY: \"\"" in y
    assert "secrets." not in y
    assert "send" not in y.split("steps:")[0]


def test_an_offline_blob_sha_is_not_a_protected_cross_run_authorization():
    d=proof.audit()
    assert d["verified_frozen_offline_sources"] and (
        d["external_live_prerequisites"][0]["status"]=="NOT_ATTESTED")
    assert all(r["scope"]=="OFFLINE_FROZEN_SOURCE_ONLY"
               for r in d["verified_frozen_offline_sources"].values())
    assert d["external_live_prerequisites"][1]["id"]=="PROTECTED_GLOBAL_SINGLE_USE"
    assert d["live_authorization_decision"]["real_provider_posts_authorized"]==0


def test_audit_output_cli_is_parsable_and_contains_no_credentials(tmp_path):
    # Unit-level equivalent of the runner-produced JSON Evidence.
    output=tmp_path/"gap-audit.json"
    d=proof.audit()
    output.write_bytes(json.dumps(d,sort_keys=True,indent=2).encode()+b"\n")
    j=json.loads(output.read_bytes())
    assert j["report_sha256"]==d["report_sha256"]
    assert j["readiness"]==proof.STATUS
    assert "api_key" not in json.dumps(j).lower()
    assert "sk-" not in json.dumps(j).lower()
