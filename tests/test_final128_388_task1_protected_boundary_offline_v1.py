"""#388 offline-only Task1 protected boundary: no trusted execution authority."""
from __future__ import annotations
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import json
import pytest

from scripts import final128_388_task1_protected_boundary_offline_v1 as m
from scripts import final128_387_legacy_manual_provider_quarantine_audit_v1 as previous

def spec():
    return m.load_contract()

def test_contract_exact_matches_expected():
    assert spec() == m.expected_contract()
    assert m.validate_contract(spec()) is True

@pytest.mark.parametrize("section,key,value", [
    ("proposed_job", "event", "push"),
    ("proposed_job", "branch", "refs/heads/other"),
    ("proposed_job", "environment", "default"),
    ("proposed_job", "credential", "REPOSITORY_SECRET_OPENAI_API_KEY"),
    ("proposed_job", "model", "gpt-4o-mini"),
    ("proposed_job", "max_first_provider_attempts", 8),
    ("proposed_job", "max_first_provider_attempts", True),
    ("proposed_job", "proposed_spend_ceiling_usd", "10.00"),
    ("proposed_job", "max_run_attempt", 2),
    ("proposed_job", "no_automatic_retry", False),
    ("proposed_job", "global_single_use_tag", "refs/tags/per-run-ref"),
    ("proposed_job", "consume_outcome_unknown", "RETRY"),
    ("proposed_job", "provider_step", "POST_API"),
    ("manually_observed_not_machine_attested", "wait_timer_minutes", 0),
    ("manually_observed_not_machine_attested", "admin_bypass_allowed", True),
    ("manually_observed_not_machine_attested", "repository_openai_secret_removed", False),
    ("manually_observed_not_machine_attested", "prevent_self_review", True),
    ("externally_unverified", "effective_provider_project_hard_spend_stop", False),
    ("externally_unverified", "trusted_protected_issuer_and_credential_bound_runner", False),
])
def test_any_contract_tamper_or_asserted_proof_is_denied(section, key, value):
    x = deepcopy(spec())
    x[section][key] = value
    with pytest.raises(m.Denied, match="CONTRACT_DRIFT_OR_CLAIMED_PROOF|TYPE_CONFUSION"):
        m.validate_contract(x)

@pytest.mark.parametrize("field,value", [
    ("repository", "wrong/repo"),
    ("event", "push"),
    ("ref", "refs/heads/dev"),
    ("actor", "another-user"),
    ("environment", "wrong-env"),
    ("model", "other-model"),
    ("run_attempt", 2),
    ("run_attempt", True),
    ("main_sha", "main"),
    ("run_id", "not-a-run"),
    ("max_calls", 3),
    ("max_usd", "2.00"),
])
def test_changed_scope_denies_before_fake_consume(field, value):
    fake = m.FakeGlobalOnce()
    with pytest.raises(m.Denied, match="388_CANDIDATE"):
        m.simulate_only(candidate=replace(m.Candidate(), **{field: value}), fake=fake)
    assert fake.attempts == 0

def test_claimed_approval_and_fake_provider_receipt_do_not_authorize():
    fake = m.FakeGlobalOnce()
    result = m.simulate_only(candidate=m.Candidate(), fake=fake, claims={
        "approved": True,
        "independent_reviewer": True,
        "real_provider_origin": True,
        "github_ref_201": True,
        "project_hard_limit": True,
        "spend_usd": "0.00",
    })
    assert result["outcome"] == "FAKE_CONSUMED_NOT_AUTHORITY"
    assert result["permission_to_call_provider"] is False
    assert result["actual_github_ref_created"] is False
    assert result["real_provider_calls"] == 0
    assert result["environment_secret_accessed"] is False

def test_protocol_global_once_replayed_across_run_ids_is_denied():
    fake = m.FakeGlobalOnce()
    m.simulate_only(candidate=m.Candidate(), fake=fake)
    with pytest.raises(m.Denied, match="GLOBAL_REPLAY"):
        m.simulate_only(candidate=replace(m.Candidate(), run_id="38227769502"),
                        fake=fake)
    assert fake.attempts == 1

@pytest.mark.parametrize("failure", [
    "unknown_before_write", "unknown_after_write", "rejected",
])
def test_issuer_failure_or_uncertainty_permanently_blocks_retry(failure):
    fake = m.FakeGlobalOnce()
    with pytest.raises(m.Denied):
        m.simulate_only(candidate=m.Candidate(), fake=fake, failure=failure)
    assert fake.terminal == "UNKNOWN_STOP_NO_RETRY"
    with pytest.raises(m.Denied, match="GLOBAL_REPLAY"):
        m.simulate_only(candidate=m.Candidate(), fake=fake)
    assert fake.attempts == 1

def test_bad_fake_store_or_claim_shape_rejected():
    with pytest.raises(m.Denied, match="FAKE_ONLY_EXACT_TYPE"):
        m.simulate_only(candidate=m.Candidate(), fake={})
    with pytest.raises(m.Denied, match="CLAIMS_UNTRUSTED_OBJECT"):
        m.simulate_only(candidate=m.Candidate(), fake=m.FakeGlobalOnce(), claims=True)

def test_fake_lease_not_reusable_after_success_even_when_sha_changes():
    f = m.FakeGlobalOnce()
    m.simulate_only(candidate=m.Candidate(), fake=f)
    with pytest.raises(m.Denied, match="GLOBAL_REPLAY"):
        m.simulate_only(candidate=replace(m.Candidate(), main_sha="b"*40), fake=f)

def test_contract_rejects_duplicate_json_keys(tmp_path):
    p = tmp_path / "duplicate.json"
    p.write_text('{"schema":"one","schema":"two"}')
    with pytest.raises(m.Denied, match="DUPLICATE_JSON_KEY"):
        m.load_contract(p)

def test_source_inventory_only_counts_jobs_declaring_task1_environment_and_binding():
    real = ("name: Potential job\non:\n  workflow_dispatch:\njobs:\n"
            "  sender:\n    environment: task1-real-model-pilot\n"
            "    runs-on: ubuntu-24.04\n    env:\n"
            "      OPENAI_API_KEY: "+ "$"+"{{ secrets.OPENAI_API_KEY }}\n")
    unrelated = real.replace("task1-real-model-pilot", "task4-real-provider-first-two-calls")
    inv = m.source_inventory({
        ".github/workflows/potential.yml": real,
        ".github/workflows/unrelated.yml": unrelated,
    })
    assert inv["task1_environment_secret_binding_jobs_found"] == [
        {"path": ".github/workflows/potential.yml", "job": "sender"}]
    assert len(inv["task4_environment_jobs_found_not_modified"]) == 1
    assert inv["source_inventory_is_not_admin_state"] is True

def test_actual_repository_readonly_inventory_never_authorizes():
    actual = previous.actual_workflows(".")
    result = m.audit(spec=spec(), files=actual)
    assert result["inventory"]["source_workflows_scanned"] >= 330
    # As of #387 there was no protected Task1 live Provider job; if one
    # appeared it requires explicit audit rather than silently accepting it.
    assert result["inventory"]["task1_environment_secret_binding_jobs_found"] == []
    assert result["execution_authorized"] is False
    assert result["actual_task1_provider_posts"] == 0
    assert result["new_utility_score"] is None
    assert result["trusted_protected_singleton_issuer_verified"] is False
    assert result["provider_project_hard_spend_cap_verified"] is False

def test_current_script_and_new_ci_do_not_import_or_bind_live_provider():
    source = Path(m.__file__).read_text()
    workflow = Path(".github/workflows/final128-388-task1-protected-boundary-offline-v1.yml").read_text()
    for forbidden in ("from openai import", "import openai", "requests.post(", "urlopen(",
                      "gh api -X POST", "secrets.OPENAI_API_KEY", "workflow_dispatch:"):
        assert forbidden not in source
    for forbidden in ("workflow_dispatch:", "secrets.OPENAI_API_KEY",
                      "environment: task1-real-model-pilot", "curl -X POST"):
        assert forbidden not in workflow
    assert "contents: read" in workflow
    assert "persist-credentials: false" in workflow
