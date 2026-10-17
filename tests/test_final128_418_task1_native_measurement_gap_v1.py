"""#418 cross-seam Task1 evidence exit: existing native pipeline, NOT a model score."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import subprocess

import pytest

from scripts import final128_418_task1_native_measurement_gap_v1 as gate


@pytest.fixture(autouse=True)
def forbid_network_provider_credentials(monkeypatch):
    def no_network(*_a, **_kw):
        pytest.fail("418_NO_NETWORK_OR_PAID_PROVIDER")
    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket.socket, "connect_ex", no_network)
    for key in ("OPENAI_API_KEY", "TASK4_OPENAI_API_KEY",
                "ANTHROPIC_API_KEY", "OPENAI_BASE_URL",
                "VERITAS_DATABASE_URL", "GITHUB_TOKEN", "GH_TOKEN"):
        monkeypatch.delenv(key, raising=False)


@pytest.fixture(scope="module")
def captured_native():
    root = os.environ.get("FINAL128_403_AGENTDOJO_ROOT")
    if not root:
        if os.environ.get("FINAL128_418_REQUIRE_NATIVE") == "1":
            pytest.fail("418_DEDICATED_CI_REQUIRES_REAL_PINNED_AGENTDOJO")
        pytest.skip("418_GENERIC_CI_HAS_NO_PINNED_NATIVE_CHECKOUT")
    assert subprocess.check_output(["git", "-C", root, "rev-parse", "HEAD"],
                                   text=True).strip() == gate.AGENTDOJO_SHA
    from agentdojo.task_suite.load_suites import get_suite
    roster = json.loads(gate.native.source.ROSTER_FILE.read_text(encoding="utf-8"))
    local = gate.native.run_frozen_task1_integrated_native_ab(
        suite=get_suite("v1.2.2", "banking"),
        enrollment=roster, write_count=2)
    ledger = json.loads((gate.ROOT / gate.LEDGER).read_text(encoding="utf-8"))
    return local, ledger


def test_actual_existing_native_chain_yields_only_gap_not_score(captured_native):
    local, ledger = captured_native
    measured = gate.audit_run(local, ledger)
    assert measured["status"] == gate.STATUS
    assert measured["case_id"] == gate.native.source.CASE
    assert measured["native_actual_pipeline_and_bind_checked"] is True
    assert measured["native_b_bind_refusals"] == 2
    assert measured["native_a_synthetic_in_memory_effects"] == 2
    assert measured["native_b_protected_effects"] == 0
    assert measured["same_model_generated_candidate_proven"] is False
    assert measured["authentic_model_a_and_b_terminals_proven"] is False
    assert measured["one_native_execution_and_official_scorer_same_origin"] is False
    assert measured["new_official_native_utility"] is None
    assert measured["new_official_injection_result"] is None
    assert measured["new_final128_utility_recoveries"] == 0
    assert measured["official_native_scorer_calls"] == 0
    assert measured["eligible_for_official_scoring"] is False
    assert measured["fresh_provider_consent_granted"] is False
    assert measured["remaining_measurement_gates"] == list(gate.BLOCKERS)
    # Never embed user banking contents, injected subjects, synthetic
    # assistant transcripts or native scorer diagnostic outputs.
    exported = json.dumps(measured)
    assert "OFFLINE_403_SCRIPTED_TERMINAL" not in exported
    assert local["ephemeral_original_direct_attack"] not in exported
    assert "1050.00" not in exported


@pytest.mark.parametrize(("field", "invalid"), [
    ("real_independent_provider_model_responses", 2),
    ("paid_provider_calls", 2),
    ("official_native_user_or_attack_scorer_calls", 4),
    ("native_official_utility_B", True),
    ("native_official_attack_success_B", False),
    ("full_production_effect_bypass_resistance_proven", True),
    ("real_credential_egress_enforcement_proven", True),
    ("external_single_use_lease_consumed", True),
    ("fresh_paid_provider_approval_granted", True),
    ("native_actual_pipeline_from_config", False),
    ("B_real_veritas_bind_blocked", 1),
    ("B_protected_native_effects", 1),
    ("scripted_fake_model_steps_per_arm", 0),
])
def test_unearned_model_native_or_authority_promotion_is_refused(
        captured_native, field, invalid):
    run, ledger = captured_native
    fake = deepcopy(run)
    fake["redacted_manifest"][field] = invalid
    with pytest.raises(gate.NotEligible):
        gate.audit_run(fake, ledger)


def test_different_native_tool_source_and_script_histories_refused(captured_native):
    run, ledger = captured_native
    fake = deepcopy(run)
    fake["ephemeral_b"]["pre_mutation_native_yaml_hash"] = "0" * 64
    with pytest.raises(gate.NotEligible, match="PARITY"):
        gate.audit_run(fake, ledger)
    fake = deepcopy(run)
    fake["ephemeral_a"]["events"] = ["forged model"]
    with pytest.raises(gate.NotEligible, match="SYNTHETIC_HISTORY"):
        gate.audit_run(fake, ledger)


def test_unchanged_v13_historical_scores_cannot_count_as_new_recovery(captured_native):
    run, ledger = captured_native
    fake = deepcopy(ledger)
    fake["optimization_target"]["new_official_utility_recoveries"] = 1
    with pytest.raises(gate.NotEligible, match="V13_HISTORICAL"):
        gate.audit_run(run, fake)
    fake = deepcopy(ledger)
    fake["historical_reproduced"]["v13_run"]["artifact_zip_sha256"] = "a" * 64
    with pytest.raises(gate.NotEligible, match="V13_HISTORICAL"):
        gate.audit_run(run, fake)


def test_fake_scored_source_or_foreign_report_shape_is_denied(captured_native):
    run, ledger = captured_native
    fake = deepcopy(run)
    fake["redacted_manifest"]["schema"] = "contract-from-task15-not-task1"
    with pytest.raises(gate.NotEligible, match="EXACT_FROZEN"):
        gate.audit_run(fake, ledger)
    fake = deepcopy(run)
    fake["native_scorer_results"] = {"user": True, "attack": False}
    with pytest.raises(gate.NotEligible, match="RETURN_SHAPE"):
        gate.audit_run(fake, ledger)


def test_non_native_source_pin_must_fail_before_readiness(tmp_path):
    outside = tmp_path / "fake"
    outside.mkdir()
    with pytest.raises((gate.NotEligible, subprocess.CalledProcessError)):
        gate.check_local_pins(outside, outside)


def test_no_paid_provider_or_scoring_added_to_gap_source():
    text = Path(gate.__file__).read_text()
    for token in (
        "client.responses.create(", "client.chat.completions.create(",
        "OpenAI(", "suite._check_task_result(",
        "execute_bind_adjudication(", "send_money(",
    ):
        assert token not in text
    assert "native.run_frozen_task1_integrated_native_ab(" in text
    assert "eligible_for_official_scoring\": False" in text
