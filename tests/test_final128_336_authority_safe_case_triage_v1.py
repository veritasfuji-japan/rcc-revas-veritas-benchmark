"""#336: authentic prior-result provenance triage. No Provider or tool effects."""
from collections import Counter
from copy import deepcopy
import socket

import pytest

from scripts import final128_336_authority_safe_case_triage_v1 as m


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refused(*args, **kwargs):
        pytest.fail("NO_OUTBOUND_NETWORK_IN_336")
    monkeypatch.setattr(socket.socket, "connect", refused)
    monkeypatch.setattr(socket.socket, "connect_ex", refused)


@pytest.fixture(scope="module")
def report():
    return m.triage()


def test_all_source_blobs_match_exact_parent():
    c = m.read("contracts/FINAL128_336_AUTHORITY_SAFE_CASE_TRIAGE_V1.json")
    m.check_contract(c)
    assert c["base_main_sha"] == "3ef1f9c8e638599f6a11a06f075b1f1c196d7c40"
    assert set(c["source_blobs"]) == set(m.SOURCE_PINS)
    assert all(m.blob(p) == blob for p, blob in m.SOURCE_PINS.items())


def test_same_run_v13_frozen_and_not_cross_run_gain(report):
    assert report["historical_scored_reference"] == {
        "run": 37585673492, "arm_a": 93, "arm_b": 64,
        "arm_b_injection": 0, "net_gap": 29,
    }
    assert report["official_utility_improvement"] == 0
    assert report["new_final128_scored_runs"] == 0


def test_exact_30_unique_cases_no_unproven_recovery(report):
    rows = report["case_triage"]
    assert report["exact_case_count"] == len(rows) == 30
    assert len({r["case_id"] for r in rows}) == 30
    assert all(r["independently_authorized_as_historical"] is False
               and r["recoverable_from_existing_335_evidence"] is False
               and r["new_native_utility_scored"] is False for r in rows)
    assert Counter(r["v13_failure_lane"] for r in rows) == Counter(m.LANES)


def test_eight_v13_task4_dates_are_not_grants(report):
    rows = [r for r in report["case_triage"]
            if r["case_id"].split(":")[1] == "user_task_4"]
    assert len(rows) == 8
    assert all(r["observed_disposition"] ==
               "PRESERVE_HISTORICAL_DENY_NO_PREISSUED_DATE" for r in rows)
    assert {r["task4_frozen_candidate_date_is_not_authority"] for r in rows} == {
        "2022-03-07", "2024-06-01"}


def test_real_third_two_bind_refusals_not_v13_scores(report):
    assert report["task4_genuine_third_proposals_separate_from_v13"] == 2
    assert report["task4_genuine_third_bind_denials"] == 2
    assert report["task4_genuine_third_native_terminal"] == "UNSCORED"
    assert report["verified_authority_safe_historical_recoveries"] == 0


def test_seven_task14_missing_predicate_never_become_allow(report):
    rows = [r for r in report["case_triage"]
            if r["observed_disposition"] ==
            "PRESERVE_DENY_MISSING_TRUSTED_PREDICATE"]
    assert len(rows) == report["task14_missing_preregistered_predicate_cases"] == 7
    assert all(r["case_id"].split(":")[1] == "user_task_14" for r in rows)


def test_every_other_lane_retains_original_fail_closed_disposition(report):
    mapping = {
        "AUTHORITY_PROTECTIVE_BLOCK": "PRESERVE_DENY_PENDING_EXACT_ORIGINAL_AUTHORITY",
        "MODEL_OR_TRAJECTORY_VARIANCE": "NO_CAUSAL_GOVERNANCE_RECOVERY_ESTABLISHED",
    }
    for row in report["case_triage"]:
        if row["v13_failure_lane"] in mapping:
            assert row["observed_disposition"] == mapping[row["v13_failure_lane"]]


def test_no_paid_model_native_execution_or_claim_promotion(report):
    assert report["provider_dispatch"] == "DENY"
    assert report["new_paid_provider_calls"] == 0
    assert report["native_bank_effects"] == 0
    assert report["new_final128_scored_runs"] == 0
    assert report["treatment_freeze"] is False
    assert report["independent_validation"] is False
    assert report["current_rcc_main_continuity"] == "IMPLEMENTATION_PROOF_PENDING"
    body = deepcopy(report)
    assert body.pop("report_sha256") == m.sha(body)


@pytest.mark.parametrize("field,value", [
    ("base_main_sha", "0"*40),
    ("rule_of_one", "CLAIM_RECOVERY"),
    ("schema", "future.v2"),
])
def test_scope_substitution_rejected(field, value):
    c = m.read("contracts/FINAL128_336_AUTHORITY_SAFE_CASE_TRIAGE_V1.json")
    c[field] = value
    with pytest.raises(m.Refused):
        m.triage(contract_override=c)


@pytest.mark.parametrize("field,value", [
    ("new_recovered_utility", 1),
    ("historical_task4_third_native_applies", 1),
    ("regression_task4", 0),
    ("v13_utility_b", 93),
])
def test_historical_measurement_edit_rejected(field, value):
    c = m.read("contracts/FINAL128_336_AUTHORITY_SAFE_CASE_TRIAGE_V1.json")
    c["expected"][field] = value
    with pytest.raises(m.Refused):
        m.triage(contract_override=c)


@pytest.mark.parametrize("field,value", [
    ("provider_dispatch", "ALLOW"),
    ("retrospective_grant_promotion", True),
    ("model_or_scorer_derived_authority", True),
    ("previously_spent_consent_reusable", True),
    ("change_veritas_resolver_or_bind", True),
    ("independently_issued_production_date_authority", True),
    ("current_wrapper_external_main_proven", True),
    ("all_historical_regressions_recoverable", True),
])
def test_authenticity_or_authority_promotion_rejected(field, value):
    c = m.read("contracts/FINAL128_336_AUTHORITY_SAFE_CASE_TRIAGE_V1.json")
    c["claim_boundary"][field] = value
    with pytest.raises(m.Refused):
        m.triage(contract_override=c)


def test_original_source_hash_tamper_rejected():
    c = m.read("contracts/FINAL128_336_AUTHORITY_SAFE_CASE_TRIAGE_V1.json")
    p = "contracts/TASK4_TRUSTED_EXECUTION_DATE_PROFILE_V1.json"
    c["source_blobs"][p] = "0"*40
    with pytest.raises(m.Refused):
        m.triage(contract_override=c)


def test_model_date_not_upgraded_to_trust(monkeypatch):
    original = m.read
    def changed(path):
        x = original(path)
        if path == "contracts/TASK4_TRUSTED_EXECUTION_DATE_PROFILE_V1.json":
            x["bounded_profile"]["candidate_or_scorer_or_gold_date_as_authority"] = True
        return x
    monkeypatch.setattr(m, "read", changed)
    with pytest.raises(m.Refused, match="TASK4_PROSPECTIVE_DATE"):
        m.triage()


def test_task14_invented_predicate_rejected(monkeypatch):
    original = m.read
    def changed(path):
        x = original(path)
        if path == "contracts/TASK14_CONDITIONAL_PREDICATE_AUTHORITY_V1.json":
            x["determination"]["deterministic_suspiciousness_predicate"] = "PRESENT"
        return x
    monkeypatch.setattr(m, "read", changed)
    with pytest.raises(m.Refused, match="TASK14_MISSING_TRUSTED_PREDICATE"):
        m.triage()


def test_missing_v13_case_fails_not_reclassified(monkeypatch):
    original = m.previous.audit
    def wrong():
        r = deepcopy(original())
        r["v13_regressions_case_level"].pop()
        return r
    monkeypatch.setattr(m.previous, "audit", wrong)
    with pytest.raises(m.Refused, match="EXACT_30_CASE_IDS"):
        m.triage()


def test_arbitrary_output_or_overwrite_fails(tmp_path):
    with pytest.raises(m.Refused, match="FRESH_RESULTS_FILE_ONLY"):
        m.main(["--output", str(tmp_path/"forbidden.json")])
