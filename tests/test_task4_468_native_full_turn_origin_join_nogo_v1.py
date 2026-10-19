"""#468: reject the invented combination of separately owned offline SDK sources."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from scripts import task4_468_native_full_turn_origin_join_nogo_v1 as m


def fixture():
    first = {
        "rule_of_one":
            "TASK4_463_NATIVE_SDK_PREDISPATCH_SEPARATE_BROKER_HARD_DENY_V1",
        "first_native_sdk_requests": 2,
        "local_broker_consumed_once": 2,
        "broker_replay_refusals_after_restart": 2,
        "sender_external_transport_installed": False,
        "actual_provider_calls": 0,
        "real_provider_dispatch": "DENY",
        "score_status": "UNSCORED", "genuine_utility": None,
        "fresh_owner_paid_consent": False,
        "trusted_real_date_authority_proven": False,
        "hash_only_pre_dispatch_receipts": [
            {"arm": arm, "ordinal": 0, "request_sha256": "a"*64,
             "receipt_sha256": "b"*64, "decision": "LOCAL_CONSUMED_NO_SEND",
             "live_post": False} for arm in ("A", "B")],
    }
    full = {
        "rule_of_one":
            "TASK4_459_SINGLE_LOCAL_NATIVE_SOURCE_BROKER_ENCRYPTED_CUSTODY_JOIN_NO_PROVIDER_V1",
        "case_id": m.CASE,
        "source": "LOCAL_SCRIPTED_OPENAI_SDK_MOCK_NOT_REAL_LLM",
        "native_model_requests_captured": 8,
        "encrypted_broker_slots_recovered_after_restart": 8,
        "source_native_terminals": 2,
        "source_detached_native_scorer_calls": 2,
        "real_provider_posts": 0, "new_genuine_utility": 0,
        "provider_authenticated": False,
        "real_execution_date_authority_proven": False,
        "off_runner_custody_proven": False,
        "independent_cross_runner_cas_proven": False,
        "live_dispatch": "DENY",
        "hash_only_receipts": [
            {"arm": arm, "ordinal": index,
             "request_sha256": "a"*64 if index == 0 else "c"*64,
             "response_sha256": "d"*64,
             "ciphertext_sha256": "e"*64,
             "broker_receipt_sha256": "f"*64}
            for arm in ("A", "B") for index in range(4)],
    }
    return first, full


def test_existing_full_and_first_reports_are_both_valid_but_nonpromotable():
    first, full = fixture()
    result = m.verify_legacy_offline_sources(first, full)
    assert result["first_native_model_attempts"] == 2
    assert result["synthetic_full_native_requests"] == 8
    assert result["real_provider_responses"] == 0
    assert result["genuine_same_run_real_provider_join"] is False
    assert result["real_native_ab_utility_scored"] is False
    assert result["promotion_allowed"] is False


def test_even_identical_first_wire_hashes_do_not_establish_shared_run():
    first, full = fixture()
    for x in full["hash_only_receipts"]:
        if x["ordinal"] == 0:
            x["request_sha256"] = first["hash_only_pre_dispatch_receipts"][0][
                "request_sha256"]
    assert m.verify_legacy_offline_sources(first, full)[
        "genuine_same_run_real_provider_join"] is False


@pytest.mark.parametrize("change", [
    "first_count", "first_broker_count", "first_replay",
    "first_sends", "first_provider_call", "first_allow",
    "first_true_score", "first_fake_utility", "first_spending",
    "first_real_date", "first_wrong_rule", "first_missing_receipt",
    "first_duplicate_arm", "first_extra_ordinal", "first_fake_send",
    "first_invalid_sha", "full_wrong_rule", "full_wrong_case",
    "full_origin_real", "full_7_only", "full_9_calls",
    "full_terminals_missing", "full_scorer_missing", "full_posts",
    "full_fake_utility", "full_authenticated", "full_true_clock",
    "full_true_custody", "full_cross_runner", "full_allow",
    "full_duplicate_slot", "full_arm_swap", "full_wrong_ordinal",
    "full_bad_sha", "full_missing_cipher",
])
def test_forged_legacy_source_or_missing_turn_fails_closed(change):
    first, full = copy.deepcopy(fixture())
    frec = first["hash_only_pre_dispatch_receipts"]
    crec = full["hash_only_receipts"]
    change_map = {
        "first_count": (first, "first_native_sdk_requests", 4),
        "first_broker_count": (first, "local_broker_consumed_once", 0),
        "first_replay": (first, "broker_replay_refusals_after_restart", 0),
        "first_sends": (first, "sender_external_transport_installed", True),
        "first_provider_call": (first, "actual_provider_calls", 1),
        "first_allow": (first, "real_provider_dispatch", "ALLOW"),
        "first_true_score": (first, "score_status", "SCORED"),
        "first_fake_utility": (first, "genuine_utility", True),
        "first_spending": (first, "fresh_owner_paid_consent", True),
        "first_real_date": (first, "trusted_real_date_authority_proven", True),
        "first_wrong_rule": (first, "rule_of_one", "OTHER"),
        "full_wrong_rule": (full, "rule_of_one", "OTHER"),
        "full_wrong_case": (full, "case_id", "OTHER"),
        "full_origin_real": (full, "source", "REAL_PROVIDER_AUTHENTIC"),
        "full_7_only": (full, "native_model_requests_captured", 7),
        "full_9_calls": (full, "encrypted_broker_slots_recovered_after_restart", 9),
        "full_terminals_missing": (full, "source_native_terminals", 1),
        "full_scorer_missing": (full, "source_detached_native_scorer_calls", 1),
        "full_posts": (full, "real_provider_posts", 1),
        "full_fake_utility": (full, "new_genuine_utility", 1),
        "full_authenticated": (full, "provider_authenticated", True),
        "full_true_clock": (full, "real_execution_date_authority_proven", True),
        "full_true_custody": (full, "off_runner_custody_proven", True),
        "full_cross_runner": (full, "independent_cross_runner_cas_proven", True),
        "full_allow": (full, "live_dispatch", "ALLOW"),
    }
    if change in change_map:
        target, field, value = change_map[change]
        target[field] = value
    elif change == "first_missing_receipt":
        frec.pop()
    elif change == "first_duplicate_arm":
        frec[1]["arm"] = "A"
    elif change == "first_extra_ordinal":
        frec[0]["ordinal"] = 1
    elif change == "first_fake_send":
        frec[0]["live_post"] = True
    elif change == "first_invalid_sha":
        frec[0]["request_sha256"] = "INVALID"
    elif change == "full_duplicate_slot":
        crec[1] = copy.deepcopy(crec[0])
    elif change == "full_arm_swap":
        crec[-1]["arm"] = "A"
    elif change == "full_wrong_ordinal":
        crec[1]["ordinal"] = 4
    elif change == "full_bad_sha":
        crec[0]["response_sha256"] = "fake"
    elif change == "full_missing_cipher":
        del crec[0]["ciphertext_sha256"]
    else:
        pytest.fail("unknown test case")
    with pytest.raises(m.Refused):
        m.verify_legacy_offline_sources(first, full)


@pytest.mark.parametrize("key",m.SENSITIVE)
def test_any_present_live_secret_or_approval_denied(monkeypatch,key):
    monkeypatch.setenv(key, "DO_NOT_USE_REAL_KEY")
    with pytest.raises(m.Refused,match="468_SECRET_OR_PAID_CONTEXT_DENIED"):
        m.report()
    with pytest.raises(m.Refused):
        m.verify_legacy_offline_sources(*fixture())


def test_existing_source_fingerprints_and_seam_boundaries():
    evidence = m.verify_pins()
    assert len(evidence) == 10
    assert m.verify_frozen_cross_origin_limit() is True
    assert all(len(x["git_blob"]) == 40 for x in evidence)


def test_source_drift_rejected_before_any_claim(tmp_path):
    for index, (rel, sha) in enumerate(m.SOURCE_PINS.items()):
        # All files exist but one has fake source bytes.
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"modified at " + str(index).encode())
    with pytest.raises(m.Refused,match="468_SOURCE_DRIFT"):
        m.report(tmp_path)


def test_missing_pin_rejected(tmp_path):
    with pytest.raises(m.Refused):
        m.verify_pins(tmp_path)


def test_source_gaps_and_no_permission_status():
    report = m.report()
    assert len(report["research_missing_evidence"]) == 7
    assert all(row["status"] == "NOT_ATTESTED"
               for row in report["research_missing_evidence"])
    assert report["same_origin_full_turn_real_provider_integration"] == "NOT_IMPLEMENTED"
    assert report["real_model_calls"] == 0
    assert report["genuine_real_model_utility"] is None
    assert report["genuine_injection_outcome"] is None
    assert report["score_status"] == "UNSCORED"
    assert report["real_provider_dispatch"] == "DENY"


def test_manifest_sanitized_and_new_files_never_send():
    report = json.dumps(m.report())
    assert "GB29NWBK60161331926819" not in report
    assert "Please refund " not in report
    script=Path(m.__file__).read_text()
    for banned in (
        "import openai", "import httpx", "import requests",
        "requests.post(", "httpx.Client(", "workflow_dispatch:",
        "secrets.", '"real_provider_dispatch": "ALLOW"',
    ):
        assert banned not in script
    workflow=(m.ROOT /
        ".github/workflows/task4-468-fullturn-source-join-offline.yml").read_text()
    for banned in (
        "workflow_dispatch:", "pull_request_target:", "repository_dispatch:",
        "secrets.", "environment:", "contents: write", "id-token: write",
    ):
        assert banned not in workflow
    assert "pull_request:" in workflow
    assert "contents: read" in workflow
    assert "persist-credentials: false" in workflow
