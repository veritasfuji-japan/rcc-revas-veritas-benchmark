"""#460: source-pinned readiness, synthetic nonpromotion and refusal tests."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import pytest

from scripts import task4_460_real_model_readiness_no_go_v1 as m


def example_pair():
    p = {
        "rule_of_one": "TASK4_455_NATIVE_SDK_RESEARCH_SENDER_WIRE_HARD_NO_GO_V1",
        "status": "OFFLINE_NATIVE_SDK_PREWIRE_READY_LIVE_UNAUTHORIZED",
        "case_id": "banking:user_task_4:injection_task_0:direct",
        "actual_provider_calls": 0, "fresh_paid_permission": False,
        "new_true_model_utility_recoveries": 0,
        "new_live_provider_dispatch": "DENY",
        "arms": [{"arm": a, "provider_calls": 0,
                  "real_provider_send_enabled": False,
                  "native_scorer_calls": 0, "real_issuer_date_attested": False}
                 for a in ("A", "B")],
    }
    b = {
        "rule_of_one": "TASK4_459_SINGLE_LOCAL_NATIVE_SOURCE_BROKER_ENCRYPTED_CUSTODY_JOIN_NO_PROVIDER_V1",
        "case_id": p["case_id"],
        "source": "LOCAL_SCRIPTED_OPENAI_SDK_MOCK_NOT_REAL_LLM",
        "paired_arm_sources": ["A", "B"], "native_model_requests_captured": 8,
        "encrypted_broker_slots_recovered_after_restart": 8,
        "source_native_terminals": 2,
        "source_detached_native_scorer_calls": 2,
        "real_provider_posts": 0, "new_genuine_utility": 0,
        "provider_authenticated": False, "off_runner_custody_proven": False,
        "independent_cross_runner_cas_proven": False,
        "real_execution_date_authority_proven": False,
        "live_dispatch": "DENY",
        "hash_only_receipts": [
            {"arm": a, "ordinal": i,
             "request_sha256": "a" * 64, "response_sha256": "b" * 64,
             "ciphertext_sha256": "c" * 64, "broker_receipt_sha256": "d" * 64}
            for a in ("A", "B") for i in range(4)
        ],
    }
    return p, b


def test_exact_repo_sources_and_nogo():
    r = m.readiness()
    assert len(r["source_pins_checked"]) == 8
    assert len(r["research_gates_not_attested"]) == 8
    assert len(r["production_gates_not_attested"]) == 3
    assert r["real_provider_dispatch"] == "DENY"
    assert r["fresh_owner_paid_consent"] is False
    assert r["true_utility"] is None and r["true_injection"] is None
    assert r["score_status"] == "UNSCORED"
    assert r["same_run_real_A_B_native_terminal_proven"] is False


def test_distinct_offline_paths_stay_unscored():
    r = m.classify_distinct_offline_reports(*example_pair())
    assert r["real_provider_dispatch"] == "DENY"
    assert r["native_score"] == "UNSCORED"
    assert r["genuine_utility"] is None
    assert r["classification"] == "SEPARATE_OFFLINE_EVIDENCE_NOT_GENUINE_SAME_RUN"


@pytest.mark.parametrize("which", [
    "real_provider", "owner_consent", "fake_utility", "fake_injection",
    "fake_cas", "fake_external", "research_gate_promotion",
    "production_gate_promotion", "new_model", "other_case",
    "false_cost_guarantee", "limit_expansion", "missing_blob_pin",
    "unexpected_field"
])
def test_contract_forgery_fails_closed(which):
    c = copy.deepcopy(m.load_contract())
    if which == "real_provider": c["nonclaims"]["real_provider_dispatch"] = "ALLOW"
    if which == "owner_consent": c["nonclaims"]["fresh_owner_paid_consent"] = True
    if which == "fake_utility": c["nonclaims"]["genuine_task4_utility"] = 1
    if which == "fake_injection": c["nonclaims"]["genuine_injection_outcome"] = 0
    if which == "fake_cas": c["nonclaims"]["cross_runner_cas_proven"] = True
    if which == "fake_external": c["nonclaims"]["external_validation"] = True
    if which == "research_gate_promotion": c["research_gates"][0]["state"] = "PROVEN"
    if which == "production_gate_promotion": c["production_gates"][0]["state"] = "PROVEN"
    if which == "new_model": c["model_candidate"] = "gpt-6"
    if which == "other_case": c["case_id"] = "different"
    if which == "false_cost_guarantee": c["planning_limits_not_consent"]["estimate_not_hard_cap"] = False
    if which == "limit_expansion": c["planning_limits_not_consent"]["posts_total"] = 11
    if which == "missing_blob_pin": del c["source_blob_pins"][next(iter(c["source_blob_pins"]))]
    if which == "unexpected_field": c["live_approval"] = True
    with pytest.raises(m.Refused):
        m.validate(c)


@pytest.mark.parametrize("which", [
    "reclassify_provider", "reclassify_owner", "new_utility",
    "false_real_origin", "false_terminal", "wrong_arm", "reused_slot",
    "changed_digest", "missing_slot", "forged_date",
    "cross_runner_proven", "provider_authenticated"
])
def test_offline_report_promotion_is_refused(which):
    p, b = example_pair()
    if which == "reclassify_provider": p["actual_provider_calls"] = 1
    if which == "reclassify_owner": p["fresh_paid_permission"] = True
    if which == "new_utility": b["new_genuine_utility"] = 1
    if which == "false_real_origin": b["source"] = "PROVIDER"
    if which == "false_terminal": b["source_native_terminals"] = 1
    if which == "wrong_arm": p["arms"][0]["arm"] = "B"
    if which == "reused_slot": b["hash_only_receipts"][1]["ordinal"] = 0
    if which == "changed_digest": b["hash_only_receipts"][0]["request_sha256"] = "xyz"
    if which == "missing_slot": b["hash_only_receipts"].pop()
    if which == "forged_date": b["real_execution_date_authority_proven"] = True
    if which == "cross_runner_proven": b["independent_cross_runner_cas_proven"] = True
    if which == "provider_authenticated": b["provider_authenticated"] = True
    with pytest.raises(m.Refused):
        m.classify_distinct_offline_reports(p, b)


def test_source_tampering_denied(tmp_path):
    c = m.load_contract()
    p = tmp_path / "task4_323_single_arm_trajectory_v1.py"
    p.write_bytes(b"synthetic mutated source\n")
    with pytest.raises(m.Refused):
        m.source_fingerprint_check(c, tmp_path)


def test_symlink_source_denied(tmp_path):
    c = m.load_contract()
    (tmp_path / "task4_323_single_arm_trajectory_v1.py").symlink_to("/etc/hosts")
    with pytest.raises(m.Refused):
        m.source_fingerprint_check(c, tmp_path)


def test_secret_environment_fails_closed(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fake")
    with pytest.raises(m.Refused):
        m.readiness()


def test_duplicate_json_fields_are_refused():
    with pytest.raises(m.Refused):
        json.loads('{"x":1,"x":2}', object_pairs_hook=m.strict_pairs)


def test_no_provider_sender_code_or_switch():
    text = Path(m.__file__).read_text(encoding="utf-8")
    for forbidden in ("openai.OpenAI(", "requests.post(", "httpx.Client(",
                      "socket.socket(", "subprocess.run(", "workflow_dispatch"):
        assert forbidden not in text
