"""#337 real published current-upstream RCC handoff verification (source-only)."""
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import sys

import pytest

from scripts import final128_337_current_rcc_main_request_boundary_v1 as m


@pytest.fixture(autouse=True)
def no_network_and_no_creds(monkeypatch):
    def stop(*args, **kwargs):
        pytest.fail("337_ANY_NETWORK_IS_FORBIDDEN")
    monkeypatch.setattr(socket.socket, "connect", stop)
    monkeypatch.setattr(socket.socket, "connect_ex", stop)
    for name in m.BANNED_KEYS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(scope="module")
def resources():
    root = Path(os.environ["FINAL128_337_UPSTREAM_ROOT"]).resolve()
    report_dir = m.ROOT / "results/final128-337-current-rcc-main"
    contract = m.validate_contract(m.load_json(m.CONTRACT))
    release = m.verify_source(root, contract)
    sys.path.insert(0, str(release))
    from rcc_revas_eval import native_veritas as native
    run_dir = report_dir / "rcc-run"
    prepared = m.read_jsonl(report_dir / "prepared/veritas_decide_requests.jsonl")
    handoffs = {h["rcc_revas"]["audit"]["case_id"]: h for h in
                m.read_jsonl(run_dir / "handoff_results.jsonl")}
    return report_dir, contract, release, native, run_dir, prepared, handoffs


def test_source_is_real_current_main_not_historical_adapter(resources):
    report_dir, c, release, native, run_dir, prepared, h = resources
    assert c["upstream_main_sha"] == m.PIN
    assert not (release.parent.parent.parent / c["legacy_source_path"]).exists()
    assert len(h) == 36
    assert len(prepared) > 0
    assert native.NATIVE_ADAPTER_VERSION == "rcc-revas-veritas-native-adapter-v0.1.0"


def test_real_current_upstream_full_36_accounting_and_claim_boundary(resources):
    report_dir, c, release, native, run_dir, prepared, h = resources
    report = m.load_json(report_dir / "report.json")
    sha = report.pop("report_sha256")
    assert sha == m.digest(report)
    m.assert_claim_boundary(report)
    assert report["actual_upstream_observed"]["enrolled"] == 36
    assert (report["actual_upstream_observed"]["prepared_requests"] +
            report["actual_upstream_observed"]["withheld"]) == 36
    assert report["actual_upstream_observed"]["errors"] == 0
    assert report["historical_v13_reference_only"]["official_new_utility"] == 0
    assert [j["stage"] for j in report["stage_journal"]] == [
        "preflight", "register-takeshi", "evaluate",
        "verify-artifacts", "prepare-veritas"]


def test_live_prepared_request_is_recomputed_from_real_upstream(resources):
    report_dir, c, release, native, run_dir, prepared, h = resources
    for row in prepared:
        m.verify_one_prepared(row, h[row["case_id"]], run_dir, native)


def test_tamper_candidate_hash_rejected_before_wire(resources):
    report_dir, c, release, native, run_dir, prepared, h = resources
    row = prepared[0]
    forged = deepcopy(h[row["case_id"]])
    forged["candidate"]["selected_output_hash"] = "sha256:" + "0"*64
    with pytest.raises(native.ContractError):
        native.build_decide_request(forged, run_dir)


def test_tamper_source_artifact_reference_rejected(resources):
    report_dir, c, release, native, run_dir, prepared, h = resources
    row = prepared[0]
    forged = deepcopy(h[row["case_id"]])
    forged["source_artifact"]["artifact_hash"] = "sha256:" + "0"*64
    with pytest.raises(native.ContractError):
        native.build_decide_request(forged, run_dir)


def test_tamper_prepared_wire_rejected_without_dispatch(resources):
    report_dir, c, release, native, run_dir, prepared, h = resources
    row = deepcopy(prepared[0])
    row["request"]["context"]["rcc_revas"]["candidate"] = {
        "candidate_type": "malicious_insertion"}
    with pytest.raises(m.Refused, match="337_PREPARED_WIRE_OR_ORIGIN_CHANGED"):
        m.verify_one_prepared(row, h[row["case_id"]], run_dir, native)


def test_matching_response_echo_does_not_prove_native_effect(resources):
    report_dir, c, release, native, run_dir, prepared, h = resources
    proof = prepared[0]["request_proof"]
    echo = {"extras": {"rcc_revas_echo": {
        k: proof[k] for k in (
            "candidate_semantic_hash", "candidate_object_hash",
            "decision_state_binding_fingerprint", "upstream_decision_hash",
            "correlation_id", "evaluation_pre_state_hash")}}}
    result = native.verify_response_echo(echo, proof)
    assert result["status"] == "MATCHING_ECHO_ONLY"
    assert result["exact_candidate_consumption_verified"] is False
    echo["extras"]["rcc_revas_echo"]["candidate_semantic_hash"] = "fake"
    assert native.verify_response_echo(echo, proof)["status"] == "MISMATCH"


@pytest.mark.parametrize("field,value", [
    ("http_posts", 1), ("provider_calls", 1), ("native_bind_calls", 1),
    ("bank_effects", 1), ("canonical_128_new_scores", 1),
    ("native_consumption_verified", True),
    ("current_main_release_v039_adapter_exists", True),
    ("current_full_wrapper_continuity", "PROVEN"),
    ("provider_dispatch", "ALLOW"),
])
def test_fabricated_native_or_performance_claim_rejected(resources, field, value):
    report_dir, c, release, native, run_dir, prepared, h = resources
    report = m.load_json(report_dir / "report.json")
    report[field] = value
    with pytest.raises(m.Refused):
        m.assert_claim_boundary(report)


@pytest.mark.parametrize("section,field,value", [
    ("historical_final128", "official_new_utility", 1),
    ("boundary", "veritas_native_bind_invocations", 1),
    ("boundary", "provider_calls", 1),
    ("boundary", "current_full_wrapper_continuity_status", "PROVEN"),
])
def test_contract_promotion_rejected(section, field, value):
    c = m.load_json(m.CONTRACT)
    c[section][field] = value
    with pytest.raises(m.Refused):
        m.validate_contract(c)


def test_changing_upstream_main_hash_or_release_rejected():
    c = m.load_json(m.CONTRACT)
    c["upstream_main_sha"] = "0"*40
    with pytest.raises(m.Refused):
        m.validate_contract(c)


def test_unapproved_live_cli_action_rejected(resources):
    _, _, release, _, _, _, _ = resources
    with pytest.raises(m.Refused):
        m.run_stage(release, ["invoke-veritas", "--base-url", "https://example.com"])


def test_no_unknown_outdir_or_second_execution(tmp_path):
    with pytest.raises(m.Refused, match="337_FRESH_FIXED_OUTPUT_DIRECTORY_ONLY"):
        # This test does not execute or request any upstream stage.
        m.require(str(tmp_path) == str(m.ROOT / "results/final128-337-current-rcc-main"),
                  "337_FRESH_FIXED_OUTPUT_DIRECTORY_ONLY")
