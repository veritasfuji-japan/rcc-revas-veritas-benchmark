"""#463 research sender pre-dispatch: fail-closed source/receipt provenance."""
from __future__ import annotations
import copy
import os
from pathlib import Path

import pytest
from scripts import task4_463_research_sender_broker_hard_nogo_v1 as m
from scripts import task4_455_research_native_sender_hard_nogo_v1 as sdk

def offline_pair():
    digest = "a" * 64
    rows = [{
        "arm": arm, "provider_calls": 0, "native_scorer_calls": 0,
        "real_issuer_date_attested": False,
        "real_provider_send_enabled": False,
        "sdk_request": {
            "sdk_body_sha256": digest, "provider_post_allowed": False,
            "date_trust": "OFFLINE_FIXTURE_NOT_REAL_ISSUER",
        },
    } for arm in ("A", "B")]
    old = {
        "rule_of_one": sdk.RULE, "case_id": sdk.CASE,
        "new_live_provider_dispatch": "DENY",
        "actual_provider_calls": 0, "fresh_paid_permission": False,
        "arms": rows,
    }
    receipt = [{
        "arm": arm, "ordinal": 0, "request_sha256": digest,
        "decision": "LOCAL_CONSUMED_NO_SEND", "live_post": False,
    } for arm in ("A", "B")]
    return old, receipt

def test_original_offline_receipts_not_promoted():
    assert m.check_offline_bridge(*offline_pair()) is True

@pytest.mark.parametrize("mode", [
    "wrong_rule", "wrong_case", "provider_allow", "provider_count",
    "fake_paid_approval", "missing_arm", "swapped_arm", "true_date",
    "send_enabled", "scorer_claim", "source_post", "sdk_allow",
    "fake_date_auth", "missing_broker", "wrong_broker_arm",
    "wrong_ordinal", "wrong_request_sha", "duplicate_broker",
    "live_send_claim", "fake_broker_decision", "fake_source_evidence",
])
def test_fake_authority_or_provenance_denied(mode):
    source, receipts = copy.deepcopy(offline_pair())
    if mode == "wrong_rule": source["rule_of_one"] = "OTHER"
    if mode == "wrong_case": source["case_id"] = "banking:wrong"
    if mode == "provider_allow": source["new_live_provider_dispatch"] = "ALLOW"
    if mode == "provider_count": source["actual_provider_calls"] = 1
    if mode == "fake_paid_approval": source["fresh_paid_permission"] = True
    if mode == "missing_arm": source["arms"].pop()
    if mode == "swapped_arm": source["arms"][0]["arm"] = "B"
    if mode == "true_date": source["arms"][0]["real_issuer_date_attested"] = True
    if mode == "send_enabled": source["arms"][0]["real_provider_send_enabled"] = True
    if mode == "scorer_claim": source["arms"][0]["native_scorer_calls"] = 1
    if mode == "source_post": source["arms"][0]["provider_calls"] = 1
    if mode == "sdk_allow": source["arms"][0]["sdk_request"]["provider_post_allowed"] = True
    if mode == "fake_date_auth": source["arms"][0]["sdk_request"]["date_trust"] = "REAL_ISSUER"
    if mode == "missing_broker": receipts.pop()
    if mode == "wrong_broker_arm": receipts[1]["arm"] = "A"
    if mode == "wrong_ordinal": receipts[0]["ordinal"] = 1
    if mode == "wrong_request_sha": receipts[1]["request_sha256"] = "0" * 64
    if mode == "duplicate_broker": receipts[1] = copy.deepcopy(receipts[0])
    if mode == "live_send_claim": receipts[0]["live_post"] = True
    if mode == "fake_broker_decision": receipts[0]["decision"] = "LIVE_ALLOW"
    if mode == "fake_source_evidence": source["arms"][0]["sdk_request"]["sdk_body_sha256"] = "0" * 64
    with pytest.raises(m.Denied):
        m.check_offline_bridge(source, receipts)

@pytest.mark.parametrize("key", [
    "OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "OPENAI_BASE_URL",
    "ANTHROPIC_API_KEY", "VERITAS_DATABASE_URL",
    "TASK4_463_PAID_APPROVAL", "GITHUB_TOKEN", "GH_TOKEN",
])
def test_real_credential_or_approval_env_denied(monkeypatch, key):
    monkeypatch.setenv(key, "sentinel-never-real")
    with pytest.raises(m.Denied):
        m.no_live_environment()

def test_exact_455_and_458_source_pins():
    rows = m.verify_sources()
    assert [r["path"] for r in rows] == list(m.SOURCE_PINS)

def test_source_drift_rejected(tmp_path):
    (tmp_path / "scripts").mkdir()
    for name in m.SOURCE_PINS:
        (tmp_path / name).write_bytes(b"tampered source")
    with pytest.raises(m.Denied):
        m.verify_sources(tmp_path)

def test_no_sender_network_or_live_workflow_code():
    source = Path(m.__file__).read_text()
    for prohibited in (
        "import openai", "httpx.Client(", "requests.post(",
        "socket.socket(", "workflow_dispatch", "secrets.",
        '"real_provider_dispatch": "ALLOW"',
    ):
        assert prohibited not in source
    wf = (Path(m.__file__).resolve().parents[1] /
          ".github/workflows/task4-463-research-sender-broker-hard-nogo.yml").read_text()
    for forbidden in (
        "workflow_dispatch:", "pull_request_target:", "repository_dispatch:",
        "secrets.", "environment:", "contents: write",
        "id-token: write", "OPENAI_API_KEY: ${{",
    ):
        assert forbidden not in wf
    assert "pull_request:" in wf and "contents: read" in wf
    assert "persist-credentials: false" in wf

@pytest.mark.skipif(os.environ.get("TASK4_463_NATIVE_PROOF") != "1",
                    reason="Needs pinned Native AgentDojo/RCC/VERITAS, SDK, tokenizer")
def test_actual_sdk_native_first_two_arms_broker_first_denial():
    report = m.review_native_first_pair()
    assert report["first_native_sdk_requests"] == 2
    assert report["local_broker_consumed_once"] == 2
    assert report["broker_replay_refusals_after_restart"] == 2
    assert [x["arm"] for x in report["hash_only_pre_dispatch_receipts"]] == ["A", "B"]
    assert report["environment_accessed"] is False
    assert report["sender_external_transport_installed"] is False
    assert report["real_provider_dispatch"] == "DENY"
    assert report["actual_provider_calls"] == 0
    assert report["score_status"] == "UNSCORED"
    assert report["genuine_utility"] is None
