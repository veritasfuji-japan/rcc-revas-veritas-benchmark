"""Task4 #473 offline-only budget envelope, actual Native SDK wire preflight."""
from __future__ import annotations

from decimal import Decimal
import os
from pathlib import Path

import pytest

from scripts import task4_473_offline_sender_budget_envelope_no_go_v1 as m

RUN_NATIVE = os.environ.get("TASK4_473_NATIVE_PROOF") == "1"


def test_screenshot_limits_and_cost_are_not_authorization():
    d = m.check_envelope()
    assert d["organization_limit_snapshot_usd"] == "1.10"
    assert d["organization_used_snapshot_usd"] == "0.60"
    assert d["project_limit_snapshot_usd"] == "1.00"
    assert d["project_used_snapshot_usd"] == "0.00"
    assert m.screenshot_headroom() == Decimal("0.50")
    assert m.proposed_ceiling() == Decimal("0.396288")
    assert m.proposed_ceiling() < m.PROPOSED_MAX_SPEND
    assert d["provider_token_count_verified"] is False
    assert d["hard_billable_spend_cap_verified"] is False
    assert d["owner_approved"] is False
    assert d["send_enabled"] is False


@pytest.mark.parametrize("tokens,out", [
    (0,0), (1,1), (10000,256), (96000,256), (98048,256)
])
def test_decimal_prices_exact(tokens,out):
    expected = (Decimal(tokens)*Decimal("0.40") +
                Decimal(out)*Decimal("1.60")) / Decimal(1_000_000)
    assert m.price_usd(tokens,out) == expected


@pytest.mark.parametrize("tokens,out", [
    (-1,0),(0,-1),(True,1),(0,False),(0,1.0),
    ("1",0),(10_000_001,0),(0,10_000_001)
])
def test_bad_token_inputs_denied(tokens,out):
    with pytest.raises(m.Denied,match="473_EXACT_NONNEGATIVE"):
        m.price_usd(tokens,out)


@pytest.mark.parametrize("name",m.REJECTED_ENV)
def test_secret_or_approval_context_always_refused(monkeypatch,name):
    monkeypatch.setenv(name,"FORBIDDEN")
    with pytest.raises(m.Denied,match="473_NO_LIVE"):
        m.no_live()


def test_scope_planning_fails_if_headroom_shrinks(monkeypatch):
    monkeypatch.setattr(m,"ORG_USED_SCREENSHOT",Decimal("0.70"))
    with pytest.raises(m.Denied,match="473_PROPOSED_BUDGET"):
        m.check_envelope()


def test_scope_planning_fails_if_approval_claim_changes(monkeypatch):
    monkeypatch.setattr(m,"OWNER_APPROVAL",True)
    with pytest.raises(m.Denied,match="473_MUST_NEVER"):
        m.check_envelope()


def test_scope_planning_fails_if_output_cap_changes(monkeypatch):
    monkeypatch.setattr(m,"MAX_OUTPUT_PER_REQUEST",512)
    with pytest.raises(m.Denied,match="473_SOURCE_PLANNING_SCOPE_DRIFT"):
        m.check_envelope()


def test_proposed_envelope_not_a_proven_token_cap():
    assert m.PLANNING_MAX_INPUT_PROXY == 98048
    assert m.MAX_BODY_BYTES == 96000
    assert m.MAX_TOTAL == 10
    assert m.MAX_PER_ARM == 5
    assert m.MAX_OUTPUT_PER_REQUEST == 256
    assert m.OWNER_APPROVAL is False


def test_new_source_and_ci_never_expose_live_sender():
    src=Path(m.__file__).read_text()
    wf=(m.ROOT/".github/workflows/task4-473-budget-envelope-native-offline.yml").read_text()
    for forbidden in ("requests.post(", "httpx.HTTPTransport(", "socket.AF_INET",
                      "workflow_dispatch:", "pull_request_target:",
                      "secrets.", "contents: write", "id-token: write"):
        assert forbidden not in src
        assert forbidden not in wf
    assert "persist-credentials: false" in wf
    assert "contents: read" in wf
    assert "TASK4_473_NATIVE_PROOF: '1'" in wf


@pytest.mark.skipif(not RUN_NATIVE,
                    reason="requires frozen Native AgentDojo and local AEAD deps")
def test_original_sdk_a_b_wires_preflight_before_separate_worker_and_aead():
    report=m.run_offline_native_budget_join()
    assert report["offline_sdk_requests_budget_checked"] == 8
    assert report["same_run_worker_once_claims"] == 8
    assert report["same_run_preparse_aead_scripted_responses"] == 8
    assert report["same_run_scripted_terminal_arms"] == 2
    assert report["same_run_local_scripted_scorers"] == 2
    assert report["restart_replays_denied"] == 8
    assert len(report["hash_only_budget_preflight_receipts"]) == 8
    assert all(x["sdk_json_bytes"] <= m.MAX_BODY_BYTES
               for x in report["hash_only_budget_preflight_receipts"])
    assert report["real_provider_posts"] == 0
    assert report["external_bank_effects"] == 0
    assert report["genuine_native_utility"] is None
    assert report["score_status"] == "UNSCORED"
    assert report["owner_authorization"] == "ABSENT"
    assert report["sender"] == "NOT_IMPLEMENTED"
    assert report["no_go"] is True
