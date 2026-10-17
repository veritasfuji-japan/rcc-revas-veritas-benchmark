"""#419: verify existing #403 true Native packet stages, no model/Provider API."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import subprocess

import pytest

from scripts import final128_419_task1_native_three_stage_wire_lineage_v1 as freeze


@pytest.fixture(autouse=True)
def no_external_provider(monkeypatch):
    def block(*_args, **_kwargs):
        pytest.fail("419_NO_EXTERNAL_NETWORK_OR_PROVIDER")
    monkeypatch.setattr(socket.socket, "connect", block)
    monkeypatch.setattr(socket.socket, "connect_ex", block)
    for key in ("OPENAI_API_KEY", "TASK4_OPENAI_API_KEY",
                "ANTHROPIC_API_KEY", "OPENAI_BASE_URL",
                "VERITAS_DATABASE_URL", "GITHUB_TOKEN", "GH_TOKEN"):
        monkeypatch.delenv(key, raising=False)


@pytest.fixture(scope="module")
def native_run():
    root = os.environ.get("FINAL128_403_AGENTDOJO_ROOT")
    if not root:
        if os.environ.get("FINAL128_419_REQUIRE_NATIVE") == "1":
            pytest.fail("419_DEDICATED_MUST_HAVE_REAL_PINNED_NATIVE")
        pytest.skip("419_GENERIC_CI_NO_PINNED_NATIVE_CHECKOUT")
    sha = subprocess.check_output(["git", "-C", root, "rev-parse", "HEAD"],
                                  text=True).strip()
    assert sha == freeze.previous.AGENTDOJO_SHA
    from agentdojo.task_suite.load_suites import get_suite
    ledger = json.loads((freeze.previous.ROOT / freeze.previous.LEDGER).read_text())
    enrollment = json.loads(
        freeze.previous.native.source.ROSTER_FILE.read_text(encoding="utf8"))
    run = freeze.previous.native.run_frozen_task1_integrated_native_ab(
        suite=get_suite("v1.2.2", "banking"),
        enrollment=enrollment,
        write_count=2)
    return run, ledger


def test_exact_existing_native_three_stages_are_frozen_but_never_scored(native_run):
    local, ledger = native_run
    result = freeze.packet_freeze(local, ledger)
    assert result["status"] == freeze.STATUS
    assert result["native_a_and_b_call_ids_distinct"] is True
    assert result["post_executor_b_only_context_position_verified"] is True
    assert result["three_existing_unsent_wire_packets_per_arm"] is True
    assert result["owned_stage_packet_sha256"]["A"]["first"] == (
        result["owned_stage_packet_sha256"]["B"]["first"])
    assert result["owned_stage_packet_sha256"]["A"]["post_read"] != (
        result["owned_stage_packet_sha256"]["B"]["post_read"])
    assert set(result["owned_stage_packet_sha256"]) == {"A", "B"}
    assert all(set(result["owned_stage_packet_sha256"][arm]) == set(freeze.STAGES)
               for arm in freeze.ARMS)
    assert result["new_utility_recoveries"] == 0
    assert result["eligible_for_paid_dispatch"] is False
    assert result["eligible_for_official_scoring"] is False
    assert result["actual_same_run_user_attack_native_scores"] is None
    assert result["genuine_provider_request_response_verified"] is False
    # Never publish actual banking rows, original malicious subject,
    # full Native LLM packets, or the synthetic tool call IDs.
    public = json.dumps(result)
    assert "OFFLINE_403_SCRIPTED_TERMINAL" not in public
    assert local["ephemeral_original_direct_attack"] not in public
    assert "call_403_FAKE_READ_A" not in public


@pytest.mark.parametrize("arm,stage", [
    ("A", "first"), ("B", "first"),
    ("A", "post_read"), ("B", "post_read"),
    ("A", "post_mutation"), ("B", "post_mutation"),
])
def test_packet_tool_catalog_substitution_is_rejected(native_run, arm, stage):
    local, ledger = native_run
    forged = deepcopy(local)
    forged["ephemeral_" + arm.lower()][stage]["tools"] = []
    with pytest.raises((freeze.Refused, freeze.previous.NotEligible)):
        freeze.packet_freeze(forged, ledger)


@pytest.mark.parametrize("arm,stage", [
    ("A", "first"), ("B", "first"),
    ("A", "post_read"), ("B", "post_read"),
    ("A", "post_mutation"), ("B", "post_mutation"),
])
def test_packet_model_or_tool_choice_change_is_rejected(native_run, arm, stage):
    local, ledger = native_run
    forged = deepcopy(local)
    forged["ephemeral_" + arm.lower()][stage]["tool_choice"] = "none"
    with pytest.raises((freeze.Refused, freeze.previous.NotEligible)):
        freeze.packet_freeze(forged, ledger)


def test_swapped_native_arm_tool_return_is_refused(native_run):
    local, ledger = native_run
    forged = deepcopy(local)
    forged["ephemeral_b"]["post_read"]["messages"][3]["tool_call_id"] = (
        forged["ephemeral_a"]["readonly_call_id"])
    with pytest.raises((freeze.Refused, freeze.previous.NotEligible)):
        freeze.packet_freeze(forged, ledger)


def test_post_mutation_tool_call_id_tamper_is_refused(native_run):
    local, ledger = native_run
    forged = deepcopy(local)
    forged["ephemeral_b"]["post_mutation"]["messages"][-1]["tool_call_id"] = "call_FOREIGN"
    with pytest.raises(freeze.Refused, match="RETURN_ID_DRIFT"):
        freeze.packet_freeze(forged, ledger)


def test_same_arm_history_order_shift_is_refused(native_run):
    local, ledger = native_run
    forged = deepcopy(local)
    mm = forged["ephemeral_a"]["post_mutation"]["messages"]
    mm[-1], mm[-2] = mm[-2], mm[-1]
    with pytest.raises(freeze.Refused, match="RETURN_ID_DRIFT"):
        freeze.packet_freeze(forged, ledger)


def test_fake_source_promoted_to_real_model_or_new_utility_is_refused(native_run):
    local, ledger = native_run
    forged = deepcopy(local)
    forged["redacted_manifest"]["native_official_utility_B"] = True
    with pytest.raises(freeze.previous.NotEligible, match="FAKE_NATIVE_SCORE"):
        freeze.packet_freeze(forged, ledger)
    forged = deepcopy(local)
    forged["redacted_manifest"]["real_independent_provider_model_responses"] = 2
    with pytest.raises(freeze.previous.NotEligible, match="SYNTHETIC_EXECUTION"):
        freeze.packet_freeze(forged, ledger)


def test_no_external_paid_sender_or_scorer_in_source():
    source = Path(freeze.__file__).read_text(encoding="utf8")
    for unsafe in ("client.responses.create(", "client.chat.completions.create(",
                   "OpenAI(", "requests.post(", "_check_task_result(",
                   "execute_bind_adjudication(", "send_money("):
        assert unsafe not in source
    assert "previous.native.run_frozen_task1_integrated_native_ab(" in source
