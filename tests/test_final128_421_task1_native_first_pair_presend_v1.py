"""#421 true #403 Native first Chat packet only, never live Provider."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import subprocess

import pytest

from scripts import final128_421_task1_native_first_pair_presend_v1 as m
from scripts import final128_420_task1_native_chat_reply_admission_v1 as reply


@pytest.fixture(autouse=True)
def no_network_or_privileged_env(monkeypatch):
    def block(*_a, **_kw):
        pytest.fail("421_NO_EXTERNAL_NETWORK_OR_PROVIDER")
    monkeypatch.setattr(socket.socket, "connect", block)
    monkeypatch.setattr(socket.socket, "connect_ex", block)
    for name in ("OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                 "OPENAI_BASE_URL", "VERITAS_DATABASE_URL", "GITHUB_TOKEN",
                 "GH_TOKEN"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(scope="module")
def native():
    root = os.getenv("FINAL128_403_AGENTDOJO_ROOT")
    if not root:
        if os.getenv("FINAL128_421_REQUIRE_NATIVE") == "1":
            pytest.fail("421_DEDICATED_NATIVE_REQUIRED_NO_SKIP")
        pytest.skip("421_GENERIC_CI_NO_PINNED_NATIVE_CHECKOUT")
    assert subprocess.check_output(["git", "-C", root, "rev-parse", "HEAD"],
                                   text=True).strip() == m.owned.previous.AGENTDOJO_SHA
    from agentdojo.task_suite.load_suites import get_suite
    predecessor = m.owned.previous.native
    roster = json.loads(predecessor.source.ROSTER_FILE.read_text())
    result = predecessor.run_frozen_task1_integrated_native_ab(
        suite=get_suite("v1.2.2", "banking"), enrollment=roster,
        write_count=2)
    ledger = json.loads((m.owned.previous.ROOT / m.owned.previous.LEDGER).read_text())
    return result, ledger


def test_initial_native_presend_is_exact_unsent_two_arm_same_input(native):
    result, ledger = native
    freeze = m.freeze_native_first_pair(source_run=result, ledger=ledger)
    head = freeze["redacted_manifest"]
    packets = freeze["ephemeral_unsent_packets"]
    assert head["status"] == m.STATUS
    assert head["number_of_proposed_first_chat_calls"] == 2
    assert head["native_later_scripted_stages_sendable"] is False
    assert head["first_packet_SHA256_by_arm"]["A"] == head["first_packet_SHA256_by_arm"]["B"]
    assert packets["A"] == packets["B"] and packets["A"] is not packets["B"]
    assert packets["A"]["messages"] is not packets["B"]["messages"]
    assert packets["A"]["tools"] is not packets["B"]["tools"]
    assert packets["A"]["model"] == m.frozen_chat.MODEL_ID
    assert packets["A"]["max_completion_tokens"] == 256
    assert packets["A"]["n"] == 1
    assert packets["A"]["store"] is False and packets["A"]["stream"] is False
    assert head["eligible_for_live_dispatch"] is False
    assert head["eligible_for_official_scoring"] is False
    assert head["provider_request_count"] == 0
    assert head["new_utility_recoveries"] == 0
    for arm in m.ARMS:
        chk = m.validate_owned_presend_payload(
            prepared=freeze, arm=arm, proposed_payload=packets[arm])
        assert chk["eligible_to_send"] is False
        assert chk["request_sha256"] == head["first_packet_SHA256_by_arm"][arm]
    public = json.dumps(head)
    assert result["ephemeral_original_direct_attack"] not in public
    assert "call_403_FAKE_READ_" not in public
    assert "subject" not in public


@pytest.mark.parametrize("arm", ["A", "B"])
@pytest.mark.parametrize("mutate", [
    lambda p: p.update(model="gpt-other"),
    lambda p: p.update(tool_choice="none"),
    lambda p: p.update(n=2),
    lambda p: p.update(n=True),
    lambda p: p.update(max_completion_tokens=999),
    lambda p: p.update(store=True),
    lambda p: p.update(stream=True),
    lambda p: p.update(messages=[]),
    lambda p: p.update(tools=[]),
    lambda p: p.update(temperature=1.0),
    lambda p: p.update(extra_approval=True),
])
def test_future_send_contract_refuses_tampered_native_inputs(native, arm, mutate):
    source_run, ledger = native
    frozen = m.freeze_native_first_pair(source_run=source_run, ledger=ledger)
    altered = deepcopy(frozen["ephemeral_unsent_packets"][arm])
    mutate(altered)
    with pytest.raises(m.Refused, match="MODIFIED_OR_UNBOUNDED"):
        m.validate_owned_presend_payload(
            prepared=frozen, arm=arm, proposed_payload=altered)


def test_native_first_pair_rejects_scripted_arm_and_bank_source_tamper(native):
    result, ledger = native
    altered = deepcopy(result)
    altered["ephemeral_b"]["first"]["messages"][0]["content"] = (
        "Injected synthetic B-only initial request")
    with pytest.raises((m.Refused, m.owned.Refused,
                        m.owned.previous.NotEligible)):
        m.freeze_native_first_pair(source_run=altered, ledger=ledger)
    altered = deepcopy(result)
    altered["ephemeral_a"]["post_read"]["messages"][3]["content"] = [
        {"text": "tampered attacked tool result"}]
    with pytest.raises((m.Refused, m.owned.Refused,
                        m.owned.previous.NotEligible)):
        m.freeze_native_first_pair(source_run=altered, ledger=ledger)


def test_test_only_tag_cannot_serve_as_production_authorization(native):
    result, ledger = native
    prepared = m.freeze_native_first_pair(source_run=result, ledger=ledger)
    for spoof in [
        {"authenticated_operator_approval": True},
        {"protected_production_single_use_lease_consumed": True},
        {"provider_request_count": 1},
        {"eligible_for_live_dispatch": True},
        {"old_test_only_tag_is_valid_production_lease": True,
         "eligible_for_live_dispatch": True},
    ]:
        bad = deepcopy(prepared)
        bad["redacted_manifest"].update(spoof)
        with pytest.raises(m.Refused, match="CANNOT_MINT_PROVIDER_AUTHORITY"):
            m.validate_owned_presend_payload(
                prepared=bad, arm="A",
                proposed_payload=bad["ephemeral_unsent_packets"]["A"])


def test_future_postread_packet_not_a_valid_first_native_send(native):
    result, ledger = native
    prepared = m.freeze_native_first_pair(source_run=result, ledger=ledger)
    fake_later = deepcopy(result["ephemeral_b"]["post_read"])
    fake_later.update({"n": 1, "max_completion_tokens": 256,
                       "store": False, "stream": False})
    with pytest.raises(m.Refused, match="MODIFIED_OR_UNBOUNDED"):
        m.validate_owned_presend_payload(
            prepared=prepared, arm="B", proposed_payload=fake_later)


def test_first_fake_chat_reply_can_be_inspected_by_420_but_not_promoted(native):
    result, ledger = native
    prepared = m.freeze_native_first_pair(source_run=result, ledger=ledger)
    packet = prepared["ephemeral_unsent_packets"]["A"]
    response = {
        "id": "chatcmpl-LOCAL_REHEARSAL_012345",
        "model": packet["model"],
        "choices": [{
            "index": 0, "finish_reason": "tool_calls",
            "message": {"role": "assistant", "content": None,
                "tool_calls": [{"id": "call_LOCAL_REHEARSAL_56789",
                                "type": "function",
                                "function": {
                                    "name": "get_most_recent_transactions",
                                    "arguments": '{"n":100}'}}]}
        }],
        "usage": {"prompt_tokens": 200, "completion_tokens": 10},
    }
    checked = reply.inspect_untrusted_native_chat_reply(
        source_run=result, frozen_ledger=ledger, arm="A",
        stage="first", raw_response=json.dumps(response).encode())
    assert checked["source_owned_request_sha256"] == (
        prepared["redacted_manifest"]["original_native_initial_input_sha256"])
    assert checked["native_tool_call_count"] == 1
    assert checked["independent_tls_provider_origin_verified"] is False
    assert checked["eligible_for_provider_dispatch"] is False
    assert checked["eligible_for_official_utility"] is False


def test_proposed_budget_is_not_a_verified_project_hard_stop():
    upper = m.reserve_upper_bound_usd()
    assert upper > 0 and upper < m.BUDGET_PROPOSED_USD
    with pytest.raises(m.Refused, match="NO_PROTECTED_LIVE_CHAT_SENDER"):
        m.deny_provider_send_or_model_scoring("consent")
    code = Path(m.__file__).read_text()
    for banned in (
        "client.chat.completions.create(", "client.responses.create(",
        "OpenAI(", "requests.post(", "http.client.HTTPSConnection(",
        "invoke_native_agentdojo_scorer(", "execute_bind_adjudication(",
    ):
        assert banned not in code
