"""#422: full Chat HTTP reply capture, source-owned native first A/B only.

No live sender, approval, lease, Provider secret, Native effect or score.
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
import socket
import subprocess

import pytest

from scripts import final128_422_task1_native_chat_http_capture_v1 as m


@pytest.fixture(autouse=True)
def protect_no_paid_network(monkeypatch):
    def deny(*_a, **_kw):
        pytest.fail("422_NO_PAID_PROVIDER_OR_NETWORK")
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket.socket, "connect_ex", deny)
    for key in ("OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                "OPENAI_BASE_URL", "VERITAS_DATABASE_URL",
                "GH_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(key, raising=False)


@pytest.fixture(scope="module")
def native():
    root = os.getenv("FINAL128_403_AGENTDOJO_ROOT")
    if not root:
        if os.getenv("FINAL128_422_REQUIRE_NATIVE") == "1":
            pytest.fail("422_DEDICATED_REAL_NATIVE_REQUIRED_NO_SKIP")
        pytest.skip("422_GENERIC_NO_PINNED_NATIVE_ENV")
    assert subprocess.check_output(["git", "-C", root, "rev-parse", "HEAD"],
                                   text=True).strip() == m.first.owned.previous.AGENTDOJO_SHA
    from agentdojo.task_suite.load_suites import get_suite
    src = m.first.owned.previous.native
    roster = json.loads(src.source.ROSTER_FILE.read_text(encoding="utf8"))
    run = src.run_frozen_task1_integrated_native_ab(
        suite=get_suite("v1.2.2", "banking"), enrollment=roster,
        write_count=2)
    ledger = json.loads((m.first.owned.previous.ROOT /
                         m.first.owned.previous.LEDGER).read_text(encoding="utf8"))
    prepared = m.first.freeze_native_first_pair(source_run=run, ledger=ledger)
    return run, ledger, prepared


def response(native, arm="A", function_call=True):
    packet = native[2]["ephemeral_unsent_packets"][arm]
    if function_call:
        message = {"role": "assistant", "content": None,
                   "refusal": None, "annotations": [],
                   "tool_calls": [{
                       "id": "call_FAKE_NATIVE_" + arm + "_00001",
                       "type": "function",
                       "function": {"name": "get_most_recent_transactions",
                                    "arguments": '{"n":100}'},
                   }]}
        reason = "tool_calls"
    else:
        message = {"role": "assistant", "content": "OFFLINE REPLY NOT MODEL",
                   "refusal": None, "tool_calls": None}
        reason = "stop"
    return {
        "id": "chatcmpl-FAKE_NATIVE_" + arm + "_000000",
        "object": "chat.completion",
        "created": 1750000000,
        "model": packet["model"],
        "system_fingerprint": None,
        "service_tier": "default",
        "choices": [{"index": 0, "finish_reason": reason,
                     "message": message, "logprobs": None}],
        "usage": {"prompt_tokens": 400, "completion_tokens": 25,
                  "total_tokens": 425,
                  "prompt_tokens_details": {"cached_tokens": 0},
                  "completion_tokens_details": {"reasoning_tokens": 0}},
    }


def wire(native, arm="A", function_call=True):
    return {
        "client_request_id": "task1-422-" + arm + "-123456",
        "response_status": 200,
        "response_headers": {"x-request-id": "req_NATIVE_FAKE_" + arm + "000000"},
        "raw_response": json.dumps(response(native, arm, function_call),
                                   sort_keys=True).encode("utf8"),
    }


@pytest.mark.parametrize("arm", ["A", "B"])
@pytest.mark.parametrize("function_call", [True, False])
def test_full_chat_http_reduces_to_existing_420_untrusted_validation(native,
                                                                    arm, function_call):
    run, ledger, prepared = native
    candidate = wire(native, arm, function_call)
    result = m.capture_one(native_run=run, ledger=ledger, prepared=prepared,
                           arm=arm, **candidate)
    assert result["status"].endswith("UNAUTHENTICATED")
    assert result["arm"] == arm
    assert result["native_tool_call_count"] == int(function_call)
    assert result["provider_origin_independently_attested"] is False
    assert result["trusted_tls_sender_verified"] is False
    assert result["eligible_for_native_effect"] is False
    assert result["eligible_for_official_scoring"] is False
    assert result["native_tool_dispatches"] == 0
    assert result["new_utility_recoveries"] == 0
    published = json.dumps(result)
    assert "OFFLINE REPLY" not in published
    assert "call_FAKE_NATIVE_" not in published
    assert run["ephemeral_original_direct_attack"] not in published


def test_pair_first_reply_from_distinct_untrusted_provider_sessions_is_still_unscored(native):
    run, ledger, prepared = native
    paired = m.quarantine_pair(native_run=run, ledger=ledger, prepared=prepared,
                               capture_a=wire(native, "A"),
                               capture_b=wire(native, "B"))
    assert paired["status"].endswith("QUARANTINED")
    assert paired["first_A_B_actual_model_generation_proven"] is False
    assert paired["native_tools_dispatched"] == 0
    assert paired["eligible_for_official_scoring"] is False
    assert paired["total_estimated_cost_usd_not_invoice"] != "0"


@pytest.mark.parametrize("alter", [
    lambda d: d.update(object="other"),
    lambda d: d.update(created=True),
    lambda d: d.update(origin_authenticated=True),
    lambda d: d.update(protected_lease=True),
    lambda d: d["choices"][0].update(logprobs={"sensitive":"data"}),
    lambda d: d["choices"][0]["message"].update(function_call={"name":"send_money"}),
    lambda d: d["choices"][0]["message"].update(refusal="I refuse"),
    lambda d: d["choices"][0]["message"].update(audio={"content":"opaque"}),
    lambda d: d["choices"][0]["message"].update(annotations=[{"bad":True}]),
    lambda d: d["usage"].update(total_tokens=100),
    lambda d: d["usage"].update(prompt_tokens=True),
    lambda d: d["usage"].update(completion_tokens=257,total_tokens=657),
    lambda d: d["usage"].update(prompt_tokens=12001,total_tokens=12026),
    lambda d: d["choices"][0]["message"]["tool_calls"][0]["function"].update(
        name="unknown_non_native_tool"),
    lambda d: d["choices"][0]["message"]["tool_calls"][0]["function"].update(
        arguments='{"n":100,"n":1}'),
])
def test_unsupported_full_provider_fields_or_tool_tamper_rejected(native, alter):
    run, ledger, prepared = native
    candidate = wire(native, "A")
    body = json.loads(candidate["raw_response"])
    alter(body)
    candidate["raw_response"] = json.dumps(body).encode()
    with pytest.raises((m.Refused, m.reply.Refused)):
        m.capture_one(native_run=run, ledger=ledger, prepared=prepared,
                      arm="A", **candidate)


@pytest.mark.parametrize("status", [0, 201, 400, 429, 500, 599, True])
def test_unknown_or_non_200_http_is_never_accepted(native, status):
    run, ledger, prepared = native
    candidate = wire(native, "A")
    candidate["response_status"] = status
    with pytest.raises(m.Refused, match="HTTP_NON_SUCCESS"):
        m.capture_one(native_run=run, ledger=ledger, prepared=prepared,
                      arm="A", **candidate)


def test_no_cross_arm_swaps_and_server_replay(native):
    run, ledger, prepared = native
    candidate = wire(native, "A")
    with pytest.raises(m.Refused, match="EXACT_ARM_CLIENT"):
        m.capture_one(native_run=run, ledger=ledger, prepared=prepared,
                      arm="B", **candidate)
    b = wire(native, "B")
    b["response_headers"] = candidate["response_headers"]
    with pytest.raises(m.Refused, match="INDEPENDENT_A_B"):
        m.quarantine_pair(native_run=run, ledger=ledger, prepared=prepared,
                          capture_a=candidate, capture_b=b)
    b = wire(native, "B")
    b["raw_response"] = candidate["raw_response"]
    with pytest.raises(m.Refused, match="INDEPENDENT_A_B"):
        m.quarantine_pair(native_run=run, ledger=ledger, prepared=prepared,
                          capture_a=candidate, capture_b=b)


def test_caller_cannot_spoof_protected_senders_or_source(native):
    run, ledger, prepared = native
    candidate = wire(native, "A")
    candidate["response_headers"] = {"x-request-id": "req_NATIVE_FAKE_A000000",
                                     "authenticated_tls": True}
    with pytest.raises(m.Refused, match="EXACT_SERVER_REQUEST_ID"):
        m.capture_one(native_run=run, ledger=ledger, prepared=prepared,
                      arm="A", **candidate)
    candidate = wire(native, "A")
    changed = deepcopy(prepared)
    changed["ephemeral_unsent_packets"]["A"]["model"] = "gpt-4o"
    with pytest.raises(m.Refused, match="EXACT_LOCAL_NATIVE_FIRST_PAIR"):
        m.capture_one(native_run=run, ledger=ledger, prepared=changed,
                      arm="A", **candidate)
    with pytest.raises(m.Refused, match="NO_PROTECTED_TLS_SENDER"):
        m.deny_paid_send_and_auth("old tag")


def test_standalone_always_has_zero_provider_send_capability():
    from pathlib import Path
    source = Path(m.__file__).read_text()
    for unsafe in ("http.client.HTTPSConnection(", "client.chat.completions.create(",
                   "OpenAI(", "client.responses.create(", "requests.post(",
                   "invoke_native_agentdojo_scorer(", "execute_bind_adjudication("):
        assert unsafe not in source
