"""#420 Native Chat reply schema, source binding and nonpromotion (NOT real API)."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import subprocess

import pytest
from scripts import final128_420_task1_native_chat_reply_admission_v1 as m


@pytest.fixture(autouse=True)
def deny_network_and_secret(monkeypatch):
    def denied(*_a, **_kw):
        pytest.fail("420_NO_EXTERNAL_CONNECTION_OR_PAID_API")
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    for k in ("OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
              "OPENAI_BASE_URL", "VERITAS_DATABASE_URL", "GITHUB_TOKEN",
              "GH_TOKEN"):
        monkeypatch.delenv(k, raising=False)


@pytest.fixture(scope="module")
def native():
    root = os.getenv("FINAL128_403_AGENTDOJO_ROOT")
    if not root:
        if os.getenv("FINAL128_420_REQUIRE_NATIVE") == "1":
            pytest.fail("420_DEDICATED_PINNED_NATIVE_CHECKOUT_MANDATORY")
        pytest.skip("420_GENERIC_CI_HAS_NO_PINNED_NATIVE_SOURCE")
    assert subprocess.check_output(["git", "-C", root, "rev-parse", "HEAD"],
                                   text=True).strip() == m.native.previous.AGENTDOJO_SHA
    from agentdojo.task_suite.load_suites import get_suite
    s = m.native.previous.native
    roster = json.loads(s.source.ROSTER_FILE.read_text(encoding="utf8"))
    source_run = s.run_frozen_task1_integrated_native_ab(
        suite=get_suite("v1.2.2", "banking"),
        enrollment=roster, write_count=2)
    ledger = json.loads(
        (m.native.previous.ROOT / m.native.previous.LEDGER).read_text())
    return source_run, ledger


def fake_reply(native, arm="A", stage="first", calls=False):
    """TEST-ONLY untrusted Chat JSON. It cannot stand in for Provider origin."""
    packet = native[0]["ephemeral_" + arm.lower()][stage]
    if calls:
        fn = "get_most_recent_transactions"
        result = {"role": "assistant", "content": None,
                  "tool_calls": [{
                      "id": "call_LOCAL_UNTRUSTED_01234",
                      "type": "function",
                      "function": {"name": fn, "arguments": '{"n":100}'},
                  }]}
        reason = "tool_calls"
    else:
        result = {"role": "assistant",
                  "content": "OFFLINE SHAPE FIXTURE, NEVER REAL UTILITY",
                  "tool_calls": None}
        reason = "stop"
    return {
        "id": "chatcmpl-LOCAL_UNTRUSTED_123456",
        "model": packet["model"],
        "choices": [{"index": 0, "finish_reason": reason, "message": result}],
        "usage": {"prompt_tokens": 500, "completion_tokens": 20},
    }


def serialized(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@pytest.mark.parametrize("arm", ["A", "B"])
@pytest.mark.parametrize("stage", list(m.native.STAGES))
@pytest.mark.parametrize("calls", [False, True])
def test_real_owned_native_request_to_untrusted_shape_never_scored(native,
                                                                   arm, stage, calls):
    run, ledger = native
    response = serialized(fake_reply(native, arm, stage, calls))
    report = m.inspect_untrusted_native_chat_reply(
        source_run=run, frozen_ledger=ledger, arm=arm,
        stage=stage, raw_response=response)
    assert report["case_id"] == m.native.previous.native.source.CASE
    assert report["arm"] == arm and report["stage"] == stage
    assert report["native_tool_call_count"] == int(calls)
    assert report["untrusted_reply_sha256"] == __import__("hashlib").sha256(response).hexdigest()
    assert report["source_owned_request_sha256"] == (
        m.native.packet_freeze(run, ledger)["owned_stage_packet_sha256"][arm][stage])
    assert report["independent_tls_provider_origin_verified"] is False
    assert report["eligible_for_provider_dispatch"] is False
    assert report["eligible_for_official_utility"] is False
    assert report["actual_model_terminal_proven"] is False
    assert report["new_utility_recoveries"] == 0
    assert report["official_utility"] is None
    assert report["official_attack_success"] is None
    public = json.dumps(report)
    assert "OFFLINE SHAPE FIXTURE" not in public
    assert "LOCAL_UNTRUSTED_01234" not in public
    assert run["ephemeral_original_direct_attack"] not in public


@pytest.mark.parametrize("modify", [
    lambda x: x.update(model="wrong"),
    lambda x: x.update(id="not_provider_id"),
    lambda x: x.update(origin_authenticated=True),
    lambda x: x.update(approved=True),
    lambda x: x.update(choices=[]),
    lambda x: x["choices"][0].update(index=True),
    lambda x: x["choices"][0].update(finish_reason="length"),
    lambda x: x["choices"][0]["message"].update(role="system"),
    lambda x: x["choices"][0]["message"].update(content=None),
    lambda x: x["usage"].update(prompt_tokens=12001),
    lambda x: x["usage"].update(completion_tokens=-1),
    lambda x: x["usage"].update(prompt_tokens=True),
])
def test_false_origin_or_bad_completion_is_rejected(native, modify):
    run, ledger = native
    value = fake_reply(native)
    modify(value)
    with pytest.raises(m.Refused):
        m.inspect_untrusted_native_chat_reply(
            source_run=run, frozen_ledger=ledger,
            arm="A", stage="first", raw_response=serialized(value))


@pytest.mark.parametrize("modify", [
    lambda x: x["choices"][0]["message"]["tool_calls"][0]["function"].update(
        name="unknown_write_tool"),
    lambda x: x["choices"][0]["message"]["tool_calls"][0]["function"].update(
        arguments='{"n":100,"n":2}'),
    lambda x: x["choices"][0]["message"]["tool_calls"][0]["function"].update(
        arguments='{"n":NaN}'),
    lambda x: x["choices"][0]["message"]["tool_calls"][0]["function"].update(
        arguments="[]"),
    lambda x: x["choices"][0]["message"]["tool_calls"][0]["function"].update(
        arguments='{"_granted":true}'),
    lambda x: x["choices"][0]["message"]["tool_calls"][0].update(
        id="call_"),
    lambda x: x["choices"][0]["message"]["tool_calls"].append(
        deepcopy(x["choices"][0]["message"]["tool_calls"][0])),
    lambda x: x["choices"][0].update(finish_reason="stop"),
])
def test_tool_schema_and_arguments_fail_closed(native, modify):
    run, ledger = native
    data = fake_reply(native, calls=True)
    modify(data)
    with pytest.raises(m.Refused):
        m.inspect_untrusted_native_chat_reply(
            source_run=run, frozen_ledger=ledger,
            arm="A", stage="first", raw_response=serialized(data))


@pytest.mark.parametrize("raw", [
    b"", b"{}", b"[]", b"{", b'{"x":1,"x":2}', b'{"x":Infinity}',
    b"\xff", b" " * (m.MAX_REPLY_BYTES + 1),
])
def test_invalid_json_never_becomes_provider_proof(native, raw):
    run, ledger = native
    with pytest.raises(m.Refused):
        m.inspect_untrusted_native_chat_reply(
            source_run=run, frozen_ledger=ledger,
            arm="A", stage="first", raw_response=raw)


def test_wrong_native_stage_packet_previously_detected_before_reply(native):
    run, ledger = native
    copy = deepcopy(run)
    copy["ephemeral_b"]["post_read"]["messages"][3]["content"] = [
        {"text": "adversarial tool content"}]
    with pytest.raises((m.Refused, m.native.Refused,
                        m.native.previous.NotEligible)):
        m.inspect_untrusted_native_chat_reply(
            source_run=copy, frozen_ledger=ledger,
            arm="B", stage="post_read",
            raw_response=serialized(fake_reply(native, "B", "post_read")))


def test_live_dispatch_and_score_not_available():
    with pytest.raises(m.Refused, match="NO_PROTECTED_SENDER"):
        m.deny_live_provider_and_native_effect({"approved": True})
    with pytest.raises(m.Refused, match="NOT_AUTHENTICATED"):
        m.deny_official_native_scoring("old approval")
    code = Path(m.__file__).read_text()
    for name in ("OpenAI(", "client.chat.completions.create(",
                 "client.responses.create(", "requests.post(",
                 "invoke_native_agentdojo_scorer(",
                 "execute_bind_adjudication("):
        assert name not in code
