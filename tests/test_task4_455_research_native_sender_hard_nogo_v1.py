"""#455: source-level hard stop at the real Native→SDK first HTTP wire.

No real Provider, Secrets, protected Environment, real bank effect, or spend.
Only the dedicated job executes pinned native integration; ordinary CI covers
immutable denial and replay invariant tests without installing AgentDojo.
"""
from __future__ import annotations

import os
from pathlib import Path
import socket
import sys

import pytest

from scripts import task4_455_research_native_sender_hard_nogo_v1 as m

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/task4-455-research-native-sdk-sender-deny.yml"


@pytest.fixture(autouse=True)
def block_external_socket(monkeypatch):
    def fail(*_args, **_kw):
        pytest.fail("455_EXTERNAL_SOCKET_CALL_FORBIDDEN")
    monkeypatch.setattr(socket.socket, "connect", fail)
    monkeypatch.setattr(socket.socket, "connect_ex", fail)
    monkeypatch.setattr(socket, "create_connection", fail)


@pytest.mark.parametrize("key", m.SENSITIVE)
def test_credentials_or_live_context_are_refused(key, monkeypatch):
    for name in m.SENSITIVE:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(key, "NON_SECRET_TEST_SENTINEL")
    with pytest.raises(m.Refused, match="455_PROVIDER_SECRET_OR_LIVE_CONTEXT_DENIED"):
        m.deny_real_context()


def test_gateway_never_delegates_even_if_client_provides_request(monkeypatch):
    for name in m.SENSITIVE:
        monkeypatch.delenv(name, raising=False)
    gate = m.RejectingResearchWire("A")
    monkeypatch.setattr(m, "inspect_sdk_request",
                        lambda *_: {"sdk_body_sha256": "a" * 64})
    with pytest.raises(m.Refused, match="455_HARD_NO_GO"):
        gate.handle_request(object())
    assert gate.calls == 1 and gate.sealed
    assert gate.last == {"sdk_body_sha256": "a" * 64}
    with pytest.raises(m.Refused, match="455_SINGLE_REFUSAL_NO_REPEAT_OR_RETRY"):
        gate.handle_request(object())
    assert gate.calls == 1
    gate.close()


def test_invalid_sdk_request_is_consumed_without_send(monkeypatch):
    gate = m.RejectingResearchWire("B")
    def malformed(*_):
        raise m.Refused("INVALID_WIRE")
    monkeypatch.setattr(m, "inspect_sdk_request", malformed)
    with pytest.raises(m.Refused, match="INVALID_WIRE"):
        gate.handle_request(object())
    assert gate.sealed and gate.calls == 1 and gate.last is None
    with pytest.raises(m.Refused, match="SINGLE_REFUSAL_NO_REPEAT"):
        gate.handle_request(object())


def test_sender_modes_only_offline_native_and_no_secret_read(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(sys, "argv",
                        ["sender", "--mode", "send",
                         "--output", str(tmp_path / "bad.json")])
    with pytest.raises(SystemExit) as e:
        m.main()
    assert e.value.code == 2
    assert not list(tmp_path.iterdir())
    assert "invalid choice" in capsys.readouterr().err


def test_actual_workflow_must_not_be_a_live_sender():
    yaml = WORKFLOW.read_text()
    assert "  pull_request:" in yaml
    assert "\n  workflow_dispatch:" not in yaml
    assert "\n  pull_request_target:" not in yaml
    assert "\n  push:" not in yaml
    assert "\n  schedule:" not in yaml
    assert "contents: read" in yaml
    assert "contents: write" not in yaml
    assert "id-token: write" not in yaml
    assert "environment:" not in yaml
    assert "secrets." not in yaml
    assert "persist-credentials: false" in yaml
    assert "tiktoken==0.12.0" in yaml
    for key in ("OPENAI_API_KEY", "TASK4_OPENAI_API_KEY",
                "ANTHROPIC_API_KEY", "OPENAI_BASE_URL"):
        assert key + ': ""' in yaml
    assert "--mode offline-native-prewire" in yaml
    assert "--mode send" not in yaml


def test_sender_has_no_live_network_fallback_or_persisted_key():
    source = Path(m.__file__).read_text()
    assert "http.client" not in source
    assert "HTTPSConnection(" not in source
    assert "httpx.HTTPTransport" not in source
    assert "requests.post(" not in source
    assert "api_key=os.environ" not in source
    assert "REAL_PROVIDER_DISPATCH = \"DENY\"" in source
    assert "raise Refused(\"455_HARD_NO_GO_EXTERNAL_PROVIDER_TRANSPORT_ABSENT\")" in source
    assert "max_retries=0" in source
    assert "trust_env=False" in source


@pytest.mark.skipif(os.environ.get("TASK4_455_NATIVE_PROOF") != "1",
                    reason="PINNED_NATIVE_CHECKOUT_NOT_AVAILABLE_IN_GENERAL_CI")
def test_original_native_generates_two_exact_first_sdk_requests_but_no_send(monkeypatch):
    for k in m.SENSITIVE:
        monkeypatch.delenv(k, raising=False)
    report = m.stage_paired_native_ab()
    assert report["new_live_provider_dispatch"] == "DENY"
    assert report["actual_provider_calls"] == 0
    assert report["new_true_model_utility_recoveries"] == 0
    assert report["fresh_paid_permission"] is False
    arms = report["arms"]
    assert len(arms) == 2 and [x["arm"] for x in arms] == ["A", "B"]
    assert all(x["status"] ==
               "REAL_NATIVE_FIRST_SDK_REQUEST_CONSTRUCTED_PROVIDER_HARD_DENIED"
               for x in arms)
    assert all(x["first_model_query_attempts"] == 1 and
               x["native_terminal_responses"] == 0 and
               x["native_tool_effects"] == 0 and
               x["native_scorer_calls"] == 0 and
               x["provider_calls"] == 0 and
               x["real_issuer_date_attested"] is False
               for x in arms)
    assert arms[0]["sdk_request"]["sdk_body_sha256"] == \
           arms[1]["sdk_request"]["sdk_body_sha256"]
    for a in arms:
        req = a["sdk_request"]
        assert req["first_own_date"] == "2031-07-08"
        assert req["source_class"] == "REAL_SDK_WIRE_NO_REAL_MODEL"
        assert req["provider_post_allowed"] is False
        assert req["model"] == m.MODEL
        assert 0 < req["sdk_body_bytes"] <= 10_000
        assert 0 < req["local_bpe_not_provider_usage"] <= 10_000


@pytest.mark.skipif(os.environ.get("TASK4_455_NATIVE_PROOF") != "1",
                    reason="PINNED_NATIVE_CHECKOUT_NOT_AVAILABLE_IN_GENERAL_CI")
def test_actual_native_refuses_injected_provider_secret_before_any_sdk_call(monkeypatch):
    monkeypatch.setenv("TASK4_OPENAI_API_KEY", "SENTINEL_NOT_A_KEY")
    with pytest.raises(m.Refused, match="455_PROVIDER_SECRET_OR_LIVE_CONTEXT_DENIED"):
        m.stage_paired_native_ab()
