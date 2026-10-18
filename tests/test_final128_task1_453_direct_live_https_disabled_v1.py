"""#453: Direct Provider HTTPS unreachable from actual #423 CLI.

No Provider, GitHub, secrets, IAM mutation, tag write, effect or paid call.
An explicitly injected fake transport is not an independently trusted actor.
"""
from __future__ import annotations

from pathlib import Path
import socket
import sys

import pytest

from scripts import final128_423_task1_protected_first_native_chat_sender_v1 as sender

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/final128-423-task1-protected-first-two-native-chat-live-v1.yml"
DOC = ROOT / "docs/optimization/FINAL128_TASK1_453_DIRECT_HTTPS_REMOVAL_NO_GO_V1.md"


@pytest.fixture(autouse=True)
def deny_network_and_sensitive_env(monkeypatch):
    def disallow(*_a, **_kw):
        pytest.fail("453_NETWORK_IS_FORBIDDEN_IN_OFFLINE_TEST")
    monkeypatch.setattr(socket.socket, "connect", disallow)
    monkeypatch.setattr(socket.socket, "connect_ex", disallow)
    monkeypatch.setattr(socket, "create_connection", disallow)
    for name in ("OPENAI_API_KEY", "TASK1_OPENAI_API_KEY",
                 "TASK1_CAPTURE_AES256_KEY", "TASK4_OPENAI_API_KEY",
                 "GH_TOKEN", "GITHUB_TOKEN", "OPENAI_BASE_URL"):
        monkeypatch.delenv(name, raising=False)


def test_real_send_refused_before_native_source_secrets_network(monkeypatch, tmp_path):
    called = []
    def forbidden_native():
        called.append("native")
        pytest.fail("REAL_SEND_MUST_REFUSE_BEFORE_NATIVE_RECONSTRUCTION")
    def forbidden_secrets(*_a, **_kw):
        called.append("secrets")
        pytest.fail("REAL_SEND_MUST_REFUSE_BEFORE_PROVIDER_SECRET_READ")
    monkeypatch.setattr(sender, "source_pair", forbidden_native)
    monkeypatch.setattr(sender, "check_live_runtime", forbidden_secrets)
    with pytest.raises(sender.Denied, match="EXTERNAL_EXECUTOR_REQUIRED"):
        sender.execute(mode="send", out_dir=tmp_path)
    assert called == []
    assert not list(tmp_path.iterdir())


def test_one_post_direct_network_connector_is_removed():
    with pytest.raises(sender.Denied, match="EXTERNAL_EXECUTOR_REQUIRED"):
        sender.one_post(
            arm="A",
            payload={"model": sender.MODEL, "max_completion_tokens": 256,
                     "store": False, "stream": False, "n": 1,
                     "tool_choice": "auto"},
            api_key="OFFLINE_DUMMY_VALUE_MORE_THAN_20",
            client_id="task1-422-A-12345678",
            connection_factory=None)


def test_real_cli_send_is_no_go_without_protected_context(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(sys, "argv", [
        "sender", "--mode", "send", "--output-dir", str(tmp_path)])
    monkeypatch.setattr(sender, "source_pair",
                        lambda: pytest.fail("CLI_MUST_REFUSE_BEFORE_NATIVE"))
    with pytest.raises(SystemExit) as e:
        sender.main()
    assert e.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "TASK1_423_REFUSED_Denied\n"
    assert not list(tmp_path.iterdir())


def test_no_implicit_provider_https_constructor_in_actual_sender():
    content = Path(sender.__file__).read_text(encoding="utf-8")
    assert "http.client.HTTPSConnection(" not in content
    assert "import http.client" not in content
    assert "import ssl" not in content
    assert "connection_factory or (lambda:" not in content
    assert "connection_factory is not None" in content
    assert 'if mode == "send" and connection_factory is None:' in content


def test_workflow_jobs_remain_inert_until_external_controls():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "  preflight:\n    if: ${{ false &&" in text
    assert "  issuer:\n    needs: [preflight]" in text
    assert "  sender:\n    needs: [issuer]\n    if: ${{ false }}" in text
    assert text.count("--mode send --output-dir results") == 1
    assert text.count("TASK1_OPENAI_API_KEY: ${{ secrets.TASK1_OPENAI_API_KEY }}") == 2
    docs = DOC.read_text()
    assert all(k in docs for k in (
        "NO-GO", "#452", "#423", "#427", "external Executor",
        "not externally enforced", "Utility"))
