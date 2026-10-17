"""#423 protected Native first A/B Chat sender tests: NO external calls."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
from types import SimpleNamespace as NS

import pytest

from scripts import final128_423_task1_protected_first_native_chat_sender_v1 as m


@pytest.fixture(autouse=True)
def zero_paid_network(monkeypatch):
    def blocked(*_args, **_kwargs):
        pytest.fail("423_NO_OUTBOUND_NETWORK_IN_CI")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    for key in ("OPENAI_API_KEY", "TASK1_OPENAI_API_KEY", "TASK1_CAPTURE_AES256_KEY",
                "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GH_TOKEN", "GITHUB_TOKEN",
                "OPENAI_BASE_URL", "VERITAS_DATABASE_URL"):
        monkeypatch.delenv(key, raising=False)


@pytest.fixture(scope="module")
def native_ready():
    root = os.environ.get("FINAL128_403_AGENTDOJO_ROOT")
    if not root:
        if os.environ.get("FINAL128_423_REQUIRE_NATIVE") == "1":
            pytest.fail("423_PINNED_NATIVE_CHECKOUT_REQUIRED")
        pytest.skip("423_GENERIC_CI_NO_PINNED_NATIVE_CHECKOUT")
    sha = subprocess.check_output(["git", "-C", root, "rev-parse", "HEAD"], text=True).strip()
    assert sha == m.exit_gate.AGENTDOJO_SHA
    run, ledger, pair = m.source_pair()
    return run, ledger, pair


def make_body(arm="A", model=m.MODEL, reason="tool_calls"):
    call = [{
        "id": f"call_LOCAL_FAKE_{arm}_000000",
        "type": "function",
        "function": {"name": "get_most_recent_transactions", "arguments": '{"n":100}'},
    }] if reason == "tool_calls" else None
    return json.dumps({
        "id": f"chatcmpl-LOCAL_FAKE_{arm}_000000",
        "model": model,
        "object": "chat.completion",
        "created": 1750000000,
        "choices": [{
            "index": 0, "finish_reason": reason,
            "message": {"role": "assistant", "content":
                        None if call else "OFFLINE_NON_MODEL_TERMINAL",
                        "tool_calls": call, "refusal": None}, "logprobs": None,
        }],
        "usage": {"prompt_tokens": 405, "completion_tokens": 12, "total_tokens": 417},
        "system_fingerprint": None,
    }, sort_keys=True).encode()


class FakeReply:
    def __init__(self, body: bytes, arm: str, status=200):
        self.body = body
        self.status = status
        self.arm = arm

    def getheader(self, name):
        assert name == "x-request-id"
        return "req_LOCAL_FAKE_" + self.arm + "_000000"

    def read(self, n):
        assert n == m.MAX_BODY_BYTES + 1
        return self.body


class FakeConnection:
    def __init__(self, arm: str, tracker: list, *, fails=False, status=200):
        self.arm = arm
        self.tracker = tracker
        self.fails = fails
        self.status = status

    def request(self, method, path, body, headers):
        assert method == "POST" and path == "/v1/chat/completions"
        assert headers["X-Client-Request-Id"].startswith("task1-422-" + self.arm + "-")
        assert headers["Content-Type"] == "application/json"
        assert headers["Authorization"] == "Bearer local_fake_key_123456789012345"
        parsed = json.loads(body)
        assert parsed["model"] == m.MODEL
        assert parsed["max_completion_tokens"] == 256
        assert parsed["store"] is False and parsed["stream"] is False
        self.tracker.append(self.arm)
        if self.fails:
            raise TimeoutError("unknown/possibly-billed")

    def getresponse(self):
        return FakeReply(make_body(self.arm), self.arm, self.status)

    def close(self):
        pass


def fake_factory(tracker, *, fail_arm=None, status=200):
    arm_number = len(tracker)
    arm = m.ARMS[arm_number] if arm_number < len(m.ARMS) else "UNEXPECTED"
    return lambda: FakeConnection(arm, tracker, fails=arm == fail_arm, status=status)


def set_test_protected_env(monkeypatch):
    env = {
        "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main", "GITHUB_REPOSITORY": m.REPO,
        "GITHUB_ACTOR": "veritasfuji-japan", "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_RUN_ID": "12345678",
        "GITHUB_SHA": "a" * 40,
        "TASK1_423_APPROVAL": m.APPROVAL,
        "TASK1_423_TAG_CONSUMED": "1",
        "TASK1_423_TAG_READBACK_SHA": "a" * 40,
        "TASK1_423_ENVIRONMENT": m.ENVIRONMENT,
        "TASK1_423_OPERATOR_BILLING_REVIEW":
            "I REVIEWED PROJECT BILLING AND APPROVE MAX USD 1",
        "TASK1_OPENAI_API_KEY": "local_fake_key_123456789012345",
        "TASK1_CAPTURE_AES256_KEY": base64.b64encode(bytes(range(32))).decode(),
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)


def test_preflight_never_issues_authority_or_records_model_calls(native_ready, tmp_path):
    manifest = m.execute(mode="preflight", out_dir=tmp_path)
    assert manifest["case_id"] == m.CASE
    assert manifest["proposed_provider_calls"] == 2
    assert manifest["live_sender_called"] is False
    assert manifest["protected_approval_observed"] is False
    assert manifest["enforced_provider_project_spend_cap_proven"] is False
    assert manifest["new_genuine_utility_recoveries"] == 0
    assert manifest["eligible_for_official_scoring"] is False
    assert json.loads((tmp_path / "task1-423-presend-status.json").read_text()) == manifest
    assert not list(tmp_path.glob("*.enc.json"))


def test_one_mock_post_is_only_single_attempt_no_tool_effect(native_ready):
    run, ledger, pair = native_ready
    tracker = []
    arm = "A"
    conn = lambda: FakeConnection(arm, tracker)
    wire = m.one_post(
        arm=arm, payload=pair["ephemeral_unsent_packets"][arm],
        api_key="local_fake_key_123456789012345",
        client_id="task1-422-A-12345678",
        connection_factory=conn)
    checked = m.shape.capture_one(
        native_run=run, ledger=ledger, prepared=pair, arm=arm, **wire)
    assert tracker == ["A"]
    assert checked["native_tool_dispatches"] == 0
    assert checked["eligible_for_official_scoring"] is False
    assert checked["provider_origin_independently_attested"] is False


def test_real_format_mock_pair_encrypted_and_never_reported_as_real(native_ready, tmp_path, monkeypatch):
    set_test_protected_env(monkeypatch)
    tracker = []
    factory = lambda: FakeConnection(m.ARMS[len(tracker)], tracker)
    results = m.execute(mode="send", out_dir=tmp_path, connection_factory=factory)
    assert tracker == ["A", "B"]
    assert set(results) == {"A", "B"}
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    for arm in m.ARMS:
        f = tmp_path / ("task1-423-" + arm + "-raw-chat.enc.json")
        result = json.loads(f.read_text())
        nonce = base64.b64decode(result["nonce_base64"])
        cipher = base64.b64decode(result["ciphertext_base64"])
        aad = m.canonical({
            "case": m.CASE, "run": "12345678",
            "arm": arm, "request_sha256": results[arm]["request_sha256"],
        })
        raw = AESGCM(bytes(range(32))).decrypt(nonce, cipher, aad)
        assert json.loads(raw)["object"] == "chat.completion"
        assert hashlib.sha256(raw).hexdigest() == result["raw_sha256"]
        assert f"call_LOCAL_FAKE_{arm}" not in f.read_text()
    public = (tmp_path / "task1-423-redacted-journal.jsonl").read_text()
    assert '"actual_call_count": 2' in public
    assert "local_fake_key" not in public
    assert "OFFLINE_NON_MODEL_TERMINAL" not in public
    assert "call_LOCAL_FAKE_" not in public
    assert "provider_enforced_spend_cap_verified" in public
    with pytest.raises(m.Denied, match="NEVER_RESTART"):
        m.execute(mode="send", out_dir=tmp_path, connection_factory=factory)
    assert tracker == ["A", "B"]


@pytest.mark.parametrize("key,changed", [
    ("TASK1_423_APPROVAL", "OLD APPROVAL"),
    ("TASK1_423_TAG_CONSUMED", "0"),
    ("TASK1_423_TAG_READBACK_SHA", "b" * 40),
    ("TASK1_423_ENVIRONMENT", "task4-real-provider-third-two-calls"),
    ("TASK1_423_OPERATOR_BILLING_REVIEW", "unknown"),
    ("GITHUB_RUN_ATTEMPT", "2"),
    ("GITHUB_REF", "refs/heads/not-main"),
    ("GITHUB_EVENT_NAME", "pull_request"),
    ("GITHUB_REPOSITORY", "attacker/forged-repo"),
    ("TASK1_OPENAI_API_KEY", ""),
    ("TASK1_CAPTURE_AES256_KEY", "abc"),
])
def test_deny_missing_or_cross_case_live_boundaries(native_ready, tmp_path, monkeypatch, key, changed):
    set_test_protected_env(monkeypatch)
    monkeypatch.setenv(key, changed)
    tracker = []
    with pytest.raises(m.Denied):
        m.execute(mode="send", out_dir=tmp_path,
                  connection_factory=lambda: FakeConnection("A", tracker))
    assert tracker == []


@pytest.mark.parametrize("arm", ["A", "B"])
def test_timeout_or_429_after_one_attempt_is_not_retried(native_ready, tmp_path, monkeypatch, arm):
    set_test_protected_env(monkeypatch)
    tracker = []
    factory = lambda: FakeConnection(m.ARMS[len(tracker)], tracker,
                                      fails=m.ARMS[len(tracker)] == arm)
    with pytest.raises(TimeoutError):
        m.execute(mode="send", out_dir=tmp_path, connection_factory=factory)
    assert tracker == (["A"] if arm == "A" else ["A", "B"])
    event = (tmp_path / "task1-423-redacted-journal.jsonl").read_text()
    assert "UNKNOWN_PROVIDER_OUTCOME_STOP_NEVER_RETRY" in event
    assert "may_have_billed_after_this_event" in event


@pytest.mark.parametrize("name", ["client.responses.create(", "invoke_native_agentdojo_scorer(",
                                   "send_money(", "execute_bind_adjudication("])
def test_sender_never_runs_native_protected_tools_or_official_scorer(name):
    source = Path(m.__file__).read_text(encoding="utf8")
    assert name not in source
