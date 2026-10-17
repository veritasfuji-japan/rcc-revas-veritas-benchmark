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


def test_protected_manual_live_workflow_is_never_triggered_by_pr_ci():
    live = Path(".github/workflows/final128-423-task1-protected-first-two-native-chat-live-v1.yml").read_text()
    ci = Path(".github/workflows/final128-423-task1-protected-first-native-chat-offline-ci-v1.yml").read_text()
    assert "\n  workflow_dispatch:" in live
    assert "\n  pull_request:" not in live
    assert "\n  push:" not in live
    assert "environment: task1-real-model-pilot" in live
    assert "cancel-in-progress: false" in live
    assert "APPROVE_TASK1_FIRST_NATIVE_A_B_TWO_CALLS_MAX_USD_1" in live
    assert "refs/tags/final128-task1-first-two-real-responses-v1-consumed" in live
    assert "423_PRODUCTION_ONCE_TAG_ALREADY_CONSUMED" in live
    assert "423_NO_EXACT_ACTIVE_NO_BYPASS_PRODUCTION_TAG_RULESET" in live
    assert "TASK1_OPENAI_API_KEY: ${{ secrets.TASK1_OPENAI_API_KEY }}" in live
    assert "TASK1_CAPTURE_AES256_KEY: ${{ secrets.TASK1_CAPTURE_AES256_KEY }}" in live
    assert "gh api -X DELETE" not in live
    assert "curl --retry" not in live
    assert "retention-days: 1" in live
    assert "\n  pull_request:" in ci
    assert "\n  workflow_dispatch:" not in ci
    assert "\npermissions:\n  contents: read\n" in ci
    assert "TASK1_OPENAI_API_KEY: ${{ secrets." not in ci
    assert "TASK1_CAPTURE_AES256_KEY: ${{ secrets." not in ci


def test_live_workflow_uses_exact_consent_and_source_without_task4_authority():
    live = Path(".github/workflows/final128-423-task1-protected-first-two-native-chat-live-v1.yml").read_text()
    assert "task4-real-provider-third-two-calls" not in live
    assert "TASK4_OPENAI_API_KEY: ${{ secrets." not in live
    assert "run_attempt == 1" in live
    assert "refs/heads/main" in live
    assert "task1-423-agentdojo-lock.txt" in live
    assert "TASK1_423_TAG_READBACK_SHA" in live
    assert live.index("TASK1_423_GLOBAL_SINGLETON_TAG_CONSUMED") < live.index(
        "Send ONE FIRST Native Chat POST each A/B")


def test_valid_secrets_preflight_before_consumed_tag_without_provider(native_ready, tmp_path, monkeypatch):
    set_test_protected_env(monkeypatch)
    monkeypatch.delenv("TASK1_423_TAG_CONSUMED", raising=False)
    monkeypatch.delenv("TASK1_423_TAG_READBACK_SHA", raising=False)
    status = m.execute(mode="secrets-preflight", out_dir=tmp_path)
    assert status == {
        "status": "SECRETS_SYNTAX_CHECKED_PRETAG_NOT_APPROVED_TO_SEND",
        "credentials_syntax_checked": True,
        "actual_provider_key_validity_proven": False,
        "enforced_provider_spend_stop_proven": False,
        "production_tag_consumed": False,
        "provider_requests_sent": 0,
        "permission_to_send": False,
    }
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("secret_name, invalid", [
    ("TASK1_OPENAI_API_KEY", ""),
    ("TASK1_OPENAI_API_KEY", "short"),
    ("TASK1_OPENAI_API_KEY", " " + "x" * 24),
    ("TASK1_OPENAI_API_KEY", "x" * 24 + "\n"),
    ("TASK1_CAPTURE_AES256_KEY", ""),
    ("TASK1_CAPTURE_AES256_KEY", "%%%invalid_base64%%"),
    ("TASK1_CAPTURE_AES256_KEY", "not-base64!"),
    ("TASK1_CAPTURE_AES256_KEY", base64.b64encode(bytes(31)).decode()),
    ("TASK1_CAPTURE_AES256_KEY", base64.b64encode(bytes(33)).decode()),
    ("TASK1_CAPTURE_AES256_KEY", base64.b64encode(bytes(16)).decode()),
    ("TASK1_CAPTURE_AES256_KEY", base64.b64encode(bytes(32)).decode() + "\n"),
])
def test_invalid_secret_format_refused_before_irreversible_tag(
    native_ready, tmp_path, monkeypatch, secret_name, invalid
):
    set_test_protected_env(monkeypatch)
    monkeypatch.delenv("TASK1_423_TAG_CONSUMED", raising=False)
    monkeypatch.delenv("TASK1_423_TAG_READBACK_SHA", raising=False)
    monkeypatch.setenv(secret_name, invalid)
    with pytest.raises(m.Denied):
        m.execute(mode="secrets-preflight", out_dir=tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("variable, altered", [
    ("TASK1_423_APPROVAL", "PREVIOUS_TASK4_APPROVAL"),
    ("TASK1_423_ENVIRONMENT", "task4-real-provider-third-two-calls"),
    ("TASK1_423_OPERATOR_BILLING_REVIEW", "no billing check"),
    ("GITHUB_EVENT_NAME", "pull_request"),
    ("GITHUB_RUN_ATTEMPT", "2"),
    ("GITHUB_REF", "refs/heads/test"),
])
def test_pretag_refuses_wrong_runtime_context_or_prior_approval(
    native_ready, tmp_path, monkeypatch, variable, altered
):
    set_test_protected_env(monkeypatch)
    monkeypatch.delenv("TASK1_423_TAG_CONSUMED", raising=False)
    monkeypatch.delenv("TASK1_423_TAG_READBACK_SHA", raising=False)
    monkeypatch.setenv(variable, altered)
    with pytest.raises(m.Denied):
        m.execute(mode="secrets-preflight", out_dir=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_real_send_still_needs_consumed_tag_after_valid_precheck(
    native_ready, tmp_path, monkeypatch
):
    set_test_protected_env(monkeypatch)
    monkeypatch.delenv("TASK1_423_TAG_CONSUMED", raising=False)
    monkeypatch.delenv("TASK1_423_TAG_READBACK_SHA", raising=False)
    pre = m.execute(mode="secrets-preflight", out_dir=tmp_path)
    assert pre["permission_to_send"] is False
    tracker = []
    with pytest.raises(m.Denied, match="POSTCONSUME_TAG_SHA_REQUIRED"):
        m.execute(mode="send", out_dir=tmp_path,
                  connection_factory=lambda: FakeConnection("A", tracker))
    assert tracker == []
    assert list(tmp_path.iterdir()) == []


def test_manual_workflow_pretag_validation_order_and_no_secret_outputs():
    live = Path(
        ".github/workflows/final128-423-task1-protected-first-two-native-chat-live-v1.yml"
    ).read_text(encoding="utf8")
    validate = live.index("Validate Environment API and AES256 secret formats BEFORE singleton consumption")
    precheck = live.index("--mode secrets-preflight")
    consume = live.index("- name: Atomically consume exact no-bypass production once tag")
    send = live.index("- name: Send ONE FIRST Native Chat POST each A/B")
    assert validate < precheck < consume < send
    assert "test -n \"$TASK1_CAPTURE_AES256_KEY\"" not in live
    assert live.count("--mode secrets-preflight") == 1
    assert "--mode send --output-dir results" in live
    assert 'echo "$TASK1_CAPTURE_AES256_KEY"' not in live
    assert 'echo "$TASK1_OPENAI_API_KEY"' not in live
    assert "TASK1_423_GLOBAL_SINGLETON_TAG_CONSUMED_ONE_OPERATION_NO_RETRY" in live
    assert "environment: task1-real-model-pilot" in live
    assert "\n  workflow_dispatch:" in live
    assert "\n  pull_request:" not in live


def test_unknown_preflight_mode_is_no_auth_even_with_environment(native_ready, tmp_path, monkeypatch):
    set_test_protected_env(monkeypatch)
    with pytest.raises(m.Denied, match="MODE_ONLY"):
        m.execute(mode="operator-approves-everything", out_dir=tmp_path)
    assert list(tmp_path.iterdir()) == []


# #425: GitHub operator can read a fixed REASON CATEGORY only, NEVER a
# secret value, length, prefix/suffix, or arbitrary exception message.
@pytest.mark.parametrize("variable,bad,expected", [
    ("GITHUB_EVENT_NAME", "pull_request", "GITHUB_RUNTIME_CONTEXT"),
    ("GITHUB_RUN_ATTEMPT", "2", "GITHUB_RUNTIME_CONTEXT"),
    ("GITHUB_REF", "refs/heads/test", "GITHUB_RUNTIME_CONTEXT"),
    ("GITHUB_ACTOR", "some-other-actor", "GITHUB_RUNTIME_CONTEXT"),
    ("TASK1_423_APPROVAL", "OLD_TEST_CONSENT", "APPROVAL_OR_ENVIRONMENT"),
    ("TASK1_423_ENVIRONMENT", "wrong-environment", "APPROVAL_OR_ENVIRONMENT"),
    ("TASK1_423_OPERATOR_BILLING_REVIEW", "no billing consent", "BILLING_REVIEW"),
    ("TASK1_OPENAI_API_KEY", "", "API_KEY_FORMAT"),
    ("TASK1_OPENAI_API_KEY", "too-short", "API_KEY_FORMAT"),
    ("TASK1_OPENAI_API_KEY", "secret-do-not-log-" + "X" * 28 + "\n",
     "API_KEY_FORMAT"),
    ("TASK1_CAPTURE_AES256_KEY", "", "AES_KEY_BASE64_OR_LENGTH"),
    ("TASK1_CAPTURE_AES256_KEY", "SECRET_DO_NOT_LOG@@" + "x" * 80,
     "AES_KEY_BASE64_OR_LENGTH"),
    ("TASK1_CAPTURE_AES256_KEY", base64.b64encode(bytes(31)).decode(),
     "AES_KEY_BASE64_OR_LENGTH"),
    ("TASK1_CAPTURE_AES256_KEY", base64.b64encode(bytes(33)).decode(),
     "AES_KEY_BASE64_OR_LENGTH"),
    ("TASK1_CAPTURE_AES256_KEY", base64.b64encode(bytes(32)).decode() + "\n",
     "AES_KEY_BASE64_OR_LENGTH"),
])
def test_safe_pretag_cli_redacts_values_and_distinguishes_failure_classes(
    native_ready, tmp_path, monkeypatch, capsys, variable, bad, expected
):
    import sys
    set_test_protected_env(monkeypatch)
    monkeypatch.delenv("TASK1_423_TAG_CONSUMED", raising=False)
    monkeypatch.delenv("TASK1_423_TAG_READBACK_SHA", raising=False)
    monkeypatch.setenv(variable, bad)
    monkeypatch.setattr(sys, "argv", [
        "task1-423", "--mode", "secrets-preflight",
        "--output-dir", str(tmp_path),
    ])
    with pytest.raises(SystemExit) as rejected:
        m.main()
    assert rejected.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "TASK1_425_PRETAG_DENIAL_CATEGORY=" + expected + "\n"
    )
    assert bad not in captured.err or bad == ""
    assert "Traceback" not in captured.err
    assert "SECRET_DO_NOT_LOG" not in captured.err
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("invalid_exception,expected", [
    (m.Denied("423_DEDICATED_ENVIRONMENT_API_SECRET_MISSING"), "API_KEY_FORMAT"),
    (m.Denied("423_NO_VALID_ENVIRONMENT_ENCRYPTION_KEY"), "AES_KEY_BASE64_OR_LENGTH"),
    (m.Denied("423_ENCRYPTION_KEY_MUST_BE_CANONICAL_BASE64_OF_32_BYTES"),
     "AES_KEY_BASE64_OR_LENGTH"),
    (m.Denied("423_POSTCONSUME_TAG_SHA_REQUIRED"), "OTHER_PRETAG_FAILURE"),
    (m.Denied("SECRET_SENTINEL_INVALID_BECAUSE_SOMEONE_INJECTED_IT"),
     "OTHER_PRETAG_FAILURE"),
    (ValueError("SECRET_SENTINEL_ARBITRARY_EXCEPTION"), "OTHER_PRETAG_FAILURE"),
    (RuntimeError("SECRET_SENTINEL_UNEXPECTED_RUNTIME"), "OTHER_PRETAG_FAILURE"),
])
def test_pretag_category_allowlist_is_closed_to_arbitrary_exception_text(
    invalid_exception, expected
):
    result = m.safe_pretag_refusal_category(invalid_exception)
    assert result == expected
    assert "SECRET_SENTINEL" not in result
    assert result == "OTHER_PRETAG_FAILURE" or result in set(
        m.SAFE_PRETAG_REFUSAL_CATEGORIES.values()
    )


def test_unexpected_exception_in_pretag_cli_never_prints_secret_exception(
    native_ready, tmp_path, monkeypatch, capsys
):
    import sys
    set_test_protected_env(monkeypatch)
    marker = "SECRET_SENTINEL_DO_NOT_EVER_PRINT"
    def invalid_native_source():
        raise RuntimeError(marker)
    monkeypatch.setattr(m, "source_pair", invalid_native_source)
    monkeypatch.setattr(sys, "argv", [
        "task1-423", "--mode", "secrets-preflight",
        "--output-dir", str(tmp_path)
    ])
    with pytest.raises(SystemExit) as rejected:
        m.main()
    assert rejected.value.code == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "TASK1_425_PRETAG_DENIAL_CATEGORY=OTHER_PRETAG_FAILURE\n"
    assert marker not in output.err
    assert not list(tmp_path.iterdir())


def test_safe_pretag_cli_valid_credential_format_never_grants_send(
    native_ready, tmp_path, monkeypatch, capsys
):
    import sys
    set_test_protected_env(monkeypatch)
    monkeypatch.delenv("TASK1_423_TAG_CONSUMED", raising=False)
    monkeypatch.delenv("TASK1_423_TAG_READBACK_SHA", raising=False)
    monkeypatch.setattr(sys, "argv", [
        "task1-423", "--mode", "secrets-preflight",
        "--output-dir", str(tmp_path)
    ])
    m.main()
    c = capsys.readouterr()
    assert "TASK1_425_PRETAG_DENIAL_CATEGORY" not in c.err
    assert "TASK1_OPENAI_API_KEY" not in c.out
    assert list(tmp_path.iterdir()) == []


def test_safe_reason_diagnostics_do_not_modify_manual_live_workflow():
    live = Path(
        ".github/workflows/final128-423-task1-protected-first-two-native-chat-live-v1.yml"
    ).read_text()
    assert live.index("--mode secrets-preflight") < live.index(
        "- name: Atomically consume exact no-bypass production once tag")
    assert live.count("--mode send") == 1
    assert "\n  workflow_dispatch:" in live
    assert "\n  pull_request:" not in live
    assert "TASK1_OPENAI_API_KEY: ${{ secrets.TASK1_OPENAI_API_KEY }}" in live
    assert "TASK1_CAPTURE_AES256_KEY: ${{ secrets.TASK1_CAPTURE_AES256_KEY }}" in live


# #425's read-only GitHub Environment diagnostic is distinct from the
# irreversible paid workflow and has no tag/Provider/GITHUB_TOKEN rights.
@pytest.mark.parametrize("secret_name,bad,expected", [
    ("TASK1_OPENAI_API_KEY", "", "API_KEY_FORMAT"),
    ("TASK1_OPENAI_API_KEY", "short", "API_KEY_FORMAT"),
    ("TASK1_OPENAI_API_KEY", "X" * 60 + "\n", "API_KEY_FORMAT"),
    ("TASK1_CAPTURE_AES256_KEY", "", "AES_KEY_BASE64_OR_LENGTH"),
    ("TASK1_CAPTURE_AES256_KEY", "DO_NOT_PRINT_SECRET!BAD_BASE64",
     "AES_KEY_BASE64_OR_LENGTH"),
    ("TASK1_CAPTURE_AES256_KEY", base64.b64encode(bytes(31)).decode(),
     "AES_KEY_BASE64_OR_LENGTH"),
    ("TASK1_CAPTURE_AES256_KEY", base64.b64encode(bytes(33)).decode(),
     "AES_KEY_BASE64_OR_LENGTH"),
    ("TASK1_CAPTURE_AES256_KEY", base64.b64encode(bytes(32)).decode() + "\n",
     "AES_KEY_BASE64_OR_LENGTH"),
])
def test_separate_environment_only_diagnostic_classifies_secret_format(
    monkeypatch, capsys, secret_name, bad, expected
):
    from scripts import final128_425_task1_environment_secret_diagnostic_v1 as safe
    set_test_protected_env(monkeypatch)
    monkeypatch.setenv("TASK1_425_DIAGNOSTIC_ENVIRONMENT", safe.ENV)
    monkeypatch.setenv(secret_name, bad)
    with pytest.raises(SystemExit) as v:
        safe.main()
    assert v.value.code == 1
    o=capsys.readouterr()
    assert o.out == safe.PREFIX + expected + "\n"
    assert o.err == ""
    assert bad not in o.out or bad == ""
    assert "DO_NOT_PRINT_SECRET" not in o.out


def test_readonly_diagnostic_accepts_shape_without_proving_provider_auth(
    monkeypatch, capsys
):
    from scripts import final128_425_task1_environment_secret_diagnostic_v1 as safe
    set_test_protected_env(monkeypatch)
    monkeypatch.setenv("TASK1_425_DIAGNOSTIC_ENVIRONMENT", safe.ENV)
    with pytest.raises(SystemExit) as done:
        safe.main()
    assert done.value.code == 0
    out=capsys.readouterr()
    assert out.out == (safe.PREFIX +
        "SHAPES_OK_NOT_A_PROVIDER_AUTHENTICATION\n")
    assert out.err == ""


@pytest.mark.parametrize("name,wrong,expected", [
    ("GITHUB_EVENT_NAME", "pull_request", "GITHUB_RUNTIME_CONTEXT"),
    ("GITHUB_RUN_ATTEMPT", "2", "GITHUB_RUNTIME_CONTEXT"),
    ("GITHUB_REF", "refs/heads/branch", "GITHUB_RUNTIME_CONTEXT"),
    ("GITHUB_REPOSITORY", "wrong/repo", "GITHUB_RUNTIME_CONTEXT"),
    ("GITHUB_ACTOR", "another-user", "GITHUB_RUNTIME_CONTEXT"),
    ("TASK1_425_DIAGNOSTIC_ENVIRONMENT", "wrong-env", "ENVIRONMENT_SCOPE"),
])
def test_readonly_diagnostic_denies_unexpected_context(
    monkeypatch, capsys, name, wrong, expected
):
    from scripts import final128_425_task1_environment_secret_diagnostic_v1 as safe
    set_test_protected_env(monkeypatch)
    monkeypatch.setenv("TASK1_425_DIAGNOSTIC_ENVIRONMENT", safe.ENV)
    monkeypatch.setenv(name, wrong)
    with pytest.raises(SystemExit) as denied:
        safe.main()
    assert denied.value.code == 1
    out=capsys.readouterr()
    assert out.out == safe.PREFIX + expected + "\n"
    assert out.err == ""


def test_readonly_diagnostic_and_paid_sender_share_exact_format_predicate(
    native_ready, monkeypatch
):
    from scripts import final128_425_task1_environment_secret_diagnostic_v1 as safe
    set_test_protected_env(monkeypatch)
    good = safe.classify_secret_shapes(
        api_key=os.environ["TASK1_OPENAI_API_KEY"],
        capture_base64=os.environ["TASK1_CAPTURE_AES256_KEY"])
    assert good == "SHAPES_OK_NOT_A_PROVIDER_AUTHENTICATION"
    key, aes = m.check_live_runtime(require_consumed_tag=True)
    assert key == os.environ["TASK1_OPENAI_API_KEY"]
    assert len(aes) == 32
    monkeypatch.setenv("TASK1_CAPTURE_AES256_KEY", "!UNSAFE_KEY")
    assert safe.classify_secret_shapes(
        api_key=os.environ["TASK1_OPENAI_API_KEY"],
        capture_base64=os.environ["TASK1_CAPTURE_AES256_KEY"]) == (
            "AES_KEY_BASE64_OR_LENGTH")
    with pytest.raises(m.Denied, match="ENCRYPTION_KEY_MUST_BE_CANONICAL"):
        m.check_live_runtime(require_consumed_tag=True)


def test_diagnostic_workflow_is_truly_readonly_and_never_consumes_singleton():
    safe_workflow = Path(
        ".github/workflows/final128-425-task1-readonly-environment-secret-shape-diagnostic-v1.yml"
    ).read_text()
    python = Path(
        "scripts/final128_425_task1_environment_secret_diagnostic_v1.py"
    ).read_text()
    assert "\n  workflow_dispatch:" in safe_workflow
    assert "\n  pull_request:" not in safe_workflow
    assert "\n  push:" not in safe_workflow
    assert "\npermissions:\n  contents: read\n" in safe_workflow
    assert "\n  contents: write" not in safe_workflow
    assert "environment: task1-real-model-pilot" in safe_workflow
    assert "github.run_attempt == 1" in safe_workflow
    assert "persist-credentials: false" in safe_workflow
    assert "TASK1_OPENAI_API_KEY: ${{ secrets.TASK1_OPENAI_API_KEY }}" in safe_workflow
    assert "TASK1_CAPTURE_AES256_KEY: ${{ secrets.TASK1_CAPTURE_AES256_KEY }}" in safe_workflow
    forbidden = (
        "gh api", "GH_TOKEN:", "GITHUB_TOKEN:", "create-refs",
        "git push", "curl ", "wget ", "http.client", "requests.post",
        "openai.chat", "chat.completions", "Run workflow", "--mode send",
        "TASK1_423_APPROVAL", "TASK1_423_OPERATOR_BILLING_REVIEW",
        "actions/upload-artifact", "retention-days", "/git/refs",
        "production_once", "PRODUCTION_TAG",
    )
    for phrase in forbidden:
        assert phrase not in safe_workflow
    for phrase in ("import http.client", "import requests", "from openai",
                   "urllib.request", "create_ref", "one_post(", "subprocess"):
        assert phrase not in python
    assert "print(PREFIX + result)" in python
    assert "raise SystemExit(0 if result ==" in python
