"""Task1 #423 capture-first integration contract; offline and NO EFFECT.

The existing #434 rehearsal already proves mock encryption-before-parse.
These tests pinpoint the still-open #423 LIVE-path integration gap; the
desired live-path properties are strict XFAIL, not a claim of protection.
Nothing in this module imports or runs #423's HTTP sender.
"""
from __future__ import annotations

import ast
import base64
import json
from pathlib import Path
import socket

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest

from scripts import final128_task1_research_capture_first_offline_v1 as mock


ROOT = Path(__file__).resolve().parents[1]
SENDER = ROOT / "scripts/final128_423_task1_protected_first_native_chat_sender_v1.py"
LIVE_WORKFLOW = ROOT / ".github/workflows/final128-423-task1-protected-first-two-native-chat-live-v1.yml"
TEST_KEY = bytes(range(32))  # Public fake-fixture key. NEVER use in production.
FAKE_RUN = "12345678"
FAKE_SHA = "a" * 40
FAKE_PACKET = "b" * 64
RAW_INVALID = b"NOT_VALID_JSON__OFFLINE_FAKE_UNTRUSTED_RESPONSE"


@pytest.fixture(autouse=True)
def prohibit_effects(monkeypatch):
    def deny_network(*_args, **_kwargs):
        pytest.fail("TASK1_423_CAPTURE_CONTRACT_NEVER_NETWORK")
    monkeypatch.setattr(socket.socket, "connect", deny_network)
    monkeypatch.setattr(socket.socket, "connect_ex", deny_network)
    monkeypatch.setattr(socket, "create_connection", deny_network)
    for key in (
        "OPENAI_API_KEY", "TASK1_OPENAI_API_KEY",
        "TASK1_CAPTURE_AES256_KEY", "TASK1_RESEARCH_OPENAI_API_KEY",
        "TASK1_RESEARCH_CAPTURE_AES256_KEY", "GITHUB_TOKEN", "GH_TOKEN",
        "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)


def _sender_function(name: str) -> str:
    text = SENDER.read_text(encoding="utf8")
    functions = [
        node for node in ast.parse(text).body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    ]
    assert len(functions) == 1, f"expected exact named function: {name}"
    return ast.get_source_segment(text, functions[0])


def _private_dir(tmp_path):
    target = tmp_path / "private"
    target.mkdir(mode=0o700)
    target.chmod(0o700)
    return target


def _rehearse(folder):
    return mock.rehearse_mock_then_validate(
        raw=RAW_INVALID, aes256_key=TEST_KEY,
        output_dir=folder, arm="A", run_id=FAKE_RUN,
        main_sha=FAKE_SHA, request_sha256=FAKE_PACKET,
        validator=json.loads,
    )


def test_existing_434_mock_capture_keeps_invalid_body_encrypted(tmp_path):
    """Positive control only: this is NOT integrated into the real sender."""
    target = _private_dir(tmp_path)
    result = _rehearse(target)
    assert result["status"] == "MOCK_VALIDATION_REFUSED_RAW_REMAINS_SEALED"
    assert result["provider_requests"] == 0
    assert result["production_tag_writes"] == 0
    ciphertext_file = target / result["file"]
    stored = ciphertext_file.read_bytes()
    assert RAW_INVALID not in stored
    envelope = json.loads(stored)
    aad = mock._aad(
        arm="A", run_id=FAKE_RUN,
        main_sha=FAKE_SHA, request_sha256=FAKE_PACKET,
    )
    recovered = AESGCM(TEST_KEY).decrypt(
        base64.b64decode(envelope["nonce_base64"]),
        base64.b64decode(envelope["ciphertext_base64"]),
        aad,
    )
    assert recovered == RAW_INVALID
    assert envelope["origin_authenticated"] is False
    assert envelope["eligible_for_paid_dispatch"] is False
    with pytest.raises(FileExistsError):
        _rehearse(target)
    assert ciphertext_file.read_bytes() == stored


def test_scope_does_not_dispatch_live_workflow():
    """Inspection only; no GitHub API, secret, tag or Provider calls."""
    workflow = LIVE_WORKFLOW.read_text(encoding="utf8")
    assert "\n  workflow_dispatch:" in workflow
    assert "\n  pull_request:" not in workflow
    assert "\n  push:" not in workflow
    assert "environment: task1-real-model-pilot" in workflow


@pytest.mark.xfail(
    strict=True,
    reason="OPEN #427: #423 one_post currently rejects HTTP response before sealing",
)
def test_required_live_transport_return_unvalidated_bounded_response():
    """Must become PASS after reviewed integration; no HTTP invoked here."""
    transport = _sender_function("one_post")
    assert "HTTP_UNKNOWN_OR_NON_200_NO_RETRY" not in transport
    assert "NO_PROVIDER_SERVER_REQUEST_ID" not in transport


@pytest.mark.xfail(
    strict=True,
    reason="OPEN #427: #423 shape.capture_one precedes encrypted persistence",
)
def test_required_real_sender_seals_before_schema_or_usage_validation():
    sender = _sender_function("execute")
    assert sender.index("enc = _encrypt_capture(") < sender.index(
        "checked = shape.capture_one("
    )


@pytest.mark.xfail(
    strict=True,
    reason="OPEN #427: #423 encrypted evidence uses non-exclusive write_bytes",
)
def test_required_real_sender_uses_exclusive_durable_ciphertext_commit():
    sender = _sender_function("execute")
    assert "encrypted_path.write_bytes(" not in sender
    assert (
        "_write_private_capture(" in sender
        or "_write_exclusive_encrypted(" in sender
        or "seal_mock_before_parse(" in sender
    )
