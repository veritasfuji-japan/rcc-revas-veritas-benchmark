"""#456: fail-closed raw in-memory SDK bytes, no model or bank external effects."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys

import pytest

from scripts import task4_456_raw_response_native_lineage_offline_v1 as m

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/task4-456-native-sdk-raw-capture-no-provider.yml"


def test_journal_initial_state_is_empty_and_not_exportable():
    journal = m.RawResponseJournal()
    assert journal._records == []
    assert journal._bytes == {}
    assert not journal._sealed and not journal._failed
    journal.clear()


def test_no_capture_may_seal_as_real_completion():
    journal = m.RawResponseJournal()
    with pytest.raises(m.Refused, match="EXACT_EIGHT"):
        journal.seal([])
    assert journal._sealed
    with pytest.raises(m.Refused, match="CANNOT_SEAL"):
        journal.seal([])


@pytest.mark.parametrize("bad", [
    b"", b"\xff", b"{", b'{"a":1,"a":2}', b'{"a":NaN}',
    b"x" * (m.MAX_BYTES + 1),
])
def test_decode_rejects_ambiguous_raw_bytes(bad):
    with pytest.raises(m.Refused):
        m.exact_json(bad)


def test_invalid_arm_also_freezes_session():
    journal = m.RawResponseJournal()
    with pytest.raises(m.Refused, match="ARM_REQUIRED"):
        journal.observe(arm="OTHER", request=None, response=None)
    assert journal._failed and journal._bytes == {}
    with pytest.raises(m.Refused, match="SEALED_OR_FAILED"):
        journal.observe(arm="A", request=None, response=None)


@pytest.mark.parametrize("key", m.SENSITIVE)
def test_live_secrets_forbidden(monkeypatch, key):
    for k in m.SENSITIVE:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv(key, "SENTINEL_NOT_A_KEY")
    with pytest.raises(m.Refused, match="LIVE_SECRET_OR_PROVIDER_ENV_DENIED"):
        m.deny_live_environment()


def test_workflow_pure_pr_no_provider_or_secrets():
    y = WORKFLOW.read_text()
    assert "\n  pull_request:" in y
    assert "\n  workflow_dispatch:" not in y
    assert "\n  push:" not in y
    assert "\n  schedule:" not in y
    assert "pull_request_target" not in y
    assert "secrets." not in y
    assert "environment:" not in y
    assert "contents: read" in y and "contents: write" not in y
    assert "id-token: write" not in y
    assert "persist-credentials: false" in y
    assert "--mode offline-native-raw-capture" in y
    for k in ("OPENAI_API_KEY", "TASK4_OPENAI_API_KEY",
              "ANTHROPIC_API_KEY", "OPENAI_BASE_URL"):
        assert k + ': ""' in y


def test_no_other_sender_or_real_provider_network_connection():
    s = Path(m.__file__).read_text()
    assert "http.client" not in s
    assert "requests.post(" not in s
    assert "HTTPSConnection(" not in s
    assert "httpx.HTTPTransport" not in s
    assert "secrets." not in s
    assert "new_genuine_native_utility_scores" in s
    assert '"live_provider_dispatch": "DENY"' in s
    assert 'driver.OneArmMock.__call__' in s
    assert 'original(server, request)' in s


@pytest.fixture
def disabled_external_sockets(monkeypatch):
    def no_socket(*_args, **_kwargs):
        pytest.fail("TASK4_456_EXTERNAL_SOCKET_FORBIDDEN")
    monkeypatch.setattr(socket.socket, "connect", no_socket)
    monkeypatch.setattr(socket.socket, "connect_ex", no_socket)
    monkeypatch.setattr(socket, "create_connection", no_socket)


@pytest.mark.skipif(os.environ.get("TASK4_456_NATIVE_PROOF") != "1",
                    reason="DEDICATED_PINNED_NATIVE_ONLY")
def test_actual_local_sdk_raw_bytes_through_existing_native_and_scorer(
        disabled_external_sockets, monkeypatch):
    for k in m.SENSITIVE:
        monkeypatch.delenv(k, raising=False)
    r = m.run_local_native_sdk_capture()
    assert r["case_id"] == m.CASE
    assert r["source_class"] == "LOCAL_SCRIPTED_RAW_SDK_HTTP_BYTES"
    assert r["distinct_raw_sdk_response_count"] == 8
    assert r["native_selected_arms"] == ["A", "B"]
    assert r["complete_native_terminals_locally"] == 2
    assert r["detached_native_scorer_calls_locally"] == 2
    assert r["durable_encrypted_provider_capture_present"] is False
    assert r["provenance_authenticated_by_provider"] is False
    assert r["real_provider_calls"] == 0
    assert r["new_genuine_native_utility_scores"] == 0
    assert r["live_provider_dispatch"] == "DENY"
    receipts = r["response_receipts"]
    assert len(receipts) == 8
    assert all(x["response_id"] == f'offline-323-{x["arm"]}-{x["ordinal"]}'
               for x in receipts)
    assert len({x["original_response_raw_sha256"] for x in receipts}) == 8
    assert len({x["response_id"] for x in receipts}) == 8
    assert all(x["provider_authenticated"] is False and
               x["raw_response_bytes_volatile_only"] is True
               for x in receipts)
    assert [x["finish_reason"] for x in receipts if x["arm"] == "A"] == \
           ["tool_calls"] * 3 + ["stop"]
    assert [x["finish_reason"] for x in receipts if x["arm"] == "B"] == \
           ["tool_calls"] * 3 + ["stop"]
    assert r["native_audit_report_sha256"] != r["native_wire_lineage_sha256"]


@pytest.mark.skipif(os.environ.get("TASK4_456_NATIVE_PROOF") != "1",
                    reason="DEDICATED_PINNED_NATIVE_ONLY")
def test_native_capture_denies_secret_before_any_sdk_response(
        disabled_external_sockets, monkeypatch):
    monkeypatch.setenv("TASK4_OPENAI_API_KEY", "TEST_SENTINEL_NOT_KEY")
    with pytest.raises(m.Refused, match="LIVE_SECRET_OR_PROVIDER_ENV_DENIED"):
        m.run_local_native_sdk_capture()
