"""Offline fake-HTTP regression: #423 seals bytes BEFORE untrusted validation.

Tests never call the real Provider or GitHub, use no actual credentials,
and do not grant future paid execution authority. Only injected in-memory
fake connections and source-owned synthetic Native packets are exercised.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import socket

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest

from scripts import final128_423_task1_protected_first_native_chat_sender_v1 as m


KEY = bytes(range(32))
FAKE_KEY = "local_fake_offline_never_provider_key_123456789"
FAKE_SHA = "a" * 40
FAKE_RUN = "12345678"
FAKE_RAW_OK = b'{"fake":"OFFLINE_ONLY_VALID_JSON_NO_PROVIDER"}'
FAKE_RAW_BAD = b"OFFLINE_ONLY_INVALID_JSON_PRIVATE_TEST_MARKER"
FAKE_STATUS_BODY = b"OFFLINE_ONLY_HTTP_429_PRIVATE_TEST_MARKER"


@pytest.fixture(autouse=True)
def no_external_network_or_secrets(monkeypatch):
    def deny(*_args, **_kwargs):
        pytest.fail("TASK1_423_CAPTURE_FIRST_TEST_NEVER_NETWORK")
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket.socket, "connect_ex", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    for key in (
        "OPENAI_API_KEY", "TASK1_OPENAI_API_KEY",
        "TASK1_CAPTURE_AES256_KEY", "TASK1_RESEARCH_OPENAI_API_KEY",
        "TASK1_RESEARCH_CAPTURE_AES256_KEY", "GITHUB_TOKEN", "GH_TOKEN",
        "ANTHROPIC_API_KEY", "OPENAI_BASE_URL",
    ):
        monkeypatch.delenv(key, raising=False)


def fake_packet():
    return {
        "model": m.MODEL,
        "messages": [{"role": "user", "content": "OFFLINE_SOURCE_OWNED_TEST"}],
        "max_completion_tokens": 256,
        "n": 1,
        "store": False,
        "stream": False,
        "tool_choice": "auto",
    }


class FakeReply:
    def __init__(self, *, status=200, raw=FAKE_RAW_OK, rid="req_FAKE_A_1234"):
        self.status, self.raw, self.rid = status, raw, rid

    def read(self, n):
        assert n == m.MAX_BODY_BYTES + 1
        return self.raw[:n]

    def getheader(self, name):
        assert name == "x-request-id"
        return self.rid


class FakeConnection:
    def __init__(self, response, attempts):
        self.response, self.attempts = response, attempts

    def request(self, method, path, body, headers):
        assert method == "POST" and path == "/v1/chat/completions"
        assert headers["Authorization"] == "Bearer " + FAKE_KEY
        assert json.loads(body)["model"] == m.MODEL
        self.attempts.append((method, path))

    def getresponse(self):
        return self.response

    def close(self):
        pass


def factory_for(replies, attempts):
    def make():
        idx = len(attempts)
        return FakeConnection(replies[min(idx, len(replies) - 1)], attempts)
    return make


def set_offline_runner(monkeypatch, out_dir):
    """Deliberately override runtime auth; tests use fake connection only."""
    out_dir.chmod(0o700)
    packet = fake_packet()
    ready = {"ephemeral_unsent_packets": {"A": dict(packet), "B": dict(packet)}}
    monkeypatch.setattr(m, "source_pair", lambda: (object(), object(), ready))
    monkeypatch.setattr(
        m, "preflight_manifest",
        lambda _ready: {"first_AB_native_request_sha256": {
            "A": m.first.digest(packet), "B": m.first.digest(packet),
        }},
    )
    monkeypatch.setattr(m.first, "validate_owned_presend_payload", lambda **_: None)
    monkeypatch.setattr(m, "check_live_runtime", lambda **_: (FAKE_KEY, KEY))
    monkeypatch.setenv("GITHUB_RUN_ID", FAKE_RUN)
    monkeypatch.setenv("GITHUB_SHA", FAKE_SHA)
    return packet


def filename(out_dir, arm="A"):
    return out_dir / f"task1-423-{arm}-raw-chat.enc.json"


def decrypt_capture(out_dir, *, arm, packet, response):
    path = filename(out_dir, arm)
    stored = path.read_bytes()
    if response.raw:
        assert response.raw[:m.MAX_BODY_BYTES + 1] not in stored
    assert FAKE_KEY.encode() not in stored
    envelope = json.loads(stored)
    raw = response.raw[:m.MAX_BODY_BYTES + 1]
    aad = m._capture_aad(
        arm=arm, run_id=FAKE_RUN, request_sha=m.first.digest(packet),
        response_status=response.status,
        response_headers={"x-request-id": response.rid}, raw=raw,
    )
    assert envelope["aad_sha256"] == hashlib.sha256(aad).hexdigest()
    assert envelope["raw_sha256"] == hashlib.sha256(raw).hexdigest()
    assert envelope["format"] == "AES256_GCM"
    assert envelope["origin_independently_authenticated"] is False
    assert envelope["http_body_truncated"] is (len(raw) > m.MAX_BODY_BYTES)
    assert envelope["http_status_observed"] == response.status
    recovered = AESGCM(KEY).decrypt(
        base64.b64decode(envelope["nonce_base64"]),
        base64.b64decode(envelope["ciphertext_base64"]),
        aad,
    )
    assert recovered == raw
    assert (path.stat().st_mode & 0o077) == 0
    return envelope, stored


@pytest.mark.parametrize("response", [
    FakeReply(status=429, raw=FAKE_STATUS_BODY, rid="req_fake_429"),
    FakeReply(status=500, raw=b"OFFLINE_PRIVATE_HTTP_500", rid="req_fake_500"),
    FakeReply(status=200, raw=FAKE_RAW_BAD, rid="req_fake_badjson"),
    FakeReply(status=200, raw=FAKE_RAW_OK, rid=None),
    FakeReply(status=200, raw=b"", rid="req_fake_empty"),
    FakeReply(status=200, raw=b"X" * (m.MAX_BODY_BYTES + 5),
              rid="req_fake_partial"),
])
def test_received_untrusted_bytes_are_sealed_before_refusal(
    monkeypatch, tmp_path, response
):
    packet = set_offline_runner(monkeypatch, tmp_path)
    attempts = []
    checks = []

    def fake_parser(*, arm, raw_response, response_status,
                    response_headers, **_):
        assert filename(tmp_path, arm).exists(), "must seal before any parse"
        checks.append(arm)
        if response_status != 200:
            raise m.Denied("OFFLINE_INVALID_HTTP_STATUS")
        if response_headers.get("x-request-id") is None:
            raise m.Denied("OFFLINE_MISSING_REQUEST_ID")
        json.loads(raw_response)
        return {"request_sha256": m.first.digest(packet)}

    monkeypatch.setattr(m.shape, "capture_one", fake_parser)
    with pytest.raises((m.Denied, ValueError)):
        m.execute(mode="send", out_dir=tmp_path,
                  connection_factory=factory_for([response], attempts))
    assert attempts == [("POST", "/v1/chat/completions")]
    envelope, stored = decrypt_capture(
        tmp_path, arm="A", packet=packet, response=response
    )
    assert "UNTRUSTED_HTTP_BYTES_SEALED_BEFORE_VALIDATION" == envelope["status"]
    if len(response.raw) > m.MAX_BODY_BYTES:
        assert checks == []  # size rejected only after encrypted persistence
        assert envelope["http_body_truncated"] is True
    elif response.status == 200 and response.rid is not None:
        assert checks == ["A"]
    journal = (tmp_path / "task1-423-redacted-journal.jsonl").read_bytes()
    assert b"HTTP_BYTES_ENCRYPTED_DURABLE_BEFORE_VALIDATION" in journal
    assert b"UNKNOWN_PROVIDER_OUTCOME_STOP_NEVER_RETRY" in journal
    assert b"OFFLINE_PRIVATE" not in journal
    assert FAKE_RAW_BAD not in stored
    assert not filename(tmp_path, "B").exists()
    assert len(list(tmp_path.glob("task1-423-*.enc.json"))) == 1


def test_two_fake_responses_are_sealed_before_validation_and_no_real_send(
    monkeypatch, tmp_path
):
    packet = set_offline_runner(monkeypatch, tmp_path)
    attempts, checked = [], []
    replies = [
        FakeReply(raw=FAKE_RAW_OK, rid="req_FAKE_A_1234"),
        FakeReply(raw=b'{"fake":"OFFLINE_B"}', rid="req_FAKE_B_5678"),
    ]

    def fake_parser(*, arm, response_status, response_headers,
                    raw_response, **_):
        assert filename(tmp_path, arm).exists()
        assert response_status == 200
        assert json.loads(raw_response)["fake"]
        checked.append(arm)
        return {
            "request_sha256": m.first.digest(packet),
            "client_request_id_sha256": m.digest(("client" + arm).encode()),
            "server_request_id_sha256": m.digest(("server" + arm).encode()),
            "model_response_id_sha256": m.digest(("model" + arm).encode()),
            "estimated_cost_usd_not_invoice": "0.01",
            "raw_response_sha256": m.digest(raw_response),
            "native_tool_dispatches": 0,
        }

    monkeypatch.setattr(m.shape, "capture_one", fake_parser)
    result = m.execute(mode="send", out_dir=tmp_path,
                       connection_factory=factory_for(replies, attempts))
    assert len(attempts) == 2
    assert checked == ["A", "B"] and set(result) == {"A", "B"}
    for arm, reply in zip(("A", "B"), replies):
        decrypt_capture(tmp_path, arm=arm, packet=packet, response=reply)
    journal = (tmp_path / "task1-423-redacted-journal.jsonl").read_text()
    assert journal.count("HTTP_BYTES_ENCRYPTED_DURABLE_BEFORE_VALIDATION") == 2
    assert "FIRST_AB_PAIR_CAPTURED_ENCRYPTED_NOT_SCORED" in journal
    assert "OFFLINE_B" not in journal
    assert FAKE_KEY not in journal


def test_transport_does_not_reject_non200_or_missing_id_before_capture():
    attempts = []
    for response in (
        FakeReply(status=429, raw=FAKE_STATUS_BODY, rid="invalid"),
        FakeReply(status=200, raw=FAKE_RAW_BAD, rid=None),
    ):
        wire = m.one_post(
            arm="A", payload=fake_packet(), api_key=FAKE_KEY,
            client_id="task1-422-A-12345678",
            connection_factory=factory_for([response], attempts),
        )
        assert wire["response_status"] == response.status
        assert wire["raw_response"] == response.raw
        assert wire["response_headers"]["x-request-id"] == response.rid
    assert len(attempts) == 2


def test_exclusive_capture_writer_refuses_overwrite_and_restricts_directory(
    tmp_path
):
    tmp_path.chmod(0o700)
    name = "task1-423-A-raw-chat.enc.json"
    response = FakeReply()
    encoded = m._encrypt_capture(
        raw=response.raw, key=KEY, arm="A", run_id=FAKE_RUN,
        request_sha="b" * 64, response_status=response.status,
        response_headers={"x-request-id": response.rid},
    )
    envelope = m.canonical(encoded) + b"\n"
    m._write_private_capture(tmp_path, name, envelope)
    first = (tmp_path / name).read_bytes()
    with pytest.raises(FileExistsError):
        m._write_private_capture(tmp_path, name, envelope)
    assert (tmp_path / name).read_bytes() == first
    assert not list(tmp_path.glob("*.tmp"))
    wrong = tmp_path / "world-readable"
    wrong.mkdir()
    wrong.chmod(0o755)
    with pytest.raises(m.Denied, match="PRIVATE_OUTPUT_DIRECTORY"):
        m._write_private_capture(wrong, name, envelope)
    assert list(wrong.iterdir()) == []


def test_workflow_stays_manual_and_no_pilot_authority_is_added():
    wf = Path(
        ".github/workflows/final128-423-task1-protected-first-two-native-chat-live-v1.yml"
    ).read_text(encoding="utf8")
    assert "\n  workflow_dispatch:" in wf
    assert "\n  push:" not in wf and "\n  pull_request:" not in wf
    source = Path(m.__file__).read_text(encoding="utf8")
    assert "HTTP_BYTES_ENCRYPTED_DURABLE_BEFORE_VALIDATION" in source
    assert source.index("enc = _encrypt_capture(") < source.index(
        "checked = shape.capture_one(", source.index("def execute(")
    )
    assert "encrypted_path.write_bytes(" not in source
    assert "mcp__GitHub" not in source
