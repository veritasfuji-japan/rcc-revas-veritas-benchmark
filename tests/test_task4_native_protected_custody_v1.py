"""Adapter cryptographic binding and original Native integration, offline only."""
import base64
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from scripts import task4_native_protected_custody_v1 as m
from scripts.task4_457_local_response_aead_v1 import SealedLocalVault


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    adapter = m.ProtectedAdapter()
    recipient = X25519PrivateKey.generate()
    pub = recipient.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    adapter.recipient = m.sha(pub)
    adapter.database, adapter.socket_path = root / "store.sqlite", root / "protected.sock"
    m.custody.initialize(adapter.database, adapter.public, adapter.recipient)
    server = m.custody.Custody(adapter.database, adapter.public, adapter.recipient)
    # Unit fixture only: real signed dispatch and real SQLite, no socket proof.
    monkeypatch.setattr(m.custody, "exchange", lambda sock, packet: server.dispatch(packet))
    wire, response = b"SYNTHETIC_ADAPTER_WIRE", b"SYNTHETIC_ADAPTER_RESPONSE"
    vault = SealedLocalVault(root, recipient.public_key())
    row = vault.commit_before_parser(arm="A", ordinal=0, request=SimpleNamespace(content=wire),
                                    response=SimpleNamespace(content=response, status_code=200))
    blob = (root / row["envelope_filename"]).read_bytes()
    return SimpleNamespace(adapter=adapter, server=server, blob=blob, wire=wire,
                           response=response, recipient=recipient)


def key():
    return {"trial": m.custody.TRIAL, "arm": "A", "ordinal": 0}


def consume(f):
    return f.adapter.exchange(f.adapter.socket_path,
        {"op": "consume", **key(), "request_sha": m.sha(f.wire)})


def attach(f, receipt):
    return f.adapter.exchange(f.adapter.socket_path, {
        "op": "attach", **key(), "receipt_sha": receipt,
        "envelope_b64": base64.b64encode(f.blob).decode()})


def test_adapter_signed_consume_attach_read_and_exact_recovery(fixture):
    f = fixture
    result = consume(f)
    assert result["decision"] == "LOCAL_CONSUMED_NO_SEND"
    assert attach(f, result["receipt_sha"])["sha256"] == m.sha(f.blob)
    read = f.adapter.exchange(f.adapter.socket_path, {"op": "read", **key()})
    assert m.ProtectedAdapter.recover_test_ciphertext(m.custody.unb64(read["envelope_b64"]), f.recipient) == f.response
    assert consume(f)["decision"] == "DENY_ALREADY_CONSUMED"
    assert f.adapter.verified_replies == {"consume": 1, "attach": 1, "read": 1, "replay_denied": 1}


def test_wrong_receipt_is_not_resigned_for_new_scope(fixture):
    f = fixture
    result = consume(f)
    with pytest.raises(m.old.Refused, match="WRONG_RECEIPT"):
        attach(f, "b"*64)
    assert attach(f, result["receipt_sha"])["decision"] == "LOCAL_CIPHERTEXT_SEALED"


def test_changed_envelope_wire_refused_by_server(fixture):
    f = fixture
    result = consume(f)
    env = m.custody.parse(f.blob)
    env["header"]["local_request_sha256"] = "b"*64
    f.blob = m.custody.canonical(env)
    with pytest.raises(m.custody.Denied):
        attach(f, result["receipt_sha"])


def test_bad_read_reply_hash_fails_adapter(fixture, monkeypatch):
    f = fixture
    receipt = consume(f)["receipt_sha"]
    attach(f, receipt)
    monkeypatch.setattr(m.custody, "exchange", lambda *a: {
        "decision": "CIPHERTEXT_READ_ONLY", "live_post": False,
        "envelope_sha256": m.sha(f.blob), "envelope_b64": base64.b64encode(b"changed").decode()})
    with pytest.raises(m.old.Refused, match="READ_MISMATCH"):
        f.adapter.exchange(f.adapter.socket_path, {"op": "read", **key()})


@pytest.mark.parametrize("op", ["send_live", "raw_action", "attach_unsigned"])
def test_adapter_unknown_opcode_refused(fixture, op):
    with pytest.raises(m.old.Refused):
        fixture.adapter.exchange(fixture.adapter.socket_path, {"op": op, **key()})


def test_missing_store_not_recreated_on_restart(fixture):
    f = fixture
    consume(f)
    f.adapter.database.unlink()
    with pytest.raises(m.custody.Denied):
        f.adapter.spawn_server(f.adapter.database, f.adapter.socket_path, f.adapter.recipient)
    assert not f.adapter.database.exists()


def test_frozen_component_pins_and_no_old_orchestrator():
    for path, digest in m.ADDITIONAL_PINS.items():
        assert m.sha((m.ROOT/path).read_bytes()) == digest
    import ast
    tree = ast.parse(Path(m.__file__).read_text())
    calls = [ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)]
    assert "old.run_local_native_allturn_join" not in calls
    assert not any(c in calls for c in ("legacy.action", "legacy.Broker", "legacy.spawn_server"))


@pytest.mark.parametrize("event,args", [
    ("socket.bind", (SimpleNamespace(family=m.socket.AF_UNIX), "/tmp/unexpected.sock")),
    ("socket.connect", (SimpleNamespace(family=m.socket.AF_INET), ("127.0.0.1", 1))),
    ("subprocess.Popen", ("legacy",)),
])
def test_parent_watch_rejects_unexpected_operation_without_performing_it(event, args):
    watch = m.ParentWatch()
    with pytest.raises(m.custody.Denied):
        watch.audit(event, args)
    assert watch.denied == 1 and watch.connections == 0
    watch.allowed.add("/tmp/expected.sock")
    watch.audit("socket.connect", (SimpleNamespace(family=m.socket.AF_UNIX), "/tmp/expected.sock"))
    assert watch.connections == 1


def test_selected_runner_tripwire_refuses_legacy_start(monkeypatch):
    from scripts import task4_458_local_broker_once_ciphertext_v1 as legacy
    monkeypatch.setattr(m, "native_join", lambda watch: legacy.spawn_server(None, None, None))
    with pytest.raises(m.custody.Denied, match="LEGACY_ENTRYPOINT_FORBIDDEN"):
        m.run()


@pytest.mark.skipif(os.environ.get("TASK4_NATIVE_CUSTODY_PROOF") != "1",
                    reason="dedicated frozen Native SDK integration dependencies")
def test_original_native_eight_requests_use_new_custody():
    report = m.run()
    assert report["capped_sdk_requests"] == 8
    assert report["encrypted_original_scripted_response_count"] == 8
    assert report["same_run_scripted_native_scorer_invocations"] == 2
    assert report["protected_operation_counts"] == {
        "consume": 8, "attach": 8, "read": 8, "replay_denied": 8}
    assert len(report["protected_broker_startups"]) == 2
    assert all(p == {"distinct_from_parent": True, "observed_protected_binds": 1}
               for p in report["protected_broker_startups"])
    assert report["legacy_entrypoint_attempts_in_parent"] == 0
    assert report["observed_parent_protected_socket_connections"] == 32
    assert report["unexpected_parent_operations"] == 0
    assert report["real_provider_posts"] == report["external_bank_effects"] == 0
    assert report["genuine_native_utility"] is None
    assert report["score_status"] == "UNSCORED"
    assert report["production_bypass_resistance_proven"] is False


def test_swallowed_subprocess_attempt_still_fails_runner(monkeypatch):
    import subprocess

    def swallowed(watch):
        try:
            subprocess.Popen(["must-not-execute"])
        except m.custody.Denied:
            pass
        return {}

    monkeypatch.setattr(m, "native_join", swallowed)
    with pytest.raises(m.old.Refused, match="SUBPROCESS_ATTEMPT_OBSERVED"):
        m.run()


def test_offline_sdk_metadata_does_not_probe_platform(monkeypatch):
    import httpx
    import openai

    def sdk_request(watch):
        def response(request):
            assert request.headers["X-Stainless-OS"] == "Unknown"
            return httpx.Response(200, json={"id": "fixture", "choices": []})
        with httpx.Client(transport=httpx.MockTransport(response)) as http:
            with openai.OpenAI(api_key="offline-fixture", http_client=http) as client:
                client.chat.completions.create(model="offline-fixture", messages=[])
        # This unit test does not claim native socket evidence.
        raise RuntimeError("offline SDK request completed")

    monkeypatch.setattr(m, "native_join", sdk_request)
    monkeypatch.setattr("platform.platform", lambda: pytest.fail("OS subprocess probe reached"))
    with pytest.raises(RuntimeError, match="offline SDK request completed"):
        m.run()
