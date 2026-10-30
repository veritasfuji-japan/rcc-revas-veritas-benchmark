"""Closed-local variable Native/archive joins, no external Provider or spending."""
from copy import deepcopy
from dataclasses import replace
import os
from pathlib import Path
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from validation.task4_research_runner_native_checks import harness
from task4_research_experiment_profile_v1 import canonical, digest
from task4_research_archive_bridge_v1 import (
    ArchivedResearchRun, ResearchArchiveCustody, seed_request, raw, sha, verify_signed,
)


@pytest.fixture(autouse=True)
def forbid_ip_and_credentials(monkeypatch):
    import socket
    original = socket.socket.connect
    def connect(channel, address):
        assert channel.family == socket.AF_UNIX, "NO_PROVIDER_OR_IP_IN_RESEARCH_TEST"
        return original(channel, address)
    monkeypatch.setattr(socket.socket, "connect", connect)
    for name in ("OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_BASE_URL",
                 "VERITAS_DATABASE_URL", "GH_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(name, raising=False)


def response(request_wire, op, actions):
    request = raw.strict(request_wire)
    action = actions[int(op[1:])]
    if action == "stop":
        message = dict(role="assistant", content="LOCAL FINAL " + op)
    else:
        args = {"get_iban": {}, "get_balance": {}, "get_most_recent_transactions": {"n": 100},
                "send_money": dict(recipient="GB29NWBK60161331926819", amount=10,
                                   subject="Refund", date="2027-02-05")}[action]
        message = dict(role="assistant", content=None, tool_calls=[dict(id="call-" + op,
            type="function", function=dict(name=action, arguments=canonical(args)))])
    value = dict(id="completion-independent-" + op, object="chat.completion", created=0,
                 model=request["model"], choices=[dict(index=0, message=message,
                 finish_reason="stop" if action == "stop" else "tool_calls")])
    body = canonical(value).encode()
    return (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Request-Id: upstream-other-" + op.encode()
            + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)


def deployment(tmp_path, harness, actions, *, profile=None, receiver=None):
    p, build, _ = harness
    profile = profile or p
    for name in ("public", "custody/archives"):
        (tmp_path / name).mkdir(parents=True, exist_ok=True)
    recipient = X25519PrivateKey.generate()
    (tmp_path / "public/recipient.pub").write_bytes(recipient.public_key().public_bytes_raw())
    signer = Ed25519PrivateKey.generate()
    runner = build(profile=profile)
    requests = []
    def receive(wire, op):
        requests.append((wire, op))
        return response(wire, op, actions), "eof"
    custody = ResearchArchiveCustody(base=tmp_path, profile=profile,
        initial_request=seed_request(profile, runner.suite), signer=signer,
        receive=receiver or receive, create=True)
    return ArchivedResearchRun(runner=runner, custody=custody), custody, requests, recipient


@pytest.mark.parametrize("actions", [
    ["stop"], ["get_iban", "stop"], ["send_money", "stop"],
    ["get_most_recent_transactions", "send_money", "get_balance", "stop"],
    ["get_balance", "get_iban", "get_most_recent_transactions", "send_money", "get_balance", "stop"],
])
@pytest.mark.parametrize("arm", ["A", "B"])
def test_actual_native_history_archive_and_score(tmp_path, harness, actions, arm):
    bridge, custody, requests, recipient = deployment(tmp_path, harness, actions)
    result = bridge.run_arm(arm)
    assert result["archive_join_complete"] is True
    assert result["score"]["native_scorer_calls"] == 1
    assert result["score"]["local_utility"] is ("send_money" in actions)
    assert result["score"]["local_attack_goal_success"] is False
    assert result["official_utility"] is None and result["new_measured_utility_recoveries"] == 0
    assert len(requests) == len(result["records"]) == len(actions)
    for index, joined in enumerate(result["records"]):
        op = arm + str(index)
        receipt = joined["receipt"]
        verify_signed(custody.enrollment["signer_public"], receipt)
        verify_signed(custody.enrollment["signer_public"], joined["observation"])
        assert receipt["statement"]["operation_id"] == op
        assert receipt["statement"]["upstream_request_id"] == "upstream-other-" + op
        assert receipt["statement"]["completion_id"] == "completion-independent-" + op
        blob = (tmp_path / "custody/archives" / (op + ".enc.json")).read_bytes()
        assert sha(blob) == receipt["statement"]["archive"]["envelope_sha256"]
        envelope = raw.strict(blob)
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        import base64
        plain = AESGCM(raw.derive(recipient, X25519PublicKey.from_public_bytes(bytes.fromhex(envelope["ephemeral"])))).decrypt(
            bytes.fromhex(envelope["nonce"]), base64.b64decode(envelope["ciphertext"]), raw.canonical(envelope["header"]))
        assert plain == response(requests[index][0], op, actions)
        assert envelope["header"]["request_sha256"] == sha(requests[index][0])
        assert joined["observation"]["statement"]["history_sha256"] == joined["observed_history_sha256"]
    # Reopen the retained service without rebuilding a fresh attempt ledger.
    reopened = ResearchArchiveCustody(base=tmp_path, profile=custody.profile, initial_request=custody.seed,
        signer=custody.signer, receive=custody.receive)
    with pytest.raises(ValueError):
        reopened.exchange(arm, custody.seed)


def test_changed_model_label_and_both_independent_arms(tmp_path, harness):
    profile = replace(harness[0], model_id="local-research-other-model", output_token_cap=512)
    bridge, custody, requests, _ = deployment(tmp_path, harness, ["send_money", "stop"], profile=profile)
    for arm in ("A", "B"):
        result = bridge.run_arm(arm)
        assert result["archive_join_complete"] and result["score"]["local_utility"]
    assert len(requests) == 4
    assert all(raw.strict(wire)["model"] == profile.model_id for wire, _ in requests)


@pytest.mark.parametrize("fault", ["truncated", "malformed", "duplicate-id", "wrong-model", "length"])
def test_incomplete_cannot_score_or_reissue_and_raw_is_preserved(tmp_path, harness, fault):
    captured = []
    def receive(wire, op):
        value = response(wire, op, ["stop"])
        completion = "eof"
        if fault == "truncated":
            value, completion = value[:-5], "timeout"
        elif fault == "malformed":
            value = b"not http"
        elif fault == "duplicate-id":
            value = value.replace(b"Content-Type:", b"X-Request-Id: another-id\r\nContent-Type:")
        elif fault == "wrong-model":
            value = value.replace(harness[0].model_id.encode(), b"x" * len(harness[0].model_id))
        else:
            value = value.replace(b'"stop"', b'"length"')
            head, _, body = value.partition(b"\r\n\r\n")
            import re
            value = re.sub(rb"Content-Length: [0-9]+", b"Content-Length: " + str(len(body)).encode(), head) + b"\r\n\r\n" + body
        captured.append(value)
        return value, completion
    bridge, custody, _, _ = deployment(tmp_path, harness, ["stop"], receiver=receive)
    result = bridge.run_arm("B")
    assert not result["archive_join_complete"] and result["score"]["native_scorer_calls"] == 0
    assert result["record"].payload()["model_attempts"] == 1
    assert (tmp_path / "custody/archives/B0.enc.json").is_file()
    with pytest.raises(ValueError):
        custody.exchange("B", custody.seed)
    assert len(captured) == 1


def test_receiver_loss_is_retained_before_any_retry(tmp_path, harness):
    def fail(wire, op):
        raise OSError("synthetic loss")
    bridge, custody, _, _ = deployment(tmp_path, harness, ["stop"], receiver=fail)
    result = bridge.run_arm("A")
    assert not result["archive_join_complete"]
    with custody.db() as db:
        assert db.execute("SELECT state FROM attempts").fetchall() == [("UNKNOWN",)]
    with pytest.raises(ValueError):
        custody.exchange("A", custody.seed)


def test_tampered_release_is_refused_before_native(tmp_path, harness, monkeypatch):
    bridge, custody, _, _ = deployment(tmp_path, harness, ["send_money", "stop"])
    original = custody.exchange
    def tamper(arm, request, parent):
        reply = original(arm, request, parent)
        reply["body"] = reply["body"].replace(b'Refund', b'Attack')
        return reply
    monkeypatch.setattr(custody, "exchange", tamper)
    result = bridge.run_arm("B")
    assert not result["archive_join_complete"]
    assert result["record"].payload()["native_protected_dispatches"] == 0
    assert result["score"]["native_scorer_calls"] == 0


def test_lost_terminal_observation_ack_keeps_native_record_unscored(tmp_path, harness, monkeypatch):
    bridge, custody, _, _ = deployment(tmp_path, harness, ["send_money", "stop"])
    original = custody.observe
    def lost(*args, **kwargs):
        result = original(*args, **kwargs)
        if args[-1] is True:
            raise OSError("lost ACK after observation commit")
        return result
    monkeypatch.setattr(custody, "observe", lost)
    result = bridge.run_arm("B")
    assert result["record"].payload()["stop_reason"] == "TERMINAL"
    assert result["record"].payload()["native_protected_dispatches"] == 1
    assert not result["archive_join_complete"] and result["score"]["native_scorer_calls"] == 0
    with pytest.raises(ValueError):
        custody.exchange("B", custody.seed)


def custody_worker(pipe, base, profile, seed, private, receiver_config):
    """Test-only spawned custody: no shared Python service instance with Native."""
    from task4_research_archive_bridge_v1 import UnixTLSReceiver
    service = ResearchArchiveCustody(base=Path(base), profile=profile, initial_request=seed,
        signer=Ed25519PrivateKey.from_private_bytes(private), receive=UnixTLSReceiver(**receiver_config))
    while True:
        message = pipe.recv()
        if message is None:
            return
        name, args = message
        try:
            result = getattr(service, name)(*args)
            pipe.send((os.getpid(), True, result))
        except Exception as error:
            pipe.send((os.getpid(), False, type(error).__name__))


@pytest.mark.parametrize("actions", [
    ["send_money", "stop"],
    ["get_balance", "get_iban", "get_most_recent_transactions", "send_money", "get_balance", "stop"],
])
def test_separate_custody_process_actual_unix_tls_archive_and_native_score(tmp_path, harness, actions):
    import multiprocessing
    import re
    import socket
    import ssl
    import subprocess
    import threading
    from task4_research_archive_bridge_v1 import UnixTLSReceiver

    cert, key = tmp_path / "server.crt", tmp_path / "server.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-keyout", str(key), "-out", str(cert), "-subj", "/CN=research.example.invalid",
        "-addext", "subjectAltName=DNS:research.example.invalid"], check=True, capture_output=True)
    config = dict(address=str(tmp_path / "backend.sock"), ca_file=str(cert), hostname="research.example.invalid",
                  leaf_sha256=sha(ssl.PEM_cert_to_DER_cert(cert.read_text())), peer_uid=os.geteuid())
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    requests, failures = [], []
    bridge, custody, _, _ = deployment(tmp_path, harness, ["send_money", "stop"])
    parent, child = multiprocessing.get_context("spawn").Pipe()
    process = multiprocessing.get_context("spawn").Process(target=custody_worker, args=(
        child, str(tmp_path), custody.profile, custody.seed, custody.signer.private_bytes_raw(), config))
    class Remote:
        profile, enrollment = custody.profile, custody.enrollment
        pids = set()
        def call(self, name, *args):
            parent.send((name, args))
            assert parent.poll(15), "CUSTODY_RPC_DEADLINE"
            pid, ok, result = parent.recv()
            self.pids.add(pid)
            assert ok, result
            return result
        def exchange(self, *args):
            return self.call("exchange", *args)
        def observe(self, *args):
            return self.call("observe", *args)
    remote = Remote()
    bridge.custody = remote
    def backend(server):
        try:
            for _ in range(2 * len(actions)):
                channel, _ = server.accept()
                with context.wrap_socket(channel, server_side=True) as tls:
                    incoming = bytearray()
                    while b"\r\n\r\n" not in incoming:
                        incoming.extend(tls.recv(4096))
                    head, _, body = bytes(incoming).partition(b"\r\n\r\n")
                    size = int(re.search(rb"Content-Length: ([0-9]+)", head)[1])
                    while len(body) < size:
                        body += tls.recv(size-len(body))
                    op = re.search(rb"X-Client-Request-Id: ([AB][0-9]+)", head)[1].decode()
                    requests.append((body, op))
                    tls.sendall(response(body, op, actions))
        except Exception as error:
            failures.append(type(error).__name__)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(config["address"])
        server.listen(4)
        server.settimeout(15)
        process.start()
        thread = threading.Thread(target=backend, args=(server,), daemon=True)
        thread.start()
        try:
            for arm in ("A", "B"):
                result = bridge.run_arm(arm)
                assert result["archive_join_complete"], result["record"].payload()["stop_reason"]
                assert result["score"]["local_utility"] and not result["score"]["local_attack_goal_success"]
                assert result["official_utility"] is None
            assert remote.pids == {process.pid} and process.pid != os.getpid()
            assert len(requests) == len(list((tmp_path / "custody/archives").glob("*.enc.json"))) == 2 * len(actions)
            with custody.db() as db:
                assert db.execute("SELECT arm,ordinal,state FROM arms ORDER BY arm").fetchall() == [
                    ("A", len(actions), "TERMINAL"), ("B", len(actions), "TERMINAL")]
            thread.join(3)
            assert not failures and not thread.is_alive()
        finally:
            parent.send(None)
            process.join(3)
            if process.is_alive():
                process.terminate()
                process.join(3)
            parent.close()
            child.close()


def test_sdk_nullable_message_metadata_does_not_block_valid_completion(tmp_path, harness):
    from openai.types.chat import ChatCompletion
    def receive(wire, op):
        original = response(wire, op, ["stop"])
        value = raw.strict(original.partition(b"\r\n\r\n")[2])
        value = ChatCompletion.model_validate(value).model_dump()
        body = canonical(value).encode()
        head = (b"HTTP/1.1 200 OK\r\nX-Request-Id: nullable-metadata\r\nContent-Length: "
                + str(len(body)).encode() + b"\r\n\r\n")
        return head + body, "eof"
    bridge, _, _, _ = deployment(tmp_path, harness, ["stop"], receiver=receive)
    result = bridge.run_arm("B")
    assert result["archive_join_complete"] and result["score"]["native_scorer_calls"] == 1
    assert result["score"]["local_utility"] is False


def test_next_request_requires_exact_signed_observation_parent(tmp_path, harness, monkeypatch):
    bridge, custody, requests, _ = deployment(tmp_path, harness, ["get_iban", "stop"])
    original = custody.exchange
    def changed_parent(arm, request, parent):
        return original(arm, request, None if parent is None else "0" * 64)
    monkeypatch.setattr(custody, "exchange", changed_parent)
    result = bridge.run_arm("A")
    assert not result["archive_join_complete"] and result["score"]["native_scorer_calls"] == 0
    assert result["record"].payload()["model_attempts"] == 2
    assert len(requests) == 1
