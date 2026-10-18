"""Multi-process local mock Runner -> independent fake Executor service tests."""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import json
import multiprocessing
import os
from pathlib import Path
import socket

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from scripts import final128_task1_mock_executor_service_offline_v1 as m
from scripts import final128_task1_research_signed_run_handoff_offline_v1 as h
from scripts import final128_task1_mock_provider_presend_bind_no_effect_v1 as mock

ROOT = Path(__file__).resolve().parents[1]
FROZEN = ROOT / "evidence/final128_task1_research_tag_live_readback_2026-10-18_v1.json"
DOC = ROOT / "docs/optimization/FINAL128_TASK1_MOCK_EXECUTOR_SERVICE_OFFLINE_V1.md"
CTX = multiprocessing.get_context("spawn")


@pytest.fixture(autouse=True)
def disable_inet_and_secrets(monkeypatch):
    old_connect = socket.socket.connect
    old_connect_ex = socket.socket.connect_ex
    def unix_only(conn, address):
        if conn.family != socket.AF_UNIX:
            pytest.fail("TASK1_448_NO_INET_NETWORK")
        return old_connect(conn, address)
    def unix_only_ex(conn, address):
        if conn.family != socket.AF_UNIX:
            pytest.fail("TASK1_448_NO_INET_NETWORK")
        return old_connect_ex(conn, address)
    monkeypatch.setattr(socket.socket, "connect", unix_only)
    monkeypatch.setattr(socket.socket, "connect_ex", unix_only_ex)
    for name in ("GH_TOKEN", "GITHUB_TOKEN", "OPENAI_API_KEY", "TASK1_OPENAI_API_KEY",
                 "TASK1_CAPTURE_AES256_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(name, raising=False)


def _identity():
    ctx = h.MockJobContext(
        main_sha=mock.SHA, run_id="39012345678",
        issuer_job_id="117123456781", sender_job_id="117123456782",
        request_sha256=mock.PACKET_SHA256, run_attempt=1)
    signer = Ed25519PrivateKey.generate()
    signed = h.mock_sign(h.mock_payload(ctx), signer, ctx)
    pub = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    return ctx, signer, signed, pub


def _frozen():
    return json.loads(FROZEN.read_text(encoding="utf-8"))


@contextmanager
def executor(directory, ctx, public, *, fault="none", allowed_uid=None):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    sock = directory / "executor.sock"
    db = directory / "ledger.sqlite"
    ready = CTX.Event()
    stop = CTX.Event()
    proc = CTX.Process(target=m.serve, kwargs={
        "socket_path": sock, "db_path": db,
        "expected": ctx, "test_public_key_raw": public,
        "frozen_snapshot": _frozen(),
        "ready_event": ready, "stop_event": stop,
        "admitted_uid": os.getuid() if allowed_uid is None else allowed_uid,
        "configured_fault": fault,
    })
    proc.start()
    try:
        assert ready.wait(timeout=12), "executor did not start"
        assert proc.is_alive()
        assert (sock.stat().st_mode & 0o077) == 0
        yield sock, db
    finally:
        stop.set()
        proc.join(timeout=5)
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=4)
        assert proc.exitcode == 0


def _worker(sock, arm, signed, start, output):
    if not start.wait(timeout=12):
        output.put("NOT_STARTED")
        return
    try:
        result = m.request(socket_path=Path(sock), arm=arm, signed=signed)
        output.put(result["status"])
    except Exception as e:
        output.put("EXCEPTION:" + str(e)[:100])


def test_single_executor_ab_order_replay_and_no_provider(tmp_path):
    ctx, _, signed, public = _identity()
    with executor(tmp_path / "service", ctx, public) as (sock, _db):
        assert m.request(socket_path=sock, arm="B", signed=signed)["status"] == "DENIED"
        assert m.request(socket_path=sock, arm="A", signed=signed) == {
            "status": "ACK", "arm": "A", "real_provider_requests": 0}
        assert m.request(socket_path=sock, arm="A", signed=signed)["status"] == "DENIED"
        assert m.request(socket_path=sock, arm="B", signed=signed)["status"] == "ACK"
        assert m.request(socket_path=sock, arm="B", signed=signed)["status"] == "DENIED"


def test_two_distinct_mock_runner_processes_compete_for_one_A(tmp_path):
    ctx, _, signed, public = _identity()
    with executor(tmp_path / "service", ctx, public) as (sock, _db):
        start, out = CTX.Event(), CTX.Queue()
        procs = [CTX.Process(target=_worker, args=(str(sock), "A", signed, start, out))
                 for _ in range(2)]
        try:
            for proc in procs:
                proc.start()
            start.set()
            statuses = sorted(out.get(timeout=20) for _ in procs)
            for proc in procs:
                proc.join(timeout=12)
            assert statuses == ["ACK", "DENIED"]
            assert all(proc.exitcode == 0 for proc in procs)
        finally:
            for proc in procs:
                if proc.is_alive():
                    proc.terminate()
                proc.join(timeout=3)
        assert m.request(socket_path=sock, arm="B", signed=signed)["status"] == "ACK"


def test_executor_restart_reuses_db_and_denies_any_duplicate(tmp_path):
    ctx, _, signed, public = _identity()
    directory = tmp_path / "service"
    with executor(directory, ctx, public) as (sock, db):
        assert m.request(socket_path=sock, arm="A", signed=signed)["status"] == "ACK"
        assert db.is_file()
    with executor(directory, ctx, public) as (sock, _):
        assert m.request(socket_path=sock, arm="A", signed=signed)["status"] == "DENIED"
        assert m.request(socket_path=sock, arm="B", signed=signed)["status"] == "ACK"
    with executor(directory, ctx, public) as (sock, _):
        assert m.request(socket_path=sock, arm="B", signed=signed)["status"] == "DENIED"


@pytest.mark.parametrize("failure", ["A_TIMEOUT", "A_BAD_ACK",
                                      "AFTER_RESERVATION_BEFORE_FAKE_SEND",
                                      "AFTER_FAKE_SEND_BEFORE_ACK"])
def test_unknown_after_attempt_stops_even_after_restart(tmp_path, failure):
    ctx, _, signed, public = _identity()
    directory = tmp_path / "service"
    with executor(directory, ctx, public, fault=failure) as (sock, _):
        assert m.request(socket_path=sock, arm="A", signed=signed)["status"] == "UNKNOWN"
    with executor(directory, ctx, public) as (sock, _):
        assert m.request(socket_path=sock, arm="A", signed=signed)["status"] == "DENIED"
        assert m.request(socket_path=sock, arm="B", signed=signed)["status"] == "DENIED"


@pytest.mark.parametrize("failure", ["B_TIMEOUT", "B_BAD_ACK"])
def test_unknown_B_after_A_blocks_B_retry(tmp_path, failure):
    ctx, _, signed, public = _identity()
    directory = tmp_path / "service"
    with executor(directory, ctx, public) as (sock, _):
        assert m.request(socket_path=sock, arm="A", signed=signed)["status"] == "ACK"
    with executor(directory, ctx, public, fault=failure) as (sock, _):
        assert m.request(socket_path=sock, arm="B", signed=signed)["status"] == "UNKNOWN"
    with executor(directory, ctx, public) as (sock, _):
        assert m.request(socket_path=sock, arm="B", signed=signed)["status"] == "DENIED"


def test_rogue_caller_cannot_claim_os_peer_identity(tmp_path):
    ctx, _, signed, public = _identity()
    # Simulate an enrolled peer that is not this test's actual Linux UID.
    with executor(tmp_path / "service", ctx, public, allowed_uid=os.getuid() + 1) as (sock, db):
        assert m.request(socket_path=sock, arm="A", signed=signed)["status"] == "DENIED"
        assert m.request(socket_path=sock, arm="A", signed=signed,
                         claimed_uid=os.getuid() + 1)["status"] == "DENIED"
        assert db.is_file()


def test_wrong_signer_and_modified_signed_claims_denied(tmp_path):
    ctx, _, signed, public = _identity()
    wrong_ctx, wrong_signer, _, _ = _identity()
    forged = h.mock_sign(h.mock_payload(wrong_ctx), wrong_signer, wrong_ctx)
    tampered = deepcopy(signed)
    tampered["payload"]["paid_consent"] = True
    with executor(tmp_path / "service", ctx, public) as (sock, _):
        for bad in (forged, tampered):
            assert m.request(socket_path=sock, arm="A", signed=bad)["status"] == "DENIED"
        assert m.request(socket_path=sock, arm="A", signed=signed)["status"] == "ACK"


@pytest.mark.parametrize("raw", [
    b'{"schema":1,"schema":2}\n',
    b'{}\n',
    b'{"schema":NaN}\n',
    b'{\n',
    b'\xff\n',
    b'{"operation":"shutdown"}\n',
    b'{"status":"PAID_GO"}\n',
])
def test_strict_untrusted_frame_refused(tmp_path, raw):
    ctx, _, signed, public = _identity()
    with executor(tmp_path / "service", ctx, public) as (sock, _):
        response = m._round_trip(sock, raw)
        assert response["status"] == "DENIED"
        assert m.request(socket_path=sock, arm="A", signed=signed)["status"] == "ACK"


def test_separate_executor_ledger_counterexample(tmp_path):
    ctx, _, signed, public = _identity()
    with executor(tmp_path / "one", ctx, public) as (sock, db):
        assert m.request(socket_path=sock, arm="A", signed=signed)["status"] == "ACK"
        # The SAME Linux user that launched this service can still access its DB.
        # This is a documented bypass of purported OS/IAM independence.
        assert os.access(db, os.W_OK)
    with executor(tmp_path / "other", ctx, public) as (sock, _):
        assert m.request(socket_path=sock, arm="A", signed=signed)["status"] == "ACK"


def test_source_nonclaims_and_no_effect_routines():
    src = Path(m.__file__).read_text(encoding="utf-8")
    assert m.SCHEMA in src
    for forbidden in ("import http.client", "from openai", "import requests",
                      "import urllib", "api.openai.com", "workflow_dispatch",
                      "TASK1_OPENAI_API_KEY", "POST /git/refs"):
        assert forbidden not in src
    assert not hasattr(m, "send_live_provider")
    docs = DOC.read_text(encoding="utf-8")
    for expected in ("NO-GO", "Issue #427", "#446", "#447", "same UID",
                     "not real GitHub", "no Provider", "separate ledgers"):
        assert expected in docs
