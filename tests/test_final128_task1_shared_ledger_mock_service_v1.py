"""Task1 separate local ledger / Executor / simulated Runner tests (NO EFFECT)."""
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

from scripts import final128_task1_shared_ledger_mock_service_v1 as m
from scripts import final128_task1_research_signed_run_handoff_offline_v1 as h
from scripts import final128_task1_mock_provider_presend_bind_no_effect_v1 as mock

CTX = multiprocessing.get_context("spawn")
ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "evidence/final128_task1_research_tag_live_readback_2026-10-18_v1.json"
DOC = ROOT / "docs/optimization/FINAL128_TASK1_SHARED_LEDGER_MOCK_SERVICE_V1.md"


@pytest.fixture(autouse=True)
def clear_live_credentials(monkeypatch):
    for key in ("GH_TOKEN", "GITHUB_TOKEN", "OPENAI_API_KEY", "TASK1_OPENAI_API_KEY",
                "TASK1_CAPTURE_AES256_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(key, raising=False)


def identity():
    context = h.MockJobContext(
        main_sha=mock.SHA, run_id="39012345678",
        issuer_job_id="117123456781", sender_job_id="117123456782",
        request_sha256=mock.PACKET_SHA256, run_attempt=1)
    signer = Ed25519PrivateKey.generate()
    signed = h.mock_sign(h.mock_payload(context), signer, context)
    public = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    return context, signed, public


def frozen():
    return json.loads(SNAPSHOT.read_text(encoding="utf-8"))


@contextmanager
def process(target, **args):
    ready, stop = CTX.Event(), CTX.Event()
    worker = CTX.Process(target=target, kwargs={**args, "ready": ready, "stop": stop})
    worker.start()
    try:
        assert ready.wait(timeout=12), "service did not become ready"
        assert worker.is_alive()
        yield worker
    finally:
        stop.set()
        worker.join(timeout=6)
        if worker.is_alive():
            worker.terminate()
            worker.join(timeout=6)
        assert worker.exitcode == 0


@contextmanager
def environment(folder: Path, *, failure="none"):
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    folder.chmod(0o700)
    ctx, signed, public = identity()
    cap = os.urandom(32)  # held by test supervisor and the two test daemons
    ledger_socket, executor_socket = folder / "ledger.sock", folder / "executor.sock"
    db_path = folder / "remote-shaped.sqlite"
    with process(m.ledger_serve, socket_path=ledger_socket,
                 db_path=db_path, mock_capability=cap):
        with process(m.executor_serve, socket_path=executor_socket,
                     ledger_socket=ledger_socket, mock_capability=cap,
                     expected=ctx, test_public_key_raw=public, frozen=frozen(),
                     failure=failure):
            yield executor_socket, ledger_socket, db_path, ctx, signed, public, cap


def runner_worker(socket_path, scratch_dir, signed, arm, start, output):
    """Independent simulated Runner with private scratch, NO DB path or secret."""
    scratch = Path(scratch_dir)
    scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
    (scratch / "runner-only.txt").write_text("not a ledger", encoding="ascii")
    if not start.wait(timeout=15):
        output.put("NOT_STARTED")
        return
    try:
        response = m.runner_request(socket_path=Path(socket_path),
                                    arm=arm, signed=signed)
        output.put(response["status"])
    except Exception as exc:
        output.put("ERROR:" + type(exc).__name__)


def request(sock, signed, arm="A"):
    return m.runner_request(socket_path=sock, signed=signed, arm=arm)["status"]


def test_two_simulated_runners_share_one_ledger_with_one_winner(tmp_path):
    with environment(tmp_path / "backend") as (exe, _led, db, _ctx, signed, _public, _cap):
        start, q = CTX.Event(), CTX.Queue()
        runners = [CTX.Process(target=runner_worker, args=(
            str(exe), str(tmp_path / ("runner-" + str(i))), signed, "A", start, q))
                   for i in range(2)]
        try:
            for p in runners:
                p.start()
            start.set()
            outcomes = sorted(q.get(timeout=25) for p in runners)
            for p in runners:
                p.join(timeout=15)
            assert outcomes == ["ACK", "DENIED"]
            assert all(p.exitcode == 0 for p in runners)
            assert m.Ledger(db).phase() == "A_ACK"
            assert request(exe, signed, "A") == "DENIED"
            assert request(exe, signed, "B") == "ACK"
            assert request(exe, signed, "B") == "DENIED"
        finally:
            for p in runners:
                if p.is_alive():
                    p.terminate()
                p.join(timeout=4)


def test_service_restarts_share_same_db_without_replay(tmp_path):
    directory = tmp_path / "backend"
    directory.mkdir(mode=0o700)
    ctx, signed, public = identity()
    cap = os.urandom(32)
    ledger_sock, exe_sock, db = (directory / "ledger.sock",
                                directory / "executor.sock",
                                directory / "backend.sqlite")
    with process(m.ledger_serve, socket_path=ledger_sock,
                 db_path=db, mock_capability=cap):
        with process(m.executor_serve, socket_path=exe_sock,
                     ledger_socket=ledger_sock, mock_capability=cap,
                     expected=ctx, test_public_key_raw=public, frozen=frozen()):
            assert request(exe_sock, signed, "A") == "ACK"
        with process(m.executor_serve, socket_path=exe_sock,
                     ledger_socket=ledger_sock, mock_capability=cap,
                     expected=ctx, test_public_key_raw=public, frozen=frozen()):
            assert request(exe_sock, signed, "A") == "DENIED"
            assert request(exe_sock, signed, "B") == "ACK"
    assert m.Ledger(db).phase() == "PAIR_ACK"
    with process(m.ledger_serve, socket_path=ledger_sock,
                 db_path=db, mock_capability=cap):
        with process(m.executor_serve, socket_path=exe_sock,
                     ledger_socket=ledger_sock, mock_capability=cap,
                     expected=ctx, test_public_key_raw=public, frozen=frozen()):
            assert request(exe_sock, signed, "A") == "DENIED"
            assert request(exe_sock, signed, "B") == "DENIED"


@pytest.mark.parametrize("failure", [
    "A_TIMEOUT", "A_BAD_ACK", "AFTER_RESERVATION_BEFORE_FAKE_SEND",
    "AFTER_FAKE_SEND_BEFORE_ACK",
])
def test_unknown_a_committed_before_fake_and_blocks_restarts(tmp_path, failure):
    with environment(tmp_path / "backend", failure=failure) as (
            exe, _led, db, _ctx, signed, _public, _cap):
        assert request(exe, signed, "A") == "UNKNOWN"
        assert m.Ledger(db).phase() == "UNKNOWN_A"
        assert request(exe, signed, "A") == "DENIED"
        assert request(exe, signed, "B") == "DENIED"


@pytest.mark.parametrize("failure", ["B_TIMEOUT", "B_BAD_ACK"])
def test_unknown_b_stops_replay(tmp_path, failure):
    directory = tmp_path / "backend"
    directory.mkdir(mode=0o700)
    ctx, signed, public = identity()
    cap = os.urandom(32)
    lsocket, esocket, db = directory / "l.sock", directory / "e.sock", directory / "ledger.sqlite"
    with process(m.ledger_serve, socket_path=lsocket,
                 db_path=db, mock_capability=cap):
        with process(m.executor_serve, socket_path=esocket, ledger_socket=lsocket,
                     mock_capability=cap, expected=ctx,
                     test_public_key_raw=public, frozen=frozen()):
            assert request(esocket, signed, "A") == "ACK"
        with process(m.executor_serve, socket_path=esocket, ledger_socket=lsocket,
                     mock_capability=cap, expected=ctx,
                     test_public_key_raw=public, frozen=frozen(), failure=failure):
            assert request(esocket, signed, "B") == "UNKNOWN"
            assert m.Ledger(db).phase() == "UNKNOWN_B"
        with process(m.executor_serve, socket_path=esocket, ledger_socket=lsocket,
                     mock_capability=cap, expected=ctx,
                     test_public_key_raw=public, frozen=frozen()):
            assert request(esocket, signed, "B") == "DENIED"


def test_ledger_outage_fails_closed_before_reservation(tmp_path):
    d = tmp_path / "service"
    d.mkdir(mode=0o700)
    ctx, signed, public = identity()
    cap = os.urandom(32)
    with process(m.executor_serve, socket_path=d / "ex.sock",
                 ledger_socket=d / "absent-ledger.sock", mock_capability=cap,
                 expected=ctx, test_public_key_raw=public, frozen=frozen()):
        assert request(d / "ex.sock", signed, "A") == "DENIED"


def test_direct_unauthenticated_ledger_protocol_cannot_reserve(tmp_path):
    with environment(tmp_path / "backend") as (exe, ledger, db, _ctx, signed, _public, _cap):
        bad_cap = b"x" * 32
        cmd = m.ledger_command(operation="reserve", arm="A",
                               fingerprint="a" * 64, cap=bad_cap)
        assert m._ledger_round_trip(ledger, cmd) == "DENIED"
        assert m.Ledger(db).phase() == "FRESH"
        assert request(exe, signed, "A") == "ACK"


@pytest.mark.parametrize("mutation", [
    lambda t: t["payload"].update(paid_consent=True),
    lambda t: t["payload"].update(run_attempt=2),
    lambda t: t["payload"].update(model="gpt-6"),
    lambda t: t["payload"].update(sender_job_id="117123456781"),
    lambda t: t.update(signature_base64="!BAD!"),
])
def test_forged_signed_handoff_refused(tmp_path, mutation):
    with environment(tmp_path / "backend") as (exe, _led, db, _ctx, signed, _pub, _cap):
        tampered = deepcopy(signed)
        mutation(tampered)
        assert request(exe, tampered, "A") == "DENIED"
        assert m.Ledger(db).phase() == "FRESH"
        assert request(exe, signed, "A") == "ACK"


def test_separate_ledgers_accept_same_A_counterexample(tmp_path):
    ctx, signed, public = identity()
    cap = os.urandom(32)
    for n in ("one", "two"):
        d = tmp_path / n
        d.mkdir(mode=0o700)
        ledger, exe = d / "ledger.sock", d / "executor.sock"
        with process(m.ledger_serve, socket_path=ledger,
                     db_path=d / "ledger.sqlite", mock_capability=cap):
            with process(m.executor_serve, socket_path=exe, ledger_socket=ledger,
                         mock_capability=cap, expected=ctx,
                         test_public_key_raw=public, frozen=frozen()):
                assert request(exe, signed, "A") == "ACK"
        assert os.access(d / "ledger.sqlite", os.W_OK)  # same-UID bypass remains


def test_only_local_mock_apis_and_explicit_nonclaims():
    source = Path(m.__file__).read_text(encoding="utf-8")
    for forbidden in ("import http.client", "import requests", "from openai",
                      "api.openai.com", "POST /git/refs", "TASK1_OPENAI_API_KEY",
                      "workflow_dispatch"):
        assert forbidden not in source
    assert not hasattr(m, "send_provider")
    assert not hasattr(m, "invoke_paid")
    doc = DOC.read_text(encoding="utf-8")
    for required in ("NO-GO", "Issue #427", "#446", "#448",
                     "same UID", "different ledgers", "no Provider"):
        assert required in doc
