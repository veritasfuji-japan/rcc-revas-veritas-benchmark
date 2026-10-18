#!/usr/bin/env python3
"""Task1 real Linux cross-UID mock Executor/Ledger test harness (NO EFFECT).

Run ONLY in an ephemeral, trusted Linux test supervisor. It creates numerical
test UIDs by dropping root in forked children; no passwd/system account writes.
Root orchestrator is TRUSTED and out of scope. Reuses #449 fake signed handoff,
local SQLite state machine, and fake Provider; never accesses a Provider key.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import multiprocessing
import os
from pathlib import Path
import socket
import stat
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from scripts import final128_task1_shared_ledger_mock_service_v1 as mock_service
from scripts import final128_task1_mock_executor_service_offline_v1 as ipc
from scripts import final128_task1_research_signed_run_handoff_offline_v1 as handoff
from scripts import final128_task1_mock_provider_presend_bind_no_effect_v1 as mock

SCHEMA = "veritas.final128.task1.linux-crossuid-shared-ledger.offline.v1"
LEDGER_UID = 62101
EXECUTOR_UID = 62102
RUNNER_A_UID = 62103
RUNNER_B_UID = 62104
ALLOWED_RUNNERS = (RUNNER_A_UID, RUNNER_B_UID)
CTX = multiprocessing.get_context("fork")
ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "evidence/final128_task1_research_tag_live_readback_2026-10-18_v1.json"


class Denied(RuntimeError):
    pass


def _drop(uid: int) -> None:
    assert os.geteuid() == 0 and uid in (LEDGER_UID, EXECUTOR_UID, *ALLOWED_RUNNERS)
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)
    assert os.geteuid() == os.getegid() == uid


def _bind(path: Path) -> socket.socket:
    # Root-owned common directory: untrusted UIDs cannot unlink/rebind socket.
    assert path.parent.stat().st_uid == 0
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o755
    assert not path.exists()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(path))
    os.chmod(path, 0o666)  # Permit kernel peer checks, not socket-DAC as identity.
    s.listen(16)
    s.settimeout(0.1)
    return s


def _child_ledger(listener: socket.socket, other: socket.socket, db: Path,
                  cap: bytes, ready: object, stop: object) -> None:
    other.close()
    _drop(LEDGER_UID)
    ledger = mock_service.Ledger(db)
    assert db.stat().st_uid == LEDGER_UID
    assert stat.S_IMODE(db.stat().st_mode) == 0o600
    ready.set()
    while not stop.is_set():
        try:
            conn, _ = listener.accept()
        except socket.timeout:
            continue
        with conn:
            conn.settimeout(4)
            try:
                if ipc._actual_peer_uid(conn) != EXECUTOR_UID:
                    raise Denied("LEDGER_ONLY_ACCEPTS_KERNEL_EXECUTOR_UID")
                command = mock_service._decode_command(ipc._frame(conn), cap)
                status = ledger.apply(command)
            except (Denied, mock_service.Denied, ipc.Denied,
                    ValueError, TypeError, KeyError, OSError):
                status = "DENIED"
            try:
                conn.sendall(ipc._wire({"status": status, "real_provider_requests": 0}))
            except OSError:
                pass
    listener.close()


def _child_executor(listener: socket.socket, other: socket.socket,
                    ledger_path: Path, cap: bytes,
                    expected: handoff.MockJobContext, public_raw: bytes,
                    frozen: object, ready: object, stop: object,
                    fault: str = "none") -> None:
    other.close()
    _drop(EXECUTOR_UID)
    public = Ed25519PublicKey.from_public_bytes(public_raw)
    mode = fault if fault in ("A_TIMEOUT", "B_TIMEOUT", "A_BAD_ACK", "B_BAD_ACK") else "none"
    fake = mock.InMemoryFakeProviderPort(mode)
    ready.set()
    while not stop.is_set():
        try:
            conn, _ = listener.accept()
        except socket.timeout:
            continue
        with conn:
            conn.settimeout(5)
            arm, reserved = "NONE", False
            try:
                if ipc._actual_peer_uid(conn) not in ALLOWED_RUNNERS:
                    raise Denied("ONLY_ENROLLED_MOCK_RUNNER_UIDS")
                data = ipc._parse(ipc._frame(conn))
                if type(data) is not dict or set(data) != {
                        "schema", "operation", "arm", "packet_sha256", "signed"}:
                    raise Denied("EXACT_FRAME")
                if (data["schema"] != mock_service.SCHEMA or data["operation"] != "attempt"
                        or type(data["arm"]) is not str or data["arm"] not in ("A", "B")
                        or data["packet_sha256"] != mock.PACKET_SHA256):
                    raise Denied("WRONG_FRAME")
                arm = data["arm"]
                fp = mock_service._verified_fingerprint(
                    signed=data["signed"], expected=expected, public=public, frozen=frozen)
                reply = mock_service._ledger_round_trip(
                    ledger_path, mock_service.ledger_command(
                        operation="reserve", arm=arm, fingerprint=fp, cap=cap))
                if reply != "RESERVED":
                    raise Denied("REMOTE_LEDGER_REFUSED")
                reserved = True
                if fault == "AFTER_RESERVATION_BEFORE_FAKE_SEND":
                    raise TimeoutError("MOCK_UNKNOWN_BEFORE_FAKE_EFFECT")
                local_reply = fake.deliver(arm, mock.PACKET)
                if fault == "AFTER_FAKE_SEND_BEFORE_ACK":
                    raise TimeoutError("MOCK_UNKNOWN_AFTER_FAKE_EFFECT")
                wanted = {"marker": mock.FAKE_ACK, "arm": arm,
                          "packet_sha256": mock.PACKET_SHA256}
                if (type(local_reply) is not dict
                        or set(local_reply) != set(wanted) | {"ordinal"}
                        or any(type(local_reply[k]) is not type(v) or local_reply[k] != v
                               for k, v in wanted.items())
                        or type(local_reply["ordinal"]) is not int
                        or not 1 <= local_reply["ordinal"] <= 2):
                    raise Denied("INVALID_FAKE_ACK")
                result = mock_service._ledger_round_trip(
                    ledger_path, mock_service.ledger_command(
                        operation="ack", arm=arm, fingerprint=fp, cap=cap))
                if result != "ACK":
                    raise Denied("LEDGER_ACK_MISSING")
                status = "ACK"
            except (Denied, mock_service.Denied, ipc.Denied,
                    handoff.Refused, ValueError, TypeError, KeyError,
                    OSError, TimeoutError):
                status = "UNKNOWN" if reserved else "DENIED"
            try:
                conn.sendall(ipc._wire({"status": status, "arm": arm,
                                        "real_provider_requests": 0}))
            except OSError:
                pass
    listener.close()


def _runner(uid: int, exe_path: Path, signed: dict,
            arm: str, start: object, result: object,
            inherited_fds: tuple[int, ...]) -> None:
    for fd in inherited_fds:
        os.close(fd)
    _drop(uid)
    if not start.wait(timeout=12):
        result.put("NOT_STARTED")
        return
    try:
        result.put(mock_service.runner_request(
            socket_path=exe_path, arm=arm, signed=signed)["status"])
    except (OSError, ValueError, TypeError) as exc:
        result.put("EXCEPTION_" + type(exc).__name__)


def _probe_os_dac(uid: int, private_dir: Path, db: Path,
                  result: object, inherited_fds: tuple[int, ...]) -> None:
    for fd in inherited_fds:
        os.close(fd)
    _drop(uid)
    refused = {}
    for name, func in {
        "list": lambda: os.listdir(private_dir),
        "read": lambda: os.open(db, os.O_RDONLY),
        "write": lambda: os.open(db, os.O_WRONLY),
        "unlink": lambda: os.unlink(db),
        "chmod": lambda: os.chmod(db, 0o666),
        "replace": lambda: os.replace(db, private_dir / "reset.sqlite"),
    }.items():
        try:
            output = func()
            if isinstance(output, int):
                os.close(output)
            refused[name] = False
        except PermissionError:
            refused[name] = True
    result.put({"uid": os.geteuid(), "denied": refused})


@contextmanager
def _services(root: Path, private: Path, cap: bytes,
              context: handoff.MockJobContext, public: bytes,
              snapshot: object, fault: str = "none"):
    ledger_path, executor_path = root / "ledger.sock", root / "executor.sock"
    ledger_listener = _bind(ledger_path)
    executor_listener = _bind(executor_path)
    stop = CTX.Event()
    ledger_ready, executor_ready = CTX.Event(), CTX.Event()
    l = CTX.Process(target=_child_ledger,
                    args=(ledger_listener, executor_listener,
                          private / "ledger.sqlite", cap, ledger_ready, stop))
    e = CTX.Process(target=_child_executor,
                    args=(executor_listener, ledger_listener, ledger_path, cap,
                          context, public, snapshot, executor_ready, stop, fault))
    try:
        l.start()
        e.start()
        assert ledger_ready.wait(12) and executor_ready.wait(12)
        assert l.is_alive() and e.is_alive()
        # Parent (trusted root) need not hold listener handles during test.
        fds = (ledger_listener.fileno(), executor_listener.fileno())
        yield executor_path, ledger_path, (l, e), fds
    finally:
        stop.set()
        for p in (l, e):
            if p.pid:
                p.join(timeout=7)
                if p.is_alive():
                    p.terminate()
                    p.join(timeout=4)
                assert p.exitcode == 0
        ledger_listener.close()
        executor_listener.close()
        ledger_path.unlink(missing_ok=True)
        executor_path.unlink(missing_ok=True)


def _fixture():
    context = handoff.MockJobContext(
        main_sha=mock.SHA, run_id="39012345678",
        issuer_job_id="117123456781", sender_job_id="117123456782",
        request_sha256=mock.PACKET_SHA256, run_attempt=1)
    ephemeral = Ed25519PrivateKey.generate()
    signed = handoff.mock_sign(handoff.mock_payload(context), ephemeral, context)
    public = ephemeral.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf8"))
    return context, signed, public, snapshot


def _test_root_case(root: Path, fault: str = "none") -> dict:
    root.mkdir(mode=0o755)
    assert root.stat().st_uid == 0 and stat.S_IMODE(root.stat().st_mode) == 0o755
    private = root / "ledger-private"
    private.mkdir(mode=0o700)
    os.chown(private, LEDGER_UID, LEDGER_UID)
    private.chmod(0o700)
    context, signed, public, snapshot = _fixture()
    cap = os.urandom(32)
    with _services(root, private, cap, context, public, snapshot, fault) as (
            exe, ledger_sock, procs, fds):
        q = CTX.Queue()
        probe = CTX.Process(target=_probe_os_dac,
                            args=(RUNNER_A_UID, private, private / "ledger.sqlite", q, fds))
        probe.start()
        observed = q.get(timeout=10)
        probe.join(timeout=8)
        assert probe.exitcode == 0
        assert observed["uid"] == RUNNER_A_UID
        assert all(observed["denied"].values()), observed
        # Even a separate Executor UID cannot directly replace ledger files.
        executor_probe = CTX.Process(target=_probe_os_dac,
                                    args=(EXECUTOR_UID, private, private / "ledger.sqlite", q, fds))
        executor_probe.start()
        exec_observed = q.get(timeout=10)
        executor_probe.join(timeout=8)
        assert executor_probe.exitcode == 0
        assert all(exec_observed["denied"].values()), exec_observed

        # Direct ledger ingress from Runner is denied by kernel peer UID,
        # even if the ROOT supervisor supplies the correct ephemeral HMAC.
        direct = CTX.Queue()
        def forged_direct():
            for fd in fds:
                os.close(fd)
            _drop(RUNNER_A_UID)
            cmd = mock_service.ledger_command(
                operation="reserve", arm="A", fingerprint="a" * 64, cap=cap)
            direct.put(mock_service._ledger_round_trip(ledger_sock, cmd))
        attacker = CTX.Process(target=forged_direct)
        attacker.start()
        direct_status = direct.get(timeout=10)
        attacker.join(timeout=8)
        assert attacker.exitcode == 0 and direct_status == "DENIED"

        start = CTX.Event()
        outcomes = CTX.Queue()
        runners = [CTX.Process(target=_runner, args=(
            uid, exe, signed, "A", start, outcomes, fds))
            for uid in ALLOWED_RUNNERS]
        for p in runners:
            p.start()
        start.set()
        statuses = sorted(outcomes.get(timeout=16) for _ in runners)
        for p in runners:
            p.join(timeout=10)
            assert p.exitcode == 0
        if fault == "none":
            assert statuses == ["ACK", "DENIED"], statuses
        else:
            assert statuses == ["DENIED", "UNKNOWN"], statuses
        assert procs[0].is_alive() and procs[1].is_alive()
        # Observations from the ledger belong to root test-supervisor only.
        phase = mock_service.Ledger(private / "ledger.sqlite").phase()
        assert phase == ("A_ACK" if fault == "none" else "UNKNOWN_A")
    # Both services have exited. Restart on the exact same ledger path.
    with _services(root, private, cap, context, public, snapshot) as (exe, _, _, fds):
        out = CTX.Queue()
        ready = CTX.Event()
        p = CTX.Process(target=_runner,
                        args=(RUNNER_A_UID, exe, signed, "A", ready, out, fds))
        p.start()
        ready.set()
        replay = out.get(timeout=10)
        p.join(timeout=7)
        assert p.exitcode == 0 and replay == "DENIED"
    return {"case": fault, "distinct_kernel_uids": 4,
            "os_dac_runner_denial": all(observed["denied"].values()),
            "os_dac_executor_denial": all(exec_observed["denied"].values()),
            "direct_ledger_peer_refused": direct_status == "DENIED",
            "runner_race": statuses, "after_restart_A": replay,
            "phase": phase, "real_provider_calls": 0,
            "remote_cross_host_proven": False, "production_iam_proven": False}


def proof() -> dict:
    assert os.name == "posix" and os.geteuid() == 0
    assert len(set((LEDGER_UID, EXECUTOR_UID, *ALLOWED_RUNNERS))) == 4
    with tempfile.TemporaryDirectory(prefix="task1-450-offline-") as tmp:
        base = Path(tmp)
        base.chmod(0o755)  # root-owned, others may traverse but not mutate.
        results = [
            _test_root_case(base / "positive"),
            _test_root_case(base / "unknown", "AFTER_FAKE_SEND_BEFORE_ACK"),
        ]
        assert results[0]["runner_race"] == ["ACK", "DENIED"]
        assert results[1]["runner_race"] == ["DENIED", "UNKNOWN"]
        return {"schema": SCHEMA, "status": "CROSSUID_LOCAL_MOCK_ONLY_NO_GO",
                "cases": results, "paid_dispatch_authorized": False,
                "external_provider_calls": 0, "issue_427_closed": False}


if __name__ == "__main__":
    import sys
    if sys.argv != [sys.argv[0], "--prove"]:
        raise SystemExit("OFFLINE_ONLY_USAGE: --prove")
    print(json.dumps(proof(), sort_keys=True, separators=(",", ":")))
