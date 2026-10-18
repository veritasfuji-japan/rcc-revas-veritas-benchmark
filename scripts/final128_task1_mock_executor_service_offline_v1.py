#!/usr/bin/env python3
"""Task1 synthetic signed handoff -> separate local UNIX socket executor.

OFFLINE / NO EFFECT. Reuses #446 source gate and fake Provider only.
Both client and executor run under test-owned host identity; NOT IAM isolation,
remote cross-Runner storage, provider egress protection or paid authorization.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import struct
import stat

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from scripts import final128_task1_research_signed_run_handoff_offline_v1 as handoff
from scripts import final128_task1_mock_provider_presend_bind_no_effect_v1 as mock
from scripts import final128_task1_signed_handoff_sqlite_mock_presend_v1 as sqlite_gate

SCHEMA = "veritas.final128.task1.mock-executor-service.offline.v1"
MAX_FRAME = 32768
MAX_REPLY = 4096
FAULTS = ("none", "A_TIMEOUT", "B_TIMEOUT", "A_BAD_ACK", "B_BAD_ACK",
          "AFTER_RESERVATION_BEFORE_FAKE_SEND", "AFTER_FAKE_SEND_BEFORE_ACK")

class Denied(ValueError):
    """Malformed/unauthorized local mock request; no fake Provider call."""


def exact(got: object, expected: object) -> bool:
    if type(got) is not type(expected):
        return False
    if type(expected) is dict:
        return set(got) == set(expected) and all(
            exact(got[k], v) for k, v in expected.items()
        )
    if type(expected) is list:
        return len(got) == len(expected) and all(exact(a, b) for a, b in zip(got, expected))
    return got == expected


def _parse(raw: bytes) -> object:
    if type(raw) is not bytes or len(raw) > MAX_FRAME:
        raise Denied("FRAME_SIZE_OR_TYPE")
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise Denied("DUPLICATE_KEY")
            result[k] = v
        return result
    def nonfinite(_value):
        raise Denied("NONFINITE")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=nonfinite)
    except (ValueError, UnicodeError, TypeError) as exc:
        raise Denied("MALFORMED_JSON") from exc


def _wire(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"


def request(*, socket_path: Path, arm: str, signed: dict,
            claimed_uid: object = None) -> dict:
    """A mock Runner's only proposed port. Does not read secret or database."""
    payload = {"schema": SCHEMA, "operation": "attempt", "arm": arm,
               "packet_sha256": mock.PACKET_SHA256, "signed": signed}
    if claimed_uid is not None:  # deliberate forgery / extra-field negative test
        payload["claimed_uid"] = claimed_uid
    return _round_trip(socket_path, _wire(payload))


def _round_trip(socket_path: Path, frame: bytes) -> dict:
    if not isinstance(socket_path, Path) or type(frame) is not bytes or len(frame) > MAX_FRAME:
        raise Denied("BAD_CLIENT_FRAME")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(6)
        conn.connect(str(socket_path))
        conn.sendall(frame)
        raw = bytearray()
        while b"\n" not in raw and len(raw) <= MAX_REPLY:
            chunk = conn.recv(512)
            if not chunk:
                break
            raw.extend(chunk)
        if b"\n" not in raw or len(raw) > MAX_REPLY:
            raise Denied("INVALID_EXECUTOR_REPLY")
        response = _parse(bytes(raw).split(b"\n", 1)[0])
        if type(response) is not dict or set(response) != {"status", "arm", "real_provider_requests"}:
            raise Denied("INVALID_EXECUTOR_REPLY_SCHEMA")
        if response["status"] not in ("ACK", "DENIED", "UNKNOWN") or response["real_provider_requests"] != 0:
            raise Denied("INVALID_EXECUTOR_REPLY_CONTENT")
        return response


def _frame(conn: socket.socket) -> bytes:
    raw = bytearray()
    while len(raw) <= MAX_FRAME:
        b = conn.recv(min(4096, MAX_FRAME + 2 - len(raw)))
        if not b:
            raise Denied("INCOMPLETE_FRAME")
        raw.extend(b)
        if b"\n" in b:
            line, remainder = bytes(raw).split(b"\n", 1)
            if remainder or len(line) > MAX_FRAME:
                raise Denied("MULTIFRAME_OR_OVERSIZE")
            return line
    raise Denied("FRAME_TOO_LARGE")


def _actual_peer_uid(conn: socket.socket) -> int:
    """Linux SO_PEERCRED; no trust in self-declared uid/run claims."""
    if not hasattr(socket, "SO_PEERCRED"):
        raise Denied("LINUX_PEERCRED_REQUIRED")
    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                            struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", creds)
    return uid


def _reply_for_frame(raw: bytes, gate: sqlite_gate.SQLiteLocalFakePresendGate,
                     frozen_snapshot: object, configured_fault: str) -> dict:
    candidate = _parse(raw)
    if type(candidate) is not dict or set(candidate) != {
            "schema", "operation", "arm", "packet_sha256", "signed"}:
        raise Denied("EXACT_REQUEST_FIELDS")
    if candidate["schema"] != SCHEMA or candidate["operation"] != "attempt":
        raise Denied("WRONG_PROTOCOL_OR_OPERATION")
    if type(candidate["arm"]) is not str or candidate["arm"] not in ("A", "B"):
        raise Denied("INVALID_ARM")
    if type(candidate["packet_sha256"]) is not str or candidate["packet_sha256"] != mock.PACKET_SHA256:
        raise Denied("UNTRUSTED_PACKET")
    fault = (configured_fault if configured_fault.startswith("AFTER_")
             else "none")
    receipt = gate.attempt(arm=candidate["arm"], packet=mock.PACKET,
                           signed=candidate["signed"],
                           frozen_snapshot=frozen_snapshot, fault=fault)
    assert receipt.local_fake_ack is True and receipt.real_provider_requests == 0
    return {"status": "ACK", "arm": receipt.arm, "real_provider_requests": 0}


def serve(*, socket_path: Path, db_path: Path, expected: handoff.MockJobContext,
          test_public_key_raw: bytes, frozen_snapshot: object,
          ready_event: object, stop_event: object, admitted_uid: int,
          configured_fault: str = "none") -> None:
    """Separate spawned OS process (same-UID test supervision), AF_UNIX only.

    Caller does not pass a DB object and cannot access fake port over IPC.
    This deliberately does NOT keep the DB safe from another process with
    the same host UID or the parent test supervisor.
    """
    if not isinstance(socket_path, Path) or not isinstance(db_path, Path):
        raise Denied("EXACT_PRIVATE_PATHS")
    if socket_path.parent != db_path.parent or socket_path == db_path:
        raise Denied("SHARED_PRIVATE_SERVICE_DIRECTORY_REQUIRED")
    directory = socket_path.parent
    if not directory.is_dir() or directory.is_symlink() or (stat.S_IMODE(directory.stat().st_mode) & 0o077):
        raise Denied("PRIVATE_0700_DIR_REQUIRED")
    if socket_path.exists() or socket_path.is_symlink():
        raise Denied("SOCKET_PATH_MUST_BE_ABSENT")
    if type(admitted_uid) is not int or admitted_uid < 0 or configured_fault not in FAULTS:
        raise Denied("PEER_OR_FAULT_CONFIG")
    public = Ed25519PublicKey.from_public_bytes(test_public_key_raw)
    # No Provider keys are read. Fake port and local DB instantiated ONLY here.
    fake_mode = configured_fault if configured_fault in (
        "A_TIMEOUT", "B_TIMEOUT", "A_BAD_ACK", "B_BAD_ACK") else "none"
    local_port = mock.InMemoryFakeProviderPort(fake_mode)
    gate = sqlite_gate.SQLiteLocalFakePresendGate(
        db_path=db_path, expected=expected,
        pinned_test_public_key=public, local_fake_port=local_port)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        listener.listen(16)
        listener.settimeout(0.15)
        ready_event.set()
        try:
            while not stop_event.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                with conn:
                    conn.settimeout(4)
                    arm = "NONE"
                    try:
                        if _actual_peer_uid(conn) != admitted_uid:
                            raise Denied("UNENROLLED_LOCAL_PEER")
                        raw = _frame(conn)
                        result = _reply_for_frame(raw, gate, frozen_snapshot,
                                                  configured_fault)
                        arm = result["arm"]
                    except sqlite_gate.UnknownAfterAttempt:
                        result = {"status": "UNKNOWN", "arm": arm,
                                  "real_provider_requests": 0}
                    except (Denied, sqlite_gate.Refused, handoff.Refused,
                            TypeError, ValueError, KeyError, OSError):
                        result = {"status": "DENIED", "arm": arm,
                                  "real_provider_requests": 0}
                    try:
                        conn.sendall(_wire(result))
                    except OSError:
                        # Attempt remains durably reserved; never replay.
                        pass
        finally:
            # Only the owning test supervisor can stop this process; no
            # shutdown or reset operation is exposed to the mock Runner.
            try:
                socket_path.unlink()
            except FileNotFoundError:
                pass
