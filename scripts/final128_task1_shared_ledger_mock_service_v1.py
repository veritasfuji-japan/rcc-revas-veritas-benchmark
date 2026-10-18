#!/usr/bin/env python3
"""OFFLINE Task1 fake Provider: two local services, one executor-owned ledger.

Simulated Runners -> local Executor -> separately started local SQLite ledger.
Test supervisor supplies an ephemeral HMAC capability only to these services.
All actors run on ONE test host with the SAME UID: no real IAM/cross-host
durability, no independent signing authority, no actual Provider or payment.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import hmac
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from scripts import final128_task1_mock_executor_service_offline_v1 as ipc
from scripts import final128_task1_research_signed_run_handoff_offline_v1 as handoff
from scripts import final128_task1_mock_provider_presend_bind_no_effect_v1 as mock

SCHEMA = "veritas.final128.task1.shared-ledger-mock.offline.v1"
LEDGER_SCHEMA = "veritas.final128.task1.remote-shaped-ledger.offline.v1"
SCOPE = "FIRST_A_B_SYNTHETIC_ONE_SHARED_LEDGER_V1"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
FAULTS = ("none", "A_TIMEOUT", "B_TIMEOUT", "A_BAD_ACK", "B_BAD_ACK",
          "AFTER_RESERVATION_BEFORE_FAKE_SEND", "AFTER_FAKE_SEND_BEFORE_ACK")


class Denied(ValueError):
    """No fake effect is allowed from an untrusted/missing permission."""


def need(ok: bool, reason: str) -> None:
    if ok is not True:
        raise Denied("TASK1_SHARED_LEDGER_MOCK_" + reason)


def _private(path: Path) -> None:
    need(type(path) is Path and path.is_dir() and not path.is_symlink()
         and stat.S_IMODE(path.stat().st_mode) & 0o077 == 0, "PRIVATE_0700")


def _listen(path: Path) -> socket.socket:
    _private(path.parent)
    need(not path.exists() and not path.is_symlink(), "UNUSED_SOCKET_PATH")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    os.chmod(path, 0o600)
    listener.listen(16)
    listener.settimeout(0.15)
    return listener


def _command_key(command: dict, key: bytes) -> str:
    return hmac.new(key, ipc._wire(command).rstrip(b"\n"), hashlib.sha256).hexdigest()


def ledger_command(*, operation: str, arm: str, fingerprint: str, cap: bytes) -> dict:
    fields = {"schema": LEDGER_SCHEMA, "operation": operation,
              "arm": arm, "fingerprint": fingerprint}
    return {**fields, "mac_sha256": _command_key(fields, cap)}


def _decode_command(raw: bytes, cap: bytes) -> dict:
    obj = ipc._parse(raw)
    need(type(obj) is dict and set(obj) == {
        "schema", "operation", "arm", "fingerprint", "mac_sha256"
    }, "EXACT_LEDGER_FIELDS")
    need(obj["schema"] == LEDGER_SCHEMA
         and obj["operation"] in ("reserve", "ack")
         and type(obj["arm"]) is str and obj["arm"] in ("A", "B")
         and type(obj["fingerprint"]) is str
         and SHA256.fullmatch(obj["fingerprint"]) is not None
         and type(obj["mac_sha256"]) is str
         and SHA256.fullmatch(obj["mac_sha256"]) is not None,
         "EXACT_LEDGER_SCOPE")
    payload = {k: obj[k] for k in ("schema", "operation", "arm", "fingerprint")}
    need(hmac.compare_digest(obj["mac_sha256"], _command_key(payload, cap)),
         "UNENROLLED_MOCK_EXECUTOR_CAPABILITY")
    return obj


class Ledger:
    """Local SQLite process owner; no client filesystem API or reset operation."""

    def __init__(self, db_path: Path) -> None:
        _private(db_path.parent)
        need(type(db_path) is Path and db_path.suffix == ".sqlite"
             and not db_path.is_symlink(), "EXACT_SQLITE_PATH")
        if not db_path.exists():
            try:
                fd = os.open(str(db_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY
                             | getattr(os, "O_NOFOLLOW", 0), 0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
        need(db_path.is_file() and not db_path.is_symlink()
             and stat.S_IMODE(db_path.stat().st_mode) & 0o077 == 0,
             "OWNER_ONLY_DB")
        self.db_path = db_path
        with closing(self._connect()) as db:
            db.execute("CREATE TABLE IF NOT EXISTS pair ("
                       "scope TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,"
                       "phase TEXT NOT NULL CHECK(phase IN "
                       "('UNKNOWN_A','A_ACK','UNKNOWN_B','PAIR_ACK')))")
            db.execute("CREATE TABLE IF NOT EXISTS attempt ("
                       "arm TEXT PRIMARY KEY CHECK(arm IN ('A','B')),"
                       "fingerprint TEXT NOT NULL, state TEXT NOT NULL"
                       " CHECK(state IN ('UNKNOWN','ACK')))")
            db.commit()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(str(self.db_path), timeout=5)
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def apply(self, cmd: dict) -> str:
        with closing(self._connect()) as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                old = db.execute("SELECT fingerprint,phase FROM pair WHERE scope=?",
                                 (SCOPE,)).fetchone()
                arm, fingerprint, op = (cmd["arm"], cmd["fingerprint"], cmd["operation"])
                if op == "reserve":
                    if old is None:
                        need(arm == "A", "B_BEFORE_A")
                        db.execute("INSERT INTO pair VALUES(?,?,?)",
                                   (SCOPE, fingerprint, "UNKNOWN_A"))
                    else:
                        seen, phase = old
                        need(seen == fingerprint and arm == "B" and phase == "A_ACK",
                             "REPLAY_OR_UNKNOWN_STOP")
                        db.execute("UPDATE pair SET phase='UNKNOWN_B' WHERE scope=?",
                                   (SCOPE,))
                    db.execute("INSERT INTO attempt VALUES(?,?,?)",
                               (arm, fingerprint, "UNKNOWN"))
                    db.commit()  # durable *before* potential local fake call
                    return "RESERVED"
                need(op == "ack" and old is not None, "INVALID_ACK_OPERATION")
                seen, phase = old
                before, after = (("UNKNOWN_A", "A_ACK") if arm == "A" else
                                 ("UNKNOWN_B", "PAIR_ACK"))
                need(seen == fingerprint and phase == before, "ACK_SCOPE_MISMATCH")
                changed = db.execute(
                    "UPDATE attempt SET state='ACK' WHERE arm=?"
                    " AND fingerprint=? AND state='UNKNOWN'", (arm, fingerprint))
                need(changed.rowcount == 1, "NO_MATCHING_UNKNOWN_ATTEMPT")
                db.execute("UPDATE pair SET phase=? WHERE scope=?", (after, SCOPE))
                db.commit()
                return "ACK"
            except BaseException:
                db.rollback()
                raise

    def phase(self) -> str:
        with closing(self._connect()) as db:
            v = db.execute("SELECT phase FROM pair WHERE scope=?", (SCOPE,)).fetchone()
        return v[0] if v else "FRESH"


def ledger_serve(*, socket_path: Path, db_path: Path, mock_capability: bytes,
                 ready: object, stop: object) -> None:
    need(type(mock_capability) is bytes and len(mock_capability) == 32,
         "EPHEMERAL_LOCAL_CAPABILITY_REQUIRED")
    ledger = Ledger(db_path)
    with closing(_listen(socket_path)) as listener:
        ready.set()
        try:
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                with conn:
                    conn.settimeout(4)
                    try:
                        command = _decode_command(ipc._frame(conn), mock_capability)
                        result = ledger.apply(command)
                    except (Denied, ipc.Denied, TypeError, ValueError,
                            sqlite3.Error, OSError, KeyError):
                        result = "DENIED"
                    try:
                        conn.sendall(ipc._wire({"status": result, "real_provider_requests": 0}))
                    except OSError:
                        pass
        finally:
            socket_path.unlink(missing_ok=True)


def _ledger_round_trip(path: Path, command: dict) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(4)
        conn.connect(str(path))
        conn.sendall(ipc._wire(command))
        raw = ipc._frame(conn)
    response = ipc._parse(raw)
    need(type(response) is dict and set(response) == {
        "status", "real_provider_requests"
    } and type(response["status"]) is str
    and response["status"] in ("ACK", "RESERVED", "DENIED")
    and type(response["real_provider_requests"]) is int
    and response["real_provider_requests"] == 0, "INVALID_LEDGER_REPLY")
    return response["status"]


def runner_request(*, socket_path: Path, arm: str, signed: dict) -> dict:
    return ipc._round_trip(socket_path, ipc._wire({
        "schema": SCHEMA, "operation": "attempt", "arm": arm,
        "packet_sha256": mock.PACKET_SHA256, "signed": signed}))


def _verified_fingerprint(*, signed: dict, expected: handoff.MockJobContext,
                          public: Ed25519PublicKey, frozen: object) -> str:
    try:
        checked = mock.evidence.review_frozen_snapshot(frozen)
        need(checked.decision == "PAID_TASK1_NO_GO"
             and checked.authorized_to_send_provider is False
             and checked.run_job_origin_authenticated is False,
             "FROZEN_EVIDENCE_MUST_DENY_LIVE")
        verdict = handoff.verify_and_mark_mock(
            signed, expected=expected, pinned_test_public_key=public,
            replay_ledger=handoff.EphemeralReplayLedger())
        need(verdict.mock_integrity_ok is True
             and verdict.provider_dispatch_authorized is False,
             "ONLY_SYNTHETIC_SIGNED_HANDOFF")
        need(expected.request_sha256 == mock.PACKET_SHA256, "FAKE_PACKET_ONLY")
    except (handoff.Refused, ValueError, KeyError, TypeError) as exc:
        raise Denied("SIGNED_MOCK_SCOPE_REFUSED") from exc
    return hashlib.sha256(
        handoff.canonical(signed["payload"]) +
        signed["signature_base64"].encode("ascii")
    ).hexdigest()


def executor_serve(*, socket_path: Path, ledger_socket: Path,
                   mock_capability: bytes, expected: handoff.MockJobContext,
                   test_public_key_raw: bytes, frozen: object,
                   ready: object, stop: object, failure: str = "none") -> None:
    need(type(mock_capability) is bytes and len(mock_capability) == 32,
         "EPHEMERAL_LOCAL_CAPABILITY_REQUIRED")
    need(failure in FAULTS, "EXACT_FAKE_FAILURE")
    public = Ed25519PublicKey.from_public_bytes(test_public_key_raw)
    fake_mode = failure if failure in (
        "A_TIMEOUT", "B_TIMEOUT", "A_BAD_ACK", "B_BAD_ACK") else "none"
    fake = mock.InMemoryFakeProviderPort(fake_mode)
    with closing(_listen(socket_path)) as listener:
        ready.set()
        try:
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                with conn:
                    conn.settimeout(5)
                    arm = "NONE"
                    reserved = False
                    try:
                        candidate = ipc._parse(ipc._frame(conn))
                        need(type(candidate) is dict and set(candidate) == {
                            "schema", "operation", "arm", "packet_sha256", "signed"
                        }, "EXACT_RUNNER_FIELDS")
                        need(candidate["schema"] == SCHEMA
                             and candidate["operation"] == "attempt"
                             and type(candidate["arm"]) is str
                             and candidate["arm"] in ("A", "B")
                             and candidate["packet_sha256"] == mock.PACKET_SHA256,
                             "RUNNER_SCOPE")
                        arm = candidate["arm"]
                        fp = _verified_fingerprint(
                            signed=candidate["signed"], expected=expected,
                            public=public, frozen=frozen)
                        reserve = _ledger_round_trip(ledger_socket, ledger_command(
                            operation="reserve", arm=arm, fingerprint=fp,
                            cap=mock_capability))
                        need(reserve == "RESERVED", "REMOTE_LEDGER_RESERVE_DENIED")
                        reserved = True
                        if failure == "AFTER_RESERVATION_BEFORE_FAKE_SEND":
                            raise TimeoutError("UNKNOWN_NO_FAKE_SEND")
                        reply = fake.deliver(arm, mock.PACKET)  # NEVER HTTPS
                        if failure == "AFTER_FAKE_SEND_BEFORE_ACK":
                            raise TimeoutError("UNKNOWN_FAKE_ACK")
                        expected_reply = {"marker": mock.FAKE_ACK, "arm": arm,
                                          "packet_sha256": mock.PACKET_SHA256}
                        need(type(reply) is dict
                             and set(reply) == set(expected_reply) | {"ordinal"}
                             and all(type(reply[k]) is type(v) and reply[k] == v
                                     for k, v in expected_reply.items())
                             and type(reply["ordinal"]) is int
                             and 1 <= reply["ordinal"] <= 2,
                             "MALFORMED_FAKE_ACK")
                        ack = _ledger_round_trip(ledger_socket, ledger_command(
                            operation="ack", arm=arm, fingerprint=fp,
                            cap=mock_capability))
                        need(ack == "ACK", "LEDGER_ACK_UNKNOWN")
                        status = "ACK"
                    except (Denied, ipc.Denied, handoff.Refused, ValueError,
                            TypeError, KeyError, OSError, sqlite3.Error,
                            TimeoutError):
                        status = "UNKNOWN" if reserved else "DENIED"
                    try:
                        conn.sendall(ipc._wire({"status": status, "arm": arm,
                                                "real_provider_requests": 0}))
                    except OSError:
                        pass
        finally:
            socket_path.unlink(missing_ok=True)
