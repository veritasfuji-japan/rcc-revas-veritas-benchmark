#!/usr/bin/env python3
"""OFFLINE Task1 A/B: signed synthetic handoff -> SQLite reservation -> fake sink.

Combines previously separate #437 signing and #442 mock-Provider tests.
Zero Provider network, secrets, GitHub API, tags, workflow dispatch or live IAM.
The public key, mock Run/job context, sqlite owner and sink are test-owned,
not independently enrolled GitHub identities or non-bypassable credentials.
A shared *local* SQLite file survives new objects/processes, NOT remote runners.
"""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3
import stat
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts import final128_task1_research_signed_run_handoff_offline_v1 as handoff
from scripts import final128_task1_mock_provider_presend_bind_no_effect_v1 as mock

SCHEMA = "veritas.final128.task1.signed-handoff-sqlite-mock-presend.v1"
SCOPE = "TASK1_FIRST_A_B_OFFLINE_SINGLE_LOCAL_DATABASE"
ARMS = ("A", "B")


class Refused(ValueError):
    """Missing, stale, replayed or untrusted mock authorization; no fake call."""


class UnknownAfterAttempt(Refused):
    """Local attempt has an unknown outcome; NEVER retry from this ledger."""


def need(ok: bool, code: str) -> None:
    if ok is not True:
        raise Refused("TASK1_SIGNED_SQLITE_MOCK_" + code)


def exact(got: object, expected: object) -> bool:
    if type(got) is not type(expected):
        return False
    if type(expected) is dict:
        return set(got) == set(expected) and all(
            exact(got[k], v) for k, v in expected.items()
        )
    if type(expected) is list:
        return len(got) == len(expected) and all(
            exact(a, b) for a, b in zip(got, expected)
        )
    return got == expected


@dataclass(frozen=True)
class LocalReceipt:
    schema: str
    arm: str
    request_sha256: str
    local_fake_ack: bool
    real_provider_requests: int = 0
    github_identity_authenticated: bool = False
    paid_dispatch_authorized: bool = False
    external_durable_lease_proven: bool = False
    actual_job_permission_split_proven: bool = False


class SQLiteLocalFakePresendGate:
    """Fail-closed SQLite ledger for ONE synthetic A/B pair.

    Can be used by different test processes sharing exactly the same local
    file. The owner can delete/replace the DB; remote Runners do not share it.
    This is NOT an independently controlled Provider egress gate.
    """

    def __init__(self, *, db_path: Path,
                 expected: handoff.MockJobContext,
                 pinned_test_public_key: Ed25519PublicKey,
                 local_fake_port: mock.InMemoryFakeProviderPort) -> None:
        need(isinstance(db_path, Path) and db_path.name.endswith(".sqlite")
             and not db_path.is_symlink(), "EXACT_LOCAL_DB_PATH")
        need(db_path.parent.is_dir() and not db_path.parent.is_symlink(),
             "LOCAL_PRIVATE_PARENT_EXISTS")
        mode = db_path.parent.stat().st_mode
        need(stat.S_ISDIR(mode) and stat.S_IMODE(mode) & 0o077 == 0,
             "PRIVATE_PARENT_0700_REQUIRED")
        need(type(expected) is handoff.MockJobContext,
             "EXACT_UNTRUSTED_MOCK_CONTEXT")
        expected.check()
        need(isinstance(pinned_test_public_key, Ed25519PublicKey),
             "EXPLICIT_TEST_PUBLIC_KEY")
        need(type(local_fake_port) is mock.InMemoryFakeProviderPort,
             "NO_NETWORK_TRANSPORT_ALLOWED")
        # Create the file with 0600, not relying on SQLite defaults/umask.
        if not db_path.exists():
            try:
                fd = os.open(
                    db_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                    getattr(os, "O_NOFOLLOW", 0), 0o600,
                )
            except FileExistsError:
                pass
            else:
                os.close(fd)
        need(not db_path.is_symlink() and db_path.is_file()
             and stat.S_IMODE(db_path.stat().st_mode) & 0o077 == 0,
             "OWNER_ONLY_DB_REQUIRED")
        self.db_path = db_path
        self.expected = expected
        self.public = pinned_test_public_key
        self.port = local_fake_port
        with closing(self._connection()) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS pair ("
                " scope TEXT PRIMARY KEY NOT NULL,"
                " fingerprint TEXT NOT NULL,"
                " phase TEXT NOT NULL CHECK(phase IN "
                " ('UNKNOWN_A','A_ACK','UNKNOWN_B','PAIR_ACK')))"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS attempts ("
                " arm TEXT PRIMARY KEY NOT NULL CHECK(arm IN ('A','B')),"
                " fingerprint TEXT NOT NULL,"
                " state TEXT NOT NULL CHECK(state IN ('UNKNOWN','ACK')))"
            )
            db.commit()

    def _connection(self) -> sqlite3.Connection:
        db = sqlite3.connect(str(self.db_path), timeout=5)
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA synchronous=FULL")
        # SQLite default rollback-journal mode; avoid resetting it during races.
        return db

    def _verify(self, *, arm: str, packet: bytes, signed: object,
                frozen_snapshot: object) -> str:
        need(type(arm) is str and arm in ARMS, "EXACT_ARM")
        need(type(packet) is bytes and packet == mock.PACKET
             and hashlib.sha256(packet).hexdigest() == mock.PACKET_SHA256
             and self.expected.request_sha256 == mock.PACKET_SHA256,
             "SOURCE_OWNED_FAKE_PACKET_ONLY")
        # Historical tag evidence must stay a NO-GO, never authorizing calls.
        try:
            review = mock.evidence.review_frozen_snapshot(frozen_snapshot)
        except (ValueError, TypeError, KeyError) as exc:
            raise Refused("TASK1_SIGNED_SQLITE_MOCK_FROZEN_EVIDENCE_DENIED") from exc
        need(review.authorized_to_send_provider is False
             and review.decision == "PAID_TASK1_NO_GO"
             and review.run_job_origin_authenticated is False,
             "NO_LIVE_AUTHORITY_ALLOWED")
        # Reuse #437's exact context and Ed25519 signature checker. Its
        # ephemeral ledger is disposable; ONLY SQLite below excludes replay.
        try:
            result = handoff.verify_and_mark_mock(
                signed, expected=self.expected,
                pinned_test_public_key=self.public,
                replay_ledger=handoff.EphemeralReplayLedger(),
            )
        except (handoff.Refused, TypeError, KeyError) as exc:
            raise Refused("TASK1_SIGNED_SQLITE_MOCK_SIGNED_SCOPE_DENIED") from exc
        need(result.mock_integrity_ok is True
             and result.provider_dispatch_authorized is False
             and result.github_identity_authenticated is False,
             "SYNTHETIC_INTEGRITY_ONLY")
        fingerprint = hashlib.sha256(
            handoff.canonical(signed["payload"]) +
            signed["signature_base64"].encode("ascii")
        ).hexdigest()
        return fingerprint

    def _reserve(self, arm: str, fingerprint: str) -> None:
        with closing(self._connection()) as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                rows = db.execute(
                    "SELECT fingerprint,phase FROM pair WHERE scope=?",
                    (SCOPE,),
                ).fetchall()
                need(len(rows) <= 1, "LEDGER_SCOPE_DRIFT")
                if not rows:
                    need(arm == "A", "A_REQUIRED_BEFORE_B")
                    db.execute(
                        "INSERT INTO pair(scope,fingerprint,phase) VALUES(?,?,?)",
                        (SCOPE, fingerprint, "UNKNOWN_A"),
                    )
                else:
                    seen, phase = rows[0]
                    need(seen == fingerprint, "DIFFERENT_RUN_OR_SIGNER_DENIED")
                    need(phase == "A_ACK" and arm == "B",
                         "REPLAY_OR_UNKNOWN_STOP")
                    db.execute(
                        "UPDATE pair SET phase='UNKNOWN_B' WHERE scope=?",
                        (SCOPE,),
                    )
                db.execute(
                    "INSERT INTO attempts(arm,fingerprint,state) VALUES(?,?,?)",
                    (arm, fingerprint, "UNKNOWN"),
                )
                db.commit()  # persisted BEFORE any local fake send
            except BaseException:
                db.rollback()
                raise

    def _ack(self, arm: str, fingerprint: str) -> None:
        before, after = (
            ("UNKNOWN_A", "A_ACK") if arm == "A"
            else ("UNKNOWN_B", "PAIR_ACK")
        )
        with closing(self._connection()) as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                changed = db.execute(
                    "UPDATE pair SET phase=? WHERE scope=?"
                    " AND fingerprint=? AND phase=?",
                    (after, SCOPE, fingerprint, before),
                )
                need(changed.rowcount == 1, "UNKNOWN_DURING_FAKE_ACK")
                updated = db.execute(
                    "UPDATE attempts SET state='ACK' WHERE arm=?"
                    " AND fingerprint=? AND state='UNKNOWN'",
                    (arm, fingerprint),
                )
                need(updated.rowcount == 1, "ATTEMPT_RECEIPT_DRIFT")
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def attempt(self, *, arm: str, packet: bytes, signed: object,
                frozen_snapshot: object, fault: str = "none") -> LocalReceipt:
        """Local fake effect only. An unknown result consumes the mock arm."""
        need(type(fault) is str and fault in (
            "none", "AFTER_RESERVATION_BEFORE_FAKE_SEND",
            "AFTER_FAKE_SEND_BEFORE_ACK",
        ), "OFFLINE_FAULT_ONLY")
        fingerprint = self._verify(
            arm=arm, packet=packet, signed=signed,
            frozen_snapshot=frozen_snapshot,
        )
        self._reserve(arm, fingerprint)
        if fault == "AFTER_RESERVATION_BEFORE_FAKE_SEND":
            raise UnknownAfterAttempt(
                "TASK1_SIGNED_SQLITE_MOCK_UNKNOWN_BEFORE_FAKE_SEND_NO_RETRY"
            )
        try:
            reply = self.port.deliver(arm, packet)
            if fault == "AFTER_FAKE_SEND_BEFORE_ACK":
                raise TimeoutError("OFFLINE_AFTER_FAKE_SEND_UNKNOWN_ACK")
            expected_reply = {
                "marker": mock.FAKE_ACK,
                "arm": arm,
                "packet_sha256": mock.PACKET_SHA256,
            }
            need(type(reply) is dict
                 and set(reply) == set(expected_reply) | {"ordinal"}
                 and all(exact(reply[k], v)
                         for k, v in expected_reply.items())
                 and type(reply["ordinal"]) is int
                 and 1 <= reply["ordinal"] <= 2,
                 "FAKE_ACK_MALFORMED")
            self._ack(arm, fingerprint)
        except BaseException as exc:
            # Even if the fake sink acted, no automatic duplicate is allowed.
            raise UnknownAfterAttempt(
                "TASK1_SIGNED_SQLITE_MOCK_UNKNOWN_AFTER_FAKE_ATTEMPT_NO_RETRY"
            ) from exc
        return LocalReceipt(
            schema=SCHEMA, arm=arm, request_sha256=mock.PACKET_SHA256,
            local_fake_ack=True,
        )

    def status(self) -> dict:
        with closing(self._connection()) as db:
            rows = db.execute(
                "SELECT fingerprint,phase FROM pair WHERE scope=?",
                (SCOPE,),
            ).fetchall()
            attempts = db.execute(
                "SELECT arm,state FROM attempts ORDER BY arm"
            ).fetchall()
        return {
            "phase": rows[0][1] if rows else "FRESH",
            "attempts": tuple(attempts),
            "local_sqlite_persistence_observed": True,
            "provider_requests": 0,
            "actual_github_job_separation": False,
            "production_single_use_lease_proven": False,
            "paid_task1_authorized": False,
        }
