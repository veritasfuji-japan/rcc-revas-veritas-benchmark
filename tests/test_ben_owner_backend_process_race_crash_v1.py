"""Local multiprocess SQLite concurrency/crash proofs for #588 mock Owner backend.

These tests use *real separate Linux processes* with a shared temporary
SQLite database, zero network dispatch and synthetic deterministic test keys.
They are NOT the protected UID/netns HTTP sink and do not establish
distributed multi-node atomicity or externally durable effects.
"""
import multiprocessing as mp
import os
from pathlib import Path
import sqlite3
import time
from contextlib import closing

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import ci_mock_executor_authority_boundary_v1 as mock
from scripts import ci_mock_owner_backend_atomic_v1 as atomic

OWNER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
ISSUER = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
OWNER_PUB = OWNER.public_key().public_bytes_raw()
ISSUER_PUB = ISSUER.public_key().public_bytes_raw()
EXPECTED_RECEIPT = mock.digest({"operation_id": mock.OP, "request": mock.REQUEST})
CTX = mp.get_context("fork")


def approval_fixture():
    statement = {
        "scope": atomic.OWNER_SCOPE, "operation_id": mock.OP,
        "request_sha256": mock.digest(mock.REQUEST),
        "prestate_sha256": mock.digest({"counter": 0, "revision": 0, "effect_count": 0}),
        "valid_from_tick": 50, "valid_until_tick": 150,
    }
    return {"statement": statement, "signature":
            OWNER.sign(atomic.OWNER_DOMAIN + mock.canonical(statement)).hex()}


def seed(path):
    approval = approval_fixture()
    with closing(mock.backend_store(Path(path))) as db:
        atomic.initialize(db, mock.digest(approval["statement"]), mock.need)
    return approval


def read_reopened(path):
    """Run the real mock backend restart consistency check before returning."""
    with closing(mock.backend_store(Path(path), restart=True)) as db:
        assert db.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        counter, denials = db.execute(
            "SELECT counter,denials FROM state WHERE id=1").fetchone()
        spent = db.execute("SELECT operation_id,receipt FROM spent").fetchall()
        policy = db.execute(
            "SELECT clock_tick,revoked,epoch,statement_digest FROM owner_policy WHERE id=1"
        ).fetchone()
    return {"counter": counter, "denials": denials, "spent": spent,
            "policy": policy}


def run_effect(path, action, started, locked, release, queue):
    """Fresh OS process; no HTTP, only actual backend SQLite helper and writes."""
    with closing(sqlite3.connect(path, isolation_level=None, timeout=5)) as db:
        db.execute("PRAGMA synchronous=FULL")
        try:
            if started is not None:
                started.set()
            db.execute("BEGIN IMMEDIATE")
            atomic.check_inside_transaction(
                db, approval_fixture(), OWNER_PUB, ISSUER_PUB, mock.REQUEST,
                mock.canonical, mock.digest, mock.need, mock.OP)
            mock.need(db.execute(
                "SELECT counter FROM state WHERE id=1").fetchone() == (0,),
                "BACKEND_REPLAY")
            if action == "hold_commit":
                locked.set()
                mock.need(release.wait(5), "EFFECT_RELEASE_TIMEOUT")
            db.execute("INSERT INTO spent VALUES (?,?)", (mock.OP, EXPECTED_RECEIPT))
            db.execute("UPDATE state SET counter=1 WHERE id=1")
            if action == "crash_precommit":
                os._exit(73)
            db.commit()
            if action == "crash_postcommit":
                os._exit(74)
            queue.put("COMMITTED")
        except ValueError as exc:
            if db.in_transaction:
                db.rollback()
            queue.put("DENIED:" + str(exc))


def change_policy(path, mode, locked, release, busy, queue):
    """Separate policy-writer process; only local synthetic policy updates."""
    with closing(sqlite3.connect(path, isolation_level=None, timeout=0)) as db:
        deadline = time.monotonic() + 5
        while True:
            try:
                db.execute("BEGIN IMMEDIATE")
                break
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower():
                    raise
                if busy is not None:
                    busy.set()
                if time.monotonic() >= deadline:
                    raise RuntimeError("POLICY_WRITER_STARVED") from exc
                time.sleep(0.005)
        if locked is not None:
            locked.set()
        if release is not None and not release.wait(5):
            raise RuntimeError("POLICY_RELEASE_TIMEOUT")
        if mode == "revoked":
            result = db.execute(
                "UPDATE owner_policy SET revoked=1,epoch=epoch+1 WHERE id=1 AND epoch=0")
        elif mode == "expired":
            result = db.execute(
                "UPDATE owner_policy SET clock_tick=150,epoch=epoch+1"
                " WHERE id=1 AND epoch=0")
        else:
            raise RuntimeError("UNEXPECTED_POLICY_MODE")
        assert result.rowcount == 1
        db.commit()
        queue.put("POLICY_COMMITTED")


def joined(process, expected=0):
    process.join(timeout=8)
    if process.is_alive():
        process.terminate()
        process.join(timeout=3)
        pytest.fail("PROCESS_TIMEOUT:" + process.name)
    assert process.exitcode == expected, (process.name, process.exitcode)


def receive(queue, expected):
    assert queue.get(timeout=2) == expected


def assert_snapshot(snapshot, counter, epoch, revoked, tick):
    assert snapshot["counter"] == counter
    assert snapshot["denials"] == 0
    assert snapshot["spent"] == ([(mock.OP, EXPECTED_RECEIPT)] if counter else [])
    assert snapshot["policy"] == (tick, revoked, epoch,
                                  mock.digest(approval_fixture()["statement"]))


def test_two_real_processes_revocation_wins_before_effect_write_lock(tmp_path):
    path = str(tmp_path / "backend.sqlite3")
    seed(path)
    policy_locked, policy_release, effect_started = (
        CTX.Event(), CTX.Event(), CTX.Event())
    policy_queue, effect_queue = CTX.Queue(), CTX.Queue()
    policy = CTX.Process(name="policy-commits-first", target=change_policy,
                         args=(path, "revoked", policy_locked, policy_release,
                               None, policy_queue))
    effect = CTX.Process(name="effect-started-while-policy-locked",
                         target=run_effect,
                         args=(path, "normal", effect_started, None, None, effect_queue))
    policy.start()
    try:
        assert policy_locked.wait(4), "POLICY_NEVER_ACQUIRED_WRITE_LOCK"
        effect.start()
        assert effect_started.wait(4), "EFFECT_PROCESS_DID_NOT_START"
        assert policy.is_alive(), "POLICY_LOCK_NOT_HELD"
        policy_release.set()
        joined(policy)
        joined(effect)
        receive(policy_queue, "POLICY_COMMITTED")
        receive(effect_queue, "DENIED:BACKEND_OWNER_REVOKED")
        assert_snapshot(read_reopened(path), 0, 1, 1, 100)
        print("OWNER_SQLITE_REVOCATION_FIRST_TWO_PROCESSES_ZERO_EFFECT_PASS")
    finally:
        policy_release.set()
        for p in (policy, effect):
            if p.pid and p.is_alive():
                p.terminate()
                p.join(timeout=3)


def test_two_real_processes_effect_wins_then_policy_serializes(tmp_path):
    path = str(tmp_path / "backend.sqlite3")
    seed(path)
    effect_locked, effect_release, policy_busy = (
        CTX.Event(), CTX.Event(), CTX.Event())
    effect_queue, policy_queue = CTX.Queue(), CTX.Queue()
    effect = CTX.Process(name="effect-holds-same-sqlite-write-lock",
                         target=run_effect,
                         args=(path, "hold_commit", None, effect_locked,
                               effect_release, effect_queue))
    policy = CTX.Process(name="policy-writer-waiting-for-effect",
                         target=change_policy,
                         args=(path, "revoked", None, None, policy_busy, policy_queue))
    effect.start()
    try:
        assert effect_locked.wait(4), "EFFECT_DID_NOT_HOLD_WRITE_LOCK"
        policy.start()
        assert policy_busy.wait(4), "REAL_SQLITE_BUSY_NOT_OBSERVED"
        assert effect.is_alive(), "EFFECT_NOT_HELD_BEFORE_POLICY_UPDATE"
        effect_release.set()
        joined(effect)
        joined(policy)
        receive(effect_queue, "COMMITTED")
        receive(policy_queue, "POLICY_COMMITTED")
        assert_snapshot(read_reopened(path), 1, 1, 1, 100)
        replay_queue = CTX.Queue()
        replay = CTX.Process(name="post-revocation-replay", target=run_effect,
                             args=(path, "normal", None, None, None, replay_queue))
        replay.start()
        joined(replay)
        receive(replay_queue, "DENIED:BACKEND_OWNER_REVOKED")
        assert_snapshot(read_reopened(path), 1, 1, 1, 100)
        print("OWNER_SQLITE_EFFECT_FIRST_REAL_BUSY_SERIALIZED_ONE_EFFECT_PASS")
    finally:
        effect_release.set()
        for p in (effect, policy):
            if p.pid and p.is_alive():
                p.terminate()
                p.join(timeout=3)


def test_real_process_crash_before_commit_rolls_back_then_revoke(tmp_path):
    path = str(tmp_path / "backend.sqlite3")
    seed(path)
    queue = CTX.Queue()
    crash = CTX.Process(name="effect-crash-before-commit", target=run_effect,
                        args=(path, "crash_precommit", None, None, None, queue))
    crash.start()
    joined(crash, expected=73)
    assert_snapshot(read_reopened(path), 0, 0, 0, 100)
    writer_queue = CTX.Queue()
    writer = CTX.Process(name="revoke-after-crash", target=change_policy,
                         args=(path, "revoked", None, None, None, writer_queue))
    writer.start()
    joined(writer)
    receive(writer_queue, "POLICY_COMMITTED")
    attempt_queue = CTX.Queue()
    retry = CTX.Process(name="retry-after-revoke", target=run_effect,
                        args=(path, "normal", None, None, None, attempt_queue))
    retry.start()
    joined(retry)
    receive(attempt_queue, "DENIED:BACKEND_OWNER_REVOKED")
    assert_snapshot(read_reopened(path), 0, 1, 1, 100)
    print("OWNER_SQLITE_OS_EXIT_PRECOMMIT_ROLLBACK_RESTART_PASS")


def test_real_process_crash_after_commit_preserves_receipt_and_blocks_replay(tmp_path):
    path = str(tmp_path / "backend.sqlite3")
    seed(path)
    queue = CTX.Queue()
    crash = CTX.Process(name="effect-crash-after-commit", target=run_effect,
                        args=(path, "crash_postcommit", None, None, None, queue))
    crash.start()
    joined(crash, expected=74)
    assert_snapshot(read_reopened(path), 1, 0, 0, 100)
    replay_queue = CTX.Queue()
    replay = CTX.Process(name="post-commit-replay-process", target=run_effect,
                         args=(path, "normal", None, None, None, replay_queue))
    replay.start()
    joined(replay)
    receive(replay_queue, "DENIED:BACKEND_REPLAY")
    assert_snapshot(read_reopened(path), 1, 0, 0, 100)
    print("OWNER_SQLITE_OS_EXIT_POSTCOMMIT_DURABLE_RECEIPT_REPLAY_DENIED_PASS")
