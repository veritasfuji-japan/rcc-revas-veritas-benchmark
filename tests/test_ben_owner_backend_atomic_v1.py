"""Mock backend SQLite proof: one local atomic owner-policy/effect boundary."""
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import ci_mock_executor_authority_boundary_v1 as mock
from scripts import ci_mock_owner_backend_atomic_v1 as atomic

OWNER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
ISSUER = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
OWNER_PUB = OWNER.public_key().public_bytes_raw()
ISSUER_PUB = ISSUER.public_key().public_bytes_raw()


def fixture(tmp_path):
    statement = {
        "scope": atomic.OWNER_SCOPE, "operation_id": mock.OP,
        "request_sha256": mock.digest(mock.REQUEST),
        "prestate_sha256": mock.digest({"counter": 0, "revision": 0, "effect_count": 0}),
        "valid_from_tick": 50, "valid_until_tick": 150}
    approval = {
        "statement": statement,
        "signature": OWNER.sign(atomic.OWNER_DOMAIN + mock.canonical(statement)).hex()}
    db_path = tmp_path / "state.sqlite3"
    db = mock.backend_store(db_path)
    atomic.initialize(db, mock.digest(statement), mock.need)
    return db_path, db, approval


def verify(db, approval, owner_key=OWNER_PUB, issuer_key=ISSUER_PUB, request=None):
    return atomic.check_inside_transaction(
        db, approval, owner_key, issuer_key,
        mock.REQUEST if request is None else request,
        mock.canonical, mock.digest, mock.need, mock.OP)


def assert_unspent(db):
    assert db.execute("SELECT counter FROM state WHERE id=1").fetchone() == (0,)
    assert db.execute("SELECT * FROM spent").fetchall() == []


def test_valid_owner_policy_and_effect_share_a_real_sqlite_transaction(tmp_path):
    _, db, approval = fixture(tmp_path)
    db.execute("BEGIN IMMEDIATE")
    assert verify(db, approval) == {
        "statement_sha256": mock.digest(approval["statement"]),
        "epoch": 0, "synthetic_tick": 100}
    receipt = mock.digest({"operation_id": mock.OP, "request": mock.REQUEST})
    db.execute("INSERT INTO spent VALUES (?, ?)", (mock.OP, receipt))
    db.execute("UPDATE state SET counter=1 WHERE id=1")
    db.commit()
    assert db.execute("SELECT counter FROM state").fetchone() == (1,)
    assert db.execute("SELECT * FROM spent").fetchall() == [(mock.OP, receipt)]
    db.close()


@pytest.mark.parametrize("mode", ["revoked", "expired"])
def test_policy_committed_before_effect_transaction_blocks_effect(tmp_path, mode):
    path, db, approval = fixture(tmp_path)
    with sqlite3.connect(path, isolation_level=None) as authority:
        authority.execute("BEGIN IMMEDIATE")
        if mode == "revoked":
            authority.execute("UPDATE owner_policy SET revoked=1,epoch=1 WHERE id=1")
        else:
            authority.execute("UPDATE owner_policy SET clock_tick=150,epoch=1 WHERE id=1")
        authority.commit()
    db.execute("BEGIN IMMEDIATE")
    with pytest.raises(ValueError, match="BACKEND_OWNER_REVOKED" if mode == "revoked"
                       else "BACKEND_OWNER_EXPIRED"):
        verify(db, approval)
    db.rollback()
    assert_unspent(db)
    assert db.execute("SELECT epoch FROM owner_policy WHERE id=1").fetchone() == (1,)
    db.close()


def test_policy_writer_cannot_overtake_active_effect_transaction(tmp_path):
    path, db, approval = fixture(tmp_path)
    db.execute("BEGIN IMMEDIATE")
    verify(db, approval)
    competing = sqlite3.connect(path, isolation_level=None, timeout=0)
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            competing.execute("BEGIN IMMEDIATE")
        assert_unspent(db)
    finally:
        competing.close()
        db.rollback()
        db.close()


def test_atomic_check_refuses_no_transaction(tmp_path):
    _, db, approval = fixture(tmp_path)
    with pytest.raises(ValueError, match="BACKEND_OWNER_REQUIRES_TRANSACTION"):
        verify(db, approval)
    db.close()


@pytest.mark.parametrize("fault", ["forged_signature", "different_request",
                                    "wrong_issuer_key", "unregistered_digest"])
def test_signed_proof_and_owner_enrollment_negatives(tmp_path, fault):
    _, db, approval = fixture(tmp_path)
    kwargs = {}
    if fault == "forged_signature":
        approval["signature"] = "0" * 128
        match = "BACKEND_OWNER_SIGNATURE"
    elif fault == "different_request":
        kwargs["request"] = dict(mock.REQUEST, units=2)
        match = "BACKEND_OWNER_EXACT_BINDING"
    elif fault == "wrong_issuer_key":
        kwargs["issuer_key"] = OWNER_PUB
        match = "BACKEND_OWNER_ISSUER_KEY_REUSE"
    else:
        db.execute("UPDATE owner_policy SET statement_digest=? WHERE id=1", ("0" * 64,))
        match = "BACKEND_OWNER_UNENROLLED_STATEMENT"
    db.execute("BEGIN IMMEDIATE")
    with pytest.raises(ValueError, match=match):
        verify(db, approval, **kwargs)
    db.rollback()
    assert_unspent(db)
    db.close()


@pytest.mark.parametrize("start,end", [(50, 50), (0, 1_000_001),
                                          (True, 150), (50, False)])
def test_malformed_signed_intervals_fails_closed(tmp_path, start, end):
    _, db, approval = fixture(tmp_path)
    approval["statement"]["valid_from_tick"] = start
    approval["statement"]["valid_until_tick"] = end
    db.execute("BEGIN IMMEDIATE")
    with pytest.raises(ValueError, match="BACKEND_OWNER_INTERVAL"):
        verify(db, approval)
    db.rollback()
    assert_unspent(db)
    db.close()


def test_caller_cannot_enable_backend_atomic_mode_without_owner(tmp_path):
    with pytest.raises(ValueError, match="BACKEND_ATOMIC_REQUIRES_OWNER_ONLY"):
        mock.run(tmp_path / "out", with_bind=True, owner_backend_atomic=True)
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("drift", ["revoked", "expired"])
def test_backend_drift_requires_explicit_atomic_mode(tmp_path, drift):
    with pytest.raises(ValueError, match="BACKEND_ATOMIC_DRIFT_REQUIRES_MODE"):
        mock.run(tmp_path / "out", with_bind=True, with_owner=True,
                 owner_backend_drift=drift)
    assert not (tmp_path / "out").exists()
