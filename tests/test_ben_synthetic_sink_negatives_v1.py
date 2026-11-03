"""Offline negative tests for the existing pinned mock sink's grant and durable state.

These tests call no network, provider, Bind issuance or real owner authority.
They are not proof of the production Task4 adapter or distributed single-use.
"""
import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import ci_mock_executor_authority_boundary_v1 as sink

SIGNER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC = SIGNER.public_key().public_bytes_raw()


def grant_packet():
    statement = {"scope": "CI_ONLY", "operation_id": sink.OP,
                 "request_sha256": sink.digest(sink.REQUEST)}
    return {"request": copy.deepcopy(sink.REQUEST), "grant": {
        "statement": statement,
        "signature": SIGNER.sign(b"CI_GRANT_V2\0" + sink.canonical(statement)).hex()}}


def test_exact_signed_synthetic_request_passes_offline():
    assert sink.validate(grant_packet(), PUBLIC)["request_sha256"] == sink.digest(sink.REQUEST)


@pytest.mark.parametrize("field,value", [
    ("target", "mock://other/target"),
    ("units", 2),
    ("units", True),
    ("revision", 1),
    ("revision", False),
])
def test_signed_grant_cannot_be_retargeted(field, value):
    packet = grant_packet()
    packet["request"][field] = value
    with pytest.raises(ValueError):
        sink.validate(packet, PUBLIC)


@pytest.mark.parametrize("field,value", [
    ("scope", "PROD"),
    ("operation_id", "OTHER_OPERATION"),
    ("request_sha256", "0" * 64),
])
def test_signed_statement_cannot_be_substituted(field, value):
    packet = grant_packet()
    packet["grant"]["statement"][field] = value
    with pytest.raises(ValueError):
        sink.validate(packet, PUBLIC)


def test_attacker_cannot_reissue_under_untrusted_key():
    packet = grant_packet()
    attacker = Ed25519PrivateKey.generate()
    packet["grant"]["signature"] = attacker.sign(
        b"CI_GRANT_V2\0" + sink.canonical(packet["grant"]["statement"])).hex()
    with pytest.raises(ValueError, match="GRANT_SIGNATURE"):
        sink.validate(packet, PUBLIC)


@pytest.mark.parametrize("mutation", ["extra", "missing", "duplicate_json"])
def test_packet_shape_and_duplicate_fields_fail_closed(mutation):
    packet = grant_packet()
    if mutation == "extra":
        packet["receipt"] = {"final_outcome": "COMMITTED"}
        with pytest.raises(ValueError):
            sink.validate(packet, PUBLIC)
    elif mutation == "missing":
        packet.pop("grant")
        with pytest.raises(ValueError):
            sink.validate(packet, PUBLIC)
    else:
        with pytest.raises(ValueError, match="DUPLICATE_FIELD"):
            sink.parse(b'{"request":{},"request":{},"grant":{}}')


@pytest.mark.parametrize("counter,spent", [(1, False), (0, True)])
def test_restart_rejects_effect_and_consumption_disagreement(tmp_path, counter, spent):
    path = tmp_path / "backend.sqlite3"
    db = sink.backend_store(path)
    db.execute("UPDATE state SET counter=?", (counter,))
    if spent:
        db.execute("INSERT INTO spent VALUES (?,?)", (sink.OP,
            sink.digest({"operation_id": sink.OP, "request": sink.REQUEST})))
    db.close()
    with pytest.raises(ValueError, match="BACKEND_EFFECT_RECEIPT_CONSISTENCY"):
        sink.backend_store(path, restart=True)


def test_valid_single_effect_persists_after_restart(tmp_path):
    path = tmp_path / "backend.sqlite3"
    db = sink.backend_store(path)
    db.execute("BEGIN IMMEDIATE")
    db.execute("UPDATE state SET counter=1")
    db.execute("INSERT INTO spent VALUES (?,?)", (sink.OP,
        sink.digest({"operation_id": sink.OP, "request": sink.REQUEST})))
    db.commit()
    db.close()
    reopened = sink.backend_store(path, restart=True)
    try:
        assert reopened.execute("SELECT counter FROM state").fetchone()[0] == 1
        assert reopened.execute("SELECT count(*) FROM spent").fetchone()[0] == 1
    finally:
        reopened.close()
