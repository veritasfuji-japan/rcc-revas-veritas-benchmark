"""Synthetic local custody tests; no SDK or Provider execution."""
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import multiprocessing as mp
import os
import sqlite3
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from scripts import task4_protected_ciphertext_custody_v1 as m
from scripts.task4_457_local_response_aead_v1 import SealedLocalVault


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)


@pytest.fixture
def fixture(tmp_path):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    issuer = Ed25519PrivateKey.generate()
    recipient = X25519PrivateKey.generate()
    db = root / "custody.sqlite"
    issuer_hex, recipient_sha = public(issuer).hex(), m.digest(public(recipient))
    m.initialize(db, issuer_hex, recipient_sha)
    wire, response = b"SYNTHETIC_WIRE", b"SYNTHETIC_RESPONSE_ONLY"
    vault = SealedLocalVault(root, recipient.public_key())
    record = vault.commit_before_parser(arm="A", ordinal=0,
        request=SimpleNamespace(content=wire),
        response=SimpleNamespace(content=response, status_code=200))
    blob = (root / record["envelope_filename"]).read_bytes()
    return SimpleNamespace(root=root, db=db, issuer=issuer, recipient=recipient,
        issuer_hex=issuer_hex, recipient_sha=recipient_sha, wire=wire,
        response=response, blob=blob, gate=m.Custody(db, issuer_hex, recipient_sha))


def packet(f, operation="consume", receipt=None, blob=None, **changes):
    c = dict(schema=m.SCHEMA, trial=m.TRIAL, case=m.CASE, model=m.MODEL,
             op=operation, arm="A", ordinal=0, request_sha256=m.digest(f.wire),
             recipient_sha256=f.recipient_sha, receipt_sha256=receipt,
             envelope_sha256=m.digest(blob) if blob is not None else None,
             provider_post_allowed=False)
    c.update(changes)
    return {"claim": c, "signature_hex": f.issuer.sign(m.canonical(c)).hex(),
            "envelope_b64": base64.b64encode(blob).decode() if operation == "attach" else None}


def consumed(f):
    r = f.gate.dispatch(packet(f))
    assert r["decision"] == "CONSUMED_NO_SEND"
    return r["receipt_sha256"]


def denied(reply):
    assert reply == {"decision": "DENY", "live_post": False}


def decrypt(f, blob):
    env = json.loads(blob)
    aad = m.canonical(env["header"])
    ep = X25519PublicKey.from_public_bytes(m.unb64(env["ephemeral_x25519_public_b64"]))
    key = HKDF(algorithm=hashes.SHA256(), length=32,
               salt=m.unb64(env["hkdf_salt_b64"]),
               info=b"VERITAS_TASK4_457_LOCAL_PREPARSE_V1:" + aad
               ).derive(f.recipient.exchange(ep))
    return AESGCM(key).decrypt(m.unb64(env["aes256gcm_nonce_b64"]),
                              m.unb64(env["aes256gcm_ciphertext_b64"]), aad)


def start(f):
    ctx = mp.get_context("spawn")
    reader, writer = ctx.Pipe(duplex=False)
    sock = f.root / "protected.sock"
    p = ctx.Process(target=m.serve, args=(f.db, sock, f.issuer_hex, f.recipient_sha, writer))
    p.start()
    writer.close()
    try:
        assert reader.poll(10)
        ready = reader.recv()
        assert ready == {"ready": True, "pid": p.pid}
        assert p.pid != os.getpid()
        return p, sock
    except BaseException:
        p.join(1)
        p.terminate()
        p.join(5)
        raise
    finally:
        reader.close()


def stop(p, sock):
    p.terminate()
    p.join(5)
    if p.is_alive():
        p.kill()
        p.join(5)
    sock.unlink(missing_ok=True)


def test_process_ciphertext_recovery_restart_and_replays(fixture):
    f = fixture
    p, sock = start(f)
    try:
        denied(m.exchange(sock, {"op": "consume"}))
        reply = m.exchange(sock, packet(f))
        receipt = reply["receipt_sha256"]
        attach = packet(f, "attach", receipt, f.blob)
        assert m.exchange(sock, attach)["decision"] == "SEALED_NO_SEND"
    finally:
        stop(p, sock)
    p, sock = start(f)
    try:
        denied(m.exchange(sock, packet(f)))
        denied(m.exchange(sock, attach))
        read = packet(f, "read", receipt, f.blob)
        r = m.exchange(sock, read)
        assert r["decision"] == "CIPHERTEXT_READ_ONLY" and r["live_post"] is False
        assert decrypt(f, m.unb64(r["envelope_b64"])) == f.response
        assert m.exchange(sock, read) == r  # reads are explicitly repeatable
        assert sorted(x.name for x in f.root.glob('*.sock')) == ['protected.sock']
    finally:
        stop(p, sock)


def test_unknown_after_consume_survives_process_termination(fixture):
    f = fixture
    p, sock = start(f)
    try:
        assert m.exchange(sock, packet(f))["decision"] == "CONSUMED_NO_SEND"
    finally:
        stop(p, sock)
    p, sock = start(f)
    try:
        denied(m.exchange(sock, packet(f)))
        denied(m.exchange(sock, packet(f, "read", "a"*64, f.blob)))
    finally:
        stop(p, sock)


@pytest.mark.parametrize("changes", [
    {"request_sha256": "b"*64}, {"arm": "B"}, {"ordinal": 1},
    {"receipt_sha256": "b"*64}, {"recipient_sha256": "b"*64},
    {"envelope_sha256": "b"*64}, {"provider_post_allowed": True},
    {"op": "send_live"}, {"ordinal": False}, {"trial": "b"*64},
])
def test_signed_wrong_binding_does_not_seal(fixture, changes):
    f = fixture
    receipt = consumed(f)
    denied(f.gate.dispatch(packet(f, "attach", receipt, f.blob, **changes)))
    assert f.gate.dispatch(packet(f, "attach", receipt, f.blob))["decision"] == "SEALED_NO_SEND"


def test_unsigned_forged_or_changed_payload_rejected(fixture):
    f = fixture
    pkt = packet(f)
    pkt["signature_hex"] = "0" * 128
    denied(f.gate.dispatch(pkt))
    pkt = packet(f)
    pkt["claim"]["arm"] = "B"
    denied(f.gate.dispatch(pkt))
    receipt = consumed(f)
    pkt = packet(f, "attach", receipt, f.blob)
    pkt["envelope_b64"] = base64.b64encode(f.blob + b" ").decode()
    denied(f.gate.dispatch(pkt))


def test_signed_wrong_header_rejected(fixture):
    f = fixture
    receipt = consumed(f)
    env = json.loads(f.blob)
    env["header"]["local_request_sha256"] = "b"*64
    denied(f.gate.dispatch(packet(f, "attach", receipt, m.canonical(env))))


def test_no_attach_or_read_before_consume(fixture):
    f = fixture
    for op in ("attach", "read"):
        denied(f.gate.dispatch(packet(f, op, "a"*64, f.blob)))


def test_read_wrong_receipt_digest_and_store_tamper(fixture):
    f = fixture
    receipt = consumed(f)
    assert f.gate.dispatch(packet(f, "attach", receipt, f.blob))["decision"] == "SEALED_NO_SEND"
    for changes in ({"receipt_sha256": "b"*64}, {"envelope_sha256": "b"*64}):
        denied(f.gate.dispatch(packet(f, "read", receipt, f.blob, **changes)))
    with sqlite3.connect(f.db) as con:
        con.execute("UPDATE attempts SET envelope=?", (b"tampered",))
    denied(f.gate.dispatch(packet(f, "read", receipt, f.blob)))


def test_concurrent_consumers_and_attach_have_one_winner(fixture):
    f = fixture
    def call(pkt):
        return m.Custody(f.db, f.issuer_hex, f.recipient_sha).dispatch(pkt)
    with ThreadPoolExecutor(max_workers=6) as pool:
        replies = list(pool.map(call, [packet(f)]*6))
    wins = [r for r in replies if r["decision"] == "CONSUMED_NO_SEND"]
    assert len(wins) == 1
    attach = packet(f, "attach", wins[0]["receipt_sha256"], f.blob)
    with ThreadPoolExecutor(max_workers=6) as pool:
        replies = list(pool.map(call, [attach]*6))
    assert sum(r["decision"] == "SEALED_NO_SEND" for r in replies) == 1


def test_missing_locked_store_and_changed_identity_fail_closed(fixture):
    f = fixture
    with pytest.raises(m.Denied):
        m.Custody(f.db, "b"*64, f.recipient_sha)
    with pytest.raises(m.Denied):
        m.Custody(f.db, f.issuer_hex, "b"*64)
    with sqlite3.connect(f.db) as con:
        con.execute("BEGIN EXCLUSIVE")
        denied(f.gate.dispatch(packet(f)))
    f.db.unlink()
    denied(f.gate.dispatch(packet(f)))
    assert not f.db.exists()


@pytest.mark.parametrize("name", m.BLOCK_ENV)
def test_live_environment_denied(fixture, monkeypatch, name):
    monkeypatch.setenv(name, "NOT_A_REAL_SECRET")
    denied(fixture.gate.dispatch(packet(fixture)))


def test_duplicate_json_and_plaintext_fields_denied(fixture):
    with pytest.raises(m.Denied):
        m.parse(b'{"op":"read","op":"attach"}')
    pkt = packet(fixture)
    pkt["plaintext"] = "forbidden"
    denied(fixture.gate.dispatch(pkt))
