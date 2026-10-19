"""Task4 #480: broker-side signed synthetic NO_SEND local CAS control."""
import os
from pathlib import Path

import pytest

from scripts import task4_480_broker_owned_signed_cas_no_go_v1 as m


def assert_rejections(r):
    for key in (
        "direct_unsigned_legacy_consume_refused",
        "direct_send_live_opcode_refused",
        "forged_signature_refused",
        "signed_replay_refused",
        "changed_sdk_digest_refused",
        "broker_side_signature_verified",
        "protected_endpoint_only_exposes_signed_handler",
        "legacy_raw_broker_endpoint_still_unprotected",
    ):
        assert r[key] is True
    assert r["broker_side_atomic_local_cas_consumptions"] == 8
    assert len(r["hash_only_broker_owned_cas_receipts"]) == 8
    assert r["cross_runner_single_use_proven"] is False
    assert r["broker_sqlite_independently_protected"] is False
    assert r["production_non_bypassable_sender_proven"] is False
    assert r["real_provider_posts"] == 0
    assert r["external_bank_effects"] == 0
    assert r["score_status"] == "UNSCORED"
    assert r["no_go"] is True


def test_protected_socket_refuses_legacy_direct_no_signature():
    r=m.run(with_native=False)
    assert_rejections(r)
    assert r["native_original_sdk_inline_broker_gated"] == 0


@pytest.mark.skipif(os.environ.get("TASK4_480_NATIVE_PROOF") != "1",
                    reason="frozen AgentDojo Native SDK dependencies required")
def test_original_native_sdk_wire_is_inline_broker_gated_before_worker():
    r=m.run(with_native=True)
    assert_rejections(r)
    assert r["native_original_sdk_inline_broker_gated"] == 8
    assert r["native_deny_only_worker_claims"] == 8
    assert r["native_preparse_aead_scripted_responses"] == 8


def test_server_rejects_wrong_signed_scope_without_reservation(tmp_path):
    p=tmp_path/"cas.sqlite"
    m.ledger.init_store(p)
    b=tmp_path/"legacy.sqlite"
    m.legacy.prepare_db(b)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key=Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization
    pub=key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()
    g=m.SignedGate(p,b,pub)
    wire="a"*64
    claim=m.claim_for("A",0,wire)
    signature=key.sign(m.native.signer.canonical(claim)).hex()
    packet=m.packet_for("A",0,wire,claim,signature)
    assert g.consume(packet)["decision"] == "BROKER_SIGNED_LOCAL_CAS_CONSUMED_NO_SEND"
    with pytest.raises(m.Denied,match="480_BROKER_LOCAL_CAS_REPLAY"):
        g.consume(packet)
    assert m.ledger.count(p)==1


def test_server_rejects_revocation_and_missing_store(tmp_path):
    p=tmp_path/"cas.sqlite"
    m.ledger.init_store(p)
    b=tmp_path/"legacy.sqlite"
    m.legacy.prepare_db(b)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    key=Ed25519PrivateKey.generate()
    pub=key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()
    claim=m.claim_for("A",0,"a"*64)
    pkt=m.packet_for("A",0,"a"*64,claim,
                     key.sign(m.native.signer.canonical(claim)).hex())
    revoked=m.SignedGate(p,b,pub,revoked_slots={("A",0)})
    with pytest.raises(m.Denied,match="480_SERVER_REVOKED_SCOPE"):
        revoked.consume(pkt)
    assert m.ledger.count(p)==0
    p.unlink()
    missing=m.SignedGate(p,b,pub)
    with pytest.raises(m.Denied,match="477_STORE_UNAVAILABLE"):
        missing.consume(pkt)


@pytest.mark.parametrize("env",m.ledger.BLOCK_ENV)
def test_live_context_denied(monkeypatch,env):
    monkeypatch.setenv(env,"NO")
    with pytest.raises(m.Denied):
        m.offline()


def test_workflow_pr_only_no_credential_or_live_api():
    workflow=(m.ROOT/".github/workflows/task4-480-broker-owned-signed-cas-offline.yml").read_text()
    source=Path(m.__file__).read_text()
    for forbidden in (
        "workflow_dispatch:", "pull_request_target:", "secrets.",
        "contents: write", "id-token: write", "requests.post(",
        "httpx.HTTPTransport(",
    ):
        assert forbidden not in workflow
        assert forbidden not in source
    assert "contents: read" in workflow
    assert "persist-credentials: false" in workflow
