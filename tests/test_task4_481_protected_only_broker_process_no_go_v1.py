"""Task4 #481: protected-only Broker process; same-ID bypass remains a gap."""
import os
from pathlib import Path

import pytest

from scripts import task4_481_protected_only_broker_process_no_go_v1 as m
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def expected(r):
    for key in (
        "broker_distinct_os_process",
        "signer_distinct_os_process",
        "protected_only_process_has_no_legacy_socket",
        "protected_process_forbids_raw_legacy_action",
        "direct_unsigned_consume_refused",
        "direct_live_opcode_refused",
        "forged_signature_refused",
        "same_run_signed_replay_refused",
        "modified_original_sdk_sha_refused",
        "restart_signed_replay_refused",
        "restart_unsigned_direct_consume_refused",
        "legacy_broker_global_callable_still_available",
        "legacy_broker_cli_still_deployable",
    ):
        assert r[key] is True
    assert r["broker_owned_atomic_cas_claims"] == 8
    assert len(r["hash_only_protected_broker_receipts"]) == 8
    assert r["independently_protected_broker_and_db_proven"] is False
    assert r["cross_runner_single_use_proven"] is False
    assert r["production_unbypassable_egress_proven"] is False
    assert r["real_provider_posts"] == 0
    assert r["external_bank_effects"] == 0
    assert r["genuine_native_utility"] is None
    assert r["score_status"] == "UNSCORED"
    assert r["no_go"] is True


def test_protected_only_broker_os_process_and_restart_replay():
    r=m.run(with_native=False)
    expected(r)
    assert r["original_native_sdk_pre_worker_broker_gated"] == 0


@pytest.mark.skipif(os.environ.get("TASK4_481_NATIVE_PROOF") != "1",
                    reason="frozen AgentDojo Native SDK dependencies required")
def test_native_original_sdk_eight_requests_through_protected_only_process():
    r=m.run(with_native=True)
    expected(r)
    assert r["original_native_sdk_pre_worker_broker_gated"] == 8
    assert r["native_deny_only_worker_claims"] == 8
    assert r["native_preparse_aead_scripted_responses"] == 8


def signer_key():
    private=Ed25519PrivateKey.generate()
    public=private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return private,public


def valid_packet(key, arm="A", ordinal=0, wire="a"*64):
    claim=m.prior.claim_for(arm,ordinal,wire)
    signature=key.sign(m.NATIVE.signer.canonical(claim)).hex()
    return m.prior.packet_for(arm,ordinal,wire,claim,signature)


def test_server_owns_cas_and_duplicate_rejected(tmp_path):
    # pytest tmp_path is not guaranteed 0700, set the single local test parent.
    home=tmp_path/"private"
    home.mkdir(mode=0o700)
    db=home/"protected-only.sqlite"
    m.init_store(db)
    private,pub=signer_key()
    gate=m.ProtectedOnlyGate(db,pub)
    pkt=valid_packet(private)
    assert gate.consume(pkt)["decision"] == (
        "BROKER_PROTECTED_ONLY_SYNTHETIC_CONSUMED_NO_SEND")
    with pytest.raises(m.Denied,match="481_BROKER_ATOMIC_CAS_ALREADY_CONSUMED"):
        gate.consume(pkt)
    assert m.count(db)==1


def test_bad_signature_and_revocation_do_not_burn_slot(tmp_path):
    home=tmp_path/"private"
    home.mkdir(mode=0o700)
    db=home/"protected-only.sqlite"
    m.init_store(db)
    key,pub=signer_key()
    revoked=m.ProtectedOnlyGate(db,pub,revoked={("A",0)})
    packet=valid_packet(key)
    with pytest.raises(m.Denied,match="481_BROKER_REVOKED_SCOPE"):
        revoked.consume(packet)
    gate=m.ProtectedOnlyGate(db,pub)
    fake=dict(packet,signature_hex="0"*128)
    with pytest.raises(m.Denied,match="481_WRONG_ISSUER"):
        gate.consume(fake)
    with pytest.raises(m.Denied,match="481_CLAIM_SCOPE"):
        gate.consume(dict(packet,request_sha="b"*64))
    assert m.count(db)==0


def test_broker_missing_store_fails_closed(tmp_path):
    home=tmp_path/"private"
    home.mkdir(mode=0o700)
    db=home/"protected-only.sqlite"
    m.init_store(db)
    key,pub=signer_key()
    gate=m.ProtectedOnlyGate(db,pub)
    db.unlink()
    with pytest.raises(m.Denied,match="481_RESTART_STORE_MUST_EXIST"):
        gate.consume(valid_packet(key))


@pytest.mark.parametrize("env",m.prior.ledger.BLOCK_ENV)
def test_live_context_credential_refused(monkeypatch,env):
    monkeypatch.setenv(env,"DENY")
    with pytest.raises(m.Denied):
        m.offline()


def test_no_legacy_listener_inside_protected_only_source_and_pr_only_workflow():
    y=(m.ROOT/".github/workflows/task4-481-protected-only-broker-offline.yml").read_text()
    source=Path(m.__file__).read_text()
    for denied in (
        "workflow_dispatch:", "pull_request_target:",
        "secrets.", "contents: write", "id-token: write",
        "requests.post(", "httpx.HTTPTransport(",
        "LEGACY.action(", "LEGACY.spawn_server(", "LEGACY.Broker(",
    ):
        assert denied not in y
        assert denied not in source
    assert "contents: read" in y
    assert "persist-credentials: false" in y
