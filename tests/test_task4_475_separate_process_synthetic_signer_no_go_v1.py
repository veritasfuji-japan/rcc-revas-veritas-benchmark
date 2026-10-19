"""Task4 #475 isolated synthetic signer refusal tests."""
import os
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import task4_475_separate_process_synthetic_signer_no_go_v1 as m
from scripts.task4_474_independent_signed_authority_offline_no_go_v1 import make_claim, Denied


def claim():
    return make_claim(arm="A",ordinal=0,wire_sha="a"*64,
                      policy_digest="b"*64,nonce="475-test")


def test_separate_process_end_to_end_denies_nine_attacks():
    result=m.run()
    assert result["signer_distinct_os_pid"] is True
    assert result["signer_private_key_in_verifier"] is False
    assert result["negative_cases_denied"]==9
    assert result["live_send_opcode"]=="DENY_NOT_SYNTHETIC_NO_SEND"
    assert result["real_provider_posts"]==0
    assert result["no_go"] is True
    assert result["score_status"]=="UNSCORED"


def test_replay_is_refused():
    key=Ed25519PrivateKey.generate()
    c=claim()
    pub=key.public_key().public_bytes_raw().hex()
    sig=key.sign(m.canonical(c)).hex()
    seen=set()
    kw=dict(public_hex=pub,claim=c,signature_hex=sig,expected=c,consumed=seen)
    m.verify(**kw)
    with pytest.raises(Denied,match="475_ALREADY_CONSUMED"):
        m.verify(**kw)


def test_revocation_is_refused():
    key=Ed25519PrivateKey.generate()
    c=claim()
    with pytest.raises(Denied,match="475_REVOKED"):
        m.verify(public_hex=key.public_key().public_bytes_raw().hex(),
                 claim=c,signature_hex=key.sign(m.canonical(c)).hex(),
                 expected=c,consumed=set(),revoked=True)


@pytest.mark.parametrize("env",m.BLOCK_ENV)
def test_secrets_and_approval_are_refused(monkeypatch,env):
    monkeypatch.setenv(env,"not-authorized")
    with pytest.raises(Denied,match="475_SECRET"):
        m.ensure_offline()


def test_workflow_is_read_only_pr_only():
    path=m.ROOT/".github/workflows/task4-475-separate-signer-native-offline.yml"
    y=path.read_text()
    s=Path(m.__file__).read_text()
    for forbidden in ("workflow_dispatch:", "pull_request_target:",
                      "secrets.", "contents: write", "id-token: write",
                      "requests.post(", "httpx.HTTPTransport("):
        assert forbidden not in y
        assert forbidden not in s
    assert "persist-credentials: false" in y
    assert "contents: read" in y
