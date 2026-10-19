"""#474 Ed25519 synthetic authority scope and offline Native deny proof."""
from __future__ import annotations
from pathlib import Path
import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import task4_474_independent_signed_authority_offline_no_go_v1 as m


def fixture():
    key=Ed25519PrivateKey.generate()
    claim=m.make_claim(arm="A",ordinal=0,wire_sha="a"*64,
                       policy_digest="b"*64,nonce="A-0")
    return key,claim


def test_valid_synthetic_signature_still_never_grants_send():
    key,claim=fixture()
    receipt=m.verify_local_authority(
        public_key=key.public_key(),claim=claim,
        signature=m.sign_fixture(key,claim),expected=claim,consumed=set())
    assert receipt["provider_post_allowed"] is False
    assert receipt["live_provider_posts"] == 0
    assert receipt["decision"] == "VERIFIED_SYNTHETIC_PROVENANCE_BUT_NO_SEND"


def test_all_eleven_attacks_denied():
    key,claim=fixture()
    cases=m.verify_negative_matrix(key,claim,claim)
    assert len(cases)==11
    assert set(cases.values())=={"DENIED"}


def test_duplicate_claim_denied():
    key,claim=fixture()
    seen=set()
    kw=dict(public_key=key.public_key(),claim=claim,
            signature=m.sign_fixture(key,claim),expected=claim,consumed=seen)
    m.verify_local_authority(**kw)
    with pytest.raises(m.Denied,match="474_REPLAY"):
        m.verify_local_authority(**kw)


def test_scope_wrong_arm_or_ordinal_denied():
    for arm,ordinal in [("C",0),("A",-1),("B",4),("A",True)]:
        with pytest.raises(m.Denied,match="474_SCOPE"):
            m.make_claim(arm=arm,ordinal=ordinal,wire_sha="a"*64,
                         policy_digest="b"*64,nonce="A-0")


def test_bad_signature_and_wrong_key_denied():
    key,claim=fixture()
    with pytest.raises(m.Denied):
        m.verify_local_authority(
            public_key=Ed25519PrivateKey.generate().public_key(),
            claim=claim,signature=m.sign_fixture(key,claim),
            expected=claim,consumed=set())


@pytest.mark.parametrize("env",m.SENSITIVE)
def test_credentials_and_fake_approval_are_rejected(monkeypatch,env):
    monkeypatch.setenv(env,"FORBIDDEN")
    with pytest.raises(m.Denied,match="474_LIVE"):
        m.deny_live()


def test_ci_is_offline_read_only_and_not_dispatchable():
    workflow=(m.ROOT/".github/workflows/task4-474-independent-authority-native-offline.yml").read_text()
    source=Path(m.__file__).read_text()
    for forbidden in ("workflow_dispatch:", "pull_request_target:",
                      "secrets.", "contents: write", "id-token: write",
                      "requests.post(", "socket.AF_INET", "httpx.HTTPTransport("):
        assert forbidden not in workflow
        assert forbidden not in source
    assert "persist-credentials: false" in workflow
    assert "contents: read" in workflow


@pytest.mark.skipif(os.environ.get("TASK4_474_NATIVE_PROOF")!="1",
                    reason="frozen AgentDojo Native local dependencies required")
def test_native_signed_scope_to_separate_worker_aead():
    r=m.run_offline_native_authority_join()
    assert r["same_run_native_sdk_authority_verifications"]==8
    assert r["same_run_native_aead_scripted_responses"]==8
    assert r["same_run_isolated_worker_claims"]==8
    assert r["same_run_worker_restart_replays_denied"]==8
    assert r["negative_cases_denied"]==11
    assert r["provider_posts"]==0
    assert r["bank_effects"]==0
    assert r["score_status"]=="UNSCORED"
    assert r["no_go"] is True
