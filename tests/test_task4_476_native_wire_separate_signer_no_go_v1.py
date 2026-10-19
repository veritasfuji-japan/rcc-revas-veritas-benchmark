"""Task4 #476: separate signer process joined to original Native SDK wire."""
import pytest
from pathlib import Path
from scripts import task4_476_native_wire_separate_signer_no_go_v1 as m


def test_native_eight_original_wires_signed_in_separate_process():
    r=m.run()
    assert r["signer_separate_os_process"] is True
    assert r["native_original_sdk_wire_signatures_verified"] == 8
    assert r["native_local_worker_claims"] == 8
    assert r["native_preparse_aead_scripted_responses"] == 8
    assert r["native_restart_replays_denied"] == 8
    assert r["signed_claim_replay_denied"] is True
    assert r["live_send_opcode"] == "DENY_NOT_SYNTHETIC_NO_SEND"
    assert len(r["hash_only_native_authority_receipts"]) == 8
    assert r["provider_posts"] == 0
    assert r["external_bank_effects"] == 0
    assert r["score_status"] == "UNSCORED"
    assert r["no_go"] is True


@pytest.mark.parametrize("env",m.signer.BLOCK_ENV)
def test_live_secrets_are_denied(monkeypatch,env):
    monkeypatch.setenv(env,"not-consent")
    with pytest.raises(m.Denied):
        m.run()


def test_ci_never_dispatches_or_injects_secrets():
    y=(m.ROOT/".github/workflows/task4-476-separate-signer-native-offline.yml").read_text()
    for forbidden in ("workflow_dispatch:", "pull_request_target:",
                      "secrets.", "contents: write", "id-token: write"):
        assert forbidden not in y
    assert "persist-credentials: false" in y
    assert "contents: read" in y


def test_scope_is_explicitly_no_go():
    s=Path(m.__file__).read_text()
    assert "provider_posts" in s
    assert "real_independent_iam_or_egress_proven" in s
    assert "genuine_native_utility" in s
