"""Task4 #479: do not conceal the direct local broker bypass."""
import os
from pathlib import Path
import pytest
from scripts import task4_479_adversarial_local_bypass_matrix_no_go_v1 as m


def test_adversarial_matrix_detects_unprotected_legacy_broker():
    r=m.run(with_native=False)
    a=r["offline_adversarial_matrix"]
    for key in ("local_replay_refused",
                "local_changed_wire_replay_refused",
                "fake_provider_authority_refused",
                "missing_store_refused",
                "locked_store_refused",
                "legacy_broker_live_opcode_refused",
                "legacy_broker_direct_consume_without_inline_cas_possible",
                "direct_legacy_broker_exposes_local_hook_bypass"):
        assert a[key] is True
    assert r["bypass_resistance_proven"] is False
    assert r["direct_legacy_broker_local_bypass_detected"] is True
    assert r["real_provider_bypass_proven"] is False
    assert r["real_provider_posts"] == 0
    assert r["no_go"] is True


@pytest.mark.skipif(os.environ.get("TASK4_479_NATIVE_PROOF") != "1",
                    reason="frozen Native SDK offline dependencies required")
def test_native_inline_cas_control_and_bypass_gap_both_visible():
    r=m.run(with_native=True)
    assert r["original_native_sdk_inline_cas_control_runs"] == 8
    assert len(r["native_hash_only_control_receipts"]) == 8
    assert r["direct_legacy_broker_local_bypass_detected"] is True
    assert r["bypass_resistance_proven"] is False
    assert r["real_provider_posts"] == 0
    assert r["score_status"] == "UNSCORED"


@pytest.mark.parametrize("env",m.ledger.BLOCK_ENV)
def test_live_approval_secret_env_fails_closed(monkeypatch,env):
    monkeypatch.setenv(env,"NEVER")
    with pytest.raises(m.Denied):
        m.ledger.ensure_offline()


def test_pr_only_no_secrets_no_live_sender():
    y=(m.ROOT/".github/workflows/task4-479-adversarial-local-bypass-offline.yml").read_text()
    s=Path(m.__file__).read_text()
    for bad in ("workflow_dispatch:", "pull_request_target:",
                "secrets.", "contents: write", "id-token: write",
                "requests.post(", "httpx.HTTPTransport("):
        assert bad not in y and bad not in s
    assert "contents: read" in y
    assert "persist-credentials: false" in y
