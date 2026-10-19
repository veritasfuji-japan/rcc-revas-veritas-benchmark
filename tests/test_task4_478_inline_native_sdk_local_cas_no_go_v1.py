"""Task4 #478: local inline CAS gates the original Native SDK bytes."""
import os
from pathlib import Path
import pytest
from scripts import task4_478_inline_native_sdk_local_cas_no_go_v1 as m


@pytest.mark.skipif(os.environ.get("TASK4_478_NATIVE_PROOF") != "1",
                    reason="requires frozen Native SDK and AgentDojo deps")
def test_original_native_sdk_wire_eight_inline_local_cas():
    r=m.run()
    assert r["native_cas_inline_before_local_worker"] is True
    assert r["inline_pre_worker_local_cas_claims"] == 8
    assert r["same_run_native_sdk_wires"] == 8
    assert r["same_run_deny_only_worker_claims"] == 8
    assert r["same_run_preparse_aead_scripted_responses"] == 8
    assert r["restart_native_worker_replays_denied"] == 8
    assert r["local_cas_replays_denied"] == 8
    assert r["local_db_entries"] == 8
    assert len(r["hash_only_inline_cas_receipts"]) == 8
    assert all(x["state"] == m.ledger.STATE for x in
               r["hash_only_inline_cas_receipts"])
    assert r["production_non_bypassable_sender_proven"] is False
    assert r["remote_shared_store_cross_runner_proven"] is False
    assert r["provider_posts"] == 0
    assert r["score_status"] == "UNSCORED"
    assert r["no_go"] is True


def test_local_ledger_refuses_duplicate_before_worker(tmp_path):
    db=tmp_path/"inline.sqlite"
    m.ledger.init_store(db)
    item=m.ledger.synth()
    assert m.ledger.reserve(db,item)["decision"]=="CONSUMED_UNKNOWN_NO_SEND"
    assert m.ledger.reserve(db,item)["decision"]=="DENY_ALREADY_CONSUMED"
    assert m.ledger.count(db)==1


def test_storage_unavailable_fails_closed(tmp_path):
    with pytest.raises(m.Denied,match="477_STORE_UNAVAILABLE"):
        m.ledger.reserve(tmp_path/"absent.sqlite",m.ledger.synth())


@pytest.mark.parametrize("env",m.ledger.BLOCK_ENV)
def test_no_live_credentials_or_approval(monkeypatch,env):
    monkeypatch.setenv(env,"DENY")
    with pytest.raises(m.Denied):
        m.ledger.ensure_offline()


def test_ci_only_pr_readonly_no_secret():
    y=(m.ROOT/".github/workflows/task4-478-inline-local-cas-native-offline.yml").read_text()
    s=Path(m.__file__).read_text()
    for token in ("workflow_dispatch:", "pull_request_target:",
                  "secrets.", "contents: write", "id-token: write",
                  "requests.post(", "httpx.HTTPTransport("):
        assert token not in y
        assert token not in s
    assert "contents: read" in y
    assert "persist-credentials: false" in y
