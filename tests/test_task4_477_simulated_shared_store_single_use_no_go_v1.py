"""Task4 #477 local CAS failure matrix. Never claims cross-runner durability."""
from __future__ import annotations

import os
from pathlib import Path
import pytest

from scripts import task4_477_simulated_shared_store_single_use_no_go_v1 as m


def test_four_independent_os_processes_one_local_commit():
    report = m.demonstrate()
    assert report["simulated_local_race_processes"] == 4
    assert report["local_race_one_committed"] == 1
    assert report["local_race_replays_denied"] == 3
    assert report["restart_replay_denied"] is True
    assert report["changed_wire_same_slot_denied"] is True
    assert report["crash_after_commit_retry_denied"] is True
    assert report["store_unavailable_fail_closed"] is True
    assert report["policy_drift_denied"] is True
    assert report["local_db_records"] == 2


def test_mismatched_same_slot_and_replay_denied(tmp_path):
    db = tmp_path / "shared-same-host.sqlite"
    m.init_store(db)
    item = m.synth()
    assert m.reserve(db, item)["decision"] == "CONSUMED_UNKNOWN_NO_SEND"
    assert m.reserve(db, item)["decision"] == "DENY_ALREADY_CONSUMED"
    modified = dict(item, authority_claim_sha256="f"*64)
    assert m.reserve(db, modified)["decision"] == "DENY_ALREADY_CONSUMED"
    assert m.count(db) == 1


@pytest.mark.parametrize("change", [
    {"trial": "other-trial"},
    {"arm": "C"},
    {"ordinal": -1},
    {"ordinal": True},
    {"policy_sha256": "0"*64},
    {"provider_post_allowed": True},
    {"wire_sha256": "INVALID"},
    {"authority_claim_sha256": "INVALID"},
])
def test_invalid_scope_fails_closed_before_consume(tmp_path,change):
    db=tmp_path / "local.sqlite"
    m.init_store(db)
    item=dict(m.synth(),**change)
    with pytest.raises(m.Denied):
        m.reserve(db,item)
    assert m.count(db)==0


def test_missing_store_does_not_get_created(tmp_path):
    db=tmp_path/"offline.sqlite"
    with pytest.raises(m.Denied,match="477_STORE_UNAVAILABLE"):
        m.reserve(db,m.synth())
    assert not db.exists()


def test_store_connection_lock_fails_closed(tmp_path):
    import sqlite3
    db=tmp_path/"locked.sqlite"
    m.init_store(db)
    with sqlite3.connect(db) as lock:
        lock.execute("BEGIN EXCLUSIVE")
        with pytest.raises(m.Denied,match="477_STORAGE_ERROR_FAIL_CLOSED"):
            m.reserve(db,m.synth())
        lock.rollback()
    assert m.count(db)==0


@pytest.mark.parametrize("env",m.BLOCK_ENV)
def test_fake_approval_and_secret_env_refused(monkeypatch,env):
    monkeypatch.setenv(env,"DO_NOT_USE")
    with pytest.raises(m.Denied):
        m.ensure_offline()


def test_local_model_never_claims_real_multirunner_authority():
    out=m.run(with_native=False)
    assert out["same_run_native_posthoc_hash_joins"]==0
    assert out["durable_cross_runner_single_use_proven"] is False
    assert out["independent_protected_store_proven"] is False
    assert out["pre_dispatch_native_gate_integrated"] is False
    assert out["remote_iam_or_egress_proven"] is False
    assert out["live_sender_implemented"] is False
    assert out["real_provider_posts"]==0
    assert out["genuine_native_utility"] is None
    assert out["no_go"] is True


@pytest.mark.skipif(os.environ.get("TASK4_477_NATIVE_PROOF") != "1",
                    reason="source-pinned Native SDK dependencies required")
def test_native_posthoc_hash_joins_reject_restart():
    joined=m.native_join()
    assert len(joined)==8
    assert len({(x["arm"],x["ordinal"]) for x in joined})==8
    assert all(len(x["sdk_wire_sha256"])==64
               and len(x["ledger_receipt_sha256"])==64 for x in joined)


def test_ci_is_pr_only_no_secret_or_paid_dispatch():
    wf=(m.ROOT/".github/workflows/task4-477-local-cas-native-offline.yml").read_text()
    src=Path(m.__file__).read_text()
    for forbidden in ("workflow_dispatch:", "pull_request_target:",
                      "secrets.", "contents: write", "id-token: write",
                      "requests.post(", "httpx.HTTPTransport("):
        assert forbidden not in wf
        assert forbidden not in src
    assert "contents: read" in wf
    assert "persist-credentials: false" in wf
