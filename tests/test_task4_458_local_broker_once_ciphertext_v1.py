"""Task4 #458: local broker process isolation / restart; NO remote Provider."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sqlite3

import pytest

from scripts import task4_458_local_broker_once_ciphertext_v1 as m


def test_no_real_provider_credential_context(monkeypatch):
    for k in m.SENSITIVE:
        monkeypatch.delenv(k, raising=False)
    m.deny_live_context()
    for k in m.SENSITIVE:
        monkeypatch.setenv(k, "FAKE_TEST_SENTINEL")
        with pytest.raises(m.Refused, match="PROVIDER_SECRET_CONTEXT_DENIED"):
            m.deny_live_context()
        monkeypatch.delenv(k)


@pytest.mark.parametrize("extra", [
    {"event": "workflow_dispatch"}, {"live_send": True},
    {"api_key": "fake"}, {"authority": "ALLOW"},
])
def test_unknown_claim_fields_denied(extra, tmp_path):
    db = tmp_path / "ledger.db"
    # direct action rejects unauthorized fields independent of any transport
    with pytest.raises(m.Refused, match="EXACT_PACKET_FIELDS"):
        m.action(db, "a" * 64, {
            "op": "consume", "trial": m.SYNTHETIC_TRIAL, "arm": "A",
            "ordinal": 0, "request_sha": "b" * 64, **extra,
        })
    assert not db.exists()


def test_malformed_or_wrong_cohort_denied(tmp_path):
    db = tmp_path / "nothing"
    for p in (
        {"op":"consume","trial":"X","arm":"A","ordinal":0,"request_sha":"a"*64},
        {"op":"consume","trial":m.SYNTHETIC_TRIAL,"arm":"C","ordinal":0,"request_sha":"a"*64},
        {"op":"consume","trial":m.SYNTHETIC_TRIAL,"arm":"A","ordinal":5,"request_sha":"a"*64},
        {"op":"consume","trial":m.SYNTHETIC_TRIAL,"arm":"A","ordinal":0,"request_sha":"a"},
    ):
        with pytest.raises(m.Refused):
            m.action(db, "a"*64, p)


def test_local_sqlite_never_grants_replay_after_restart(tmp_path):
    p = tmp_path / "broker"
    p.mkdir(mode=0o700)
    db = p / "broker.db"
    m.prepare_db(db)
    claim = {"op":"consume","trial":m.SYNTHETIC_TRIAL,
             "arm":"B","ordinal":1,"request_sha":"b"*64}
    first = m.action(db,"a"*64,claim)
    assert first["decision"] == "LOCAL_CONSUMED_NO_SEND"
    assert first["live_post"] is False
    second = m.action(db,"a"*64,claim)
    assert second["decision"] == "DENY_ALREADY_CONSUMED"
    assert second["live_post"] is False
    conn = sqlite3.connect(db)
    row = conn.execute("SELECT state,ciphertext FROM attempted").fetchone()
    conn.close()
    assert row == ("UNKNOWN_PERMANENTLY_CONSUMED",None)


def test_reject_unattested_envelope_and_plaintext(tmp_path):
    p = tmp_path / "broker"
    p.mkdir(mode=0o700)
    db = p / "broker.db"
    m.prepare_db(db)
    claim = {"op":"consume","trial":m.SYNTHETIC_TRIAL,"arm":"A",
             "ordinal":0,"request_sha":"a"*64}
    receipt = m.action(db,"b"*64,claim)["receipt_sha"]
    packet = {"op":"attach","trial":m.SYNTHETIC_TRIAL,"arm":"A",
              "ordinal":0,"receipt_sha":receipt,
              "envelope_b64": m.base64.b64encode(b'{"plaintext":"NO"}').decode()}
    with pytest.raises(m.Refused, match="AEAD_ENVELOPE_FIELDS"):
        m.action(db,"b"*64,packet)
    after = m.action(db,"b"*64,{
        "op":"read","trial":m.SYNTHETIC_TRIAL,"arm":"A","ordinal":0})
    assert after["envelope_b64"] is None


def test_read_missing_consumption_does_not_create_claim(tmp_path):
    p = tmp_path / "private"
    p.mkdir(mode=0o700)
    db = p / "broker.db"
    m.prepare_db(db)
    with pytest.raises(m.Refused, match="NO_PRIOR_CONSUMPTION"):
        m.action(db, "a"*64,{
            "op":"read","trial":m.SYNTHETIC_TRIAL,"arm":"A","ordinal":0})


def test_script_has_only_af_unix_ipc_and_no_provider_sender():
    s = Path(m.__file__).read_text()
    assert "socket.AF_UNIX" in s
    assert "127.0.0.1" not in s
    assert "https://api.openai.com" not in s
    assert "openai.OpenAI(" not in s
    assert "requests.post(" not in s
    assert "HTTPSConnection(" not in s
    assert "provider_calls" in s
    assert "live_dispatch" in s
    assert '"live_post": False' in s
    assert "os._exit(74)" in s


def test_dedicated_ci_never_receives_secrets_or_workflow_dispatch():
    text = Path(".github/workflows/task4-458-local-broker-cryptographic-custody-deny.yml").read_text()
    assert "\n  pull_request:" in text
    for forbidden in ("\n  workflow_dispatch:", "\n  push:", "pull_request_target:",
                      "environment:", "secrets.", "contents: write", "id-token: write"):
        assert forbidden not in text
    assert "contents: read" in text and "persist-credentials: false" in text
    for k in ("OPENAI_API_KEY", "TASK4_OPENAI_API_KEY",
              "ANTHROPIC_API_KEY", "OPENAI_BASE_URL"):
        assert k + ': ""' in text
    assert "--mode offline-demo" in text


@pytest.mark.skipif(os.getenv("TASK4_458_PROCESS_PROOF") != "1",
                    reason="dedicated safe local-only broker proof")
def test_really_separate_processes_share_one_broker_and_resume_unknown():
    r = m.run_demo()
    assert r["distinct_isolated_client_processes"] == 13
    assert r["consumed_slots_total"] == 3
    assert r["ciphertext_slots_verified_after_restart"] == 2
    assert r["crash_unknown_slot_denied_after_restart"] is True
    assert r["cross_github_runner_distributed_authority_proven"] is False
    assert r["external_off_host_ciphertext_custody_proven"] is False
    assert r["persistent_remote_service_provisioned"] is False
    assert r["actual_provider_calls"] == 0
    assert r["genuine_utility_scores"] == 0
    assert r["live_dispatch"] == "DENY"
