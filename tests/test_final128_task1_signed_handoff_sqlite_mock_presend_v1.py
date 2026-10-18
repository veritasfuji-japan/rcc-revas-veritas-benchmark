"""Task1 signed fake first A/B, locally durable attempts; never real Provider."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import socket
from threading import Thread

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
import pytest

from scripts import final128_task1_signed_handoff_sqlite_mock_presend_v1 as m
from scripts import final128_task1_research_signed_run_handoff_offline_v1 as h
from scripts import final128_task1_mock_provider_presend_bind_no_effect_v1 as mock

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = (
    ROOT / "evidence/final128_task1_research_tag_live_readback_2026-10-18_v1.json"
)
DOC = (
    ROOT / "docs/optimization/"
    "FINAL128_TASK1_SIGNED_HANDOFF_SQLITE_MOCK_PRESEND_V1.md"
)
RUN = "39012345678"
ISSUER_JOB = "117123456781"
SENDER_JOB = "117123456782"


@pytest.fixture(autouse=True)
def block_external_connections_and_hardcoded_secret_access(monkeypatch):
    def blocked(*_args, **_kwargs):
        pytest.fail("TASK1_SQLITE_MOCK_NEVER_EXTERNAL_NETWORK")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    for key in (
        "GH_TOKEN", "GITHUB_TOKEN", "OPENAI_API_KEY", "TASK1_OPENAI_API_KEY",
        "TASK1_CAPTURE_AES256_KEY", "TASK1_RESEARCH_OPENAI_API_KEY",
        "TASK1_RESEARCH_CAPTURE_AES256_KEY", "TASK4_OPENAI_API_KEY",
        "VERITAS_RULESET_OWNER_TOKEN", "ANTHROPIC_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)


def snapshot():
    return json.loads(SNAPSHOT.read_text(encoding="utf8"))


def context(**kw):
    values = {
        "main_sha": mock.SHA,
        "run_id": RUN,
        "issuer_job_id": ISSUER_JOB,
        "sender_job_id": SENDER_JOB,
        "request_sha256": mock.PACKET_SHA256,
        "run_attempt": 1,
    }
    values.update(kw)
    return h.MockJobContext(**values)


def fixture(tmp_path, *, failure="none", dbname="once.sqlite", signed=None,
            private=None, expected=None, port=None):
    folder = tmp_path / "private"
    folder.mkdir(exist_ok=True)
    folder.chmod(0o700)
    signer = private or Ed25519PrivateKey.generate()
    ctx = expected or context()
    token = signed or h.mock_sign(h.mock_payload(ctx), signer, ctx)
    sink = port or mock.InMemoryFakeProviderPort(failure)
    gate = m.SQLiteLocalFakePresendGate(
        db_path=folder / dbname, expected=ctx,
        pinned_test_public_key=signer.public_key(),
        local_fake_port=sink,
    )
    return gate, token, signer, sink


def attempt(gate, token, arm="A", **kw):
    defaults = {
        "arm": arm, "packet": mock.PACKET,
        "signed": token, "frozen_snapshot": snapshot(),
    }
    defaults.update(kw)
    return gate.attempt(**defaults)


def no_authority(state):
    assert state["provider_requests"] == 0
    assert state["actual_github_job_separation"] is False
    assert state["production_single_use_lease_proven"] is False
    assert state["paid_task1_authorized"] is False


def test_signed_source_owned_pair_consumed_across_gate_reopens(tmp_path):
    gate, token, signer, port = fixture(tmp_path)
    a = attempt(gate, token, "A")
    assert a.local_fake_ack is True and a.arm == "A"
    assert a.real_provider_requests == 0
    assert a.github_identity_authenticated is False
    assert a.paid_dispatch_authorized is False
    assert a.external_durable_lease_proven is False
    assert a.actual_job_permission_split_proven is False
    assert port.attempts == ["A"]
    assert gate.status()["phase"] == "A_ACK"
    new_gate, _, _, new_port = fixture(
        tmp_path, private=signer, signed=token,
    )
    with pytest.raises(m.Refused, match="REPLAY_OR_UNKNOWN_STOP"):
        attempt(new_gate, token, "A")
    assert new_port.attempts == []
    b = attempt(new_gate, token, "B")
    assert b.local_fake_ack and b.arm == "B"
    assert new_port.attempts == ["B"]
    assert new_gate.status()["phase"] == "PAIR_ACK"
    assert new_gate.status()["attempts"] == (("A", "ACK"), ("B", "ACK"))
    no_authority(new_gate.status())
    for arm in ("A", "B"):
        with pytest.raises(m.Refused, match="REPLAY_OR_UNKNOWN_STOP"):
            attempt(new_gate, token, arm)
    assert new_port.attempts == ["B"]
    assert (tmp_path / "private/once.sqlite").stat().st_mode & 0o077 == 0


def test_b_first_denied_without_reservation_or_send(tmp_path):
    gate, token, _, port = fixture(tmp_path)
    with pytest.raises(m.Refused, match="A_REQUIRED_BEFORE_B"):
        attempt(gate, token, "B")
    assert gate.status()["phase"] == "FRESH"
    assert port.attempts == []


@pytest.mark.parametrize("failure,phase,deliveries", [
    ("A_TIMEOUT", "UNKNOWN_A", ["A"]),
    ("A_BAD_ACK", "UNKNOWN_A", ["A"]),
    ("B_TIMEOUT", "UNKNOWN_B", ["B"]),
    ("B_BAD_ACK", "UNKNOWN_B", ["B"]),
])
def test_unknown_after_fake_send_stops_across_gate_reopens(
    tmp_path, failure, phase, deliveries
):
    gate, token, signer, port = fixture(
        tmp_path, failure=failure if failure.startswith("A") else "none"
    )
    if failure.startswith("B"):
        a = attempt(gate, token, "A")
        assert a.local_fake_ack
        gate = m.SQLiteLocalFakePresendGate(
            db_path=tmp_path / "private/once.sqlite", expected=context(),
            pinned_test_public_key=signer.public_key(),
            local_fake_port=mock.InMemoryFakeProviderPort(failure),
        )
        port = gate.port
    arm = failure[0]
    with pytest.raises(m.UnknownAfterAttempt, match="NO_RETRY"):
        attempt(gate, token, arm)
    assert port.attempts == deliveries
    reopened, _, _, new_port = fixture(
        tmp_path, private=signer, signed=token,
    )
    assert reopened.status()["phase"] == phase
    for candidate in ("A", "B"):
        with pytest.raises(m.Refused, match="REPLAY_OR_UNKNOWN_STOP"):
            attempt(reopened, token, candidate)
    assert new_port.attempts == []
    no_authority(reopened.status())


@pytest.mark.parametrize("fault,delivered", [
    ("AFTER_RESERVATION_BEFORE_FAKE_SEND", []),
    ("AFTER_FAKE_SEND_BEFORE_ACK", ["A"]),
])
def test_mock_crash_windows_are_persistently_unknown_without_replay(
    tmp_path, fault, delivered
):
    gate, token, signer, port = fixture(tmp_path)
    with pytest.raises(m.UnknownAfterAttempt, match="NO_RETRY"):
        attempt(gate, token, "A", fault=fault)
    assert port.attempts == delivered
    next_process_gate, _, _, fresh_port = fixture(
        tmp_path, private=signer, signed=token,
    )
    assert next_process_gate.status()["phase"] == "UNKNOWN_A"
    for arm in ("A", "B"):
        with pytest.raises(m.Refused):
            attempt(next_process_gate, token, arm)
    assert fresh_port.attempts == []


@pytest.mark.parametrize("mutation", [
    lambda t: t["payload"].update(run_id="39012345679"),
    lambda t: t["payload"].update(sender_job_id=ISSUER_JOB),
    lambda t: t["payload"].update(issuer_job_id=SENDER_JOB),
    lambda t: t["payload"].update(main_sha="f" * 40),
    lambda t: t["payload"].update(research_ref=mock.PRODUCTION_REF),
    lambda t: t["payload"].update(model="gpt-6"),
    lambda t: t["payload"].update(case="another-task"),
    lambda t: t["payload"].update(first_request_sha256_by_arm={"A":"f"*64,"B":"f"*64}),
    lambda t: t["payload"].update(paid_consent=True),
    lambda t: t["payload"].update(ruleset_enrolled=True),
    lambda t: t["payload"].update(provider_secret_access=True),
    lambda t: t["payload"].update(production_tag_consumed=True),
    lambda t: t["payload"].update(run_attempt=2),
    lambda t: t["payload"].update(run_attempt=True),
    lambda t: t["payload"].update(max_first_model_posts=3),
    lambda t: t["payload"].update(no_retry=False),
    lambda t: t["payload"].update(unexpected_live_authority=True),
    lambda t: t.pop("algorithm"),
    lambda t: t.update(algorithm="ED25519_PRODUCTION_VALID"),
    lambda t: t.update(signature_base64="!!!"),
])
def test_untrusted_handoff_mutation_refused_before_fake_effect(tmp_path, mutation):
    gate, token, _, port = fixture(tmp_path)
    broken = deepcopy(token)
    mutation(broken)
    with pytest.raises(m.Refused, match="SIGNED_SCOPE_DENIED"):
        attempt(gate, broken)
    assert gate.status()["phase"] == "FRESH"
    assert port.attempts == []


@pytest.mark.parametrize("changed", [
    {"packet": b"changed"},
    {"packet": bytearray(mock.PACKET)},
    {"packet": mock.PACKET + b" "},
    {"arm": "C"},
    {"arm": True},
])
def test_packet_and_arm_drift_refused_before_sqlite(tmp_path, changed):
    gate, token, _, port = fixture(tmp_path)
    with pytest.raises(m.Refused):
        attempt(gate, token, **changed)
    assert port.attempts == []
    assert gate.status()["phase"] == "FRESH"


def test_wrong_test_signer_and_inconsistent_run_context_refused(tmp_path):
    gate, token, _, port = fixture(tmp_path)
    different_key = Ed25519PrivateKey.generate()
    forged = h.mock_sign(h.mock_payload(context()), different_key, context())
    with pytest.raises(m.Refused, match="SIGNED_SCOPE_DENIED"):
        attempt(gate, forged)
    wrong_ctx = context(sender_job_id="117123456789")
    other_signer = Ed25519PrivateKey.generate()
    # Even a correctly signed but different fake recipient must be refused.
    different_ctx_token = h.mock_sign(
        h.mock_payload(wrong_ctx), other_signer, wrong_ctx
    )
    with pytest.raises(m.Refused, match="SIGNED_SCOPE_DENIED"):
        attempt(gate, different_ctx_token)
    assert port.attempts == []


def test_historical_snapshot_tag_drift_and_false_upgrade_denied(tmp_path):
    gate, token, _, port = fixture(tmp_path)
    for changes in (
        ("research_ref", "target_sha", "f" * 40),
        ("research_ruleset", "enforcement", "disabled"),
        ("paid_execution_hold", "paid_task1_dispatch_authorized", True),
        ("provenance_limitations", "issuer_run_or_job_binding_verified", True),
    ):
        data = snapshot()
        data[changes[0]][changes[1]] = changes[2]
        with pytest.raises(m.Refused, match="FROZEN_EVIDENCE_DENIED"):
            attempt(gate, token, frozen_snapshot=data)
    assert port.attempts == []
    assert gate.status()["phase"] == "FRESH"


def test_other_ledger_can_accept_same_synthetic_A_not_global_once(tmp_path):
    a, token, private, port_a = fixture(tmp_path, dbname="first.sqlite")
    b, _, _, port_b = fixture(
        tmp_path, dbname="separate.sqlite", private=private, signed=token
    )
    assert attempt(a, token).local_fake_ack is True
    assert attempt(b, token).local_fake_ack is True
    assert port_a.attempts == port_b.attempts == ["A"]
    assert a.status()["production_single_use_lease_proven"] is False
    assert b.status()["production_single_use_lease_proven"] is False


def test_private_database_directory_and_file_required(tmp_path):
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    public.chmod(0o755)
    key = Ed25519PrivateKey.generate().public_key()
    port = mock.InMemoryFakeProviderPort()
    with pytest.raises(m.Refused, match="PRIVATE_PARENT_0700_REQUIRED"):
        m.SQLiteLocalFakePresendGate(
            db_path=public / "name.sqlite", expected=context(),
            pinned_test_public_key=key, local_fake_port=port,
        )
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    path = private / "name.sqlite"
    path.write_bytes(b"")
    path.chmod(0o644)
    with pytest.raises(m.Refused, match="OWNER_ONLY_DB_REQUIRED"):
        m.SQLiteLocalFakePresendGate(
            db_path=path, expected=context(),
            pinned_test_public_key=key, local_fake_port=port,
        )


def _competing_worker(path, key_bytes, signed, frozen, start, queue):
    """Real OS child process, local test DB only, no network/Provider call."""
    public = Ed25519PublicKey.from_public_bytes(key_bytes)
    gate = m.SQLiteLocalFakePresendGate(
        db_path=Path(path), expected=context(),
        pinned_test_public_key=public,
        local_fake_port=mock.InMemoryFakeProviderPort(),
    )
    if not start.wait(timeout=12):
        queue.put("not_started")
        return
    try:
        gate.attempt(arm="A", packet=mock.PACKET, signed=signed,
                     frozen_snapshot=frozen)
    except m.Refused:
        queue.put("denied")
    else:
        queue.put("mock_ack")


def test_separate_OS_processes_compete_on_same_local_sqlite_file(tmp_path):
    gate, token, signer, port = fixture(tmp_path)
    raw_key = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    ctx = multiprocessing.get_context("spawn")
    start = ctx.Event()
    output = ctx.Queue()
    processes = [
        ctx.Process(target=_competing_worker, args=(
            str(gate.db_path), raw_key, token, snapshot(), start, output,
        )) for _ in range(2)
    ]
    try:
        for p in processes:
            p.start()
        start.set()
        outcomes = [output.get(timeout=22) for _ in processes]
        for p in processes:
            p.join(timeout=22)
        assert sorted(outcomes) == ["denied", "mock_ack"]
        assert all(p.exitcode == 0 for p in processes)
        assert gate.status()["phase"] == "A_ACK"
        assert gate.status()["attempts"] == (("A", "ACK"),)
        assert port.attempts == []
        no_authority(gate.status())
    finally:
        for p in processes:
            if p.is_alive():
                p.terminate()
            p.join(timeout=5)


def test_no_real_sender_interface_and_docs_scope():
    source = Path(m.__file__).read_text(encoding="utf8")
    for forbidden in (
        "import socket", "import urllib", "import requests",
        "import http.client", "from openai", "import subprocess",
        "os.environ", "workflow_dispatch(", "api.openai.com",
        "POST /git/refs",
    ):
        assert forbidden not in source
    for field in (
        "NO-GO", "Issue #427", "#423", "#445", "#437", "#442",
        "separate OS processes", "one local SQLite database",
        "not independent", "not wired",
    ):
        assert field in DOC.read_text(encoding="utf8")
    assert m.SCHEMA in source
    assert not hasattr(m, "run_paid_provider")
    assert not hasattr(m, "write_real_tag")
