"""Task1 mock Provider boundary: synthetic two-attempt sink, zero live authority."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import socket
from types import SimpleNamespace

import pytest

from scripts import final128_task1_mock_provider_presend_bind_no_effect_v1 as m

ROOT = Path(__file__).resolve().parents[1]
FROZEN = ROOT / "evidence/final128_task1_research_tag_live_readback_2026-10-18_v1.json"
DOC = ROOT / "docs/optimization/FINAL128_TASK1_MOCK_PROVIDER_PRESEND_BIND_NO_EFFECT_V1.md"


@pytest.fixture(autouse=True)
def no_network_or_live_secrets(monkeypatch):
    def fail(*_args, **_kwargs):
        pytest.fail("TASK1_MOCK_PRESEND_NO_NETWORK_ALLOWED")
    monkeypatch.setattr(socket.socket, "connect", fail)
    monkeypatch.setattr(socket.socket, "connect_ex", fail)
    monkeypatch.setattr(socket, "create_connection", fail)
    for k in (
        "OPENAI_API_KEY", "TASK1_OPENAI_API_KEY", "TASK1_CAPTURE_AES256_KEY",
        "TASK1_RESEARCH_OPENAI_API_KEY", "TASK1_RESEARCH_CAPTURE_AES256_KEY",
        "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GH_TOKEN", "GITHUB_TOKEN",
        "OPENAI_BASE_URL", "VERITAS_RULESET_OWNER_TOKEN",
    ):
        monkeypatch.delenv(k, raising=False)


def snapshot():
    return json.loads(FROZEN.read_text(encoding="utf-8"))


def fixture(failure="none"):
    issuer = m.InProcessFixtureIssuer()
    port = m.InMemoryFakeProviderPort(failure)
    gate = m.MockPreSendBoundary(issuer, port)
    return issuer, port, gate


def call(gate, issuer, arm="A", **kw):
    args = dict(
        arm=arm, raw=m.PACKET, permit=issuer.issue(arm),
        frozen_snapshot=snapshot(),
    )
    args.update(kw)
    return gate.attempt(**args)


def assert_no_live(summary):
    assert summary["real_provider_calls"] == 0
    assert summary["live_execution_authorized"] is False
    assert summary["global_durable_single_use_proven"] is False
    assert summary["independent_issuer_authenticated"] is False
    assert summary["real_veritas_bind_called"] is False
    assert summary["native_utility_scored"] is False


def test_real_frozen_ref_snapshot_alone_cannot_send_anything():
    issuer, port, gate = fixture()
    with pytest.raises(m.Refused, match="MISSING_OR_AMBIGUOUS_MOCK_PERMIT"):
        gate.attempt(arm="A", raw=m.PACKET, permit=None,
                     frozen_snapshot=snapshot())
    assert gate.summary()["phase"] == "FRESH"
    assert port.attempts == []
    assert_no_live(gate.summary())
    assert m.REF != m.PRODUCTION_REF


def test_source_owned_synthetic_first_pair_only_sends_to_fake_port():
    issuer, port, gate = fixture()
    a = call(gate, issuer, "A")
    b = call(gate, issuer, "B", fake_tick=2)
    assert a["arm"] == "A" and b["arm"] == "B"
    assert a["fake_packet_sha256"] == b["fake_packet_sha256"] == m.PACKET_SHA256
    assert a["mock_only"] is True and b["mock_only"] is True
    for receipt in (a, b):
        assert receipt["provider_calls"] == 0
        assert receipt["paid_authority"] is False
        assert receipt["run_authenticated"] is False
    assert port.attempts == ["A", "B"]
    assert gate.summary()["phase"] == "PAIR_ACK"
    assert gate.summary()["fake_receipts"] == 2
    assert_no_live(gate.summary())
    for arm in ("A", "B"):
        with pytest.raises(m.Refused, match="REPLAY_WRONG_ORDER_OR_UNKNOWN_STOP"):
            call(gate, issuer, arm)
    assert port.attempts == ["A", "B"]


@pytest.mark.parametrize("changes", [
    {"arm": "B"},
    {"raw": b"altered"},
    {"raw": m.PACKET + b" "},
    {"raw": bytearray(m.PACKET)},
    {"raw": None},
    {"fake_tick": 3},
    {"fake_tick": True},
    {"fake_tick": -1},
    {"caller_run_claim": {}},
    {"caller_run_claim": {"run_id": "FAKE", "paid": True}},
])
def test_bad_input_never_arrives_at_mock_sink(changes):
    issuer, port, gate = fixture()
    with pytest.raises(m.Refused):
        call(gate, issuer, "A", **changes)
    assert port.attempts == []
    assert gate.summary()["phase"] == "FRESH"


@pytest.mark.parametrize("mutate", [
    lambda s: s["research_ref"].update(target_sha="f" * 40),
    lambda s: s["research_ref"].update(exact_ref=m.PRODUCTION_REF),
    lambda s: s["research_ruleset"].pop("bypass_actors"),
    lambda s: s["research_ruleset"].update(enforcement="disabled"),
    lambda s: s["paid_execution_hold"].update(issue_427_state="closed"),
    lambda s: s["paid_execution_hold"].update(paid_task1_dispatch_authorized=True),
    lambda s: s["provenance_limitations"].update(
        issuer_run_or_job_binding_verified=True),
    lambda s: s["provenance_limitations"].update(
        durable_global_once_only_provider_lease_proven=True),
])
def test_snapshot_tamper_denied_at_presend_without_fake_effect(mutate):
    issuer, port, gate = fixture()
    data = snapshot()
    mutate(data)
    with pytest.raises(m.Refused, match="FROZEN_EVIDENCE_DENIED"):
        call(gate, issuer, frozen_snapshot=data)
    assert port.attempts == []


@pytest.mark.parametrize("field,bad", [
    ("run_id", "gh-claimed-valid-run-999"),
    ("run_attempt", 2),
    ("run_attempt", True),
    ("issuer", "attacker-owned-issuer"),
    ("sender", "attacker-owned-sender"),
    ("research_ref", m.PRODUCTION_REF),
    ("research_sha", "f" * 40),
    ("packet_sha256", "a" * 64),
    ("expires_at_fake_tick", 99),
    ("max_fake_attempts", 200),
    ("max_fake_attempts", True),
    ("no_retry", False),
    ("production_tag_consumed", True),
    ("paid_approved", True),
    ("purpose", "REAL_APPROVED"),
    ("model", "other-model"),
    ("case_id", "another-task"),
])
def test_forged_signed_scope_never_grants_fake_send(field, bad):
    issuer, port, gate = fixture()
    permit = issuer.issue("A")
    permit.claims[field] = bad
    with pytest.raises(m.Refused, match="FAKE_RUN_OR_SCOPE_DRIFT"):
        call(gate, issuer, permit=permit)
    assert port.attempts == []


def test_extra_claim_missing_signature_and_other_fixture_issuer_denied():
    issuer, port, gate = fixture()
    permit = issuer.issue("A")
    permit.claims["unknown_live_authority"] = True
    with pytest.raises(m.Refused, match="MISSING_OR_AMBIGUOUS_MOCK_PERMIT"):
        call(gate, issuer, permit=permit)
    assert port.attempts == []

    permit = issuer.issue("A")
    with pytest.raises(m.Refused, match="MALFORMED_SYNTHETIC_MAC"):
        call(gate, issuer, permit=replace(permit, mac_sha256=None))
    with pytest.raises(m.Refused, match="WRONG_SYNTHETIC_ISSUER"):
        call(gate, issuer, permit=replace(permit, mac_sha256="f" * 64))
    wrong_issuer = m.InProcessFixtureIssuer()
    with pytest.raises(m.Refused, match="WRONG_SYNTHETIC_ISSUER"):
        call(gate, issuer, permit=wrong_issuer.issue("A"))
    assert port.attempts == []


def test_b_before_a_and_duplicated_a_are_never_delivered():
    issuer, port, gate = fixture()
    with pytest.raises(m.Refused, match="REPLAY_WRONG_ORDER_OR_UNKNOWN_STOP"):
        call(gate, issuer, "B")
    assert port.attempts == []
    call(gate, issuer, "A")
    with pytest.raises(m.Refused, match="REPLAY_WRONG_ORDER_OR_UNKNOWN_STOP"):
        call(gate, issuer, "A")
    assert port.attempts == ["A"]
    call(gate, issuer, "B")
    assert port.attempts == ["A", "B"]


@pytest.mark.parametrize("failure", ["A_TIMEOUT", "A_BAD_ACK"])
def test_unknown_first_fake_attempt_quarantines_all_retries_and_b(failure):
    issuer, port, gate = fixture(failure)
    with pytest.raises(m.UnknownAfterAttempt, match="NO_RETRY"):
        call(gate, issuer, "A")
    assert port.attempts == ["A"]
    assert gate.summary()["phase"] == "UNKNOWN_AFTER_A"
    for arm in ("A", "B"):
        with pytest.raises(m.Refused, match="REPLAY_WRONG_ORDER_OR_UNKNOWN_STOP"):
            call(gate, issuer, arm)
    assert port.attempts == ["A"]
    assert_no_live(gate.summary())


@pytest.mark.parametrize("failure", ["B_TIMEOUT", "B_BAD_ACK"])
def test_unknown_second_fake_attempt_stops_without_duplicate(failure):
    issuer, port, gate = fixture(failure)
    call(gate, issuer, "A")
    with pytest.raises(m.UnknownAfterAttempt, match="NO_RETRY"):
        call(gate, issuer, "B")
    assert port.attempts == ["A", "B"]
    assert gate.summary()["phase"] == "UNKNOWN_AFTER_B"
    assert gate.summary()["fake_receipts"] == 1
    for arm in ("A", "B"):
        with pytest.raises(m.Refused):
            call(gate, issuer, arm)
    assert port.attempts == ["A", "B"]


def test_parallel_same_gate_competition_only_one_mock_a_attempt():
    issuer, port, gate = fixture()
    def compete():
        try:
            call(gate, issuer, "A")
            return "mock_a_ack"
        except m.Refused:
            return "denied"
    with ThreadPoolExecutor(max_workers=2) as pool:
        out = list(pool.map(lambda _: compete(), range(2)))
    assert sorted(out) == ["denied", "mock_a_ack"]
    assert port.attempts == ["A"]
    assert gate.summary()["fake_receipts"] == 1
    assert_no_live(gate.summary())


def test_independent_fake_sinks_do_not_establish_global_single_use():
    first = fixture()
    second = fixture()
    call(first[2], first[0], "A")
    call(second[2], second[0], "A")
    assert first[1].attempts == second[1].attempts == ["A"]
    # This counterexample is why a real durable cross-run lease is still needed.
    assert_no_live(first[2].summary())
    assert_no_live(second[2].summary())


def test_wrong_sink_class_and_nonexistent_live_interfaces_blocked():
    issuer = m.InProcessFixtureIssuer()
    with pytest.raises(m.Refused, match="ONLY_LOCAL_FAKE_PORT_ALLOWED"):
        m.MockPreSendBoundary(issuer, SimpleNamespace(deliver=lambda *_: None))
    with pytest.raises(m.Refused, match="ONLY_SYNTHETIC_ISSUER_ALLOWED"):
        m.MockPreSendBoundary(SimpleNamespace(issue=lambda *_: None),
                              m.InMemoryFakeProviderPort())
    assert not hasattr(m, "send_openai")
    assert not hasattr(m, "github_tag_create")
    assert not hasattr(m, "paid_dispatch")


def test_frozen_snapshot_proves_no_real_provider_permission():
    assert m.PACKET_SHA256 == m.hashlib.sha256(m.PACKET).hexdigest()
    assert m.claims_for("A")["packet_sha256"] == m.claims_for("B")["packet_sha256"]
    assert m.claims_for("A")["paid_approved"] is False
    assert m.claims_for("A")["production_tag_consumed"] is False
    assert m.claims_for("A")["run_id"].startswith("OFFLINE_FIXTURE")
    assert m.evidence.review_frozen_snapshot(snapshot()).authorized_to_send_provider is False


def test_docs_honestly_bound_test_scope():
    doc = DOC.read_text(encoding="utf-8")
    for needed in (
        "NO-GO", "PR #441", "mock", "Provider", "Run ID",
        "durable", "Issue #427", "no retry", "POST /git/refs",
    ):
        assert needed in doc
    assert "not wired" in doc
