"""Task4 #471: deny cross-arm, altered, uncapped, and unsealed Native responses.

Lightweight tests use stubbed local components for failure injection; ONLY the
dedicated native full-flow test exercises original pinned SDK/Broker/AEAD.
"""
from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import task4_471_same_run_capped_sdk_aead_native_no_go_v1 as m

NATIVE = os.environ.get("TASK4_471_NATIVE_PROOF") == "1"


class LocalSource:
    def __init__(self, arm="A"):
        self.origin_arm = arm
        self.attempts = 0
        self.closed = False
        self.calls = 0
        self.fail = False
        self.tamper = False

    def __call__(self, request):
        self.calls += 1
        if self.fail:
            raise m.Refused("STUB_LOCAL_RESPONSE_UNKNOWN")
        self.attempts += 1
        raw = b'{"id":"local-pretend-not-provider","usage":{"total_tokens":0}}'
        return SimpleNamespace(status_code=200, request=request,
                               content=raw)


class LocalGate:
    def __init__(self):
        self.by_arm = {"A": 0, "B": 0}
        self.trial = "SYNTHETIC_ONLY"
        self.records = []
        self.failed = False
        self.refuse = False
        self.poison_calls = 0

    def admit(self, *, arm, request):
        if self.refuse:
            raise m.Refused("STUB_CONSUME_DENIED")
        index = self.by_arm[arm]
        self.by_arm[arm] += 1
        self.records.append({
            "arm": arm, "ordinal": index,
            "sdk_request_sha256": m.sha(request.content),
            "attempt_receipt_sha256": "a" * 64})
        return {"decision": "LOCAL_ATTEMPT_CONSUMED_EXTERNAL_SEND_DENY",
                "ordinal": index, "request_sha256": m.sha(request.content)}

    def poison(self):
        self.failed = True
        self.poison_calls += 1


class LocalBroker:
    def __init__(self):
        self.events = []
        self.fail_attach = False
        self.replay = False

    def exchange(self, socketpath, packet):
        self.events.append(packet["op"])
        if self.fail_attach:
            return {"decision": "DENY_ALREADY_ATTACHED", "live_post": False}
        return {"decision": "LOCAL_CIPHERTEXT_SEALED",
                "sha256": m.sha(b"offline-enc"), "live_post": False}


class LocalVault:
    def __init__(self, root):
        self.root = root
        self.events = []
        self.fail = False
        self.tamper = False

    def commit_before_parser(self, *, arm, ordinal, request, response):
        self.events.append("AEAD_BEFORE_PARSER")
        if self.fail:
            raise m.Refused("STUB_CUSTODY_UNKNOWN")
        filename = "encrypted-" + arm + "-" + str(ordinal) + ".bin"
        raw = b"offline-enc"
        (self.root / filename).write_bytes(
            b"tampered" if self.tamper else raw)
        return {
            "envelope_filename": filename,
            "request_sha256": m.sha(request.content),
            "response_sha256": m.sha(response.content),
            "envelope_sha256": m.sha(raw),
        }


class LocalJournal:
    def __init__(self, vault):
        self.vault = vault
        self.events = []
        self.refuse = False
        self.change_response = False

    def observe(self, *, arm, request, response):
        assert len(self.vault.events) == len(self.events) + 1
        assert self.vault.events[-1] == "AEAD_BEFORE_PARSER"
        self.events.append("JOURNAL_AFTER_ENCRYPTION")
        if self.change_response:
            response.content = b"mutated-after-encryption"
        if self.refuse:
            raise m.Refused("STUB_JOURNAL_REFUSED")


class LocalRequest:
    content = b'{"sdk":"test-local-only"}'


def harness(tmp_path, arm="A"):
    source = LocalSource(arm)
    gate = LocalGate()
    broker = LocalBroker()
    vault = LocalVault(tmp_path)
    journal = LocalJournal(vault)
    count = []
    def local_copy(fake, request):
        count.append("COPIED_NO_CONTENT_MUTATION")
        return SimpleNamespace(
            request=request, content=fake.content,
            status_code=fake.status_code)
    guard = m.CappedLocalEncryptedTransport(
        arm=arm, source=source, source_type=LocalSource, gate=gate,
        broker=broker, socketpath=tmp_path / "no-real.sock",
        root=tmp_path, vault=vault, journal=journal,
        response_factory=local_copy)
    return guard, source, gate, broker, vault, journal, count


def test_same_response_identity_and_ordering(tmp_path):
    guard, source, gate, broker, vault, journal, copied = harness(tmp_path)
    req = LocalRequest()
    response = guard.handle_request(req)
    assert response.request is req
    assert source.calls == source.attempts == 1
    assert gate.by_arm["A"] == 1
    assert broker.events == ["attach"]
    assert vault.events == ["AEAD_BEFORE_PARSER"]
    assert journal.events == ["JOURNAL_AFTER_ENCRYPTION"]
    assert copied == ["COPIED_NO_CONTENT_MUTATION"]
    assert guard.records[0]["requested_output_token_cap"] == 256
    assert guard.records[0]["provider_authenticated"] is False
    assert guard.records[0]["capped_sdk_wire_sha256"] == m.sha(req.content)
    assert gate.failed is False and guard.failed is False


def test_four_local_turns_then_fifth_denied(tmp_path):
    guard, source, gate, broker, vault, journal, copied = harness(tmp_path)
    for _ in range(4):
        guard.handle_request(LocalRequest())
    assert len(guard.records) == 4
    assert len(broker.events) == 4
    with pytest.raises(m.Refused,match="471_SOURCE_GATE_NATIVE_TURN_ORDER"):
        guard.handle_request(LocalRequest())
    assert guard.failed is True
    assert gate.failed is True
    count = source.calls
    with pytest.raises(m.Refused,match="471_FAILED_OR_CLOSED"):
        guard.handle_request(LocalRequest())
    assert source.calls == count


@pytest.mark.parametrize("alteration",[
    "source_class", "cross_arm", "already_called",
    "closed_source", "unknown_arm", "response_factory_missing",
])
def test_origin_must_be_exact_local_source(tmp_path, alteration):
    guard, source, gate, broker, vault, journal, copy = harness(tmp_path)
    kwargs = {
        "arm":"A", "source":source, "source_type":LocalSource,
        "gate":gate, "broker":broker, "socketpath":tmp_path/"local.sock",
        "root":tmp_path, "vault":vault, "journal":journal,
        "response_factory":lambda fake,request:fake,
    }
    if alteration == "source_class":
        kwargs["source_type"] = LocalRequest
    elif alteration == "cross_arm":
        kwargs["arm"] = "B"
    elif alteration == "already_called":
        source.attempts = 1
    elif alteration == "closed_source":
        source.closed = True
    elif alteration == "unknown_arm":
        kwargs["arm"] = "C"
    elif alteration == "response_factory_missing":
        kwargs["response_factory"] = None
    with pytest.raises(m.Refused,match="471_EXACT_LOCAL_SCRIPTED"):
        m.CappedLocalEncryptedTransport(**kwargs)


@pytest.mark.parametrize("fault", [
    "gate_failed", "source_fail", "vault_fail", "encrypted_tamper",
    "broker_attach_denied", "journal_reject", "response_mutate",
    "response_wrong_request", "fake_response_body_nonbytes",
    "fake_response_status_error", "closed_guard",
])
def test_failure_after_broker_or_bad_source_can_never_retry(tmp_path, fault):
    guard, source, gate, broker, vault, journal, _ = harness(tmp_path)
    if fault == "gate_failed":
        gate.refuse = True
    elif fault == "source_fail":
        source.fail = True
    elif fault == "vault_fail":
        vault.fail = True
    elif fault == "encrypted_tamper":
        vault.tamper = True
    elif fault == "broker_attach_denied":
        broker.fail_attach = True
    elif fault == "journal_reject":
        journal.refuse = True
    elif fault == "response_mutate":
        journal.change_response = True
    elif fault == "response_wrong_request":
        guard.response_factory = lambda fake, req: SimpleNamespace(
            request=LocalRequest(), content=fake.content)
    elif fault == "fake_response_body_nonbytes":
        original = source.__class__.__call__
        def stub(req):
            source.attempts += 1
            return SimpleNamespace(request=req,status_code=200,content="notbytes")
        source.__call__ = stub  # Bound special lookup ignores this; patch class below.
    elif fault == "fake_response_status_error":
        pass
    elif fault == "closed_guard":
        guard.closed = True

    def corrupt_source(req):
        source.calls += 1
        source.attempts += 1
        return SimpleNamespace(request=req,
                               status_code=400 if fault == "fake_response_status_error" else 200,
                               content="notbytes" if fault == "fake_response_body_nonbytes"
                               else b"offline-bytes")
    if fault in ("fake_response_body_nonbytes", "fake_response_status_error"):
        from unittest.mock import patch
        with patch.object(LocalSource, "__call__", lambda self,req: corrupt_source(req)):
            with pytest.raises((m.Refused, AssertionError)):
                guard.handle_request(LocalRequest())
    else:
        with pytest.raises((m.Refused, AssertionError)):
            guard.handle_request(LocalRequest())
    assert guard.failed or guard.closed
    calls = source.calls
    with pytest.raises(m.Refused):
        guard.handle_request(LocalRequest())
    assert source.calls == calls
    if fault != "closed_guard":
        assert gate.failed is True


def test_broker_receipt_source_binding_required(tmp_path):
    guard, source, gate, broker, _, _, _ = harness(tmp_path)
    original = gate.admit
    def fake_receipt(*,arm,request):
        result=original(arm=arm,request=request)
        result["request_sha256"]="0"*64
        return result
    gate.admit = fake_receipt
    with pytest.raises(m.Refused,match="471_CAPPED_NATIVE_REQUEST_NOT_CONSUMED"):
        guard.handle_request(LocalRequest())
    assert source.calls==0 and not broker.events
    assert gate.failed


@pytest.mark.parametrize("key",m.SENSITIVE)
def test_any_sensitive_context_prevents_execution(monkeypatch,key):
    monkeypatch.setenv(key,"TEST_NOT_REAL")
    with pytest.raises(m.Refused,match="471_LIVE_SECRET"):
        m.deny_live()


def test_source_pins_and_script_never_construct_live_sender():
    evidence=m.verify_pins()
    assert len(evidence)==9
    source=Path(m.__file__).read_text()
    for word in ("requests.post(", "httpx.Client(", "httpx.HTTPTransport(",
                 "httpx.AsyncHTTPTransport(", "import socket",
                 "workflow_dispatch:", "secrets.",
                 '"real_provider_dispatch": "ALLOW"'):
        assert word not in source
    workflow=(m.ROOT/".github/workflows/task4-471-capped-sdk-native-aead-offline.yml").read_text()
    for word in ("workflow_dispatch:", "pull_request_target:",
                 "repository_dispatch:", "secrets.", "environment:",
                 "contents: write", "id-token: write"):
        assert word not in workflow
    assert "pull_request:" in workflow
    assert "contents: read" in workflow
    assert "persist-credentials: false" in workflow


def test_tampered_source_refused(tmp_path):
    for path in m.PINS:
        f=tmp_path/path
        f.parent.mkdir(parents=True,exist_ok=True)
        f.write_bytes(b"unauthorized change")
    with pytest.raises(m.Refused,match="471_PINNED_SOURCE_DRIFT"):
        m.verify_pins(tmp_path)


@pytest.mark.skipif(not NATIVE,reason="Requires exact source-pinned AgentDojo/RCC/VERITAS SDK Native proof")
def test_real_sdk_capped_wire_aead_same_local_native_run():
    report=m.run_local_native_allturn_join()
    assert report["same_run_local_capped_sdk_and_preparse_aead_join"] is True
    assert report["capped_sdk_requests"] == 8
    assert report["sdk_output_cap_each"] == 256
    assert report["encrypted_original_scripted_response_count"] == 8
    assert report["local_broker_consume_once_count"] == 8
    assert report["local_broker_restart_replay_denials"] == 8
    assert report["same_run_scripted_native_terminal_arms"] == 2
    assert report["same_run_scripted_native_scorer_invocations"] == 2
    assert len(report["hash_only_same_run_receipts"]) == 8
    assert len({(r["arm"],r["ordinal"]) for r in report["hash_only_same_run_receipts"]}) == 8
    assert all(r["requested_output_token_cap"] == 256 for r in report["hash_only_same_run_receipts"])
    assert report["independent_real_provider_response_origin_attested"] is False
    assert report["cross_runner_durable_attempt_cas_attested"] is False
    assert report["provider_billed_input_token_cap_attested"] is False
    assert report["real_provider_posts"] == 0
    assert report["external_bank_effects"] == 0
    assert report["score_status"] == "UNSCORED"
    assert report["genuine_native_utility"] is None
    assert report["real_provider_dispatch"] == "DENY"
