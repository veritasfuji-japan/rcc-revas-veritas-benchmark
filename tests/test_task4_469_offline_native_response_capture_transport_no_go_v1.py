"""Task4 #469: real SDK transport adapter, offline scripted source only."""
from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import task4_469_offline_native_response_capture_transport_no_go_v1 as m

PROOF = os.environ.get("TASK4_469_NATIVE_PROOF") == "1"


class FakeRequest:
    def __init__(self):
        self.method = "POST"
        self.url = SimpleNamespace(scheme="https",host="api.openai.com",
                                   path="/v1/chat/completions",query=b"")
        self.headers={"authorization": "Bearer task4-320-local-fake-do-not-use"}
        self.content=b'{"fixture":"no model request"}'


class FakeResponse:
    def __init__(self, request, content=b'{"fake":1}'):
        self.request=request
        self.content=content


class FakeSource:
    def __init__(self, arm):
        self.origin_arm=arm
        self.attempts=0
        self.closed=False
        self.calls=0
        self.malicious=False
    def __call__(self, request):
        self.calls+=1
        self.attempts+=1
        r=FakeResponse(request)
        if self.malicious:
            r.request=FakeRequest()
        return r


class FakeBroker:
    SYNTHETIC_TRIAL="offline-local-only"
    def __init__(self):
        self.events=[]
        self.consume_decision="LOCAL_CONSUMED_NO_SEND"
        self.attach_decision="LOCAL_CIPHERTEXT_SEALED"
    def exchange(self, sock, packet):
        self.events.append(packet["op"])
        if packet["op"]=="consume":
            return {"decision": self.consume_decision,
                    "receipt_sha":"f"*64,"live_post":False}
        return {"decision":self.attach_decision,
                "sha256":m.sha(b"encrypted"),
                "live_post":False}


class FakeVault:
    def __init__(self, root):
        self.root=root
        self.events=[]
    def commit_before_parser(self, *, arm, ordinal, request, response):
        self.events.append("encrypt-before-parser")
        (self.root/"synthetic.enc").write_bytes(b"encrypted")
        return {"envelope_filename":"synthetic.enc",
                "envelope_sha256":m.sha(b"encrypted"),
                "request_sha256":m.sha(request.content),
                "response_sha256":m.sha(response.content)}


class FakeJournal:
    def __init__(self, vault):
        self.vault=vault
        self.events=[]
        self.refuse=False
    def observe(self, *, arm, request, response):
        assert self.vault.events == ["encrypt-before-parser"]
        self.events.append("journal-after-encryption")
        if self.refuse:
            raise m.Denied("TEST_JOURNAL_REJECTED")


def fake_system(tmp_path, arm="A"):
    source=FakeSource(arm)
    broker=FakeBroker()
    vault=FakeVault(tmp_path)
    journal=FakeJournal(vault)
    driver=SimpleNamespace(OneArmMock=FakeSource)
    guard=m.CapturedLocalOnly(
        arm=arm, source=source, driver=driver,
        sockpath=tmp_path/"not-a-live-socket",root=tmp_path,
        recipient_vault=vault,journal=journal,broker=broker)
    return guard, source, broker, vault, journal


def test_transport_consumes_before_source_encrypts_before_sdk_parser(tmp_path):
    guard, source, broker, vault, journal = fake_system(tmp_path)
    req=FakeRequest()
    response=guard.handle_request(req)
    assert response.request is req
    assert source.calls == source.attempts == 1
    assert broker.events == ["consume","attach"]
    assert journal.events == ["journal-after-encryption"]
    assert len(guard.records)==1
    assert guard.records[0]["arm"]=="A"
    assert guard.records[0]["ordinal"]==0
    assert guard.failed is False


@pytest.mark.parametrize("defect",[
    "wrong_source_type", "cross_arm", "source_already_attempted",
    "closed_source", "invalid_arm",
])
def test_transport_rejects_wrong_response_origin(tmp_path, defect):
    guard,source,broker,vault,journal=fake_system(tmp_path)
    driver=SimpleNamespace(OneArmMock=FakeSource)
    arm="A"
    if defect=="wrong_source_type":
        driver=SimpleNamespace(OneArmMock=FakeRequest)
    elif defect=="cross_arm":
        arm="B"
    elif defect=="source_already_attempted":
        source.attempts=1
    elif defect=="closed_source":
        source.closed=True
    elif defect=="invalid_arm":
        arm="C"
    with pytest.raises(m.Denied):
        m.CapturedLocalOnly(arm=arm,source=source,driver=driver,
                            sockpath=tmp_path/"sock",root=tmp_path,
                            recipient_vault=vault,journal=journal,broker=broker)


@pytest.mark.parametrize("defect",[
    "method", "scheme", "host", "path", "query", "auth",
    "empty_request", "oversize", "closed_guard", "failed_guard",
])
def test_refuse_unsafe_sdk_wire_before_local_mock_called(tmp_path,defect):
    guard,source,broker,_,_=fake_system(tmp_path)
    request=FakeRequest()
    if defect=="method":request.method="GET"
    if defect=="scheme":request.url.scheme="http"
    if defect=="host":request.url.host="attacker.invalid"
    if defect=="path":request.url.path="/v1/embeddings"
    if defect=="query":request.url.query=b"inject=1"
    if defect=="auth":request.headers["authorization"]="Bearer REAL_KEY"
    if defect=="empty_request":request.content=b""
    if defect=="oversize":request.content=b"x"*(m.MAX_WIRE_BYTES+1)
    if defect=="closed_guard":guard.closed=True
    if defect=="failed_guard":guard.failed=True
    with pytest.raises(m.Denied):
        guard.handle_request(request)
    assert source.calls==0
    assert broker.events==[]


@pytest.mark.parametrize("fault",[
    "consume_denied", "wrong_response_source", "attach_denied",
    "journal_denied", "envelope_tampered",
])
def test_fail_closed_after_consumption_never_retries(tmp_path,fault):
    guard,source,broker,vault,journal=fake_system(tmp_path)
    if fault=="consume_denied":
        broker.consume_decision="DENY_ALREADY_CONSUMED"
    if fault=="wrong_response_source":
        source.malicious=True
    if fault=="attach_denied":
        broker.attach_decision="DENY_ALREADY_CONSUMED"
    if fault=="journal_denied":
        journal.refuse=True
    if fault=="envelope_tampered":
        original=vault.commit_before_parser
        def corrupt(**kwargs):
            receipt=original(**kwargs)
            (tmp_path/"synthetic.enc").write_bytes(b"tampered")
            return receipt
        vault.commit_before_parser=corrupt
    with pytest.raises((m.Denied,AssertionError)):
        guard.handle_request(FakeRequest())
    assert guard.failed is True
    calls=source.calls
    with pytest.raises(m.Denied,match="469_FAILED_OR_CLOSED"):
        guard.handle_request(FakeRequest())
    assert source.calls==calls


def test_no_source_replay_or_fifth_turn(tmp_path):
    guard,source,broker,_,_=fake_system(tmp_path)
    for _ in range(4):
        guard.handle_request(FakeRequest())
    assert len(guard.records)==4
    with pytest.raises(m.Denied):
        guard.handle_request(FakeRequest())
    assert guard.failed
    assert source.attempts==4


def test_out_of_order_source_attempts_refused(tmp_path):
    guard,source,broker,_,_=fake_system(tmp_path)
    source.attempts=2
    with pytest.raises(m.Denied,match="469_EXACT_NATIVE_ORDER"):
        guard.handle_request(FakeRequest())
    assert not broker.events and source.calls==0


@pytest.mark.parametrize("key",m.SENSITIVE)
def test_live_keys_and_approval_not_admitted(monkeypatch,key):
    monkeypatch.setenv(key,"NEVER_REAL")
    with pytest.raises(m.Denied,match="469_LIVE_SECRET"):
        m.no_live()


def test_static_source_hashes_and_export_safety():
    pins=m.verify_pins()
    assert len(pins)==8
    assert all(len(row["git_blob"])==40 for row in pins)
    source=Path(m.__file__).read_text()
    for disallowed in ("requests.post(", "httpx.HTTPTransport(",
                       "httpx.AsyncHTTPTransport(", "httpx.Client(",
                       "import socket", "workflow_dispatch:", "secrets.",
                       '"real_provider_dispatch": "ALLOW"'):
        assert disallowed not in source
    workflow=(m.ROOT/
        ".github/workflows/task4-469-native-response-capture-offline.yml").read_text()
    for disallowed in ("workflow_dispatch:", "pull_request_target:",
                       "repository_dispatch:", "secrets.", "environment:",
                       "contents: write", "id-token: write"):
        assert disallowed not in workflow
    assert "pull_request:" in workflow
    assert "contents: read" in workflow
    assert "persist-credentials: false" in workflow


@pytest.mark.skipif(not PROOF,reason="Full pinned AgentDojo/RCC/VERITAS proof required")
def test_native_sdk_eight_real_transport_interceptions_to_scorer():
    report=m.run_native_pair()
    assert report["adapter_path"]=="SDK_HTTPX_BASETRANSPORT_LOCAL_MOCK_ONLY"
    assert report["legacy_mock_call_monkeypatched"] is False
    assert report["sdk_actual_native_response_turns"]==8
    assert report["native_completed_scripted_terminals"]==2
    assert report["native_detached_scripted_scorer_calls"]==2
    assert report["broker_local_attempts_nonreplayable_after_restart"]==8
    assert len(report["response_receipts_hash_only"])==8
    assert {(x["arm"],x["ordinal"]) for x in report["response_receipts_hash_only"]}=={
        (arm,n) for arm in ("A","B") for n in range(4)}
    assert report["all_responses_encrypted_before_sdk_parser"] is True
    assert report["independent_provider_response_origin_attested"] is False
    assert report["real_provider_posts"]==0
    assert report["external_bank_effects"]==0
    assert report["score_status"]=="UNSCORED"
    assert report["genuine_native_utility"] is None
    assert report["real_provider_dispatch"]=="DENY"
