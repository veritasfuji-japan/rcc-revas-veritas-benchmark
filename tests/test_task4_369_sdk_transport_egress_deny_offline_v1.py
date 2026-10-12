"""Task4 #369 offline-only actual SDK transport and bypass-negative tests."""
import os
import socket

import httpx
import pytest

if os.environ.get("TASK4_369_TRANSPORT_OFFLINE") != "1":
    pytest.skip("dedicated no-provider workflow only", allow_module_level=True)

from scripts import task4_369_sdk_transport_egress_deny_offline_v1 as m

def boundary(tmp_path, *, arm="A", handler=None, encoder=None):
    m.require_offline_context()
    if handler is None:
        handler = lambda req: m.fake_completion()
    return m.MockOnlyProviderBoundary(
        arm=arm, session_id="offline-369-"+arm,
        first_wire=m.capture_first_sdk_wire(arm),
        db_path=tmp_path/"state.db",
        mock=httpx.MockTransport(handler),
        encode=encoder or m.exact_pinned_encoder(),
    )

def raw_request(raw, *, url=m.ENDPOINT, method="POST", key=m.LOCAL_KEY):
    return httpx.Request(
        method, url, content=raw,
        headers={"Authorization":"Bearer "+key,"Content-Type":"application/json"})

def test_real_sdk_eight_distinct_presend_a_b_sqlite(tmp_path):
    states, gateways, hits = m.run_eight_sdk_calls(tmp_path/"ab-shared.db")
    assert hits == {"A":4,"B":4}
    assert [s["arm"] for s in states] == ["A","B"]
    assert [len(s["attempts"]) for s in states] == [4,4]
    for state in states:
        assert [x["ordinal"] for x in state["attempts"]] == [1,2,3,4]
        assert all(x["state"] == "LOCAL_OBSERVED" for x in state["attempts"])
        assert state["provider_calls"] == 0
        assert state["real_provider_post_allowed"] is False
        assert state["kernel_egress_enforcement_proven"] is False
        assert state["native_task4_scorer_called"] is False
    for gateway in gateways:
        gateway.shutdown()

def test_duplicate_actual_sdk_wire_consumed_without_extra_response(tmp_path):
    hits=[]
    gateway=boundary(tmp_path,handler=lambda req: (hits.append("fake"),m.fake_completion())[1])
    with m.forbid_python_socket_connect() as attempted:
        with m.sdk_client(gateway) as client:
            first=client.chat.completions.create(**m.completion_kwargs("A",1))
            assert first.choices[0].message.content == "LOCAL_SCRIPTED_FAKE"
            with pytest.raises(Exception):
                client.chat.completions.create(**m.completion_kwargs("A",1))
    snap=gateway.snapshot()
    assert not attempted and hits == ["fake"]
    assert [r["state"] for r in snap["attempts"]] == ["LOCAL_OBSERVED","CONSUMED_UNKNOWN"]
    assert gateway.closed and snap["mock_responses"]==1
    gateway.shutdown()

@pytest.mark.parametrize("kind",["wrong_host","wrong_method","wrong_fake_key"])
def test_invalid_routing_consumes_slot_before_any_mock(tmp_path,kind):
    seen=[]
    gateway=boundary(tmp_path,handler=lambda req: (seen.append(1),m.fake_completion())[1])
    original=m.capture_first_sdk_wire("A")
    request={
        "wrong_host":lambda:raw_request(original,url="https://127.0.0.1:9/v1/chat/completions"),
        "wrong_method":lambda:raw_request(original,method="GET"),
        "wrong_fake_key":lambda:raw_request(original,key="forged-key-not-real"),
    }[kind]()
    with m.forbid_python_socket_connect() as attempted:
        with pytest.raises(m.OfflineDenied,match="ENDPOINT_METHOD_OR_LOCAL_FAKE_KEY_DENIED"):
            gateway.handle_request(request)
        with pytest.raises(m.OfflineDenied,match="SESSION_CLOSED_NO_RETRY"):
            gateway.handle_request(request)
    assert seen == [] and attempted == []
    assert [r["state"] for r in gateway.snapshot()["attempts"]] == ["CONSUMED_UNKNOWN"]
    gateway.shutdown()

@pytest.mark.parametrize("raw",[
    b"x"*10001, b'{"model":"unknown"}',
    b'{"model":"bad","model":"duplicate"}',
])
def test_invalid_body_poisoned_no_mock_or_retry(tmp_path,raw):
    seen=[]
    gateway=boundary(tmp_path,handler=lambda req: (seen.append(1),m.fake_completion())[1])
    with m.forbid_python_socket_connect() as attempted:
        with pytest.raises(ValueError):
            gateway.handle_request(raw_request(raw))
        with pytest.raises(m.OfflineDenied,match="SESSION_CLOSED_NO_RETRY"):
            gateway.handle_request(raw_request(m.capture_first_sdk_wire("A")))
    assert seen==[] and attempted==[]
    assert [r["state"] for r in gateway.snapshot()["attempts"]] == ["CONSUMED_UNKNOWN"]
    gateway.shutdown()

def test_ambiguous_mock_exception_no_retry_or_second_reply(tmp_path):
    called=[]
    def broken(req):
        called.append("attempt")
        raise RuntimeError("LOCAL_FAKE_UPSTREAM_UNKNOWN")
    gateway=boundary(tmp_path,handler=broken)
    with m.forbid_python_socket_connect() as attempted:
        with pytest.raises(RuntimeError,match="LOCAL_FAKE_UPSTREAM_UNKNOWN"):
            gateway.handle_request(raw_request(m.capture_first_sdk_wire("A")))
        with pytest.raises(m.OfflineDenied,match="SESSION_CLOSED_NO_RETRY"):
            gateway.handle_request(raw_request(m.capture_first_sdk_wire("A")))
    assert attempted==[] and called==["attempt"]
    assert [r["state"] for r in gateway.snapshot()["attempts"]] == ["CONSUMED_UNKNOWN"]
    gateway.shutdown()

def test_response_failure_stays_unknown(tmp_path):
    gateway=boundary(tmp_path,handler=lambda req:httpx.Response(503,json={"error":"mock failure"}))
    with pytest.raises(m.OfflineDenied,match="MOCK_RESPONSE_UNKNOWN_OR_REJECTED"):
        gateway.handle_request(raw_request(m.capture_first_sdk_wire("A")))
    assert gateway.closed and gateway.snapshot()["mock_responses"]==0
    assert gateway.snapshot()["attempts"][0]["state"]=="CONSUMED_UNKNOWN"
    gateway.shutdown()

def test_real_transport_not_accepted_as_delegate(tmp_path):
    with pytest.raises(m.OfflineDenied,match="MOCK_ONLY_EXACT_ENROLLMENT"):
        m.MockOnlyProviderBoundary(
            arm="A",session_id="test",
            first_wire=m.capture_first_sdk_wire("A"),
            db_path=tmp_path/"db",
            mock=httpx.HTTPTransport(retries=0),
            encode=m.exact_pinned_encoder())

def test_direct_httpx_bypass_blocked_by_python_socket_tripwire():
    # Separate unguarded transport attempts loopback TCP; a Python test-level
    # tripwire blocks connect. NOT evidence of OS-level IAM/network isolation.
    with m.forbid_python_socket_connect() as attempted:
        with httpx.Client(transport=httpx.HTTPTransport(retries=0),
                          timeout=0.5,trust_env=False) as client:
            with pytest.raises(httpx.ConnectError):
                client.get("http://127.0.0.1:9/cannot-send")
    assert attempted == ["SOCKET_CONNECT_REJECTED"]

def test_raw_socket_bypass_blocked_by_python_tripwire():
    with m.forbid_python_socket_connect() as attempted:
        with socket.socket() as sock:
            with pytest.raises(m.EgressDenied,match="OFFLINE_PYTHON_SOCKET_CONNECT_DENIED"):
                sock.connect(("127.0.0.1",9))
    assert attempted == ["SOCKET_CONNECT_REJECTED"]

def test_nonempty_environment_key_rejected_even_on_mock(monkeypatch,tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY","test-nonreal-explicitly-rejected")
    with pytest.raises(m.OfflineDenied,match="NONEMPTY_LIVE_CREDENTIAL_OR_ENDPOINT"):
        m.capture_first_sdk_wire("A")
    with pytest.raises(m.OfflineDenied,match="NONEMPTY_LIVE_CREDENTIAL_OR_ENDPOINT"):
        m.MockOnlyProviderBoundary(
            arm="A",session_id="no-secret",
            first_wire=b"{}",db_path=tmp_path/"db",
            mock=httpx.MockTransport(lambda req:m.fake_completion()),
            encode=lambda s:[1])

def test_inner_mock_attempted_network_is_blocked_and_consumed(tmp_path):
    # Even the scripted handler's socket.connect is denied before reply.
    attempted_by_handler=[]
    def bad_handler(req):
        attempted_by_handler.append("handler")
        with socket.socket() as s:
            s.connect(("127.0.0.1",9))
    gateway=boundary(tmp_path,handler=bad_handler)
    with m.forbid_python_socket_connect() as attempted:
        with pytest.raises(m.EgressDenied):
            gateway.handle_request(raw_request(m.capture_first_sdk_wire("A")))
    assert attempted == ["SOCKET_CONNECT_REJECTED"]
    assert attempted_by_handler == ["handler"]
    assert gateway.closed and gateway.snapshot()["mock_responses"]==0
    assert gateway.snapshot()["attempts"][0]["state"]=="CONSUMED_UNKNOWN"
    gateway.shutdown()
