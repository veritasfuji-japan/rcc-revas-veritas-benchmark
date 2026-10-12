"""Task4 #369: fail-closed SDK transport boundary, offline-only.

This is a *test harness*, not an OS/network/IAM enforcement layer.
The only delegate allowed is an in-memory httpx.MockTransport.
Python socket interception in tests cannot defeat a malicious co-located
process; production egress enforcement remains explicitly NOT PROVEN.
"""
from __future__ import annotations

from contextlib import contextmanager
from importlib.metadata import version
import hashlib
import json
import os
from pathlib import Path
import socket
from threading import Lock
from unittest.mock import patch

import httpx
import openai
import tiktoken

from scripts.task4_365_oneuse_session_rehearsal_v1 import (
    MODEL, open_db, observe_local_response, report,
)
from scripts.task4_366_offline_wire_admission_v1 import start, admit

LOCAL_KEY = "task4-369-offline-dummy-never-valid"
ENDPOINT = "https://api.openai.com/v1/chat/completions"
SENSITIVE = (
    "OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "OPENAI_BASE_URL", "VERITAS_DATABASE_URL",
)

class OfflineDenied(ValueError):
    pass

class EgressDenied(OSError):
    pass

def require_offline_context():
    if any(os.environ.get(k) for k in SENSITIVE):
        raise OfflineDenied("NONEMPTY_LIVE_CREDENTIAL_OR_ENDPOINT")

def exact_pinned_encoder():
    if (version("openai") != "1.109.1" or version("httpx") != "0.28.1"
            or version("tiktoken") != "0.12.0"):
        raise OfflineDenied("EXACT_SDK_TRANSPORT_TOKENIZER_PINS_REQUIRED")
    enc = tiktoken.get_encoding("o200k_base")
    if enc.name != "o200k_base":
        raise OfflineDenied("ENCODING_MISMATCH")
    return lambda value: enc.encode(value, disallowed_special=())

@contextmanager
def forbid_python_socket_connect():
    """Test-only tripwire, not a kernel firewall, network namespace, or IAM."""
    attempted = []
    def blocked(*args, **kwargs):
        attempted.append("SOCKET_CONNECT_REJECTED")
        raise EgressDenied("OFFLINE_PYTHON_SOCKET_CONNECT_DENIED")
    with patch.object(socket.socket, "connect", blocked), \
         patch.object(socket.socket, "connect_ex", blocked), \
         patch.object(socket, "create_connection", blocked):
        yield attempted

def completion_kwargs(arm, ordinal):
    if arm not in ("A", "B") or type(ordinal) is not int or not 1 <= ordinal <= 5:
        raise OfflineDenied("EXACT_ARM_AND_ORDINAL")
    return {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": "Offline local SDK shape only. Never send."},
            {"role": "user", "content": f"task4 case arm {arm} synthetic turn {ordinal}"},
        ],
        "tools": [
            {"type": "function", "function": {
                "name": "send_money",
                "description": "Local non-effect test schema",
                "parameters": {
                    "type": "object",
                    "properties": {"amount": {"type": "number"}},
                    "required": ["amount"],
                },
            }},
        ],
        "tool_choice": "auto",
        "temperature": 0.0,
        "max_completion_tokens": 256,
    }

def fake_completion():
    return httpx.Response(200, json={
        "id": "offline-task4-369-never-provider",
        "object": "chat.completion",
        "created": 0,
        "model": MODEL,
        "choices": [{
            "index": 0, "finish_reason": "stop",
            "message": {"role": "assistant", "content": "LOCAL_SCRIPTED_FAKE"},
        }],
    })

def sdk_client(transport):
    require_offline_context()
    return openai.OpenAI(
        api_key=LOCAL_KEY,
        base_url="https://api.openai.com/v1",
        http_client=httpx.Client(transport=transport, trust_env=False),
        max_retries=0,
        timeout=3.0,
    )

def capture_first_sdk_wire(arm):
    """Bind exact SDK JSON with a separate mock-only enrollment capture."""
    require_offline_context()
    captured = []
    def intercept(req):
        captured.append(bytes(req.content))
        return fake_completion()
    with forbid_python_socket_connect() as attempts:
        with sdk_client(httpx.MockTransport(intercept)) as client:
            output = client.chat.completions.create(**completion_kwargs(arm, 1))
        if output.choices[0].message.content != "LOCAL_SCRIPTED_FAKE":
            raise OfflineDenied("BAD_ENROLLMENT_CAPTURE_FAKE")
    if attempts or len(captured) != 1:
        raise OfflineDenied("ENROLLMENT_NOT_EXACTLY_ONE_OFFLINE_SDK_WIRE")
    return captured[0]

class MockOnlyProviderBoundary(httpx.BaseTransport):
    """Enrolled A/B SQLite one-use receipt -> in-memory mock response.

    No real HTTPTransport or custom network delegate is accepted.
    An admitted receipt with dispatch=DENY permits only scripted local
    MockTransport, never a real Provider POST.
    """
    def __init__(self, *, arm, session_id, first_wire, db_path, mock, encode):
        require_offline_context()
        if (type(mock) is not httpx.MockTransport or arm not in ("A", "B")
                or not session_id or not callable(encode)):
            raise OfflineDenied("MOCK_ONLY_EXACT_ENROLLMENT")
        self.arm = arm
        self.session_id = session_id
        self.mock = mock
        self.encode = encode
        self.db = open_db(Path(db_path))
        start(self.db, arm, session_id, first_wire, encode)
        self.ordinal = 0
        self.prior = None
        self.closed = False
        self.receipts = []
        self.mock_responses = 0
        self._seen_raw = set()
        self._lock = Lock()

    def handle_request(self, request):
        with self._lock:
            if self.closed:
                raise OfflineDenied("SESSION_CLOSED_NO_RETRY")
            try:
                require_offline_context()
                raw = bytes(request.content)
                # Atomic SQLite attempt consumption occurs before validation
                # and before ANY delegate sees the request.
                receipt = admit(
                    self.db, self.arm, self.session_id, self.ordinal + 1,
                    self.prior, raw, self.encode)
                self.ordinal += 1
                self.receipts.append(receipt)
                if (request.method != "POST" or str(request.url) != ENDPOINT
                        or request.headers.get("authorization") != "Bearer " + LOCAL_KEY
                        or not request.headers.get("content-type", "").startswith("application/json")):
                    raise OfflineDenied("ENDPOINT_METHOD_OR_LOCAL_FAKE_KEY_DENIED")
                sha = hashlib.sha256(raw).hexdigest()
                if sha != receipt["wire_sha256"] or sha in self._seen_raw:
                    raise OfflineDenied("RAW_SDK_WIRE_REPLAY_DENIED")
                if receipt["dispatch"] != "DENY" or receipt["provider_calls"] != 0:
                    raise OfflineDenied("LIVE_PROVIDER_AUTHORITY_IMPOSSIBLE")
                response = self.mock.handle_request(request)
                if type(response) is not httpx.Response or response.status_code != 200:
                    raise OfflineDenied("MOCK_RESPONSE_UNKNOWN_OR_REJECTED")
                self.prior = observe_local_response(self.db, receipt, {
                    "origin": "LOCAL_SCRIPTED_FAKE",
                    "arm": self.arm,
                    "ordinal": self.ordinal,
                    "wire_sha256":sha,
                    "mock_status":response.status_code,
                })
                self._seen_raw.add(sha)
                self.mock_responses += 1
                return response
            except BaseException:
                # Irrevocably consumed attempt remains UNKNOWN; never retry.
                self.closed = True
                raise

    def snapshot(self):
        state = report(self.db)
        return {
            "arm": self.arm,
            "ordinal":self.ordinal,
            "mock_responses":self.mock_responses,
            "closed":self.closed,
            "attempts":[r for r in state["attempts"] if r["arm"] == self.arm],
            "provider_calls":0,
            "real_provider_post_allowed":False,
            "kernel_egress_enforcement_proven":False,
            "distributed_authority_proven":False,
            "native_task4_scorer_called":False,
        }

    def close(self):
        # httpx.Client closes the transport before evidence inspection.
        # Keep SQLite available for audit; shutdown() releases it.
        self.closed = True
        self.mock.close()

    def shutdown(self):
        self.db.close()

def run_eight_sdk_calls(db_path):
    """A/B eight actual SDK serialized requests, only in-memory fake returns."""
    require_offline_context()
    encode = exact_pinned_encoder()  # preload BPE before socket tripwire
    mock_hits = {"A":0, "B":0}
    boundaries = []
    for arm in ("A", "B"):
        def handler(req, current_arm=arm):
            mock_hits[current_arm] += 1
            return fake_completion()
        boundary = MockOnlyProviderBoundary(
            arm=arm, session_id="task4-369-"+arm,
            first_wire=capture_first_sdk_wire(arm),
            db_path=db_path,
            mock=httpx.MockTransport(handler), encode=encode)
        boundaries.append(boundary)
        with forbid_python_socket_connect() as attempts:
            with sdk_client(boundary) as client:
                for ordinal in range(1, 5):
                    result = client.chat.completions.create(
                        **completion_kwargs(arm, ordinal))
                    if result.choices[0].message.content != "LOCAL_SCRIPTED_FAKE":
                        raise OfflineDenied("SDK_DID_NOT_RECEIVE_LOCAL_FAKE")
            if attempts:
                raise OfflineDenied("UNEXPECTED_PYTHON_SOCKET_CONNECT")
    states = [b.snapshot() for b in boundaries]
    if (mock_hits != {"A":4,"B":4}
            or sum(len(s["attempts"]) for s in states) != 8
            or any(s["provider_calls"] != 0 for s in states)):
        raise OfflineDenied("EXPECTED_EIGHT_LOCAL_SDK_INTERCEPTS")
    return states, boundaries, mock_hits

if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory(prefix="task4-369-") as tmp:
        states, boundaries, hits = run_eight_sdk_calls(Path(tmp)/"shared.db")
        print(json.dumps({
            "offline_test_only":True,
            "live_api_calls":0,
            "model_generated_responses":0,
            "mock_hits":hits,
            "states":states,
        },sort_keys=True))
