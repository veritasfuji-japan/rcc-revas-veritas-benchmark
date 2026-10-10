#!/usr/bin/env python3
"""Untrusted container worker: standard-library-only AF_UNIX mock request probe.

Runs with --network=none as uid=65534. Receives the signed TEST grant only.
Never receives broker's operator-root custody, synthetic credential or DB.
"""
from __future__ import annotations

import copy
import errno
import json
import os
from pathlib import Path
import socket
import sys

SOCKET = "/ipc/broker.sock"
GRANT = "/ipc/grant.json"

def must(ok, reason):
    if not ok:
        raise AssertionError(reason)

def ask(envelope):
    raw = (json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(6)
        s.connect(SOCKET)
        s.sendall(raw)
        answer = bytearray()
        while b"\n" not in answer:
            part = s.recv(4096)
            must(part and len(answer) + len(part) <= 32768,
                 "BOUNDED_BROKER_RECEIPT_REQUIRED")
            answer.extend(part)
        return json.loads(bytes(answer).split(b"\n",1)[0])

def no_external_network():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        try:
            s.connect(("192.0.2.1", 443))
        except OSError as exc:
            must(exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH,
                                errno.ENETDOWN, errno.EAFNOSUPPORT),
                 "NETWORK_REFUSAL_WAS_NOT_NAMESPACE_EGRESS_DENIAL")
        else:
            raise AssertionError("UNTRUSTED_WORKER_HAS_EXTERNAL_NETWORK")

def main():
    must(os.geteuid() == 65534 and os.getegid() == 65534,
         "UNTRUSTED_WORKER_WRONG_OS_ID")
    for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY",
                "OPENAI_BASE_URL", "GH_TOKEN", "GITHUB_TOKEN"):
        must(not os.environ.get(key), "PROVIDER_OR_PLATFORM_KEY_IN_WORKER")
    must(not Path("/private").exists(), "BROKER_PRIVATE_DIR_MOUNTED")
    must(not Path("/var/run/docker.sock").exists(), "HOST_DOCKER_SOCKET_EXPOSED")
    must(Path(GRANT).is_file() and Path(SOCKET).exists(),
         "ONLY_EXACT_IPC_AND_TEST_GRANT_REQUIRED")
    no_external_network()
    envelope = json.loads(Path(GRANT).read_text())
    positive = ask(envelope)
    must(positive.get("status") == "MOCK_RECORDED" and
         positive["receipt"]["state"] == "MOCK_RECORDED" and
         positive["receipt"]["real_provider_requests"] == 0 and
         positive["receipt"]["bank_effects"] == 0,
         "SIGNED_MOCK_IPC_MUST_COMMIT_EXACTLY_ONCE")
    replay = ask(envelope)
    must(replay == {"status":"DENIED",
                    "code":"ONE_SHOT_REQUEST_ALREADY_CONSUMED_OR_UNKNOWN"},
         "UNTRUSTED_IPC_REPLAY_NOT_DENIED")
    altered = copy.deepcopy(envelope)
    altered["request"]["target"]["host"] = "attacker.invalid"
    substitution = ask(altered)
    must(substitution.get("status") == "DENIED" and
         substitution.get("code") == "FROZEN_MODEL_SOURCE_OR_TARGET_DRIFT",
         "IPC_TARGET_SUBSTITUTION_NOT_DENIED")
    evidence = {
        "rule_of_one":"TASK15_UNIX_IPC_MOCK_BROKER_PROCESS_V1",
        "worker_uid":os.geteuid(),"worker_gid":os.getegid(),
        "external_tcp_testnet_blocked":True,
        "broker_private_directory_absent":True,
        "provider_credentials_absent":True,
        "signed_mock_response":True,"replay_denied":True,
        "changed_target_denied":True,
        "positive_request_sha256":positive["receipt"]["request_sha256"],
        "positive_response_sha256":positive["receipt"]["response_sha256"],
        "real_provider_requests":0,"real_provider_spend_usd":0,
        "bank_effects":0
    }
    print(json.dumps(evidence, sort_keys=True))

if __name__ == "__main__":
    try:
        main()
    except BaseException as exc:
        print("ISOLATED_WORKER_IPC_FAIL_CLOSED:"+repr(exc),file=sys.stderr)
        raise
