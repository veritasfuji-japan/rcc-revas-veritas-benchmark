#!/usr/bin/env python3
"""Task15 offline-only, separate-process mock broker over AF_UNIX.

SO_PEERCRED is checked before decoding proposals. This process owns the
pre-pinned TEST public root, synthetic mock credential and durable SQLite.
No Provider API client, network transport, bank tool or real credential exists.
The security claim is bounded to the configured local process and peer UID;
this is NOT hardened production credential custody or operator enrollment.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from task15_mock_broker_authorization_boundary_v1 import (
    BrokerDenied, MockAuthorizationBroker, RULE as CORE_RULE,
)

RULE = "TASK15_UNIX_IPC_MOCK_BROKER_PROCESS_V1"
MAX_REQUEST = 16384

def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BrokerDenied("DUPLICATE_JSON_KEY_FORBIDDEN")
        result[key] = value
    return result

def receive(conn):
    data = bytearray()
    while True:
        part = conn.recv(min(4096, MAX_REQUEST + 1 - len(data)))
        if not part:
            raise BrokerDenied("TRUNCATED_IPC_MESSAGE")
        data.extend(part)
        if len(data) > MAX_REQUEST:
            raise BrokerDenied("OVERSIZE_IPC_MESSAGE")
        if b"\n" in part:
            break
    first, trailing = bytes(data).split(b"\n", 1)
    if trailing:
        raise BrokerDenied("MULTIPLE_IPC_MESSAGES_FORBIDDEN")
    try:
        payload = json.loads(first.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrokerDenied("INVALID_IPC_JSON") from exc
    if type(payload) is not dict:
        raise BrokerDenied("EXACT_IPC_OBJECT_REQUIRED")
    return payload

def peer_identity(conn):
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                          struct.calcsize("3i"))
    return struct.unpack("3i", raw)

def serve(args):
    socket_path = Path(args.socket)
    if socket_path.exists() or socket_path.is_symlink():
        raise BrokerDenied("FRESH_UNIX_SOCKET_REQUIRED")
    if not socket_path.parent.is_dir() or socket_path.parent.is_symlink():
        raise BrokerDenied("TRUSTED_SOCKET_DIRECTORY_REQUIRED")
    secret_path = Path(args.secret_file)
    if not secret_path.is_file() or secret_path.is_symlink():
        raise BrokerDenied("TRUSTED_SYNTHETIC_SECRET_FILE_REQUIRED")
    if secret_path.stat().st_mode & 0o077:
        raise BrokerDenied("HOST_ONLY_SECRET_PERMISSIONS_REQUIRED")
    secret = secret_path.read_bytes()
    broker = MockAuthorizationBroker(
        Path(args.ledger),
        pinned_operator_root=bytes.fromhex(args.operator_root_hex),
        synthetic_credential=secret,
        mock_fail=False,
    )
    events = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(socket_path))
        os.chmod(socket_path, 0o666)  # Intentional: identity enforced by SO_PEERCRED.
        server.listen(8)
        server.settimeout(20)
        for index in range(args.max_connections):
            conn, _ = server.accept()
            with conn:
                conn.settimeout(5)
                pid, uid, gid = peer_identity(conn)
                decision = "DENIED"
                code = ""
                try:
                    if uid != args.allowed_uid or gid != args.allowed_gid:
                        raise BrokerDenied("UNTRUSTED_UNIX_PEER_UID_GID")
                    envelope = receive(conn)
                    receipt = broker.execute(envelope)
                    response = {"status": "MOCK_RECORDED", "receipt": receipt}
                    decision = "MOCK_RECORDED"
                    code = "SIGNED_SINGLE_USE_ADMITTED"
                except (BrokerDenied, OSError, ValueError, TypeError) as exc:
                    # No raw signature, operator key, or secret returned to caller.
                    code = str(exc)
                    response = {"status": "DENIED", "code": code}
                events.append({"seq": index + 1, "peer_uid": uid, "peer_gid": gid,
                               "decision": decision, "reason": code})
                try:
                    conn.sendall((json.dumps(response, sort_keys=True) + "\n").encode())
                except OSError:
                    pass  # The durable claim cannot be rolled back or replayed.
    if socket_path.exists():
        socket_path.unlink()
    evidence = {"rule_of_one": RULE, "broker_core_rule": CORE_RULE,
                "connections": events, "broker_state": broker.status(),
                "mock_sink_calls": broker.mock_calls,
                "real_provider_calls": 0, "real_provider_spend_usd": 0,
                "bank_effects": 0}
    Path(args.output).write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
    if len(events) != 4 or [x["decision"] for x in events] != [
        "MOCK_RECORDED", "DENIED", "DENIED", "DENIED"
    ] or broker.mock_calls != 1:
        raise BrokerDenied("BROKER_EXACT_FOUR_REQUEST_TRACE_FAILED")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True)
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--secret-file", required=True)
    ap.add_argument("--operator-root-hex", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--allowed-uid", type=int, default=65534)
    ap.add_argument("--allowed-gid", type=int, default=65534)
    ap.add_argument("--max-connections", type=int, default=4)
    a = ap.parse_args()
    if a.max_connections != 4 or a.allowed_uid != 65534 or a.allowed_gid != 65534:
        raise BrokerDenied("FROZEN_OFFLINE_SERVER_PROFILE_REQUIRED")
    serve(a)

if __name__ == "__main__":
    main()
