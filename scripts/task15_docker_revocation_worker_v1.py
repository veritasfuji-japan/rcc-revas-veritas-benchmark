#!/usr/bin/env python3
"""Offline-only worker; mode forged has no key mount, stolen/legitimate do.

Key possessor can compute a fresh challenge MAC; only broker's independently
owned TEST signer + durably revocable SQLite decision controls mock effect.
"""
from __future__ import annotations
import argparse
import errno
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import sys

DOMAIN=b"TASK15_WORKER_SESSION_CHALLENGE_V1\x00"
SOCKET="/ipc/broker.sock"
GRANT="/ipc/grant.json"
KEYFILE="/worker-session.key"

def must(ok,reason):
    if not ok: raise AssertionError(reason)

def canonical(v):
    return json.dumps(v,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False)

def connect(envelope,key):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
        conn.settimeout(8)
        conn.connect(SOCKET)
        stream=conn.makefile("rb")
        challenge=json.loads(stream.readline())["challenge_hex"]
        must(type(challenge) is str and len(challenge)==64,
             "BROKER_FRESH_NONCE_REQUIRED")
        digest=hashlib.sha256(canonical(envelope).encode()).digest()
        tag=hmac.new(key,DOMAIN+bytes.fromhex(challenge)+digest,
                     hashlib.sha256).hexdigest()
        conn.sendall((canonical({"envelope":envelope,"session_tag_hex":tag})+"\n").encode())
        response=json.loads(stream.readline())
        stream.close()
        return response

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--role",choices=("forged","stolen","legitimate"),required=True)
    p.add_argument("--expect",choices=("session-deny","revoked","mock-once"),required=True)
    args=p.parse_args()
    must(os.geteuid()==65534 and os.getegid()==65534,
         "EXACT_UNTRUSTED_UID_GID")
    must(not Path("/private").exists() and not Path("/var/run/docker.sock").exists(),
         "BROKER_PRIVATE_OR_HOST_CONTROL_EXPOSED")
    must(not any(os.environ.get(k) for k in (
         "OPENAI_API_KEY","OPENAI_BASE_URL","ANTHROPIC_API_KEY",
         "AWS_SECRET_ACCESS_KEY","GH_TOKEN","GITHUB_TOKEN")),
         "UNTRUSTED_ENV_HAS_REAL_CREDENTIAL")
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.settimeout(2)
        try:
            s.connect(("192.0.2.1",443))
        except OSError as err:
            must(err.errno in (errno.ENETUNREACH,errno.EHOSTUNREACH,
                errno.ENETDOWN,errno.EAFNOSUPPORT),
                "UNEXPECTED_TCP_DENIAL_NOT_NETWORK_NAMESPACE")
        else:
            raise AssertionError("WORKER_EXTERNAL_NETWORK_ENABLED")
    token=Path(KEYFILE)
    if args.role=="forged":
        must(not token.exists(),"FORGED_WORKER_WRONGLY_MOUNTED_KEY")
        key=b"\x00"*32
    else:
        must(token.is_file() and (token.stat().st_mode&0o777)==0o444,
             "STOLEN_SESSION_KEY_READONLY_MOUNT_REQUIRED")
        key=token.read_bytes()
        must(len(key)==32,"SYNTHETIC_SESSION_KEY_EXACT_32")
    envelope=json.loads(Path(GRANT).read_text())
    answer=connect(envelope,key)
    status=answer.get("status")
    expected={
       "session-deny":("DENIED","INVALID_SESSION_CHALLENGE_RESPONSE"),
       "revoked":("DENIED","TRUSTED_BROKER_REQUEST_REVOKED"),
       "mock-once":("MOCK_RECORDED",None)
    }[args.expect]
    must(status==expected[0],"EXPECTED_MOCK_OR_DENY_OUTCOME_MISMATCH")
    if expected[1]:
        must(answer.get("code")==expected[1],
             "EXACT_FAIL_CLOSED_DENIAL_CODE_REQUIRED")
    else:
        receipt=answer["receipt"]
        must(receipt["state"]=="MOCK_RECORDED" and
             receipt["real_provider_requests"]==0 and
             receipt["bank_effects"]==0,
             "TEST_ONLY_SIGNED_MOCK_RECEIPT_REQUIRED")
    print(json.dumps({"role":args.role,"expected":args.expect,
                      "status":status,"denial":answer.get("code"),
                      "uid":os.geteuid(),"gid":os.getegid(),
                      "synthetic_session_key_mounted":args.role!="forged",
                      "external_network_blocked":True,"real_provider_calls":0},
                     sort_keys=True))
if __name__=="__main__":
    main()
