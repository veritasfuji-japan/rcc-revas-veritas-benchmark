#!/usr/bin/env python3
"""One-shot offline mock session worker; optionally impersonates the same UID.

Both containers use Linux UID/GID 65534. The impersonator receives the same
public grant/IPC mount but NOT the synthetic session key mount.
"""
from __future__ import annotations
import argparse
import copy
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
SESSION="/worker-session.key"

def require(ok,reason):
    if not ok: raise AssertionError(reason)

def canonical(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False)

def digest(x):
    return hashlib.sha256(canonical(x).encode()).digest()

def ask(envelope,key,wrong_nonce=False):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(6)
        s.connect(SOCKET)
        stream=s.makefile("rb")
        challenge=json.loads(stream.readline())
        nonce=challenge["challenge_hex"]
        require(type(nonce) is str and len(nonce)==64,"FRESH_BROKER_NONCE_REQUIRED")
        signed_nonce="00"*32 if wrong_nonce else nonce
        tag=hmac.new(key,DOMAIN+bytes.fromhex(signed_nonce)+digest(envelope),
                     hashlib.sha256).hexdigest()
        s.sendall((canonical({"envelope":envelope,"session_tag_hex":tag})+"\n").encode())
        response=json.loads(stream.readline())
        stream.close()
        return response

def no_external_tcp():
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
        sock.settimeout(3)
        try:
            sock.connect(("192.0.2.1",443))
        except OSError as exc:
            require(exc.errno in (errno.ENETUNREACH,errno.EHOSTUNREACH,
                     errno.ENETDOWN,errno.EAFNOSUPPORT),
                    "UNEXPECTED_NETWORK_ERROR_NOT_ISOLATION")
        else:
            raise AssertionError("DOCKER_WORKER_EXTERNAL_NETWORK_ACCESS")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--mode",choices=("legitimate","impersonator"),required=True)
    args=ap.parse_args()
    require(os.geteuid()==65534 and os.getegid()==65534,
            "WORKER_AND_IMPERSONATOR_MUST_HAVE_IDENTICAL_OS_ID")
    require(not Path("/private").exists() and
            not Path("/var/run/docker.sock").exists(),
            "BROKER_OR_DOCKER_PRIVATE_MOUNT_DISCLOSED")
    require(not any(os.environ.get(x) for x in ("OPENAI_API_KEY",
           "ANTHROPIC_API_KEY","OPENAI_BASE_URL","AWS_SECRET_ACCESS_KEY",
           "GH_TOKEN","GITHUB_TOKEN")),"REAL_PROVIDER_KEY_IN_WORKER")
    no_external_tcp()
    envelope=json.loads(Path(GRANT).read_text())
    if args.mode=="impersonator":
        require(not Path(SESSION).exists(),
                "SAME_UID_ATTACKER_WRONGLY_HAS_WORKER_SESSION_KEY")
        answer=ask(envelope,b"\x00"*32)
        require(answer=={"status":"DENIED",
                "code":"INVALID_SESSION_CHALLENGE_RESPONSE"},
                "SAME_UID_NO_SECRET_IMPERSONATOR_NOT_REJECTED")
        report={"role":"same_uid_different_container_no_session_key",
                "uid":os.geteuid(),"gid":os.getegid(),
                "session_mount_absent":True,
                "same_uid_request_denied":True,"provider_calls":0}
    else:
        p=Path(SESSION)
        require(p.is_file() and p.stat().st_mode&0o777==0o444,
                "READONLY_SYNTHETIC_SESSION_CREDENTIAL_REQUIRED")
        key=p.read_bytes()
        require(len(key)==32,"SESSION_KEY_256_BIT_REQUIRED")
        wrong_challenge=ask(envelope,key,wrong_nonce=True)
        require(wrong_challenge=={"status":"DENIED",
                "code":"INVALID_SESSION_CHALLENGE_RESPONSE"},
                "STALE_NONCE_RESPONSE_MUST_BE_REJECTED")
        good=ask(envelope,key)
        require(good.get("status")=="MOCK_RECORDED" and
                good["receipt"]["state"]=="MOCK_RECORDED" and
                good["receipt"]["real_provider_requests"]==0,
                "VALID_FRESH_CHALLENGE_AND_SIGNED_GRANT_REQUIRED")
        replay=ask(envelope,key)
        require(replay=={"status":"DENIED",
                "code":"ONE_SHOT_REQUEST_ALREADY_CONSUMED_OR_UNKNOWN"},
                "REUSED_SIGNED_APPROVAL_MUST_STAY_CONSUMED")
        tampered=copy.deepcopy(envelope)
        tampered["request"]["target"]["host"]="attacker.invalid"
        drift=ask(tampered,key)
        require(drift=={"status":"DENIED",
                "code":"FROZEN_MODEL_SOURCE_OR_TARGET_DRIFT"},
                "TAMPERED_TARGET_WITH_VALID_SESSION_MUST_FAIL")
        report={"role":"legitimate_keyed_worker","uid":os.geteuid(),
                "gid":os.getegid(),"session_key_observed":True,
                "wrong_nonce_denied":True,"signed_one_shot_passed":True,
                "durable_replay_denied":True,"target_mutation_denied":True,
                "request_sha256":good["receipt"]["request_sha256"],
                "response_sha256":good["receipt"]["response_sha256"],
                "provider_calls":0}
    print(json.dumps(report,sort_keys=True))

if __name__=="__main__":
    main()
