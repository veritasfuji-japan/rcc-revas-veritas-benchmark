#!/usr/bin/env python3
"""Offline-only mock broker with nonce/HMAC worker-session channel authentication.

SO_PEERCRED UID/GID alone cannot distinguish two same-UID Docker workers.
The broker requires a fresh challenge MAC using a synthetic per-run session
key never mounted into the same-UID impersonator's container. This does not
prove resistance to host/Docker compromise or same-container key theft.
No actual Provider sender, network client or banking effect exists.
"""
from __future__ import annotations
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from task15_mock_broker_authorization_boundary_v1 import (
    BrokerDenied, MockAuthorizationBroker, canonical, sha
)
from scripts.task15_unix_ipc_mock_broker_server_v1 import receive, peer_identity

RULE="TASK15_WORKER_SESSION_CHALLENGE_V1"
DOMAIN=b"TASK15_WORKER_SESSION_CHALLENGE_V1\x00"
MAX_CONN=6

def require(ok,reason):
    if not ok:
        raise BrokerDenied(reason)

def mac_hex(key,nonce_hex,envelope):
    return hmac.new(key,DOMAIN+bytes.fromhex(nonce_hex)+
                    bytes.fromhex(sha(envelope)),hashlib.sha256).hexdigest()

def load_secret(path,mode):
    p=Path(path)
    require(p.is_file() and not p.is_symlink(),"BROKER_PRIVATE_FILE_REQUIRED")
    require((p.stat().st_mode&0o777)==mode,"BROKER_PRIVATE_FILE_MODE_DRIFT")
    return p.read_bytes()

def serve(args):
    require(args.max_connections==MAX_CONN and
            args.allowed_uid==65534 and args.allowed_gid==65534,
            "FROZEN_SESSION_BROKER_PROFILE_REQUIRED")
    socket_path=Path(args.socket)
    require(socket_path.parent.is_dir() and
            not socket_path.parent.is_symlink() and
            not socket_path.exists() and not socket_path.is_symlink(),
            "NEW_SOCKET_TRUSTED_SHARED_DIR_REQUIRED")
    require(Path(args.secret_file).parent==Path(args.session_key_file).parent,
            "SESSION_KEY_AND_MOCK_SECRET_MUST_BE_PRIVATE")
    secret=load_secret(args.secret_file,0o600)
    session_key=load_secret(args.session_key_file,0o444)
    require(len(session_key)==32,"EXACT_SYNTHETIC_SESSION_KEY_BYTES_REQUIRED")
    broker=MockAuthorizationBroker(
        args.ledger,pinned_operator_root=bytes.fromhex(args.operator_root_hex),
        synthetic_credential=secret
    )
    events=[]
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        os.chmod(socket_path,0o666) # OS peer check + per-worker MAC, not filesystem ACL
        listener.listen(8)
        listener.settimeout(25)
        for i in range(MAX_CONN):
            connection,_=listener.accept()
            with connection:
                connection.settimeout(6)
                pid,uid,gid=peer_identity(connection)
                decision="DENIED"
                reason=""
                try:
                    require((uid,gid)==(args.allowed_uid,args.allowed_gid),
                            "UNTRUSTED_UNIX_PEER_UID_GID")
                    nonce=secrets.token_hex(32)
                    connection.sendall((json.dumps({"challenge_hex":nonce})+"\n").encode())
                    message=receive(connection)
                    require(set(message)=={"envelope","session_tag_hex"},
                            "SESSION_ENVELOPE_AND_MAC_REQUIRED")
                    envelope,tag=message["envelope"],message["session_tag_hex"]
                    require(type(envelope) is dict and
                            type(tag) is str and len(tag)==64 and
                            all(ch in "0123456789abcdef" for ch in tag),
                            "SESSION_AUTHORIZATION_FORMAT_REQUIRED")
                    expected=mac_hex(session_key,nonce,envelope)
                    require(hmac.compare_digest(expected,tag),
                            "INVALID_SESSION_CHALLENGE_RESPONSE")
                    receipt=broker.execute(envelope)
                    response={"status":"MOCK_RECORDED","receipt":receipt}
                    reason="FRESH_WORKER_SESSION_AND_SIGNED_GRANT_ACCEPTED"
                    decision="MOCK_RECORDED"
                except (BrokerDenied,ValueError,TypeError,KeyError,OSError) as err:
                    reason=str(err)
                    response={"status":"DENIED","code":reason}
                events.append({"seq":i+1,"peer_uid":uid,"peer_gid":gid,
                               "decision":decision,"reason":reason})
                try:
                    connection.sendall((json.dumps(response,sort_keys=True)+"\n").encode())
                except OSError:
                    pass
    if socket_path.exists():
        socket_path.unlink()
    state=broker.status()
    require([x["decision"] for x in events]==[
        "DENIED","DENIED","MOCK_RECORDED","DENIED","DENIED","DENIED"
    ],"FROZEN_SESSION_TRACE_DRIFT")
    require([events[j]["reason"] for j in (0,1)]==[
        "INVALID_SESSION_CHALLENGE_RESPONSE"
    ]*2,"SAME_UID_IMPERSONATOR_AND_NONCE_REPLAY_NOT_REJECTED")
    require(events[3]["reason"]=="ONE_SHOT_REQUEST_ALREADY_CONSUMED_OR_UNKNOWN"
            and events[4]["reason"]=="FROZEN_MODEL_SOURCE_OR_TARGET_DRIFT"
            and events[5]["reason"]=="UNTRUSTED_UNIX_PEER_UID_GID"
            and broker.mock_calls==1 and state["claims"]==[1],
            "REPLAY_TARGET_IDENTITY_OR_ONE_USE_DRIFT")
    output={"rule_of_one":RULE,"connections":events,"broker_state":state,
            "mock_sink_calls":broker.mock_calls,"real_provider_calls":0,
            "real_provider_spend_usd":0,"bank_effects":0}
    Path(args.output).write_text(json.dumps(output,sort_keys=True,indent=2)+"\n")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--socket",required=True)
    ap.add_argument("--ledger",required=True)
    ap.add_argument("--secret-file",required=True)
    ap.add_argument("--session-key-file",required=True)
    ap.add_argument("--operator-root-hex",required=True)
    ap.add_argument("--output",required=True)
    ap.add_argument("--allowed-uid",type=int,default=65534)
    ap.add_argument("--allowed-gid",type=int,default=65534)
    ap.add_argument("--max-connections",type=int,default=6)
    serve(ap.parse_args())

if __name__=="__main__":
    main()
