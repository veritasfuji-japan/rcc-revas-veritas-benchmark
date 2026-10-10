#!/usr/bin/env python3
"""Offline-only isolated Broker + trusted host-side revocation CLI.

No Provider network transport. Trusted administrative revocation is invoked by
docker exec from the host, never exposed as a worker AF_UNIX request.
The same on-disk SQLite BEGIN IMMEDIATE lock serializes revoke and claim.
A stolen session key plus copied TEST grant may claim first: NONCLAIM.
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
from task15_mock_broker_authorization_boundary_v1 import BrokerDenied, exact_request, sha
from task15_stolen_session_revocation_fence_v1 import RevocableMockAuthorizationBroker,REVOKED
from scripts.task15_session_challenge_broker_server_v1 import mac_hex,load_secret
from scripts.task15_unix_ipc_mock_broker_server_v1 import receive,peer_identity

RULE="TASK15_DOCKER_REVOCATION_BOUNDARY_V1"
SYNTHETIC_ONLY=True

def must(ok,reason):
    if not ok:
        raise BrokerDenied(reason)

def create_broker(args):
    secret=load_secret(args.secret_file,0o600)
    return RevocableMockAuthorizationBroker(
        args.ledger,pinned_operator_root=bytes.fromhex(args.operator_root_hex),
        synthetic_credential=secret
    )

def revoke_from_trusted_exec(args):
    # Deliberately NOT accessible through the worker's socket protocol.
    broker=create_broker(args)
    decision=broker.revoke(sha(exact_request()))
    must(broker.revocation_status()["revoked_count"]==1,
         "TRUSTED_SIDE_REVOCATION_DURABILITY_REQUIRED")
    print(json.dumps({"rule":RULE,"admin_process_uid":os.geteuid(),
                      "trusted_side_revocation":decision,
                      "live_provider_requests":0},sort_keys=True))

def serve(args):
    must(args.scenario in ("revocation_first","claim_first"),
         "FROZEN_TWO_SCENARIOS_ONLY")
    must(args.connections==3 and args.allowed_uid==65534 and
         args.allowed_gid==65534,"FROZEN_PEER_AND_CONNECTION_PROFILE")
    socket_path=Path(args.socket)
    must(socket_path.parent.is_dir() and
         not socket_path.parent.is_symlink() and
         not socket_path.exists() and not socket_path.is_symlink(),
         "FRESH_TRUSTED_UNIX_SOCKET_REQUIRED")
    token=load_secret(args.session_key_file,0o444)
    must(len(token)==32,"EXACT_TEST_SESSION_KEY_SIZE")
    broker=create_broker(args)
    events=[]
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(str(socket_path))
        os.chmod(socket_path,0o666) # Challenge and signed grant required.
        server.listen(8)
        server.settimeout(25)
        for i in range(args.connections):
            conn,_=server.accept()
            with conn:
                conn.settimeout(6)
                pid,uid,gid=peer_identity(conn)
                verdict="DENIED";reason=""
                try:
                    must((uid,gid)==(args.allowed_uid,args.allowed_gid),
                         "UNTRUSTED_UNIX_PEER_UID_GID")
                    nonce=secrets.token_hex(32)
                    conn.sendall((json.dumps({"challenge_hex":nonce})+"\n").encode())
                    msg=receive(conn)
                    must(set(msg)=={"envelope","session_tag_hex"},
                         "ONLY_SIGNED_WORKER_PROPOSAL_ALLOWED")
                    envelope,tag=msg["envelope"],msg["session_tag_hex"]
                    must(type(envelope) is dict and type(tag) is str and
                         len(tag)==64 and all(c in "0123456789abcdef" for c in tag),
                         "EXACT_SESSION_TAG_ENCODING_REQUIRED")
                    must(hmac.compare_digest(mac_hex(token,nonce,envelope),tag),
                         "INVALID_SESSION_CHALLENGE_RESPONSE")
                    receipt=broker.execute(envelope)
                    response={"status":"MOCK_RECORDED","receipt":receipt}
                    verdict="MOCK_RECORDED";reason="SIGNED_TEST_SINGLE_USE_MOCK_ADMITTED"
                except (BrokerDenied,ValueError,TypeError,KeyError,OSError) as exc:
                    reason=str(exc)
                    response={"status":"DENIED","code":reason}
                events.append({"seq":i+1,"peer_uid":uid,"peer_gid":gid,
                               "decision":verdict,"reason":reason})
                try:
                    conn.sendall((json.dumps(response,sort_keys=True)+"\n").encode())
                except OSError:
                    pass
    socket_path.unlink()
    expected={
      "revocation_first":[
         ("DENIED","INVALID_SESSION_CHALLENGE_RESPONSE"),
         ("DENIED",REVOKED),
         ("DENIED","UNTRUSTED_UNIX_PEER_UID_GID")
      ],
      "claim_first":[
         ("MOCK_RECORDED","SIGNED_TEST_SINGLE_USE_MOCK_ADMITTED"),
         ("DENIED",REVOKED),
         ("DENIED",REVOKED)
      ]
    }[args.scenario]
    must([(e["decision"],e["reason"]) for e in events]==expected,
         "SIX_SCENARIO_EVENT_TRACE_MISMATCH")
    actual=broker.mock_calls
    must(actual==(0 if args.scenario=="revocation_first" else 1),
         "REVOCATION_CLAIM_ORDER_EFFECT_BOUNDARY_FAILED")
    must(broker.revocation_status()["revoked_count"]==1,
         "TRUSTED_REVOCATION_MISSING_AFTER_SCENARIO")
    state=broker.status()
    Path(args.output).write_text(json.dumps({
        "rule_of_one":RULE,"scenario":args.scenario,
        "connections":events,"mock_sink_calls":actual,
        "broker_state":state,"revocation":broker.revocation_status(),
        "real_provider_calls":0,"real_provider_spend_usd":0,"bank_effects":0
    },sort_keys=True,indent=2)+"\n")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--mode",choices=("serve","trusted-revoke"),required=True)
    ap.add_argument("--socket")
    ap.add_argument("--ledger",required=True)
    ap.add_argument("--secret-file",required=True)
    ap.add_argument("--session-key-file")
    ap.add_argument("--operator-root-hex",required=True)
    ap.add_argument("--output")
    ap.add_argument("--scenario",choices=("revocation_first","claim_first"))
    ap.add_argument("--connections",type=int,default=3)
    ap.add_argument("--allowed-uid",type=int,default=65534)
    ap.add_argument("--allowed-gid",type=int,default=65534)
    args=ap.parse_args()
    must(not os.environ.get("OPENAI_API_KEY") and
         not os.environ.get("OPENAI_BASE_URL") and
         not os.environ.get("ANTHROPIC_API_KEY"),
         "REAL_PROVIDER_CONFIGURATION_FORBIDDEN")
    if args.mode=="serve":
        must(args.socket and args.output and args.session_key_file and args.scenario,
             "SERVER_ARGS_REQUIRED")
        serve(args)
    else:
        must(not args.socket and not args.output and not args.scenario and
             not args.session_key_file,"TRUSTED_EXEC_ONLY_NO_WORKER_SOCKET")
        revoke_from_trusted_exec(args)

if __name__=="__main__":
    main()
