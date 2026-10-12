#!/usr/bin/env python3
"""Task4 #371 unprivileged, network-isolated synthetic bind test caller."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
from urllib import request as http_request
from urllib.error import HTTPError

SENSITIVE=("OPENAI_API_KEY","OPENAI_BASE_URL","TASK4_OPENAI_API_KEY",
           "ANTHROPIC_API_KEY","AWS_SECRET_ACCESS_KEY","GH_TOKEN","GITHUB_TOKEN",
           "VERITAS_DATABASE_URL")

def insist(ok, reason):
    if not ok:
        raise AssertionError(reason)

def post(body):
    payload=json.dumps(body,sort_keys=True,separators=(",",":")).encode()
    req=http_request.Request("http://broker:8080/execute",data=payload,
        method="POST",headers={"Content-Type":"application/json"})
    try:
        with http_request.urlopen(req,timeout=7) as resp:
            return resp.status,json.loads(resp.read(8192))
    except HTTPError as error:
        return error.code,json.loads(error.read(8192))

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--arm",choices=("A","B"),default="A")
    p.add_argument("--expect",choices=("allow","block","replay"),required=True)
    p.add_argument("--reason",default="")
    args=p.parse_args()
    insist((os.geteuid(),os.getegid())==(65534,65534),
           "UNTRUSTED_NONROOT_AGENT_REQUIRED")
    insist(not Path("/run/task4-370-private.key").exists() and
           not Path("/trusted-bind").exists() and
           not Path("/brokerdata").exists() and
           not Path("/var/run/docker.sock").exists(),
           "UNTRUSTED_AGENT_HAS_TRUSTED_MOUNT")
    insist(not any(os.environ.get(k) for k in SENSITIVE),
           "REAL_PROVIDER_OR_HOST_CREDENTIAL_IN_AGENT")
    grants=json.loads(Path("/public/grants.json").read_text())
    insist(set(grants)=={"A","B"},"TWO_FROZEN_PUBLIC_SYNTHETIC_GRANTS_REQUIRED")
    code,response=post({"grant":grants[args.arm]})
    if args.expect=="allow":
        insist(code==200 and response.get("status")=="MOCK_EFFECT_CONFIRMED"
               and response.get("operation_id")=="task4-370-"+args.arm
               and response.get("real_provider_calls")==0
               and response.get("real_bank_effects")==0,
               "PINNED_VERITAS_BIND_ALLOW_DID_NOT_REACH_SYNTHETIC_EFFECT")
    elif args.expect=="replay":
        insist(code==409 and response.get("reason")=="ONE_USE_ALREADY_CONSUMED",
               "ELIGIBLE_REPLAY_NOT_DENIED_BY_ONE_USE_LEDGER")
    else:
        insist(code==403 and response.get("status")=="DENIED"
               and args.reason and args.reason in response.get("reason",""),
               "VERITAS_BIND_NEGATIVE_NOT_DENIED_WITH_EXACT_REASON")
    print(json.dumps({
        "arm":args.arm,"expect":args.expect,"expected_reason":args.reason,
        "http_status":code,"response":response,
        "untrusted_uid":os.geteuid(),
        "private_credential_absent":True,
        "trusted_signals_absent":True,
        "docker_socket_absent":True,
        "real_provider_calls":0,"real_bank_effects":0,
    },sort_keys=True))

if __name__=="__main__":
    main()
