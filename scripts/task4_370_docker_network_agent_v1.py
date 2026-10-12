#!/usr/bin/env python3
"""Unprivileged Docker worker: prove direct network denial vs broker path."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import socket
from urllib import request as http_request
from urllib.error import HTTPError

FRONT = "http://broker:8080/execute"
SINK = "http://mock-effect:8081/mock-effect"
SENSITIVE = ("OPENAI_API_KEY","OPENAI_BASE_URL","TASK4_OPENAI_API_KEY",
             "ANTHROPIC_API_KEY","AWS_SECRET_ACCESS_KEY","GH_TOKEN","GITHUB_TOKEN")

def insist(ok, reason):
    if not ok: raise AssertionError(reason)

def post(url,body):
    raw = json.dumps(body,sort_keys=True,separators=(",",":")).encode()
    req = http_request.Request(url,raw,
        headers={"Content-Type":"application/json"},method="POST")
    try:
        with http_request.urlopen(req,timeout=4) as resp:
            return resp.status,json.loads(resp.read(4096))
    except HTTPError as error:
        return error.code,json.loads(error.read(4096))

def main():
    p=argparse.ArgumentParser()
    p.add_argument("mode",choices=("valid-a","valid-b","replay-a",
        "tamper-a","empty","direct-ip","outside","rogue-back"))
    p.add_argument("--effect-ip",default="")
    a=p.parse_args()
    insist((os.geteuid(),os.getegid())==(65534,65534),"UNTRUSTED_UID_GID")
    insist(not Path("/run/task4-370-private.key").exists(),
           "UNTRUSTED_WORKER_GOT_PRIVATE_CREDENTIAL")
    insist(not Path("/var/run/docker.sock").exists(),
           "WORKER_GOT_DOCKER_CONTROL_SOCKET")
    insist(not any(os.environ.get(k) for k in SENSITIVE),
           "WORKER_GOT_LIVE_OR_HOST_CREDENTIALS")
    grants=json.loads(Path("/public/grants.json").read_text())
    evidence={"mode":a.mode,"agent_uid":os.geteuid(),
              "private_credential_present":False,
              "docker_socket_present":False,
              "real_provider_calls":0,"real_bank_effects":0}
    if a.mode in ("valid-a","valid-b","replay-a","tamper-a","empty"):
        arm="B" if a.mode=="valid-b" else "A"
        grant=grants[arm]
        if a.mode=="tamper-a":
            grant={"statement":{**grant["statement"],"amount":999},
                   "signature":grant["signature"]}
        body={"grant":grant} if a.mode!="empty" else {}
        code,resp=post(FRONT,body)
        if a.mode in ("valid-a","valid-b"):
            insist(code==200 and resp.get("status")=="MOCK_EFFECT_CONFIRMED"
                   and resp.get("operation_id")=="task4-370-"+arm
                   and resp.get("real_provider_calls")==0
                   and resp.get("real_bank_effects")==0,
                   "AUTHORIZED_MOCK_BROKER_EFFECT_NOT_CONFIRMED")
            evidence["decision"]="MOCK_EFFECT_CONFIRMED"
        elif a.mode=="replay-a":
            insist(code==409 and resp.get("reason")=="ONE_USE_ALREADY_CONSUMED",
                   "BROKER_REPLAY_NOT_DURABLY_REFUSED")
            evidence["decision"]="REPLAY_DENIED"
        else:
            insist(code==403 and resp.get("status")=="DENIED",
                   "FORGED_OR_UNSIGNED_GRANT_NOT_DENIED")
            evidence["decision"]="SIGNATURE_OR_GRANT_DENIED"
        evidence["http_status"]=code
        evidence["response"]=resp
    elif a.mode=="direct-ip":
        insist(a.effect_ip and a.effect_ip.count(".")==3,
               "REAL_EFFECT_CONTAINER_IP_REQUIRED")
        try:
            socket.getaddrinfo("mock-effect",8081)
        except socket.gaierror:
            evidence["mock_effect_alias_not_resolvable_on_agent_network"]=True
        else:
            raise AssertionError("EFFECT_DNS_LEAK_ON_FRONT_NETWORK")
        try:
            with socket.create_connection((a.effect_ip,8081),timeout=1.5):
                raise AssertionError("DIRECT_NETWORK_ROUTE_TO_EFFECT_PRESENT")
        except OSError as e:
            evidence["direct_sink_tcp_blocked"]=True
            evidence["connect_error_type"]=type(e).__name__
            evidence["connect_errno"]=e.errno
        evidence["decision"]="DIRECT_NETWORK_DENIED"
    elif a.mode=="outside":
        try:
            with socket.create_connection(("192.0.2.1",443),timeout=1.5):
                raise AssertionError("AGENT_EXTERNAL_EGRESS_PRESENT")
        except OSError as e:
            evidence["external_tcp_blocked"]=True
            evidence["connect_error_type"]=type(e).__name__
            evidence["connect_errno"]=e.errno
        evidence["decision"]="EXTERNAL_NETWORK_DENIED"
    else:
        code,resp=post(SINK,{"statement":grants["A"]["statement"]})
        insist(code==403 and resp.get("reason")==
               "BROKER_PRIVATE_CREDENTIAL_REQUIRED",
               "ROGUE_BACK_NETWORK_WITHOUT_PRIVATE_SECRET_NOT_DENIED")
        evidence["http_status"]=code
        evidence["decision"]="BACK_NETWORK_ROGUE_CREDENTIAL_DENIED"
    print(json.dumps(evidence,sort_keys=True))

if __name__=="__main__":
    main()
