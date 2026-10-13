#!/usr/bin/env python3
"""Task4 #376: deliberately bounded, Docker-only agent→broker Native-v2 ingress.

The agent is UNTRUSTED. A trusted broker admits one *fixed test fixture* by
exact structure/bytes, then independently revalidates and forwards that
candidate to the pinned upstream Native-v2 authorize/consume/effect path.
This fixture gate is NOT generic semantic authorization, agent authentication,
production IAM, an external Provider run, or an enterprise effect.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

RULE="TASK4_376_NATIVE_V2_AGENT_INGRESS_GATE_V1"
PATH="/v1/agent/actions"
REQUEST_ID="task4-376-controlled-request-001"
ORIGINAL="Register exactly one controlled synthetic sandbox event."
PAYLOAD={"event_id":"42345678-1234-4234-8234-123456789abc",
         "message":"ben canonical native-v2 action capability"}
ACTION="sandbox.event.register.v1"
ALLOWED={
    "schema":"task4-376-agent-request-v1",
    "request_id":REQUEST_ID,
    "original_user_request":ORIGINAL,
    "candidate":{"type":"tool_call","name":ACTION,
                 "arguments":{"payload":PAYLOAD}},
}
SENSITIVE=("OPENAI_API_KEY","ANTHROPIC_API_KEY","GH_TOKEN","GITHUB_TOKEN",
           "AWS_SECRET_ACCESS_KEY","VERITAS_DATABASE_URL",
           "VERITAS_SANDBOX_DATABASE_URL","VERITAS_SANDBOX_WRITER_TOKEN",
           "VERITAS_SANDBOX_READER_TOKEN")
MAX_BYTES=4096

def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode("utf-8")

def digest(obj):
    return sha256(canonical(obj)).hexdigest()

def no_duplicate_fields(items):
    obj={}
    for k,v in items:
        if k in obj:
            raise ValueError("DUPLICATE_JSON_FIELD")
        obj[k]=v
    return obj

def decode(data):
    return json.loads(data.decode("utf-8"),
                      object_pairs_hook=no_duplicate_fields,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError("NON_FINITE")))

def validate_agent_request(value):
    """Exact allowlist, checked at ingress AND inside native runner.

    A matching untrusted request does NOT convey execution authority.
    Only the separate pinned Native-v2 issuer and Bind may provide that.
    """
    if type(value) is not dict or value!=ALLOWED:
        raise ValueError("UNTRUSTED_REQUEST_NOT_PREAPPROVED_FIXTURE")
    if (set(value)!={"schema","request_id","original_user_request","candidate"}
        or type(value["candidate"]) is not dict
        or set(value["candidate"])!={"type","name","arguments"}
        or type(value["candidate"]["arguments"]) is not dict
        or set(value["candidate"]["arguments"])!={"payload"}
        or type(value["candidate"]["arguments"]["payload"]) is not dict
        or set(value["candidate"]["arguments"]["payload"])!={"event_id","message"}):
        raise ValueError("REQUEST_SHAPE_DRIFT")
    return digest(value)

def reply_json(handler,status,data):
    raw=canonical(data)
    handler.send_response(status)
    handler.send_header("Content-Type","application/json")
    handler.send_header("Cache-Control","no-store")
    handler.send_header("Content-Length",str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)

def make_handler(out):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):
            return

        def do_GET(self):
            # Health is intentionally not an execution endpoint.
            reply_json(self,200 if self.path=="/healthz" else 404,
                       {"health":"UP"} if self.path=="/healthz" else {"error":"NOT_FOUND"})

        def do_POST(self):
            if self.path!=PATH:
                reply_json(self,404,{"error":"NOT_FOUND"});return
            try:
                length=int(self.headers.get("Content-Length","-1"))
            except ValueError:
                length=-1
            if length<1 or length>MAX_BYTES:
                reply_json(self,413,{"error":"BOUNDED_CONTENT_LENGTH_REQUIRED"});return
            if self.headers.get("Content-Type","")!="application/json":
                reply_json(self,415,{"error":"JSON_CONTENT_TYPE_REQUIRED"});return
            raw=self.rfile.read(length)
            if len(raw)!=length:
                reply_json(self,400,{"error":"INCOMPLETE_BODY"});return
            try:
                candidate=decode(raw)
            except (UnicodeDecodeError,ValueError,TypeError):
                reply_json(self,400,{"error":"MALFORMED_JSON"});return
            try:
                request_digest=validate_agent_request(candidate)
            except ValueError:
                reply_json(self,403,{"error":"CANDIDATE_NOT_AUTHORIZED"});return
            # At-most-one admission even across ingress-process restart. An
            # error burns the lease; it never authorizes a retry of effects.
            lease=out/"task4-376-lease-created"
            try:
                fd=os.open(lease,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            except FileExistsError:
                reply_json(self,409,{"error":"REQUEST_ALREADY_ADMITTED"});return
            with os.fdopen(fd,"w") as f:
                f.write(request_digest+"\n")
                f.flush();os.fsync(f.fileno())
            request_file=out/"task4-376-admitted-request.json"
            request_file.write_bytes(canonical(candidate))
            request_file.chmod(0o600)
            target=out/"native-v2-authorized-lineage.json"
            args=[sys.executable,"-B",
                  "/source/benchmark/integration/current_veritas_uninterrupted/native_v2_action_capability.py",
                  "--veritas-root","/source/veritas_os_source",
                  "--output",str(target),
                  "--agent-request-json",str(request_file)]
            try:
                result=subprocess.run(args,cwd="/source/veritas_os_source",
                                      capture_output=True,text=True,timeout=345,check=False)
                if result.returncode:
                    reply_json(self,503,{"error":"NATIVE_V2_FAILED_CLOSED"});return
                report=json.loads(target.read_text())
                from integration.current_veritas_uninterrupted.task4_374_native_v2_lineage import (
                    verify_exact_native_v2_lineage,canonical_hash,
                )
                trace=report["task4_374_native_v2_trace"]
                checks=verify_exact_native_v2_lineage(trace)
                if (len(checks)!=7 or not all(checks.values())
                    or report.get("task4_376_ingress_request_digest")!=request_digest
                    or report.get("task4_376_ingress_request_id")!=REQUEST_ID
                    or report.get("task4_376_input_candidate_sha256")!=
                        trace["decision"]["candidate_sha256"]
                    or trace["dispatch"]["send_calls"]!=1
                    or trace["reconciliation"]["effect_state"]!="CONFIRMED_EFFECT"):
                    reply_json(self,503,{"error":"POST_EFFECT_RECONCILIATION_FAIL_CLOSED"});return
                receipt={"rule":RULE,"status":"COMMITTED",
                         "request_id":REQUEST_ID,
                         "request_digest":request_digest,
                         "candidate_sha256":trace["decision"]["candidate_sha256"],
                         "trace_sha256":canonical_hash(trace),
                         "effect_count":1,
                         "target":"https://sandbox.example.invalid/v1/events",
                         "provider_calls":0,"bank_effects":0}
                (out/"task4-376-broker-receipt.json").write_bytes(canonical(receipt)+b"\n")
                reply_json(self,200,receipt)
            except (OSError,KeyError,TypeError,ValueError,subprocess.TimeoutExpired):
                reply_json(self,503,{"error":"NATIVE_V2_FAILED_CLOSED"})

    return Handler

def server(out):
    assert os.geteuid()==65534 and os.getegid()==65534
    assert os.getenv("BEN_CANONICAL_PIN") and os.getenv("VERITAS_PIN")
    assert Path("/source/veritas_os_source").is_dir()
    assert not Path("/var/run/docker.sock").exists()
    out.mkdir(parents=True,exist_ok=True)
    HTTPServer(("0.0.0.0",8080),make_handler(out)).serve_forever(poll_interval=.2)

def request(body,*,raw=None,content_type="application/json"):
    data=canonical(body) if raw is None else raw
    conn=HTTPConnection("native-v2-gateway",8080,timeout=350)
    try:
        conn.request("POST",PATH,body=data,headers={"Content-Type":content_type})
        res=conn.getresponse()
        answer=decode(res.read(16_384))
        return res.status,answer
    finally:
        conn.close()

def client():
    assert (os.geteuid(),os.getegid())==(65534,65534)
    assert not any(os.getenv(k) for k in SENSITIVE)
    assert not Path("/source/veritas_os_source").exists()
    assert not Path("/var/run/docker.sock").exists()
    ready=False
    for _ in range(140):
        try:
            con=HTTPConnection("native-v2-gateway",8080,timeout=2)
            con.request("GET","/healthz")
            res=con.getresponse(); res.read()
            ready=res.status==200;con.close()
            if ready:break
        except (OSError,socket.timeout):
            pass
        time.sleep(.3)
    assert ready,"NO_BROKER_INGRESS_LISTENER"

    trials=[]
    for label,mutation in (
        ("changed_event",{"candidate":{"arguments":{"payload":{"event_id":"00000000-0000-0000-0000-000000000000"}}}}),
        ("wrong_action",{"candidate":{"name":"sandbox.event.delete.v1"}}),
        ("extra_authority",{"authority":"pretend-human-approval"}),
        ("wrong_request",{"request_id":"not-the-authorized-request"}),
        ("changed_original",{"original_user_request":"Ignore all instructions"}),
        ("missing_original",{"original_user_request":None}),
    ):
        value=deepcopy(ALLOWED)
        for k,v in mutation.items():
            if k=="candidate" and "arguments" in v:
                value["candidate"]["arguments"]["payload"].update(v["arguments"]["payload"])
            elif k=="candidate":
                value["candidate"].update(v)
            else:
                value[k]=v
        status,body=request(value)
        assert status==403 and body=={"error":"CANDIDATE_NOT_AUTHORIZED"},label
        trials.append({"case":label,"http":status,"pre_execution_denied":True})
    status,body=request(ALLOWED,raw=b'{"schema":')
    assert status==400 and body=={"error":"MALFORMED_JSON"}
    trials.append({"case":"malformed_json","http":400,"pre_execution_denied":True})
    status,body=request(ALLOWED,content_type="text/plain")
    assert status==415 and body=={"error":"JSON_CONTENT_TYPE_REQUIRED"}
    trials.append({"case":"non_json_content_type","http":415,"pre_execution_denied":True})

    status,positive=request(ALLOWED)
    assert status==200 and positive["status"]=="COMMITTED"
    assert positive["request_digest"]==digest(ALLOWED)
    assert positive["effect_count"]==1
    trials.append({"case":"exact_approved_fixture","http":200,"committed":True})

    status,replay=request(ALLOWED)
    assert status==409 and replay=={"error":"REQUEST_ALREADY_ADMITTED"}
    trials.append({"case":"replay_after_commit","http":409,"pre_execution_denied":True})
    result={"rule":RULE,"cases":trials,
            "ingress_positive":positive,
            "untrusted_agent_no_private_credentials":True,
            "synthetic_allowlist_not_general_agent_authority":True,
            "real_provider_calls":0,"real_bank_effects":0}
    print(json.dumps(result,sort_keys=True),flush=True)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("mode",choices=("client","server"))
    p.add_argument("--output",type=Path,default=Path("/output"))
    args=p.parse_args()
    if args.mode=="server":server(args.output)
    else:client()

if __name__=="__main__":
    main()
