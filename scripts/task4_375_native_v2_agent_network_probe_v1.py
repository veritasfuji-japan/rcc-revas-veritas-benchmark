#!/usr/bin/env python3
"""Untrusted container probes for Task4 #375, no patching of socket functions.

front: network-isolated agent cannot address real Native-v2 TLS sandbox.
rogue-back: a *host-created* backend-attached client proves TLS target returns
401 without independently scoped writer credentials. Both are test-only.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import socket
import ssl

SENSITIVE=("VERITAS_DATABASE_URL","VERITAS_SANDBOX_DATABASE_URL",
           "VERITAS_SANDBOX_WRITER_TOKEN","VERITAS_SANDBOX_READER_TOKEN",
           "OPENAI_API_KEY","ANTHROPIC_API_KEY","OPENAI_BASE_URL",
           "GITHUB_TOKEN","GH_TOKEN","AWS_SECRET_ACCESS_KEY")
TARGET="sandbox.example.invalid"
def insist(cond,reason):
    if cond is not True:raise AssertionError("T375_"+reason)
def check_process():
    insist((os.geteuid(),os.getegid())==(65534,65534),"UNTRUSTED_UID_REQUIRED")
    insist(not Path("/var/run/docker.sock").exists(),"DOCKER_SOCKET_UNTRUSTED")
    insist(not any(os.getenv(name) for name in SENSITIVE),"UNTRUSTED_SECRETS_LEAKED")
    insist(not Path("/source/veritas_os_source").exists(),"VERITAS_HOST_SOURCE_EXPOSED")
    insist(not Path("/tls/server.key").exists(),"SINK_TLS_PRIVATE_KEY_EXPOSED")
    insist(not Path("/output").exists(),"BROKER_OUTPUT_EXPOSED")

def denied_tcp(ip,port):
    try:
        with socket.create_connection((ip,port),timeout=2):
            raise AssertionError("T375_DIRECT_TCP_ALLOWED")
    except OSError as e:
        return {"blocked":True,"errno":e.errno,"error_type":type(e).__name__}

def front(target_ip):
    try:
        socket.getaddrinfo(TARGET,443,type=socket.SOCK_STREAM)
    except socket.gaierror:
        dns_denied=True
    else:
        raise AssertionError("T375_BACKEND_DNS_VISIBLE_FROM_FRONT")
    gateway=socket.getaddrinfo("native-v2-gateway",1,type=socket.SOCK_STREAM)
    insist(bool(gateway),"FRONT_GATEWAY_DNS_NOT_VISIBLE")
    direct=denied_tcp(target_ip,443)
    external=denied_tcp("192.0.2.1",443)
    return {
        "case":"front-only-agent","sink_dns_hidden":dns_denied,
        "real_sink_ip_tcp_refused":direct["blocked"],
        "external_testnet_tcp_refused":external["blocked"],
        "gateway_front_dns_visible":True,
        "tcp_error_type":direct["error_type"],
        "untrusted_agent_no_private_credentials":True,
        "no_real_provider_calls":True,
    }

def back_rogue():
    ctx=ssl.create_default_context(cafile="/tls/ca.crt")
    ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    raw=b'{"event_id":"42345678-1234-4234-8234-123456789abc","message":"untrusted direct bypass denied"}'
    req=(b"POST /v1/events HTTP/1.1\r\n"
         +b"Host: sandbox.example.invalid\r\n"
         +b"Content-Type: application/json\r\n"
         +b"Idempotency-Key: t375-rogue-denied\r\n"
         +b"Connection: close\r\n"
         +b"Content-Length: "+str(len(raw)).encode()+b"\r\n\r\n"+raw)
    with socket.create_connection((TARGET,443),timeout=6) as sock:
        with ctx.wrap_socket(sock,server_hostname=TARGET) as s:
            insist(s.version() in ("TLSv1.2","TLSv1.3"),
                   "ROGUE_BACK_TLS_VERSION")
            s.settimeout(6)
            s.sendall(req)
            first=b""
            while b"\r\n" not in first and len(first)<4096:
                chunk=s.recv(1024)
                insist(bool(chunk),"ROGUE_TLS_RESPONSE_EMPTY")
                first+=chunk
            first_line=first.split(b"\r\n",1)[0]
    insist(first_line.startswith(b"HTTP/1.1 401 "),
           "REAL_SANDBOX_UNAUTHENTICATED_WRITE_NOT_DENIED")
    return {
        "case":"host-attached-backend-rogue",
        "actual_upstream_sandbox_service_tls_verified":True,
        "unauthenticated_direct_write_http_status":401,
        "bearer_token_unavailable":True,
        "no_real_provider_calls":True,
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("mode",choices=("front","rogue-back"))
    p.add_argument("--sink-ip",default="")
    v=p.parse_args()
    check_process()
    result=front(v.sink_ip) if v.mode=="front" else back_rogue()
    print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
