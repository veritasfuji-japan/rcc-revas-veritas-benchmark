#!/usr/bin/env python3
"""Executable negative probes ONLY inside an OS-isolated, credential-free container.

Never pass real credentials. Never contact a real Provider. IPs are RFC 5737/3849
documentation destinations, used solely to test lack of a network route.
"""
from __future__ import annotations

import errno
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import urllib.error
import urllib.request

RULE = "TASK15_WORKER_CREDENTIAL_EGRESS_ISOLATION_V1"
IPV4 = "192.0.2.1"  # TEST-NET-1, NOT a Provider endpoint
IPV6 = "2001:db8::1"  # RFC 3849 documentation destination
BLOCKED = {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN,
           errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL}
TESTS = []

def record(name, check):
    try:
        check()
        TESTS.append({"name": name, "result": "PASS"})
    except BaseException as exc:
        TESTS.append({"name": name, "result": "FAIL",
                      "reason": type(exc).__name__ + ": " + str(exc)[:250]})

def must(condition, why):
    if not condition:
        raise AssertionError(why)

def blocked_connection(fn):
    try:
        fn()
    except (OSError, urllib.error.URLError) as exc:
        underlying = exc.reason if isinstance(exc, urllib.error.URLError) else exc
        must(isinstance(underlying, OSError) and underlying.errno in BLOCKED,
             "OUTBOUND_REFUSAL_WAS_NOT_A_NETWORK_ROUTE_DENIAL: " + str(exc))
        return
    raise AssertionError("UNAUTHORIZED_NETWORK_CONNECTION_SUCCEEDED")

def tcp_socket(family, ip):
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        s.connect((ip, 443))

def no_provider_key():
    forbidden = ("OPENAI_API_KEY", "OPENAI_BASE_URL", "ANTHROPIC_API_KEY",
                 "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "GH_TOKEN")
    must(not any(os.environ.get(k) for k in forbidden),
         "CREDENTIAL_OR_CUSTOM_ENDPOINT_IN_CHILD_ENVIRONMENT")

def no_host_sentinel():
    target = os.environ.get("EXPECTED_HOST_SECRET_SHA256", "")
    must(len(target) == 64, "SYNTHETIC_HOST_SECRET_DIGEST_MISSING")
    for k, v in os.environ.items():
        must(hashlib.sha256(v.encode()).hexdigest() != target,
             "SYNTHETIC_HOST_SECRET_LEAKED_IN_WORKER_ENV")
    for path in ("/proc/self/environ", "/proc/1/environ"):
        try:
            data = Path(path).read_bytes()
        except PermissionError:
            continue
        for field in data.split(b"\x00"):
            if b"=" in field:
                must(hashlib.sha256(field.split(b"=", 1)[1]).hexdigest() != target,
                     "SYNTHETIC_HOST_SECRET_LEAKED_IN_PROC")

def no_docker_socket_or_secret_mount():
    for p in ("/var/run/docker.sock", "/run/docker.sock",
              "/run/secrets/OPENAI_API_KEY", "/root/.aws/credentials"):
        try:
            available = Path(p).exists()
        except PermissionError:
            # Non-root cannot even traverse the owner-only location: no
            # credential access. Other unexpected errors still fail closed.
            available = False
        must(not available, "UNTRUSTED_WORKER_HAS_PRIVILEGED_MOUNT:" + p)

def non_root():
    must(os.geteuid() == 65534 and os.getegid() == 65534,
         "WORKER_MUST_BE_UNPRIVILEGED_USER")

def proc_value(label):
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith(label + ":"):
            return line.split(":", 1)[1].strip()
    raise AssertionError("MISSING_KERNEL_STATUS:" + label)

def no_caps():
    must(int(proc_value("CapEff"), 16) == 0, "EFFECTIVE_CAPABILITIES_NOT_ZERO")

def no_new_privs():
    must(proc_value("NoNewPrivs") == "1", "PRIVILEGE_ESCALATION_NOT_DISABLED")

def no_root_write():
    try:
        with open("/task15-unauthorized-root-write", "wb") as f:
            f.write(b"not allowed")
    except OSError as exc:
        must(exc.errno in (errno.EROFS, errno.EACCES, errno.EPERM),
             "UNEXPECTED_ROOT_WRITE_ERROR")
        return
    raise AssertionError("UNTRUSTED_WORKER_CAN_WRITE_ROOT")

def no_default_route():
    route = Path("/proc/net/route").read_text().splitlines()
    must(not any(line.split()[1] == "00000000" for line in route[1:]
                 if len(line.split()) > 1), "DEFAULT_ROUTE_EXISTS")

def urllib_no_egress():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    blocked_connection(lambda: opener.open("http://" + IPV4 + ":443/", timeout=2))

def http_no_egress():
    def request():
        conn = http.client.HTTPConnection(IPV4, 443, timeout=2)
        try:
            conn.request("GET", "/")
        finally:
            conn.close()
    blocked_connection(request)

def subprocess_no_egress():
    source = ("import errno,socket,sys\n"
              "s=socket.socket();s.settimeout(2)\n"
              "try:\n"
              " s.connect(('192.0.2.1',443));sys.exit(41)\n"
              "except OSError as e:\n"
              " sys.exit(0 if e.errno==errno.ENETUNREACH else 42)\n")
    p = subprocess.run([sys.executable, "-B", "-c", source],
                       capture_output=True, text=True, timeout=8)
    must(p.returncode == 0, "SUBPROCESS_EGRESS_NOT_ENETUNREACH:" + str(p.returncode))

def raw_socket_denied():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except OSError as exc:
        must(exc.errno in (errno.EPERM, errno.EACCES),
             "RAW_SOCKET_REFUSAL_NOT_PERMISSION_DENIED")
        return
    s.close()
    raise AssertionError("UNTRUSTED_WORKER_CREATED_RAW_SOCKET")

def main():
    checks = [
        ("no_provider_key", no_provider_key),
        ("no_host_sentinel", no_host_sentinel),
        ("no_docker_socket_or_secret_mount", no_docker_socket_or_secret_mount),
        ("non_root", non_root),
        ("no_caps", no_caps),
        ("no_new_privs", no_new_privs),
        ("no_root_write", no_root_write),
        ("no_default_route", no_default_route),
        ("ipv4_raw_tcp_denied", lambda: blocked_connection(lambda: tcp_socket(socket.AF_INET, IPV4))),
        ("ipv6_raw_tcp_denied", lambda: blocked_connection(lambda: tcp_socket(socket.AF_INET6, IPV6))),
        ("stdlib_http_client_denied", http_no_egress),
        ("urllib_no_proxy_denied", urllib_no_egress),
        ("subprocess_direct_tcp_denied", subprocess_no_egress),
        ("raw_socket_capability_denied", raw_socket_denied),
    ]
    for name, fn in checks:
        record(name, fn)
    report = {"rule_of_one": RULE, "kind": "UNTRUSTED_WORKER_OBSERVATION",
              "real_provider_calls": 0, "real_provider_spend_usd": 0,
              "cases": TESTS}
    print(json.dumps(report, sort_keys=True))
    return 0 if all(r["result"] == "PASS" for r in TESTS) else 1

if __name__ == "__main__":
    sys.exit(main())
