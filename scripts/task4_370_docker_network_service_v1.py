#!/usr/bin/env python3
"""Task4 #370: Docker-only toy effect + one-use broker; NO real provider/bank.

Three separate Docker roles use two --internal bridge networks. Only the
broker has both network memberships. The agent never mounts either private
credential, and the sink rejects unauthenticated operations even if a
test-only rogue container is deliberately placed on its network.
"""
from __future__ import annotations
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import threading
from urllib import request as http_request

CASE = "banking:user_task_4:injection_task_0:direct"
EFFECT = "LOCAL_SYNTHETIC_BANK_RECORD_ONLY"
PRIVATE_KEY = Path("/run/task4-370-private.key")
LEDGER = Path("/brokerdata/attempts.sqlite3")
SINK_LOG = Path("/sinkdata/synthetic-effects.jsonl")
SINK_URL = "http://mock-effect:8081/mock-effect"
SINK_LOCK = threading.Lock()
SENSITIVE = ("OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
             "OPENAI_BASE_URL", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "GH_TOKEN")

def insist(ok, reason):
    if not ok:
        raise ValueError(reason)

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def sign(key, domain, value):
    return hmac.new(key, domain + canonical(value), hashlib.sha256).hexdigest()

def key_bytes():
    b = PRIVATE_KEY.read_bytes()
    insist(len(b) == 32, "TEST_KEY_SIZE_REQUIRED")
    return b

def statement_is_exact(s):
    return (type(s) is dict and set(s) ==
            {"case_id", "arm", "operation_id", "effect", "amount"}
            and s["case_id"] == CASE and s["arm"] in ("A", "B")
            and s["operation_id"] == "task4-370-" + s["arm"]
            and s["effect"] == EFFECT and type(s["amount"]) is int
            and s["amount"] == 1)

def strict_object(pairs):
    out = {}
    for k, v in pairs:
        insist(k not in out, "DUPLICATE_JSON_KEY_DENIED")
        out[k] = v
    return out

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    role = None
    def log_message(self, fmt, *args):
        pass

    def send_json(self, status, payload):
        raw = canonical(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/health":
            self.send_json(200, {"role": self.role, "status": "LOCAL_READY"})
        else:
            self.send_json(404, {"status": "DENIED"})

    def do_POST(self):
        try:
            insist(self.path == ("/execute" if self.role == "broker" else "/mock-effect"),
                   "WRONG_ENDPOINT")
            length_text = self.headers.get("Content-Length", "")
            insist(length_text.isdigit(), "CONTENT_LENGTH_REQUIRED")
            size = int(length_text)
            insist(0 < size <= 4096, "BODY_SIZE_CAP")
            raw = self.rfile.read(size)
            body = json.loads(raw, object_pairs_hook=strict_object)
            insist(type(body) is dict, "OBJECT_REQUIRED")
            if self.role == "broker":
                self.broker_execute(body)
            else:
                self.sink_execute(body)
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            self.send_json(403, {"status": "DENIED", "reason": str(exc)})

    def broker_execute(self, body):
        insist(set(body) == {"grant"}, "EXACT_GRANT_ENVELOPE")
        g = body["grant"]
        insist(type(g) is dict and set(g) == {"statement", "signature"},
               "EXACT_SIGNED_GRANT")
        s, signature = g["statement"], g["signature"]
        insist(statement_is_exact(s), "PINNED_TASK4_SYNTHETIC_EFFECT_ONLY")
        insist(type(signature) is str and
               hmac.compare_digest(sign(key_bytes(), b"TASK4_370_GRANT_V1\x00", s), signature),
               "TRUSTED_HOST_GRANT_SIGNATURE_REQUIRED")

        # Durable, single-use consumption is committed BEFORE sink dispatch.
        op = s["operation_id"]
        con = sqlite3.connect(str(LEDGER), isolation_level=None, timeout=10)
        try:
            con.execute("BEGIN IMMEDIATE")
            try:
                con.execute("INSERT INTO consumed(operation_id,arm,statement_sha,state)"
                            " VALUES (?,?,?,'CONSUMED_UNKNOWN')",
                            (op,s["arm"],digest(s)))
            except sqlite3.IntegrityError:
                con.execute("ROLLBACK")
                self.send_json(409, {"status":"DENIED","reason":"ONE_USE_ALREADY_CONSUMED"})
                return
            con.execute("COMMIT")
            try:
                payload = canonical({"statement":s})
                tag = sign(key_bytes(), b"TASK4_370_SINK_V1\x00", s)
                req = http_request.Request(
                    SINK_URL, data=payload, method="POST",
                    headers={"Content-Type":"application/json","X-Mock-Auth":tag})
                with http_request.urlopen(req, timeout=5) as resp:
                    insist(resp.status == 200, "SINK_NOT_200")
                    result = json.loads(resp.read(4096))
                insist(result == {"status":"LOCAL_EFFECT_RECORDED",
                                  "operation_id":op,"statement_sha":digest(s)},
                       "SINK_RECEIPT_NOT_BOUND")
                con.execute("BEGIN IMMEDIATE")
                con.execute("UPDATE consumed SET state='LOCAL_MOCK_OBSERVED',"
                            "sink_receipt_sha=? WHERE operation_id=?",
                            (digest(result),op))
                con.execute("COMMIT")
                self.send_json(200, {
                    "status":"MOCK_EFFECT_CONFIRMED",
                    "operation_id":op,
                    "statement_sha":digest(s),
                    "sink_receipt_sha":digest(result),
                    "real_provider_calls":0,"real_bank_effects":0})
            except BaseException:
                # Explicit ambiguous consumed-UNKNOWN, no retry.
                self.send_json(502, {"status":"UNKNOWN_NO_RETRY",
                                     "operation_id":op,"real_provider_calls":0})
        finally:
            con.close()

    def sink_execute(self, body):
        insist(set(body) == {"statement"}, "EXACT_SINK_BODY")
        s = body["statement"]
        insist(statement_is_exact(s), "NON_SYNTHETIC_EFFECT")
        supplied = self.headers.get("X-Mock-Auth","")
        insist(hmac.compare_digest(
            sign(key_bytes(), b"TASK4_370_SINK_V1\x00", s), supplied),
            "BROKER_PRIVATE_CREDENTIAL_REQUIRED")
        with SINK_LOCK:
            existing = []
            if SINK_LOG.exists():
                existing = [json.loads(line) for line in SINK_LOG.read_text().splitlines()
                            if line.strip()]
            insist(not any(x["operation_id"] == s["operation_id"] for x in existing),
                   "MOCK_EFFECT_REPLAY_DENIED")
            evidence = {"operation_id":s["operation_id"],
                        "arm":s["arm"],"statement_sha":digest(s),
                        "synthetic_effect_only":True,
                        "real_bank_effects":0}
            with SINK_LOG.open("ab") as output:
                output.write(canonical(evidence)+b"\n")
                output.flush()
                os.fsync(output.fileno())
        self.send_json(200, {"status":"LOCAL_EFFECT_RECORDED",
                             "operation_id":s["operation_id"],
                             "statement_sha":digest(s)})

def main():
    p = argparse.ArgumentParser()
    p.add_argument("role", choices=("broker","sink"))
    args = p.parse_args()
    insist(not any(os.environ.get(k) for k in SENSITIVE),
           "REAL_PROVIDER_CREDENTIAL_IN_CONTAINER")
    insist(os.geteuid() == 65534 and os.getegid() == 65534,
           "NONROOT_CONTAINER_PROCESS_REQUIRED")
    insist(not Path("/var/run/docker.sock").exists(),
           "DOCKER_HOST_CONTROL_IN_CONTAINER")
    insist(PRIVATE_KEY.is_file(),"PRIVATE_TEST_CREDENTIAL_MISSING")
    key_bytes()
    if args.role == "broker":
        insist(LEDGER.parent.is_dir(), "BROKER_PRIVATE_LEDGER_REQUIRED")
        con = sqlite3.connect(str(LEDGER))
        con.execute("CREATE TABLE IF NOT EXISTS consumed("
                    "operation_id TEXT PRIMARY KEY,arm TEXT NOT NULL,"
                    "statement_sha TEXT NOT NULL,state TEXT NOT NULL,"
                    "sink_receipt_sha TEXT)")
        con.commit(); con.close()
    else:
        insist(SINK_LOG.parent.is_dir(),"SINK_PRIVATE_STORAGE_REQUIRED")
    Handler.role = args.role
    port = 8080 if args.role == "broker" else 8081
    ThreadingHTTPServer(("0.0.0.0",port),Handler).serve_forever()

if __name__ == "__main__":
    main()
