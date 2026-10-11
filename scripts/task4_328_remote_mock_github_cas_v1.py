#!/usr/bin/env python3
"""#328 OFFLINE GitHub Create-Ref compatible remote-CAS mock, NOT real GitHub.

A separately hosted localhost HTTP CAS SERVER owns the only database.
Independent client OS processes use HTTP and NEVER access its DB directly.
Create-only ref uniqueness is checked transactionally on server. 201/422
model the intended GitHub REST behavior but do NOT establish GitHub's actual
production behavior, security, tamper-proof retention or cross-Actions-runs
persistence. No GITHUB_TOKEN, network to api.github.com, Provider API, or
repository ref changes are performed.
"""
from __future__ import annotations
import argparse
import hashlib
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import sys
import threading

RULE="TASK4_328_LOCALHOST_REMOTE_GITREF_CREATE_ONLY_CAS_EMULATION_V1"
PARENT_MAIN="c02d0ea4a198bfdc95ab1916f95a5036ebad299e"
REPOSITORY="veritasfuji-japan/rcc-revas-veritas-benchmark"
SOURCE_CASE="banking:user_task_4:injection_task_0:direct"
MODEL="gpt-4.1-mini-2025-04-14"
NATIVE_PRESTATE="8b653f253d3b2b033ad2baebc938bb66cb09719be8b488a470e7e82d25abbe14"
NATIVE_ATTACK="0d5011fb8b275e313c83da127698f19a77095d44e82a81b4d5804046c3cb61a9"
TRIAL_ID="task4-328-offline-single-case-ab"
API_PATH=f"/repos/{REPOSITORY}/git/refs"
FAKE_HEADER="Bearer task4-328-public-no-privileges"
HEX40=re.compile(r"[a-f0-9]{40}\Z")
SENSITIVE=("GITHUB_TOKEN","GH_TOKEN","OPENAI_API_KEY","TASK4_OPENAI_API_KEY",
           "ANTHROPIC_API_KEY","OPENAI_BASE_URL","VERITAS_DATABASE_URL")

class Denied(ValueError):pass
def need(x,msg):
    if not x:raise Denied(msg)
def raw_json(o):
    return json.dumps(o,sort_keys=True,ensure_ascii=False,
                      separators=(",",":"),allow_nan=False).encode("utf-8")
def sha(o):
    return hashlib.sha256(raw_json(o)).hexdigest()
def unique_json_keys(pairs):
    result={}
    for k,v in pairs:
        need(k not in result,"DUPLICATE_JSON_KEY")
        result[k]=v
    return result
def frozen_scope():
    return {
       "trial_id":TRIAL_ID,"source_case":SOURCE_CASE,
       "model":MODEL,"base_merged_main":PARENT_MAIN,
       "injected_native_prestate_sha":NATIVE_PRESTATE,
       "injected_native_attack_sha":NATIVE_ATTACK,
       "arms":["A","B"],
       "source":"LOCAL_TEST_ONLY_NEVER_REAL_PROVIDER"
    }
REF=f"refs/heads/offline-test-ledger/task4-328-{sha(frozen_scope())[:32]}"
BODY={"ref":REF,"sha":PARENT_MAIN}
DDL="""CREATE TABLE IF NOT EXISTS refs (
 ref TEXT PRIMARY KEY NOT NULL,
 target_sha TEXT NOT NULL,
 body_sha TEXT NOT NULL,
 claim_status TEXT NOT NULL CHECK (claim_status = 'CONSUMED_FOREVER_IN_MOCK')
)"""
def forbid_real_keys():
    need(not any(os.environ.get(k) for k in SENSITIVE),
         "REAL_GITHUB_TOKEN_OR_PROVIDER_KEY_DENIED")

def init_backend(db_path):
    p=Path(db_path)
    need(p.name=="remote-emulator.sqlite3" and p.parent.exists(),
         "ONLY_ISOLATED_TEST_SERVER_DB")
    conn=sqlite3.connect(p,timeout=10,isolation_level=None)
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute(DDL)
    return conn

def backend_rows(db_path):
    db=init_backend(db_path)
    try:
        x=db.execute("SELECT ref,target_sha,body_sha,claim_status FROM refs ORDER BY ref").fetchall()
        rows=[{"ref":a,"target_sha":b,"body_sha":c,"claim_status":d} for a,b,c,d in x]
        for row in rows:
            need(row=={
              "ref":REF,"target_sha":PARENT_MAIN,
              "body_sha":sha(BODY),"claim_status":"CONSUMED_FOREVER_IN_MOCK"
            },"REMOTE_EMULATOR_DB_ROW_CHANGED")
        need(len(rows)<=1,"UNIQUE_REMOTE_EMULATOR_REF_REQUIRED")
        return rows
    finally:db.close()

class RemoteMockHandler(BaseHTTPRequestHandler):
    server_version="Task4-328-TestOnly/1"
    def log_message(self,*args):pass
    def respond(self,status,payload):
        body=raw_json(payload)
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body)))
        self.send_header("Cache-Control","no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            need(self.path==API_PATH,"EXACT_FAKE_GITHUB_POST_PATH_REQUIRED")
            need(self.headers.get("Authorization")==FAKE_HEADER,
                 "ONLY_UNPRIVILEGED_FAKE_TOKEN_ACCEPTED")
            need(self.headers.get("Content-Type")=="application/json",
                 "JSON_CONTENT_REQUIRED")
            length=self.headers.get("Content-Length","")
            need(length.isdigit() and 0<int(length)<=2048,
                 "BOUNDED_REQUEST_REQUIRED")
            buf=self.rfile.read(int(length))
            body=json.loads(buf.decode("utf-8"),object_pairs_hook=unique_json_keys)
            need(type(body) is dict and body==BODY and set(body)=={"ref","sha"} and
                 HEX40.fullmatch(body["sha"]) is not None,
                 "EXACT_FROZEN_TEST_ONLY_REF_AND_TARGET_REQUIRED")
            db=init_backend(self.server.db_path)
            try:
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute(
                     "INSERT INTO refs(ref,target_sha,body_sha,claim_status) VALUES(?,?,?,?)",
                     (REF,PARENT_MAIN,sha(BODY),"CONSUMED_FOREVER_IN_MOCK"))
                    db.execute("COMMIT")
                    won=True
                except sqlite3.IntegrityError:
                    db.execute("ROLLBACK")
                    won=False
            finally:db.close()
            if won and self.headers.get("X-OffLine-Simulate-Lost-Response")=="1":
                # Synthetic lost reply AFTER atomic commit, with remote
                # server still holding the one-shot row. Never redeliver it.
                try:self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:pass
                self.connection.close()
                return
            if won:
                self.respond(201,{"ref":REF,"object":{"sha":PARENT_MAIN},
                                  "test_only_mock_ref_created":True,
                                  "real_provider_post_allowed":False})
            else:
                self.respond(422,{"message":"Reference already exists (mock)",
                                  "real_provider_post_allowed":False})
        except (Denied,UnicodeError,ValueError,json.JSONDecodeError) as exc:
            self.respond(400,{"message":"MOCK_BAD_REQUEST","real_provider_post_allowed":False})
        except sqlite3.Error:
            self.respond(503,{"message":"MOCK_BACKEND_UNKNOWN","real_provider_post_allowed":False})

    def do_GET(self):
        self.respond(405,{"message":"CREATE_ONLY_NOT_A_READ_APPROVAL",
                          "real_provider_post_allowed":False})

def serve(db_path,port_path):
    forbid_real_keys()
    p=Path(db_path).resolve()
    ready=Path(port_path).resolve()
    need(p.name=="remote-emulator.sqlite3" and
         ready.name=="port.txt" and ready.parent==p.parent,
         "EMULATOR_FILES_MUST_SHARE_PRIVATE_TEST_DIRECTORY")
    tmp=init_backend(p);tmp.close()
    server=ThreadingHTTPServer(("127.0.0.1",0),RemoteMockHandler)
    server.db_path=str(p)
    ready.write_text(str(server.server_address[1]))
    try:server.serve_forever(poll_interval=0.1)
    finally:server.server_close()

def try_once(*,port,worker,drop_reply=False):
    """One and ONLY one outbound TCP request to 127.0.0.1 mock server.

    Any lost response / exception / unexpected status is locally UNKNOWN,
    never retry. Even a 201 only confirms test-only mock CAS, NOT real live
    Provider, credentials, billing, or GitHub ref protection.
    """
    forbid_real_keys()
    need(type(port) is int and 1<=port<=65535 and
         type(worker) is str and re.fullmatch(r"worker-[0-9]{1,3}",worker),
         "LOCALHOST_PORT_AND_BOUNDED_WORKER_REQUIRED")
    request=raw_json(BODY)
    h={"Authorization":FAKE_HEADER,"Content-Type":"application/json",
       "X-OffLine-Worker":worker}
    if drop_reply:h["X-OffLine-Simulate-Lost-Response"]="1"
    conn=HTTPConnection("127.0.0.1",port,timeout=5)
    try:
        conn.request("POST",API_PATH,body=request,headers=h)
        res=conn.getresponse()
        code=res.status
        content=res.read(2048)
        response=json.loads(content)
        need(type(response) is dict and
             response.get("real_provider_post_allowed") is False,
             "RESPONSE_MUST_ALWAYS_DENY_PROVIDER")
        if code==201:
            need(response.get("test_only_mock_ref_created") is True
                 and response.get("ref")==REF
                 and response.get("object",{}).get("sha")==PARENT_MAIN,
                 "WRONG_REMOTE_MOCK_WINNER_RECEIPT")
            state="MOCK_CREATE_ONLY_WON_NOT_REAL_AUTHORITY"
        elif code==422:
            state="MOCK_DUPLICATE_PERMANENT_DENY"
        else:
            state="UNKNOWN_OR_MOCK_REJECTED_NO_RETRY"
        return {"worker":worker,"http_status":code,"state":state,
                "ref":REF,"real_provider_post_allowed":False,
                "remote_git_hub_ref_was_created":False,
                "server_kind":"ISOLATED_LOCAL_GITHUB_REST_EMULATOR"}
    except (OSError,TimeoutError,ValueError,Denied,UnicodeError):
        return {"worker":worker,"http_status":None,
                "state":"UNKNOWN_OR_MOCK_REJECTED_NO_RETRY",
                "ref":REF,"real_provider_post_allowed":False,
                "remote_git_hub_ref_was_created":False,
                "server_kind":"ISOLATED_LOCAL_GITHUB_REST_EMULATOR"}
    finally:conn.close()

def main():
    p=argparse.ArgumentParser()
    sub=p.add_subparsers(dest="action",required=True)
    a=sub.add_parser("server")
    a.add_argument("--db",required=True);a.add_argument("--port-file",required=True)
    b=sub.add_parser("worker")
    b.add_argument("--port",type=int,required=True)
    b.add_argument("--worker",required=True)
    b.add_argument("--drop-reply",action="store_true")
    x=p.parse_args()
    if x.action=="server":
        serve(x.db,x.port_file)
        return 0
    response=try_once(port=x.port,worker=x.worker,drop_reply=x.drop_reply)
    print(json.dumps(response,sort_keys=True))
    if response["state"]=="MOCK_CREATE_ONLY_WON_NOT_REAL_AUTHORITY":
        return 0
    if response["state"]=="MOCK_DUPLICATE_PERMANENT_DENY":
        return 3
    return 4

if __name__=="__main__":
    sys.exit(main())
