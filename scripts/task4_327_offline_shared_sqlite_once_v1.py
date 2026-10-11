#!/usr/bin/env python3
"""#327: OFFLINE ONLY atomic consume-before-any-simulated-effect research fixture.

SQLite FULL synchronous BEGIN IMMEDIATE + UNIQUE(trial_id) is an actual atomic
claim across separate local processes sharing ONE physical database file.
It is NOT a GitHub Actions cross-run distributed backend: separate hosted
runners do not share this DB. An owner can delete/mutate local DB; no
production durable IAM authority, Provider permission, billing or API access.
"""
from __future__ import annotations
import argparse
from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys

RULE="TASK4_327_OFFLINE_SHARED_SQLITE_CONSUME_BEFORE_SEND_V1"
PARENT_MAIN="0791c5f774bb1e0839b329aa91a0a788bfdfdd9a"
EXPERIMENT="task4-327-one-case-scripted-ab-local-v1"
MODEL="gpt-4.1-mini-2025-04-14"
CASE="banking:user_task_4:injection_task_0:direct"
PRESTATE="8b653f253d3b2b033ad2baebc938bb66cb09719be8b488a470e7e82d25abbe14"
ATTACK="0d5011fb8b275e313c83da127698f19a77095d44e82a81b4d5804046c3cb61a9"
HEX64=re.compile(r"[0-9a-f]{64}\Z")
ID_RE=re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
SENSITIVE=("OPENAI_API_KEY","TASK4_OPENAI_API_KEY","ANTHROPIC_API_KEY",
           "OPENAI_BASE_URL","VERITAS_DATABASE_URL")
SCHEMA_VERSION=1

class Refused(ValueError):pass
def need(ok,why):
    if not ok:raise Refused(why)

def canonical(obj):
    return json.dumps(obj,sort_keys=True,ensure_ascii=False,
                      separators=(",",":"),allow_nan=False).encode("utf-8")

def sha(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()

@dataclass(frozen=True)
class FixtureAuthority:
    experiment: str=EXPERIMENT
    case: str=CASE
    model: str=MODEL
    parent_sha: str=PARENT_MAIN
    native_prestate_sha: str=PRESTATE
    native_attack_sha: str=ATTACK
    arm_pair: str="A+B"
    max_attempts: int=10
    max_completion: int=256
    shared_backend: str="ONE_SHARED_LOCAL_SQLITE_FILE_NOT_GITHUB_HOSTED_RUNNERS"
    run_class: str="OFFLINE_RESEARCH_ONLY"
    fresh_live_approval: bool=False
    external_provider_sender: bool=False
    api_secret_present: bool=False

def validate_authority(a):
    need(type(a) is FixtureAuthority and a==FixtureAuthority(),
         "OFFLINE_ONLY_FIXED_EXPERIMENT_IDENTITY_AND_DENIAL_REQUIRED")
    need(not any(os.environ.get(k) for k in SENSITIVE),
         "ACTUAL_PROVIDER_SECRET_OR_ENDPOINT_DENIED")

def db_location(path):
    root=os.environ.get("TASK4_327_LEDGER_ROOT")
    need(root is not None and bool(root.strip()),"TEST_ONLY_SQLITE_DIRECTORY_REQUIRED")
    base=Path(root).resolve(strict=True)
    need(base.is_dir() and not base.is_symlink(),"SHARED_TEST_DIRECTORY_NOT_FOUND")
    target=Path(path).resolve(strict=False)
    need(target.parent==base and target.suffix==".sqlite3" and
         target.name=="one-shot-test.sqlite3" and not target.is_symlink(),
         "DENY_REMOTE_OR_UNTRUSTED_OR_PRODUCTION_DB_PATH")
    return target

DDL="""CREATE TABLE IF NOT EXISTS one_shot (
  experiment TEXT PRIMARY KEY NOT NULL,
  scope_sha256 TEXT NOT NULL,
  request_sha256 TEXT NOT NULL,
  claimed_by TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome = 'UNKNOWN_PERMANENTLY_CONSUMED'),
  real_provider_send_allowed INTEGER NOT NULL CHECK (real_provider_send_allowed = 0),
  receipt_sha256 TEXT NOT NULL
)"""
INDEX="CREATE INDEX IF NOT EXISTS idx_one_shot_owner ON one_shot(claimed_by)"

def connect(path):
    target=db_location(path)
    db=sqlite3.connect(str(target),timeout=15.0,isolation_level=None)
    db.execute("PRAGMA busy_timeout=15000")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("PRAGMA journal_mode=DELETE")
    db.execute(DDL)
    # Validate exact schema, not merely a caller-declared table name.
    existing=db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='one_shot'").fetchone()
    need(existing is not None and existing[0]==DDL,
         "LEDGER_SCHEMA_NOT_EXPECTED")
    return db

def scope():
    a=FixtureAuthority()
    validate_authority(a)
    return sha(vars(a))

def claim_once(path,request_hash,worker_id,authority=None,*,crash_after_commit=False):
    """An INSERT's COMMIT is the irreversible local linearization point.

    Successful result is ONLY an offline receipt. No sender is present.
    A DB refusal, sqlite OperationalError or timeout is UNKNOWN, not approval.
    No release, UPSERT, overwrite, automatic retry or delete/recovery path.
    """
    a=authority if authority is not None else FixtureAuthority()
    validate_authority(a)
    need(type(worker_id) is str and ID_RE.fullmatch(worker_id) is not None,
         "BOUNDED_WORKER_LABEL_REQUIRED")
    need(type(request_hash) is str and HEX64.fullmatch(request_hash) is not None,
         "CANONICAL_SYNTHETIC_REQUEST_HASH_REQUIRED")
    value=scope()
    receipt={
      "rule_of_one":RULE,"experiment":EXPERIMENT,
      "scope_sha256":value,"request_sha256":request_hash,
      "claimed_by":worker_id,
      "outcome":"UNKNOWN_PERMANENTLY_CONSUMED",
      "real_provider_send_allowed":False,
      "backend":"ONE_SHARED_LOCAL_SQLITE_FILE_NOT_CROSS_RUN_GITHUB_BACKEND",
    }
    receipt["receipt_sha256"]=sha(receipt)
    db=None
    try:
        db=connect(path)
        db.execute("BEGIN IMMEDIATE")
        # This is the only claim write. A UNIQUE collision is a permanent deny.
        db.execute("""INSERT INTO one_shot
          (experiment,scope_sha256,request_sha256,claimed_by,outcome,
           real_provider_send_allowed,receipt_sha256)
          VALUES (?,?,?,?,?,?,?)""",
          (EXPERIMENT,value,request_hash,worker_id,"UNKNOWN_PERMANENTLY_CONSUMED",
           0,receipt["receipt_sha256"]))
        db.execute("COMMIT")
        # The effect-side boundary is intentionally absent. Even process death
        # immediately after COMMIT leaves the experiment consumed.
        if crash_after_commit:
            os._exit(74)
        return receipt
    except (sqlite3.Error,Refused) as e:
        if db is not None:
            try:db.execute("ROLLBACK")
            except sqlite3.Error:pass
        raise Refused("DURABLE_CLAIM_DENIED_OR_UNKNOWN_NEVER_RETRY") from e
    finally:
        if db is not None:db.close()

def inspect_one_shot(path):
    db=connect(path)
    try:
        rows=db.execute("""SELECT experiment,scope_sha256,request_sha256,
                        claimed_by,outcome,real_provider_send_allowed,receipt_sha256
                        FROM one_shot ORDER BY experiment""").fetchall()
        cols=("experiment","scope_sha256","request_sha256","claimed_by",
              "outcome","real_provider_send_allowed","receipt_sha256")
        res=[dict(zip(cols,row)) for row in rows]
        for row in res:
            h=row["receipt_sha256"]
            expect={
              "rule_of_one":RULE,"experiment":row["experiment"],
              "scope_sha256":row["scope_sha256"],
              "request_sha256":row["request_sha256"],
              "claimed_by":row["claimed_by"],"outcome":row["outcome"],
              "real_provider_send_allowed":False,
              "backend":"ONE_SHARED_LOCAL_SQLITE_FILE_NOT_CROSS_RUN_GITHUB_BACKEND",
            }
            need(row["real_provider_send_allowed"]==0 and
                 row["experiment"]==EXPERIMENT and
                 row["scope_sha256"]==scope() and
                 row["outcome"]=="UNKNOWN_PERMANENTLY_CONSUMED" and
                 sha(expect)==h,"DURABLE_LOCAL_RECORD_MISMATCH")
        need(len(res)<=1,"UNIQUE_EXPERIMENT_INVARIANT")
        return res
    finally:db.close()

def main():
    p=argparse.ArgumentParser()
    p.add_argument("action",choices=("claim","inspect"))
    p.add_argument("--db",required=True)
    p.add_argument("--request-sha",default="a"*64)
    p.add_argument("--worker-id",default="offline-worker")
    p.add_argument("--crash-after-commit",action="store_true")
    args=p.parse_args()
    try:
        if args.action=="inspect":
            need(not args.crash_after_commit,"INSPECT_NOT_SEND")
            data=inspect_one_shot(args.db)
            print(json.dumps({"rows":data,"live_send_allowed":False},sort_keys=True))
        else:
            out=claim_once(args.db,args.request_sha,args.worker_id,
                           crash_after_commit=args.crash_after_commit)
            print(json.dumps(out,sort_keys=True))
    except Refused as exc:
        print("TASK4_327_OFFLINE_REFUSED:"+str(exc),file=sys.stderr)
        return 3
    return 0

if __name__=="__main__":
    sys.exit(main())
