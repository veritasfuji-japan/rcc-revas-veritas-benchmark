#!/usr/bin/env python3
"""#408: crash-durable cross-UID *simulated* backend ledger and recovery.

A new SQLite-backed version of #407's local synthetic effect sink. A single
SQLite IMMEDIATE transaction atomically updates the counter, consumes a fixed
source-owned *fake* grant and records an effect receipt. The backend alone
owns its SQLite database under an owner-only 0700 Linux directory. Crash
faults are installed only at server startup, never via untrusted JSON:
  --crash-before: os._exit(77) after transaction BEGIN, BEFORE commit
  --crash-after:  os._exit(78) AFTER commit, BEFORE reply/ack
The same real #407 gateway invokes pinned VERITAS Bind for the successful
case. Gate and backend have distinct non-root OS identities/SO_PEERCRED.
After crash, independent inspection/relaunch must reconcile from backend
state, not from any assumption about lost HTTP/Unix acknowledgements.

This is NOT production durable financial effects, real banking credentials,
human-signed authorization, full exactly-once end-to-end semantics, network
IAM/egress or independent model A/B histories. In particular, a crash after
the bank committed but before Bind received acknowledgement returns
UNKNOWN until target-owned reconciliation, not falsely COMMITTED.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import stat
import sys

from scripts import final128_407_task1_synthetic_backend_singleuse_bind_v1 as prev
from scripts import final128_406_task1_cross_uid_unix_effect_owner_gate_v1 as linux

SCHEMA = "veritas.final128.task1-408-crash-durable-singleuse-mock-backend-v1"
FAIL_BEFORE = "before_sql_commit"
FAIL_AFTER = "after_sql_commit_before_ack"
NO_FAIL = "none"
FAIL_MODES = (FAIL_BEFORE,FAIL_AFTER,NO_FAIL)
CRASH_EXIT_BEFORE = 77
CRASH_EXIT_AFTER = 78
TARGET = prev.TARGET
UNITS = prev.UNITS
GRANT = prev.GRANT


class Refused(ValueError):
    pass


def need(ok,code):
    if ok is not True:
        raise Refused("408_"+code)


def _strict_db_path(path):
    linux._no_links(path)
    file=Path(path)
    directory=file.parent
    ds=directory.stat()
    need(os.geteuid()>0
         and ds.st_uid==os.geteuid()
         and stat.S_ISDIR(ds.st_mode)
         and stat.S_IMODE(ds.st_mode)==0o700,
         "OWNER_ONLY_DURABLE_DATABASE_DIRECTORY_REQUIRED")
    if file.exists():
        fs=file.lstat()
        need(stat.S_ISREG(fs.st_mode)
             and fs.st_uid==os.geteuid()
             and fs.st_nlink==1
             and stat.S_IMODE(fs.st_mode)==0o600,
             "DURABLE_DATABASE_FILE_IDENTITY_DAC_REQUIRED")


def _open_db(path):
    _strict_db_path(path)
    fresh=not Path(path).exists()
    old=os.umask(0o077)
    try:
        db=sqlite3.connect(path,timeout=5,isolation_level=None)
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=3000")
        db.execute("CREATE TABLE IF NOT EXISTS singleton (id INTEGER PRIMARY KEY CHECK (id=1), counter INTEGER NOT NULL, consumed INTEGER NOT NULL CHECK (consumed IN (0,1)))")
        db.execute("CREATE TABLE IF NOT EXISTS effects (id INTEGER PRIMARY KEY AUTOINCREMENT, grant_sha256 TEXT NOT NULL UNIQUE, target_sha256 TEXT NOT NULL, units INTEGER NOT NULL, prestate_sha256 TEXT NOT NULL, receipt_sha256 TEXT NOT NULL)")
        db.execute("INSERT OR IGNORE INTO singleton (id,counter,consumed) VALUES (1,0,0)")
        db.commit()
    finally:
        os.umask(old)
    _strict_db_path(path)
    if fresh:
        need(stat.S_IMODE(Path(path).stat().st_mode)==0o600,
             "CREATED_DB_MUST_BE_OWNER_ONLY")
    return db


def _state(db):
    row=db.execute("SELECT counter,consumed FROM singleton WHERE id=1").fetchone()
    need(row is not None,"MISSING_DURABLE_STATE")
    events=db.execute("SELECT grant_sha256,target_sha256,units,prestate_sha256 FROM effects ORDER BY id").fetchall()
    effects=[
        {"grant_sha256":g,"target_sha256":t,"units":u,"prestate_sha256":p}
        for g,t,u,p in events
    ]
    result={"counter":row[0],"consumed":bool(row[1]),"effects":effects}
    need((result["counter"]==0 and not result["consumed"] and not effects)
         or (result["counter"]==UNITS and result["consumed"]
             and len(effects)==1
             and effects[0]["grant_sha256"]==prev.digest(GRANT)
             and effects[0]["target_sha256"]==prev.digest(TARGET)
             and effects[0]["units"]==UNITS),
         "DURABLE_COUNTER_CONSUMPTION_AND_RECEIPT_INCONSISTENT")
    return result


def _reply_status(db):
    state=_state(db)
    return {
        "schema":prev.SCHEMA,"ok":True,"code":"407_BACKEND_STATUS",
        "backend_uid":os.geteuid(),"backend_pid":os.getpid(),
        "counter":state["counter"],"consumed":state["consumed"],
        "effect_count":len(state["effects"]),
        "state_sha256":prev.digest(state),
        "durable_mock_sqlite":True,
    }


def _commit_once(db,request,mode):
    need(mode in FAIL_MODES,"STARTUP_CRASH_MODE")
    before=_state(db)
    if (set(request)!={"v","op","target","units","grant"}
        or request.get("target")!=TARGET
        or type(request.get("units")) is not int
        or request.get("units")!=UNITS
        or request.get("grant")!=GRANT
        or before["consumed"]):
        return {"schema":prev.SCHEMA,"ok":False,
                "code":"407_BACKEND_UNBOUND_OR_CONSUMED",
                "backend_uid":os.geteuid(),
                "state_sha256":prev.digest(before),
                "durable_mock_sqlite":True}
    before_sha=prev.digest(before)
    try:
        db.execute("BEGIN IMMEDIATE")
        # Re-check INSIDE the transaction; no stale positive admission.
        live=_state(db)
        need(live==before and not live["consumed"],"STALE_BOUND_GRANT")
        if mode==FAIL_BEFORE:
            # Fatal process crash: SQLite has uncommitted transaction.
            os._exit(CRASH_EXIT_BEFORE)
        effect={
            "grant_sha256":prev.digest(GRANT),
            "target_sha256":prev.digest(TARGET),
            "units":UNITS,
            "prestate_sha256":before_sha,
        }
        effect_receipt_sha=prev.digest(effect)
        db.execute("UPDATE singleton SET counter=?,consumed=1 WHERE id=1 AND consumed=0",
                   (UNITS,))
        db.execute("INSERT INTO effects (grant_sha256,target_sha256,units,prestate_sha256,receipt_sha256) VALUES (?,?,?,?,?)",
                   (effect["grant_sha256"],effect["target_sha256"],
                    effect["units"],effect["prestate_sha256"],effect_receipt_sha))
        after=_state(db)
        need(after["counter"]==UNITS and after["consumed"]
             and len(after["effects"])==1,
             "ATOMIC_STATE_BEFORE_COMMIT_INCONSISTENT")
        db.commit()
    except BaseException:
        db.rollback()
        raise
    if mode==FAIL_AFTER:
        # Commit is durable; reply was NOT delivered. Reconciliation must
        # recover target-owned state, never send the effect again.
        os._exit(CRASH_EXIT_AFTER)
    return {
        "schema":prev.SCHEMA,"ok":True,"code":"407_BACKEND_ONCE_APPLIED",
        "backend_uid":os.geteuid(),
        "counter":UNITS,"effect_count":1,"consumed":True,
        "prestate_sha256":before_sha,"state_sha256":prev.digest(after),
        "effect_receipt_sha256":effect_receipt_sha,
        "durable_mock_sqlite":True,
    }


def run_durable_backend(socket_path,gateway_uid,db_path,crash_mode=NO_FAIL):
    need(type(gateway_uid) is int and gateway_uid>0
         and gateway_uid!=os.geteuid() and os.geteuid()>0,
         "OWNER_GATEWAY_CROSS_UID_REQUIRED")
    need(crash_mode in FAIL_MODES,"UNRECOGNIZED_FAULT_INJECTION_MODE")
    db=_open_db(db_path)
    def handler(conn,peer):
        if peer["uid"]!=gateway_uid:
            return False
        try:
            msg=prev._read(conn)
        except prev.Refused:
            prev._send(conn,{"schema":prev.SCHEMA,"ok":False,
                             "code":"407_INVALID_BACKEND_JSON"})
            return False
        if (type(msg) is not dict or msg.get("v")!=1
            or type(msg.get("v")) is not int):
            prev._send(conn,{"schema":prev.SCHEMA,"ok":False,
                             "code":"407_INVALID_BACKEND_ENVELOPE"})
            return False
        op=msg.get("op")
        if op=="status" and set(msg)=={"v","op"}:
            prev._send(conn,_reply_status(db))
            return False
        if op=="apply":
            reply=_commit_once(db,msg,crash_mode)
            prev._send(conn,reply)
            return False
        if op=="close" and set(msg)=={"v","op"}:
            prev._send(conn,{"schema":prev.SCHEMA,"ok":True,
                             "code":"407_BACKEND_CLOSED"})
            return True
        prev._send(conn,{"schema":prev.SCHEMA,"ok":False,
                         "code":"407_UNKNOWN_BACKEND_OP"})
        return False
    try:
        prev._listen(socket_path,handler)
    finally:
        db.close()


def redacted_recovery_manifest(*,scenario,initial,recovered,after_retry,
                               crash_code,bind_result,agent_uid,gateway_uid,
                               backend_uid,second_attempt_refused):
    need(scenario in FAIL_MODES
         and all(type(x) is int and x>0 for x in
                 (agent_uid,gateway_uid,backend_uid))
         and len({agent_uid,gateway_uid,backend_uid})==3
         and all(row["schema"]==prev.SCHEMA for row in
                 (initial,recovered,after_retry))
         and initial["counter"]==0
         and recovered["counter"]==(0 if scenario==FAIL_BEFORE else UNITS)
         and after_retry["counter"]==UNITS
         and after_retry["effect_count"]==1
         and after_retry["consumed"] is True
         and second_attempt_refused is True
         and (crash_code==CRASH_EXIT_BEFORE if scenario==FAIL_BEFORE else
              crash_code==CRASH_EXIT_AFTER if scenario==FAIL_AFTER else
              crash_code==0)
         and (bind_result=="COMMITTED" if scenario in (NO_FAIL,FAIL_BEFORE)
              else bind_result=="ACK_UNKNOWN_RECONCILED_EFFECT"),
         "CRASH_RECOVERY_LEDGER_OR_BIND_STATUS_NOT_RECONCILED")
    return {
        "schema":SCHEMA,
        "scenario":scenario,
        "status":"CROSS_UID_DURABLE_MOCK_EXACTLY_ONE_EFFECT_RECONCILED",
        "agentdojo_pin":prev.prior.native.NATIVE_PIN,
        "veritas_pin":prev.prior.native.VERITAS_PIN,
        "distinct_linux_os_uid_agent_gate_backend":True,
        "mock_sqlite_owner_uid":backend_uid,
        "mock_sqlite_owner_directory_0700_and_database_0600":True,
        "atomic_sqlite_transaction_singleuse_consumption":True,
        "state_initial_sha256":initial["state_sha256"],
        "state_recovered_sha256":recovered["state_sha256"],
        "state_after_retry_sha256":after_retry["state_sha256"],
        "effect_count_after_retry":1,
        "post_restart_replay_refused":True,
        "crash_phase":scenario,
        "observed_process_exit_code":crash_code,
        "observed_bind_final_status":bind_result,
        "lost_ack_commit_reconciled_by_backend_state":scenario==FAIL_AFTER,
        "native_task1_no_mutation_unchanged":True,
        "real_external_bank_effects":0,
        "paid_provider_calls":0,
        "official_native_scorer_calls":0,
        "production_iam_egress_real_credentials_proven":False,
        "global_production_exactly_once_proven":False,
        "production_crash_safe_recovery_proven":False,
        "signed_human_approval_verified":False,
        "independent_model_A_B_proven":False,
        "official_native_utility_A":None,
        "official_native_utility_B":None,
    }


def reject_paid_or_real_effect(*_args,**_kwargs):
    raise Refused("408_FRESH_PAID_APPROVAL_AND_REAL_BACKEND_AUTHORIZATION_ABSENT")


def main(argv):
    if len(argv) in (5,6) and argv[1]=="--durable-backend":
        crash_mode=argv[5] if len(argv)==6 else NO_FAIL
        need(crash_mode in FAIL_MODES,"CLI_CRASH_MODE")
        run_durable_backend(argv[2],int(argv[3]),argv[4],crash_mode)
    else:
        raise SystemExit("408_OFFLINE_DURABLE_MOCK_BACKEND_ONLY")


if __name__=="__main__":
    main(sys.argv)
