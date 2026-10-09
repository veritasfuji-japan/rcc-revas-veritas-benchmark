"""Durable SQLite single-consume OFFLINE Task15 rehearsal; no real provider.

Bounded claim: one on-disk SQLite database on a single host, separate Python
processes, atomic local consumption and durable unresolved claims. This does
NOT provide a production issuer, crash-safe provider-effect reconciliation,
network-distributed locking, trusted clock, a secure token or spending rights.
"""
from __future__ import annotations
import argparse
import copy
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import time

RULE="TASK15_SQLITE_DURABLE_OFFLINE_CONSUME_V1"
PRIOR_RULE="TASK15_PROVIDER_SINGLE_USE_REHEARSAL_DEFAULT_DENY_V1"
PREDECESSOR_MAIN="ec648458d79ef80f6b508b6a489bcda705426920"
START="2026-10-09T12:24:00+00:00"
END="2026-10-09T12:29:00+00:00"
MODEL="gpt-4.1-mini-2025-04-14"
MAX_MICRO_USD=5_000_000

class DurableOfflineViolation(ValueError):
    pass

def require(ok,reason):
    if not ok:raise DurableOfflineViolation(reason)

def canonical(x):
    return json.dumps(x,ensure_ascii=False,sort_keys=True,
                      separators=(",",":"),allow_nan=False)

def sha(x):
    return hashlib.sha256(canonical(x).encode()).hexdigest()

def parse_utc(value):
    require(type(value) is str and value.endswith("+00:00"),
            "TRUSTED_CLOCK_NOT_PROVIDED_ONLY_FROZEN_UTC_TEST")
    try:
        t=datetime.fromisoformat(value)
    except ValueError as exc:
        raise DurableOfflineViolation("MALFORMED_OFFLINE_UTC_TEST_TIME") from exc
    require(t.tzinfo is not None and t.utcoffset().total_seconds()==0,
            "UTC_REQUIRED")
    return t

def verified_prior(prior):
    require(type(prior) is dict and
            type(prior.get("proof")) is dict and
            type(prior.get("plan")) is dict and
            prior.get("concurrent_attempts")==16 and
            prior.get("concurrency_barrier_parties")==16 and
            prior.get("rehearsals_consumed")==1 and
            prior.get("replay_refusals")==15,
            "EXACT_PR270_REHEARSAL_EVIDENCE_REQUIRED")
    proof,plan=prior["proof"],prior["plan"]
    require(proof.get("rule_of_one")==PRIOR_RULE
            and plan.get("rule_of_one")==PRIOR_RULE
            and proof.get("determination")==
                "ONE_LOCAL_REHEARSAL_CONSUMED_PROVIDER_AUTHORITY_ABSENT"
            and plan.get("kind")=="NON_EXECUTABLE_OFFLINE_REHEARSAL_PROPOSAL"
            and proof.get("plan_sha256")==sha(plan)
            and proof.get("predecessor_proof_sha256")==
                plan.get("predecessor_proof_sha256")
            and plan.get("predecessor_merged_main_sha")==
                "5206a8e032362f0c362dba444a99ce38dd146a87"
            and proof.get("case_id")==plan.get("case_id")==
                "banking:user_task_15:injection_task_0:direct"
            and proof.get("arm")==plan.get("arm")=="A"
            and proof.get("model_snapshot")==
                plan.get("frozen_model_snapshot")==MODEL
            and proof.get("max_cost_micro_usd")==
                plan.get("max_cost_micro_usd")==MAX_MICRO_USD
            and plan.get("issued_at")==START
            and plan.get("expires_at")==END
            and plan.get("historical_ceiling_is_not_spend_permission") is True
            and plan.get("trusted_issuer_present") is False
            and plan.get("trusted_human_approval_attested") is False
            and plan.get("transport_adapter_present") is False
            and plan.get("live_provider_authority_issued") is False
            and plan.get("native_bank_execution_authority_issued") is False
            and plan.get("provider_response_authenticated") is False
            and plan.get("provider_response_id") is None
            and proof.get("local_rehearsal_consumed") is True
            and proof.get("in_memory_single_use_only") is True
            and proof.get("durable_replay_protection_proven") is False
            and proof.get("live_provider_capability_issued") is False
            and proof.get("permission_to_call_provider") is False
            and proof.get("provider_request_sent") is False
            and proof.get("provider_calls")==
                proof.get("provider_charges_usd")==
                proof.get("native_write_dispatch_count")==
                proof.get("scorer_calls")==
                proof.get("external_effects")==0,
            "NO_REAL_PROVIDER_AUTHORITY_FROM_PR270_REHEARSAL")
    require(all(type(plan.get(k)) is str and len(plan[k])==64
                and all(c in "0123456789abcdef" for c in plan[k])
                for k in ("source_request_sha256",
                          "source_tool_schemas_sha256",
                          "source_user_message_sha256",
                          "predecessor_proof_sha256")),
            "EXACT_PREDECESSOR_SHA256_BINDINGS_REQUIRED")
    return copy.deepcopy(plan)

class SQLiteOfflineRehearsal:
    """Single local filesystem durable consume, strictly no provider adapter."""

    def __init__(self,path):
        self.path=Path(path)
        require(self.path.is_file(),"EXISTING_ON_DISK_LEDGER_REQUIRED")

    @staticmethod
    def _connection(path, *, create=False):
        db=sqlite3.connect(str(path),timeout=30,isolation_level=None)
        db.execute("PRAGMA busy_timeout=30000")
        if create:
            # WAL is a database-level durable setting. Reasserting it from
            # every contender can itself race with a writer transaction.
            db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    @classmethod
    def issue_offline(cls,path,prior):
        plan=verified_prior(prior)
        path=Path(path)
        require(not path.exists(),"NO_OVERWRITE_OR_RESET_OF_DURABLE_LEDGER")
        require(path.parent.is_dir(),"LEDGER_PARENT_MUST_EXIST")
        ticket_id=sha({
            "marker":"NON_EXECUTABLE_SQLITE_OFFLINE_TICKET",
            "previous_main":PREDECESSOR_MAIN,
            "prior_evidence":sha(prior),
            "plan":sha(plan),
        })
        db=cls._connection(path,create=True)
        try:
            db.executescript("""
                CREATE TABLE tickets(
                    id TEXT PRIMARY KEY,
                    plan_sha256 TEXT NOT NULL,
                    predecessor_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN
                        ('ISSUED_OFFLINE','CLAIMED_UNRESOLVED',
                         'CONSUMED_OFFLINE','DENIED_BURNED')),
                    owner TEXT,
                    claims INTEGER NOT NULL DEFAULT 0 CHECK(claims IN (0,1))
                );
                CREATE TABLE arrivals(worker TEXT PRIMARY KEY);
                CREATE TABLE audit_events(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    event TEXT NOT NULL,
                    worker TEXT NOT NULL
                );
            """)
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO tickets(id,plan_sha256,predecessor_sha256,state)"
                       " VALUES(?,?,?,'ISSUED_OFFLINE')",
                       (ticket_id,sha(plan),sha(prior)))
            db.execute("INSERT INTO audit_events(event,worker) VALUES(?,?)",
                       ("OFFLINE_NONEXECUTABLE_TICKET_CREATED","issuer"))
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:db.execute("ROLLBACK")
            raise
        finally:
            db.close()
        return cls(path),ticket_id,plan

    def observed(self):
        db=self._connection(self.path)
        try:
            record=db.execute(
                "SELECT id,plan_sha256,predecessor_sha256,state,owner,claims"
                " FROM tickets").fetchall()
            events=db.execute(
                "SELECT seq,event,worker FROM audit_events ORDER BY seq").fetchall()
            arrivals=db.execute("SELECT COUNT(*) FROM arrivals").fetchone()[0]
            return {
                "records":[{
                    "ticket_id":r[0],"plan_sha256":r[1],
                    "predecessor_sha256":r[2],"state":r[3],
                    "owner":r[4],"claims":r[5],
                } for r in record],
                "events":[{"seq":a,"event":b,"worker":c} for a,b,c in events],
                "arrivals":arrivals,
                "live_provider_authority_issued":False,
                "trusted_human_approval_verified":False,
                "live_provider_calls":0,"provider_charges_usd":0,
                "native_bank_writes":0,"scorer_calls":0,"external_effects":0,
            }
        finally:db.close()

    def arrive_and_wait(self,worker,participants=16,timeout_seconds=60):
        require(type(worker) is str and worker and participants==16,
                "EXACT_SIXTEEN_DISTINCT_PROCESSES_REQUIRED")
        db=self._connection(self.path)
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO arrivals(worker) VALUES(?)",(worker,))
            db.execute("COMMIT")
        finally:db.close()
        start=time.monotonic()
        while time.monotonic()-start<timeout_seconds:
            db=self._connection(self.path)
            try:n=db.execute("SELECT COUNT(*) FROM arrivals").fetchone()[0]
            finally:db.close()
            if n==participants:return
            require(n<participants,"UNEXPECTED_PROCESS_COUNT")
            time.sleep(0.025)
        raise DurableOfflineViolation("MULTIPROCESS_START_BARRIER_TIMED_OUT")

    def claim(self,*,ticket_id,worker,proposed_plan,original_plan,now=START):
        """Burn first (transaction commits), then check source/time."""
        require(type(ticket_id) is str and
                type(worker) is str and bool(worker),
                "TICKET_ID_AND_PROCESS_OWNER_REQUIRED")
        db=self._connection(self.path)
        try:
            db.execute("BEGIN IMMEDIATE")
            cur=db.execute(
                "UPDATE tickets SET state='CLAIMED_UNRESOLVED',"
                " owner=?,claims=1 WHERE id=? AND state='ISSUED_OFFLINE'"
                " AND claims=0",(worker,ticket_id))
            if cur.rowcount!=1:
                db.execute("ROLLBACK")
                raise DurableOfflineViolation("DURABLE_TICKET_ALREADY_CLAIMED_OR_ABSENT")
            db.execute("INSERT INTO audit_events(event,worker) VALUES(?,?)",
                       ("ATOMIC_SINGLE_CLAIM_COMMITTED",worker))
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:db.execute("ROLLBACK")
            raise
        finally:db.close()

        try:
            db=self._connection(self.path)
            try:
                ticket=db.execute("SELECT plan_sha256,predecessor_sha256,state,owner"
                                  " FROM tickets WHERE id=?",(ticket_id,)).fetchone()
            finally:db.close()
            require(ticket is not None and
                    type(original_plan) is dict and
                    type(proposed_plan) is dict and
                    canonical(original_plan)==canonical(proposed_plan) and
                    ticket[0]==sha(original_plan) and
                    ticket[2]=="CLAIMED_UNRESOLVED" and ticket[3]==worker,
                    "CONSUMED_PLAN_OR_OWNER_MISMATCH_NO_RETRY")
            t=parse_utc(now)
            require(parse_utc(START)<=t<parse_utc(END),
                    "CONSUMED_OFFLINE_TICKET_EXPIRED_OR_PREMATURE")
            require(proposed_plan.get("live_provider_authority_issued") is False
                    and proposed_plan.get("transport_adapter_present") is False
                    and proposed_plan.get("trusted_human_approval_attested") is False
                    and proposed_plan.get("native_bank_execution_authority_issued") is False
                    and proposed_plan.get("historical_ceiling_is_not_spend_permission") is True
                    and proposed_plan.get("max_cost_micro_usd")==MAX_MICRO_USD,
                    "NO_PROVIDER_AUTHORITY_FROM_DURABLE_CLAIM")
        except BaseException:
            self._finalize(ticket_id,worker,"DENIED_BURNED",
                           "INVALID_OR_EXPIRED_TICKET_PERMANENTLY_BURNED")
            raise

    def _finalize(self,ticket_id,worker,state,event):
        db=self._connection(self.path)
        try:
            db.execute("BEGIN IMMEDIATE")
            updated=db.execute(
                "UPDATE tickets SET state=? WHERE id=?"
                " AND owner=? AND state='CLAIMED_UNRESOLVED'"
                " AND claims=1",(state,ticket_id,worker))
            require(updated.rowcount==1,"WRONG_OWNER_OR_ALREADY_FINALIZED")
            db.execute("INSERT INTO audit_events(event,worker) VALUES(?,?)",
                       (event,worker))
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:db.execute("ROLLBACK")
            raise
        finally:db.close()

    def complete_local_rehearsal(self,*,ticket_id,worker):
        self._finalize(ticket_id,worker,"CONSUMED_OFFLINE",
                       "ONE_LOCAL_DURABLE_REHEARSAL_FINISHED")
        return {
            "rule_of_one":RULE,
            "determination":"ONE_SQLITE_CROSS_PROCESS_LOCAL_CONSUME_NO_PROVIDER_AUTHORITY",
            "ticket_id":ticket_id,"owner":worker,
            "local_sqlite_single_host_replay_resistance":True,
            "cross_machine_replay_protection_proven":False,
            "crash_effect_reconciliation_proven":False,
            "trusted_clock_proven":False,
            "provider_authority_issued":False,
            "provider_calls":0,"charges_usd":0,
            "native_writes":0,"scorer_calls":0,"external_effects":0,
        }

    def attempt_live_provider(self,*,transport=None,consent=None):
        del transport,consent
        raise DurableOfflineViolation(
            "REAL_PROVIDER_TRANSPORT_AND_HUMAN_AUTHORIZATION_OUT_OF_SCOPE")

def child_main(args):
    ledger=SQLiteOfflineRehearsal(args.database)
    if args.synchronize:
        ledger.arrive_and_wait(args.worker)
    try:
        data=json.loads(Path(args.plan_file).read_text())
        ledger.claim(
            ticket_id=args.ticket_id,worker=args.worker,
            proposed_plan=data["plan"],original_plan=data["plan"],
            now=START,
        )
        if args.crash_after_claim:
            sys.stdout.flush()
            # Simulates crash only AFTER the atomic SQLite claim transaction.
            # Reopen must report CLAIMED_UNRESOLVED, never auto-reissue/retry.
            import os
            os._exit(73)
        proof=ledger.complete_local_rehearsal(
            ticket_id=args.ticket_id,worker=args.worker)
        print(json.dumps({"result":"ONE_LOCAL_CONSUME","proof":proof}))
    except DurableOfflineViolation as exc:
        print(json.dumps({"result":"REFUSED","reason":str(exc)}))
    return 0

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--database",type=Path,required=True)
    parser.add_argument("--plan-file",type=Path,required=True)
    parser.add_argument("--ticket-id",required=True)
    parser.add_argument("--worker",required=True)
    parser.add_argument("--synchronize",action="store_true")
    parser.add_argument("--crash-after-claim",action="store_true")
    raise SystemExit(child_main(parser.parse_args()))
