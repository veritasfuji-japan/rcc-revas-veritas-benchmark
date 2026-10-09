"""Task15 OFFLINE mock-provider effect / UNKNOWN reconciliation boundary.

Two independent SQLite databases stand in for controller and provider.  The
provider is a deterministic local simulator, NOT OpenAI and NOT a real bank.
An already-fenced operation with no simulated receipt remains UNKNOWN; no
automatic retry, no silent NO_EFFECT, no permission promotion.  The only
CONFIRMED_MOCK_EFFECT evidence is a matching row read from the separate mock
provider's durable SQLite ledger.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3

RULE="TASK15_MOCK_EFFECT_UNKNOWN_RECONCILE_V1"
PRIOR_RULE="TASK15_SQLITE_DURABLE_OFFLINE_CONSUME_V1"
PREDECESSOR_SHA="c32de2526ee5e2fd454fd1359ef985d582caf2c8"
CASE="banking:user_task_15:injection_task_0:direct"
MODEL="gpt-4.1-mini-2025-04-14"

class MockBoundaryViolation(ValueError):
    pass

def require(ok,reason):
    if not ok:raise MockBoundaryViolation(reason)

def canonical(x):
    return json.dumps(x,ensure_ascii=False,sort_keys=True,
                      separators=(",",":"),allow_nan=False)

def sha(x):
    return hashlib.sha256(canonical(x).encode()).hexdigest()

def pinned_prior(prior):
    require(type(prior) is dict and type(prior.get("proof")) is dict
            and type(prior.get("plan")) is dict
            and type(prior.get("durable_state")) is dict
            and prior.get("processes_started")==16
            and prior.get("barrier_arrivals")==16
            and prior.get("successful_process_consumptions")==1
            and prior.get("refused_process_consumptions")==15
            and prior.get("predecessor_proof_sha256") is not None,
            "PINNED_PR271_EVIDENCE_REQUIRED")
    p,plan,state=prior["proof"],prior["plan"],prior["durable_state"]
    require(p.get("rule_of_one")==PRIOR_RULE
            and p.get("determination")==
                "ONE_SQLITE_CROSS_PROCESS_LOCAL_CONSUME_NO_PROVIDER_AUTHORITY"
            and p.get("local_sqlite_single_host_replay_resistance") is True
            and p.get("cross_machine_replay_protection_proven") is False
            and p.get("crash_effect_reconciliation_proven") is False
            and p.get("trusted_clock_proven") is False
            and p.get("provider_authority_issued") is False
            and p.get("provider_calls")==p.get("charges_usd")==
                p.get("native_writes")==p.get("scorer_calls")==
                p.get("external_effects")==0
            and type(state.get("records")) is list
            and len(state["records"])==1
            and state["records"][0]["state"]=="CONSUMED_OFFLINE"
            and state["records"][0]["claims"]==1
            and state["arrivals"]==16
            and len(state["events"])==3
            and state["records"][0]["plan_sha256"]==sha(plan)
            and p.get("ticket_id")==prior.get("ticket_id")==
                state["records"][0]["ticket_id"]
            and plan.get("case_id")==CASE
            and plan.get("arm")=="A"
            and plan.get("frozen_model_snapshot")==MODEL
            and plan.get("max_cost_micro_usd")==5_000_000
            and plan.get("historical_ceiling_is_not_spend_permission") is True
            and plan.get("live_provider_authority_issued") is False
            and plan.get("trusted_human_approval_attested") is False
            and plan.get("trusted_issuer_present") is False
            and plan.get("transport_adapter_present") is False
            and plan.get("native_bank_execution_authority_issued") is False,
            "NO_LIVE_AUTHORITY_OR_PREDECESSOR_DRIFT_PERMITTED")
    return copy.deepcopy(plan)

class LocalMockConsequence:
    """Single-host simulator. Each new scenario must receive fresh DB files."""

    def __init__(self, controller_path, mock_provider_path, prior, *, create=True):
        self.controller=Path(controller_path)
        self.provider=Path(mock_provider_path)
        plan=pinned_prior(prior)
        require(self.controller!=self.provider,"TWO_INDEPENDENT_LEDGER_FILES_REQUIRED")
        self.plan=plan
        self.plan_sha=sha(plan)
        self.prior_sha=sha(prior)
        self._local_dispatch_armed=False
        self.operation_id=sha({
            "domain":"task15.offline-mock-provider-effect.v1",
            "source_ticket":prior["ticket_id"],
            "source_plan_sha256":self.plan_sha,
            "source_proof_sha256":self.prior_sha,
        })
        if create:
            require(not self.controller.exists() and not self.provider.exists()
                    and self.controller.parent.is_dir()
                    and self.provider.parent.is_dir(),
                    "FRESH_ISOLATED_LOCAL_MOCK_DATABASES_REQUIRED")
            self._init_databases()
        else:
            require(self.controller.is_file() and self.provider.is_file(),
                    "EXISTING_MOCK_DATABASE_PAIR_REQUIRED")
            self._verify_opened()

    @staticmethod
    def _conn(path,create=False):
        db=sqlite3.connect(str(path),timeout=20,isolation_level=None)
        db.execute("PRAGMA busy_timeout=20000")
        if create:db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def _init_databases(self):
        db=self._conn(self.controller,create=True)
        try:
            db.executescript("""
                CREATE TABLE dispatch(
                    operation_id TEXT PRIMARY KEY,
                    plan_sha256 TEXT NOT NULL,
                    prior_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN (
                      'ISSUED_OFFLINE','CLAIMED_UNRESOLVED',
                      'DISPATCH_UNKNOWN','PRE_DISPATCH_NO_EFFECT',
                      'CONFIRMED_MOCK_EFFECT')),
                    claims INTEGER NOT NULL CHECK(claims IN (0,1)),
                    dispatch_fences INTEGER NOT NULL CHECK(dispatch_fences IN (0,1)),
                    receipt_sha256 TEXT
                );
                CREATE TABLE journal(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    event TEXT NOT NULL
                );
            """)
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO dispatch VALUES (?, ?, ?, 'ISSUED_OFFLINE',0,0,NULL)",
                       (self.operation_id,self.plan_sha,self.prior_sha))
            db.execute("INSERT INTO journal(event) VALUES ('TICKET_ISSUED_OFFLINE')")
            db.execute("COMMIT")
        finally:db.close()
        mock=self._conn(self.provider,create=True)
        try:
            mock.executescript("""
                CREATE TABLE mock_effects(
                    operation_id TEXT PRIMARY KEY,
                    plan_sha256 TEXT NOT NULL,
                    receipt_sha256 TEXT NOT NULL,
                    receipt_json TEXT NOT NULL
                );
                CREATE TABLE mock_attempts(
                    operation_id TEXT PRIMARY KEY,
                    request_sha256 TEXT NOT NULL
                );
            """)
        finally:mock.close()

    def _verify_opened(self):
        row=self.state()
        require(row["operation_id"]==self.operation_id
                and row["plan_sha256"]==self.plan_sha
                and row["prior_sha256"]==self.prior_sha,
                "REOPENED_MOCK_CONSEQUENCE_SOURCE_BINDING_DRIFT")

    def state(self):
        db=self._conn(self.controller)
        try:
            rows=db.execute("SELECT operation_id,plan_sha256,prior_sha256,"
                            "state,claims,dispatch_fences,receipt_sha256"
                            " FROM dispatch").fetchall()
            require(len(rows)==1,"EXACT_ONE_CONTROLLER_RECORD_REQUIRED")
            a=rows[0]
            return dict(zip(("operation_id","plan_sha256","prior_sha256",
                             "state","claims","dispatch_fences","receipt_sha256"),a))
        finally:db.close()

    def journal(self):
        db=self._conn(self.controller)
        try:
            return [x[0] for x in db.execute(
                "SELECT event FROM journal ORDER BY seq")]
        finally:db.close()

    def _transition(self,expected,new,event,*,claim=None,fence=None,receipt_sha=None):
        db=self._conn(self.controller)
        try:
            db.execute("BEGIN IMMEDIATE")
            q="UPDATE dispatch SET state=?"
            args=[new]
            if claim is not None:q+=",claims=?";args.append(claim)
            if fence is not None:q+=",dispatch_fences=?";args.append(fence)
            if receipt_sha is not None:q+=",receipt_sha256=?";args.append(receipt_sha)
            q+=" WHERE operation_id=? AND state=?"
            args.extend((self.operation_id,expected))
            cur=db.execute(q,args)
            if cur.rowcount!=1:
                db.execute("ROLLBACK")
                raise MockBoundaryViolation("INVALID_OR_DUPLICATE_STATE_TRANSITION")
            db.execute("INSERT INTO journal(event) VALUES (?)",(event,))
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:db.execute("ROLLBACK")
            raise
        finally:db.close()

    def claim(self):
        self._transition("ISSUED_OFFLINE","CLAIMED_UNRESOLVED",
                         "CLAIM_BEFORE_ANY_DISPATCH",claim=1)

    def abort_pre_dispatch(self):
        require(self.mock_effect_count()==0,"PRE_DISPATCH_ABORT_REQUIRES_NO_MOCK_EFFECT")
        self._transition("CLAIMED_UNRESOLVED","PRE_DISPATCH_NO_EFFECT",
                         "ABORT_BEFORE_DISPATCH_FENCE")
        return self.state()

    def fence_dispatch(self):
        self._transition("CLAIMED_UNRESOLVED","DISPATCH_UNKNOWN",
                         "FENCE_BEFORE_MOCK_PROVIDER_INVOCATION",fence=1)
        # A crash/reopen MUST NOT recreate this volatile one-time call grant.
        self._local_dispatch_armed=True

    def mock_effect_count(self):
        db=self._conn(self.provider)
        try:return db.execute("SELECT COUNT(*) FROM mock_effects").fetchone()[0]
        finally:db.close()

    def mock_send(self,*,drop_response=False):
        require(self._local_dispatch_armed is True
                and self.state()["state"]=="DISPATCH_UNKNOWN"
                and self.state()["dispatch_fences"]==1,
                "MOCK_SEND_NOT_ARMED_OR_ALREADY_CONSUMED_NO_RETRY")
        # Burn before invoking even the local mock provider DB. A process
        # reopened after crash sees UNKNOWN but cannot reconstruct dispatch.
        self._local_dispatch_armed=False
        # The simulator has a durable idempotency/attempt ledger. A second
        # attempt is DENIED, never treated as a new network effect.
        receipt={
            "issuer":"LOCAL_SQLITE_SIMULATOR_NOT_A_REAL_PROVIDER",
            "operation_id":self.operation_id,
            "plan_sha256":self.plan_sha,
            "receipt_kind":"MOCK_EFFECT_COMMITTED",
            "result":"LOCAL_SIMULATED_EFFECT_ONLY",
        }
        rsha=sha(receipt)
        db=self._conn(self.provider)
        try:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("INSERT INTO mock_attempts VALUES (?,?)",
                           (self.operation_id,self.plan_sha))
                db.execute("INSERT INTO mock_effects VALUES (?,?,?,?)",
                           (self.operation_id,self.plan_sha,rsha,canonical(receipt)))
            except sqlite3.IntegrityError as exc:
                db.execute("ROLLBACK")
                raise MockBoundaryViolation(
                    "MOCK_EFFECT_ATTEMPT_ALREADY_RECORDED_DO_NOT_RETRY") from exc
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:db.execute("ROLLBACK")
            raise
        finally:db.close()
        return None if drop_response else copy.deepcopy(receipt)

    def mock_read_only_receipt(self):
        db=self._conn(self.provider)
        try:
            rows=db.execute(
                "SELECT operation_id,plan_sha256,receipt_sha256,receipt_json"
                " FROM mock_effects").fetchall()
            require(len(rows)<=1,"SIMULATOR_MULTIPLE_EFFECTS_INVALID")
            if not rows:return None
            op,plan,digest,serialized=rows[0]
            receipt=json.loads(serialized)
            require(op==self.operation_id and plan==self.plan_sha
                    and digest==sha(receipt)
                    and canonical(receipt)==serialized,
                    "MOCK_PROVIDER_RECEIPT_RECORD_CORRUPT")
            return receipt
        finally:db.close()

    def reconcile(self,receipt=None):
        # A post-fence missing observation is ALWAYS UNKNOWN, even if provider
        # presently reports zero rows; the simulator has no authoritative
        # negative-finality statement or trusted clock.
        require(self.state()["state"]=="DISPATCH_UNKNOWN",
                "ONLY_UNKNOWN_STATE_CAN_BE_RECONCILED")
        # Once reconciliation is attempted, never turn absence of a row into
        # an opportunity to send. UNKNOWN remains terminal for dispatch.
        self._local_dispatch_armed=False
        observed=self.mock_read_only_receipt()
        if observed is None:
            require(receipt is None,"FORGED_RECEIPT_WITHOUT_PROVIDER_ROW")
            return "UNKNOWN"
        if receipt is not None:
            require(type(receipt) is dict and sha(receipt)==sha(observed)
                    and canonical(receipt)==canonical(observed),
                    "RECEIPT_MUST_MATCH_INDEPENDENT_MOCK_PROVIDER_ROW")
        require(observed["issuer"]=="LOCAL_SQLITE_SIMULATOR_NOT_A_REAL_PROVIDER"
                and observed["receipt_kind"]=="MOCK_EFFECT_COMMITTED"
                and observed["operation_id"]==self.operation_id
                and observed["plan_sha256"]==self.plan_sha,
                "EXACT_MOCK_PROVIDER_RECEIPT_SCOPE_REQUIRED")
        self._transition("DISPATCH_UNKNOWN","CONFIRMED_MOCK_EFFECT",
                         "READ_ONLY_MOCK_PROVIDER_EVIDENCE_CONFIRMED",
                         receipt_sha=sha(observed))
        return "CONFIRMED_MOCK_EFFECT"

    def attempt_live_provider(self,*,client=None,approval=None):
        del client,approval
        raise MockBoundaryViolation(
            "REAL_PROVIDER_TRANSPORT_AND_SPENDING_AUTHORITY_NOT_PRESENT")

    def evidence(self):
        db=self._conn(self.provider)
        try:
            attempted=db.execute("SELECT COUNT(*) FROM mock_attempts").fetchone()[0]
            effects=db.execute("SELECT COUNT(*) FROM mock_effects").fetchone()[0]
        finally:db.close()
        return {
            "rule_of_one":RULE,"operation_id":self.operation_id,
            "source_proof_sha256":self.prior_sha,
            "source_plan_sha256":self.plan_sha,
            "controller":self.state(),
            "controller_events":self.journal(),
            "mock_dispatch_attempts":attempted,
            "mock_effect_rows":effects,
            "mock_provider_only":True,
            "real_provider_calls":0,"real_provider_charges_usd":0,
            "real_bank_writes":0,"real_native_effects":0,
            "scorer_calls":0,
            "trusted_real_provider_receipt":False,
            "production_effect_reconciliation_proven":False,
        }

def child():
    parser=argparse.ArgumentParser()
    parser.add_argument("--controller",required=True)
    parser.add_argument("--provider",required=True)
    parser.add_argument("--prior",required=True)
    parser.add_argument("--phase",choices=("crash-after-fence","crash-after-mock-effect"),
                        required=True)
    a=parser.parse_args()
    prior=json.loads(Path(a.prior).read_text())
    simulator=LocalMockConsequence(a.controller,a.provider,prior,create=False)
    simulator.claim()
    simulator.fence_dispatch()
    if a.phase=="crash-after-mock-effect":
        simulator.mock_send(drop_response=True)
    # A process crash after dispatch fence (before provider effect) or after
    # local provider commit must not reset owner or allow a fresh dispatch.
    os._exit(73)

if __name__=="__main__":
    child()
