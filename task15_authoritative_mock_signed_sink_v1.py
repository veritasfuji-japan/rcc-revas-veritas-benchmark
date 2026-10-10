"""Offline Task15 signed mock effect sink. Bounded authority is this sink only.

Unlike the legacy local simulator controller, this separately persisted sink
never trusts controller state alone. A legacy generic reconcile may change its
own controller, but CANNOT promote the signed sink; every signed-sink read
revalidates its pinned root, signed envelope and mock effect row.

There is no live provider, real issuer identity, real effect or production
system-wide bypass resistance claim. A caller with direct DB write privileges
is outside this trust boundary; tampering is detected on audited reads.
"""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3

from task15_mock_effect_unknown_reconcile_v1 import (
    LocalMockConsequence,canonical,sha,
)
from task15_mock_signed_receipt_trust_boundary_v1 import (
    BoundedSignedMockRecovery,FrozenOfflineMockTrust,MockTrustViolation,
)

RULE="TASK15_AUTHORITATIVE_MOCK_SIGNED_SINK_V1"
PREDECESSOR_MAIN="4a5c6cedef2944fd6e15c1eea4ecbb17dfd125f6"

def require(ok,why):
    if not ok:raise MockTrustViolation(why)

class AuthoritativeMockSignedSinkV1:
    """One SQLite-authoritative mock judgment for one bound source operation."""

    def __init__(self,path,sim,trust,*,create=True):
        require(type(sim) is LocalMockConsequence
                and type(trust) is FrozenOfflineMockTrust,
                "EXACT_OFFLINE_MOCK_AND_FROZEN_ROOT_REQUIRED")
        self.path=Path(path)
        self.sim=sim
        self.trust=trust
        self.gate=BoundedSignedMockRecovery(sim,trust)
        self.source_operation_id=sim.operation_id
        self.source_plan_sha256=sim.plan_sha
        self.source_prior_sha256=sim.prior_sha
        self.root_key_id=trust.key_id
        if create:
            require(not self.path.exists() and self.path.parent.is_dir(),
                    "NEW_ISOLATED_SIGNED_SINK_REQUIRED")
            db=self._connect(create=True)
            try:
                db.execute("""CREATE TABLE signed_effect_judgment(
                    operation_id TEXT PRIMARY KEY,
                    plan_sha256 TEXT NOT NULL,
                    predecessor_sha256 TEXT NOT NULL,
                    root_key_id TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN (
                        'DISPATCH_UNKNOWN','CONFIRMED_SIGNED_MOCK_EFFECT')),
                    envelope_sha256 TEXT,
                    envelope_json TEXT,
                    CHECK ((state='DISPATCH_UNKNOWN' AND
                            envelope_sha256 IS NULL AND envelope_json IS NULL) OR
                           (state='CONFIRMED_SIGNED_MOCK_EFFECT' AND
                            envelope_sha256 IS NOT NULL AND envelope_json IS NOT NULL))
                )""")
                db.execute("""CREATE TABLE sink_events(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL
                )""")
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO signed_effect_judgment VALUES"
                           "(?,?,?,?,'DISPATCH_UNKNOWN',NULL,NULL)",
                           (self.source_operation_id,self.source_plan_sha256,
                            self.source_prior_sha256,self.root_key_id))
                db.execute("INSERT INTO sink_events(kind) VALUES"
                           "('AUTHORITATIVE_MOCK_SINK_INIT_UNKNOWN')")
                db.execute("COMMIT")
            finally:db.close()
        else:
            require(self.path.is_file(),"EXISTING_SINK_REQUIRED")
        self._validate_source()

    def _connect(self,*,create=False):
        db=sqlite3.connect(self.path,timeout=20,isolation_level=None)
        db.execute("PRAGMA busy_timeout=20000")
        if create:db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def _record(self):
        db=sqlite3.connect("file:"+str(self.path.resolve())+"?mode=ro",uri=True)
        try:
            result=db.execute(
                "SELECT operation_id,plan_sha256,predecessor_sha256,"
                "root_key_id,state,envelope_sha256,envelope_json"
                " FROM signed_effect_judgment").fetchall()
            events=[r[0] for r in db.execute(
                "SELECT kind FROM sink_events ORDER BY seq").fetchall()]
        except (sqlite3.Error,ValueError) as exc:
            raise MockTrustViolation("MALFORMED_OR_UNREADABLE_SIGNED_SINK") from exc
        finally:db.close()
        require(len(result)==1,"EXACT_ONE_SIGNED_MOCK_JUDGMENT_REQUIRED")
        return result[0],events

    def _validate_source(self):
        self.trust._read_pin()
        row,events=self._record()
        require(row[0]==self.source_operation_id
                and row[1]==self.source_plan_sha256
                and row[2]==self.source_prior_sha256
                and row[3]==self.root_key_id,
                "AUTHORITATIVE_SIGNED_SINK_SOURCE_OR_ROOT_CHANGED")
        require(events and events[0]=="AUTHORITATIVE_MOCK_SINK_INIT_UNKNOWN",
                "SIGNED_SINK_AUDIT_JOURNAL_MISSING")
        return row,events

    def status(self):
        """Never return CONFIRMED without re-verifying underlying signature."""
        row,events=self._validate_source()
        if row[4]=="DISPATCH_UNKNOWN":
            require(row[5] is None and row[6] is None and len(events)==1,
                    "UNEXPECTED_UNSIGNED_SINK_PROMOTION_OR_EVENT")
            return "DISPATCH_UNKNOWN"
        require(row[4]=="CONFIRMED_SIGNED_MOCK_EFFECT"
                and len(events)==2
                and events[1]=="VERIFIED_MOCK_SIGNED_RECEIPT_ADMITTED"
                and type(row[5]) is str and type(row[6]) is str,
                "SIGNED_SINK_STATE_OR_EVENT_NOT_ADMISSIBLE")
        try:envelope=json.loads(row[6])
        except (TypeError,ValueError) as exc:
            raise MockTrustViolation("SINK_SIGNED_ENVELOPE_MALFORMED") from exc
        require(canonical(envelope)==row[6] and sha(envelope)==row[5],
                "SINK_ENVELOPE_HASH_MISMATCH")
        real_envelope=self.gate._provider_signed_row()
        require(real_envelope is not None and
                canonical(real_envelope)==canonical(envelope),
                "SINK_ROW_NOT_BACKED_BY_MOCK_PROVIDER_SIGNATURE")
        self.trust.verify(envelope,self.sim)
        return "CONFIRMED_SIGNED_MOCK_EFFECT"

    def promote(self):
        """Signed mock evidence is necessary for ANY authoritative promotion."""
        require(self.status()=="DISPATCH_UNKNOWN",
                "SINK_ALREADY_CONSUMED_NO_REPLAY")
        state=self.sim.state()
        require(state["state"]=="DISPATCH_UNKNOWN"
                and state["dispatch_fences"]==1
                and state["claims"]==1,
                "UNFENCED_OR_LEGACY_CONFIRMED_CONTROLLER_NOT_AUTHORITATIVE")
        # Never revive mock dispatch rights, including on missing signatures.
        self.sim._local_dispatch_armed=False
        receipt=self.sim.mock_read_only_receipt()
        envelope=self.gate._provider_signed_row()
        if receipt is None or envelope is None:
            require(not (receipt is None and envelope is not None),
                    "SIGNATURE_WITHOUT_MOCK_EFFECT_ROW")
            return "DISPATCH_UNKNOWN"
        self.trust.verify(envelope,self.sim)
        serialized=canonical(envelope)
        db=self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            updated=db.execute(
                "UPDATE signed_effect_judgment SET"
                " state='CONFIRMED_SIGNED_MOCK_EFFECT',"
                " envelope_sha256=?, envelope_json=?"
                " WHERE operation_id=? AND plan_sha256=?"
                " AND predecessor_sha256=? AND root_key_id=?"
                " AND state='DISPATCH_UNKNOWN'",
                (sha(envelope),serialized,self.source_operation_id,
                 self.source_plan_sha256,self.source_prior_sha256,self.root_key_id))
            if updated.rowcount!=1:
                db.execute("ROLLBACK")
                raise MockTrustViolation("SINK_ATOMIC_DUPLICATE_OR_DRIFT_REFUSED")
            db.execute("INSERT INTO sink_events(kind) VALUES"
                       "('VERIFIED_MOCK_SIGNED_RECEIPT_ADMITTED')")
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:db.execute("ROLLBACK")
            raise
        finally:db.close()
        return self.status()

    def observation(self):
        state=self.status()
        row,events=self._record()
        return {
            "rule_of_one":RULE,
            "determination":"ONLY_SIGNED_MOCK_RECEIPT_BECOMES_AUTHORITATIVE_IN_NEW_SINK",
            "operation_id":self.source_operation_id,
            "source_plan_sha256":self.source_plan_sha256,
            "source_prior_sha256":self.source_prior_sha256,
            "test_root_key_id":self.root_key_id,
            "authoritative_sink_state":state,
            "sink_events":events,
            "legacy_controller_state":self.sim.state()["state"],
            "signed_envelope_sha256":row[5],
            "real_provider_authority_issued":False,
            "real_provider_calls":0,"real_provider_charges_usd":0,
            "real_bank_writes":0,"real_native_effects":0,
            "system_wide_bypass_resistance_proven":False,
            "real_provider_authenticity_proven":False,
        }

    def attempt_live_provider(self,*,transport=None,approval=None):
        del transport,approval
        raise MockTrustViolation("REAL_PROVIDER_DISPATCH_NOT_IN_SIGNED_MOCK_SINK")
