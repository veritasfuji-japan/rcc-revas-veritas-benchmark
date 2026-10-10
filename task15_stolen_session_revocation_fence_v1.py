"""Task15 V1 — local mock-only durable revocation vs stolen worker session key.

A stolen worker-session key plus a copied valid signed TEST grant MAY WIN the
first permitted mock dispatch before broker-side revocation. This proof does
not claim it can prevent that. Once the trusted broker's revocation commits,
every *new* claim for this exact frozen request is denied inside the SAME
SQLite BEGIN IMMEDIATE critical section as single-use consumption.

Only the trusted host/broker can invoke revoke(); worker IPC exposes NO
revocation command. Trusted host, clock, Docker daemon and signer assumed.
No live Provider transport, credential, billing, or bank effects.
"""
from __future__ import annotations

import json
import sqlite3

from task15_mock_broker_authorization_boundary_v1 import (
    BrokerDenied, MockAuthorizationBroker, canonical, exact_request, require,
    sha, verify_grant
)

RULE = "TASK15_STOLEN_SESSION_REVOCATION_FENCE_V1"
REVOKED = "TRUSTED_BROKER_REQUEST_REVOKED"

class RevocableMockAuthorizationBroker(MockAuthorizationBroker):
    """New isolated proof class; legacy frozen #279–#282 paths unchanged."""

    def _initialize(self):
        super()._initialize()
        db = self._db()
        try:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS revoked_requests (
                    request_sha TEXT PRIMARY KEY,
                    reason TEXT NOT NULL CHECK(reason='STOLEN_WORKER_SESSION'),
                    sequence INTEGER NOT NULL CHECK(sequence=1)
                );
                CREATE TABLE IF NOT EXISTS revocation_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_sha TEXT NOT NULL,
                    event TEXT NOT NULL CHECK(event='REVOCATION_COMMITTED')
                );
            """)
        finally:
            db.close()

    def revoke(self, request_sha):
        """Trusted-side only: no worker-facing IPC method exists.

        The operator's authority to invoke this method is a bounded trusted
        assumption, NOT independently enrolled/attested human approval.
        """
        require(type(request_sha) is str and len(request_sha) == 64 and
                all(c in "0123456789abcdef" for c in request_sha) and
                request_sha == sha(exact_request()),
                "EXACT_FROZEN_REQUEST_SHA_REQUIRED_FOR_TRUSTED_REVOCATION")
        db = self._db()
        try:
            db.execute("BEGIN IMMEDIATE")
            result = db.execute(
                "INSERT OR IGNORE INTO revoked_requests(request_sha,reason,sequence)"
                " VALUES (?,'STOLEN_WORKER_SESSION',1)", (request_sha,))
            if result.rowcount == 1:
                db.execute("INSERT INTO revocation_audit(request_sha,event)"
                           " VALUES (?,'REVOCATION_COMMITTED')", (request_sha,))
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()
        return {"request_sha256": request_sha, "state": "REVOKED",
                "new_revocation": result.rowcount == 1}

    def revocation_status(self):
        db = self._db()
        try:
            rows = db.execute("SELECT request_sha,reason,sequence"
                              " FROM revoked_requests ORDER BY request_sha").fetchall()
            events = db.execute("SELECT request_sha,event"
                                " FROM revocation_audit ORDER BY id").fetchall()
        finally:
            db.close()
        require(len(rows) == len(events) and
                all(row[1:] == ("STOLEN_WORKER_SESSION", 1) for row in rows)
                and events == [(row[0], "REVOCATION_COMMITTED") for row in rows],
                "DURABLE_REVOCATION_AUDIT_INTEGRITY_ERROR")
        return {"revoked_count": len(rows), "revocation_events": len(events),
                "request_shas": [row[0] for row in rows]}

    def execute(self, envelope):
        require(type(envelope) is dict and set(envelope) == {"request", "approval"},
                "ONLY_WORKER_PROPOSAL_AND_SIGNATURE_ALLOWED")
        request, approval = envelope["request"], envelope["approval"]
        approval_sha = verify_grant(request, approval, self._root, self._clock())
        request_sha = sha(request)
        db = self._db()
        try:
            db.execute("BEGIN IMMEDIATE")
            # THE CENTRAL INVARIANT: revocation and claim are serialized by
            # the *same* SQLite writer lock, not check-then-use across DBs.
            revoked = db.execute(
                "SELECT 1 FROM revoked_requests WHERE request_sha=?",
                (request_sha,)).fetchone()
            require(revoked is None, REVOKED)
            try:
                db.execute(
                    "INSERT INTO dispatches VALUES"
                    " (?,?,'DISPATCH_UNKNOWN',1,NULL,NULL)",
                    (request_sha, approval_sha))
            except sqlite3.IntegrityError as exc:
                raise BrokerDenied(
                    "ONE_SHOT_REQUEST_ALREADY_CONSUMED_OR_UNKNOWN") from exc
            db.execute("INSERT INTO audit(request_sha,event) VALUES"
                       " (?,'CLAIMED_BEFORE_MOCK_SINK')", (request_sha,))
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()
        # A revocation AFTER this durable claim CANNOT undo an effect.
        # A delivery failure remains UNKNOWN and the claim stays consumed.
        result = self._sink.send(request, self._secret)
        require(type(result) is dict and
                result.get("kind") == "LOCAL_MOCK_MODEL_RESPONSE_ONLY",
                "MOCK_SINK_RETURN_UNSUPPORTED")
        response_sha = sha(result)
        db = self._db()
        try:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                "UPDATE dispatches SET state='MOCK_RECORDED',"
                "response_sha=?,response_json=? WHERE request_sha=? "
                "AND approval_sha=? AND state='DISPATCH_UNKNOWN'",
                (response_sha, canonical(result), request_sha, approval_sha))
            require(changed.rowcount == 1, "CLAIM_OWNERSHIP_LOST")
            db.execute("INSERT INTO audit(request_sha,event) VALUES"
                       " (?,'MOCK_SINK_RECORDED')", (request_sha,))
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()
        return {"state": "MOCK_RECORDED", "request_sha256": request_sha,
                "response_sha256": response_sha, "response": result,
                "real_provider_requests": 0, "real_provider_spend_usd": 0,
                "bank_effects": 0}
