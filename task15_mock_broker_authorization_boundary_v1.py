"""Task15 offline-only broker authorization core; no real Provider transport.

Rule-of-One: worker proposals cannot reach the local mock sink unless the
broker verifies a pre-pinned Ed25519 root and durably claims the request.
NOT a privileged, OS-isolated service. All secrets used here are synthetic.
"""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

RULE = "TASK15_MOCK_BROKER_AUTHORIZATION_BOUNDARY_V1"
PROFILE = "task15-offline-mock-broker-authorized-once-v1"
SOURCE_SHA = "a09c777b94e6e86edc274983fac8e447343749d7312e88397b39941741899d19"
CASE = "banking:user_task_15:injection_task_0:direct"
MODEL = "gpt-4.1-mini-2025-04-14"
HOST = "api.openai.com"
PATH = "/v1/chat/completions"
MAX_TOKENS = 256
REQUEST_FIELDS = {"profile", "case_id", "arm", "model",
                  "wire_source_sha256", "target", "max_output_tokens",
                  "live", "bank_effects"}
STATEMENT_FIELDS = {"profile", "request_sha256", "source_sha256",
                    "max_calls", "max_total_spend_micro_usd",
                    "no_live_provider", "no_bank_effects", "nonce",
                    "issued_at", "expires_at"}

class BrokerDenied(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise BrokerDenied(reason)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)

def sha(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()

def exact_request():
    """Identifier-only proposal, NOT a native model wire payload or bank tool."""
    return {"profile": PROFILE, "case_id": CASE, "arm": "A",
            "model": MODEL, "wire_source_sha256": SOURCE_SHA,
            "target": {"host": HOST, "path": PATH},
            "max_output_tokens": MAX_TOKENS, "live": False,
            "bank_effects": False}

def verify_grant(request, approval, operator_root, now):
    """Operator root and UTC clock are BROKER-owned, never worker-supplied."""
    require(type(request) is dict and set(request) == REQUEST_FIELDS,
            "UNKNOWN_WORKER_REQUEST_FIELDS")
    require(request == exact_request(), "FROZEN_MODEL_SOURCE_OR_TARGET_DRIFT")
    require(type(approval) is dict and set(approval) == {"statement", "signature_hex"},
            "MISSING_OR_EXTRA_GRANT_FIELDS")
    statement, signature = approval["statement"], approval["signature_hex"]
    require(type(statement) is dict and set(statement) == STATEMENT_FIELDS,
            "MISSING_OR_EXTRA_SIGNED_FIELDS")
    require(type(operator_root) is bytes and len(operator_root) == 32,
            "BROKER_PINNED_OPERATOR_ROOT_REQUIRED")
    require(type(signature) is str and len(signature) == 128 and
            all(c in "0123456789abcdef" for c in signature),
            "MALFORMED_SIGNED_GRANT")
    nonce = statement["nonce"]
    require(type(nonce) is str and len(nonce) == 64 and
            all(c in "0123456789abcdef" for c in nonce),
            "MALFORMED_GRANT_NONCE")
    require(statement["profile"] == PROFILE and
            statement["request_sha256"] == sha(request) and
            statement["source_sha256"] == SOURCE_SHA and
            type(statement["max_calls"]) is int and
            statement["max_calls"] == 1 and
            type(statement["max_total_spend_micro_usd"]) is int and
            statement["max_total_spend_micro_usd"] == 0 and
            statement["no_live_provider"] is True and
            statement["no_bank_effects"] is True,
            "SIGNED_SCOPE_BUDGET_OR_TARGET_DRIFT")
    require(type(now) is datetime and now.tzinfo is not None and
            now.utcoffset().total_seconds() == 0,
            "BROKER_TRUSTED_UTC_CLOCK_REQUIRED")
    try:
        issued = datetime.fromisoformat(statement["issued_at"])
        expires = datetime.fromisoformat(statement["expires_at"])
    except (ValueError, KeyError, TypeError) as exc:
        raise BrokerDenied("INVALID_GRANT_TIME_ENCODING") from exc
    require(issued.tzinfo is not None and expires.tzinfo is not None and
            issued.utcoffset().total_seconds() == 0 and
            expires.utcoffset().total_seconds() == 0 and
            issued <= now < expires and
            0 < (expires - issued).total_seconds() <= 600,
            "EXPIRED_FUTURE_OR_OVERLONG_GRANT")
    try:
        Ed25519PublicKey.from_public_bytes(operator_root).verify(
            bytes.fromhex(signature), canonical(statement).encode("utf-8"))
    except (InvalidSignature, ValueError) as exc:
        raise BrokerDenied("INVALID_PINNED_OPERATOR_SIGNATURE") from exc
    return sha(approval)

class _MockSink:
    """The only sink here: deliberately no socket, HTTP, or bank effects."""
    def __init__(self, fail=False):
        self.calls = 0
        self.fail = fail

    def send(self, request, synthetic_credential):
        self.calls += 1
        if self.fail:
            raise RuntimeError("SYNTHETIC_MOCK_DELIVERY_UNCERTAIN")
        if not synthetic_credential.startswith(b"test-only-host-owned-"):
            raise RuntimeError("NO_TEST_ONLY_BROKER_CREDENTIAL")
        return {"kind": "LOCAL_MOCK_MODEL_RESPONSE_ONLY",
                "model": MODEL, "request_sha256": sha(request),
                "choices": [{"message": {"role": "assistant",
                                          "content": "OFFLINE_MOCK_NO_TOOLS"}}]}

class MockAuthorizationBroker:
    """Trusted-side core, NOT an OS-isolated broker service.

    Operator root, synthetic credential, durable ledger and mock sink are
    configured in this constructor, never accepted inside the worker proposal.
    """
    def __init__(self, ledger_path, *, pinned_operator_root, synthetic_credential,
                 trusted_clock=None, mock_fail=False):
        require(type(pinned_operator_root) is bytes and len(pinned_operator_root) == 32,
                "EXTERNAL_OPERATOR_ROOT_MUST_BE_PINNED")
        require(type(synthetic_credential) is bytes and
                synthetic_credential.startswith(b"test-only-host-owned-") and
                len(synthetic_credential) >= 30,
                "SYNTHETIC_CREDENTIAL_ONLY_IN_OFFLINE_PROOF")
        require(not os.environ.get("OPENAI_API_KEY") and
                not os.environ.get("OPENAI_BASE_URL"),
                "LIVE_PROVIDER_ENVIRONMENT_FORBIDDEN")
        self._root = pinned_operator_root
        self._secret = synthetic_credential
        self._clock = trusted_clock or (lambda: datetime.now(timezone.utc))
        self._sink = _MockSink(fail=mock_fail)
        self.ledger = Path(ledger_path)
        require(not self.ledger.is_symlink() and self.ledger.parent.is_dir(),
                "TRUSTED_LEDGER_LOCATION_REQUIRED")
        self._initialize()

    def _db(self):
        require(self.ledger.is_file() and not self.ledger.is_symlink(),
                "TRUSTED_LEDGER_DISAPPEARED")
        # mode=rw ensures missing ledger is NEVER silently recreated.
        db = sqlite3.connect(self.ledger.resolve().as_uri() + "?mode=rw",
                             uri=True, isolation_level=None, timeout=10)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def _initialize(self):
        # Local proof assumes an operator-owned directory, not a hostile FS.
        db = sqlite3.connect(self.ledger, isolation_level=None, timeout=10)
        try:
            db.executescript("""
              CREATE TABLE IF NOT EXISTS dispatches(
                request_sha TEXT PRIMARY KEY,
                approval_sha TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('DISPATCH_UNKNOWN', 'MOCK_RECORDED')),
                claim_count INTEGER NOT NULL CHECK(claim_count=1),
                response_sha TEXT,
                response_json TEXT,
                CHECK ((state='DISPATCH_UNKNOWN' AND response_sha IS NULL AND response_json IS NULL)
                    OR (state='MOCK_RECORDED' AND response_sha IS NOT NULL AND response_json IS NOT NULL))
              );
              CREATE TABLE IF NOT EXISTS audit(
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                request_sha TEXT NOT NULL, event TEXT NOT NULL
              );
            """)
        finally:
            db.close()
        os.chmod(self.ledger, 0o600)

    @property
    def mock_calls(self):
        return self._sink.calls

    def status(self):
        db = self._db()
        try:
            rows = db.execute("SELECT request_sha,approval_sha,state,claim_count,"
                              "response_sha,response_json FROM dispatches").fetchall()
            events = db.execute("SELECT request_sha,event FROM audit ORDER BY seq").fetchall()
        finally:
            db.close()
        for request_sha, _, state, claim_count, response_sha, response_json in rows:
            require(claim_count == 1, "DURABLE_CLAIM_COUNT_INVALID")
            require((state == "DISPATCH_UNKNOWN" and response_sha is None and
                     response_json is None) or
                    (state == "MOCK_RECORDED" and
                     sha(json.loads(response_json)) == response_sha),
                    "DURABLE_MOCK_RECEIPT_INTEGRITY_FAILURE")
            mine = [event for ref, event in events if ref == request_sha]
            require(mine in (["CLAIMED_BEFORE_MOCK_SINK"],
                             ["CLAIMED_BEFORE_MOCK_SINK", "MOCK_SINK_RECORDED"]),
                    "INVALID_DURABLE_AUDIT_JOURNAL")
            require((state == "MOCK_RECORDED") == (len(mine) == 2),
                    "BROKER_LEDGER_STATE_EVENT_MISMATCH")
        return {"rows": len(rows), "events": len(events),
                "states": [r[2] for r in rows],
                "claims": [r[3] for r in rows]}

    def execute(self, envelope):
        require(type(envelope) is dict and set(envelope) == {"request", "approval"},
                "ONLY_WORKER_PROPOSAL_AND_SIGNATURE_ALLOWED")
        request, approval = envelope["request"], envelope["approval"]
        approval_sha = verify_grant(request, approval, self._root, self._clock())
        request_sha = sha(request)
        db = self._db()
        try:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("INSERT INTO dispatches VALUES (?,?,'DISPATCH_UNKNOWN',1,NULL,NULL)",
                           (request_sha, approval_sha))
            except sqlite3.IntegrityError as exc:
                raise BrokerDenied("ONE_SHOT_REQUEST_ALREADY_CONSUMED_OR_UNKNOWN") from exc
            db.execute("INSERT INTO audit(request_sha,event) VALUES"
                       " (?,'CLAIMED_BEFORE_MOCK_SINK')", (request_sha,))
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()
        # Ambiguous mock delivery always stays UNKNOWN; never retry.
        result = self._sink.send(request, self._secret)
        require(type(result) is dict and
                result.get("kind") == "LOCAL_MOCK_MODEL_RESPONSE_ONLY",
                "MOCK_SINK_RETURN_UNSUPPORTED")
        response_sha = sha(result)
        db = self._db()
        try:
            db.execute("BEGIN IMMEDIATE")
            update = db.execute("UPDATE dispatches SET state='MOCK_RECORDED',"
                                "response_sha=?,response_json=? WHERE request_sha=? "
                                "AND approval_sha=? AND state='DISPATCH_UNKNOWN'",
                                (response_sha, canonical(result), request_sha, approval_sha))
            require(update.rowcount == 1, "CLAIM_OWNERSHIP_LOST")
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
