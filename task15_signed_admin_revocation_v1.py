"""#285 mock-only broker-side signed administrator revocation.

Rule-of-One:
  An administrative revoke is impossible without a verified independent,
  narrowly scoped, short-lived, single-use TEST Ed25519 admin signature.
  The signature and nonce are durably claimed in the SAME SQLite transaction
  as the targeted request revocation. A worker socket never accepts admin ops.

This DOES NOT establish actual company/operator enrollment, hardened Docker
host identity or live Provider credential custody. No Provider HTTP sender.
"""
from __future__ import annotations

from datetime import datetime,timezone
import hashlib
import json
import sqlite3

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from task15_mock_broker_authorization_boundary_v1 import (
    BrokerDenied,canonical,sha,exact_request,require
)
from task15_stolen_session_revocation_fence_v1 import (
    RevocableMockAuthorizationBroker
)

RULE="TASK15_SIGNED_ADMIN_REVOCATION_V1"
ACTION="REVOKE_FROZEN_TASK15_MOCK_REQUEST"
DOMAIN="task15.offline.signed-admin-revocation.v1"
FIELDS={"domain","action","request_sha256","nonce","issued_at",
        "expires_at","no_live_provider","max_spend_micro_usd",
        "bank_effects"}

def verify_admin_command(envelope,operator_root,model_root,now):
    require(type(operator_root) is bytes and len(operator_root)==32 and
            type(model_root) is bytes and len(model_root)==32 and
            operator_root!=model_root,
            "INDEPENDENT_ADMIN_ROOT_DISTINCT_FROM_MODEL_SIGNER_REQUIRED")
    require(type(envelope) is dict and
            set(envelope)=={"statement","signature_hex"},
            "SIGNED_ADMIN_COMMAND_ENVELOPE_ONLY")
    statement,sig=envelope["statement"],envelope["signature_hex"]
    require(type(statement) is dict and set(statement)==FIELDS,
            "FROZEN_ADMIN_COMMAND_FIELDS_REQUIRED")
    require(statement["domain"]==DOMAIN and
            statement["action"]==ACTION and
            statement["request_sha256"]==sha(exact_request()) and
            statement["no_live_provider"] is True and
            type(statement["max_spend_micro_usd"]) is int and
            statement["max_spend_micro_usd"]==0 and
            statement["bank_effects"] is False,
            "ADMIN_COMMAND_ACTION_TARGET_OR_BUDGET_DRIFT")
    nonce=statement["nonce"]
    require(type(nonce) is str and len(nonce)==64 and
            all(ch in "0123456789abcdef" for ch in nonce),
            "MALFORMED_ADMIN_COMMAND_NONCE")
    require(type(sig) is str and len(sig)==128 and
            all(ch in "0123456789abcdef" for ch in sig),
            "MALFORMED_ADMIN_COMMAND_SIGNATURE")
    require(type(now) is datetime and now.tzinfo is not None and
            now.utcoffset().total_seconds()==0,
            "BROKER_ADMIN_TRUSTED_UTC_CLOCK_REQUIRED")
    try:
        issued=datetime.fromisoformat(statement["issued_at"])
        expires=datetime.fromisoformat(statement["expires_at"])
    except (ValueError,TypeError,KeyError) as e:
        raise BrokerDenied("MALFORMED_ADMIN_EXPIRY") from e
    require(issued.tzinfo is not None and expires.tzinfo is not None and
            issued.utcoffset().total_seconds()==0 and
            expires.utcoffset().total_seconds()==0 and
            issued<=now<expires and
            0<(expires-issued).total_seconds()<=300,
            "ADMIN_COMMAND_EXPIRED_FUTURE_OR_OVERLONG")
    try:
        Ed25519PublicKey.from_public_bytes(operator_root).verify(
            bytes.fromhex(sig),canonical(statement).encode("utf-8"))
    except (InvalidSignature,ValueError) as e:
        raise BrokerDenied("INVALID_INDEPENDENT_ADMIN_SIGNATURE") from e
    return (nonce,sha(envelope))

class SignedAdminRevocationBroker(RevocableMockAuthorizationBroker):
    """New proof-only subclass: inherited *unsigned* revoke is hard-disabled."""
    def __init__(self,ledger_path,*,pinned_admin_root,**kwargs):
        model_root=kwargs.get("pinned_operator_root")
        require(type(pinned_admin_root) is bytes and len(pinned_admin_root)==32
                and type(model_root) is bytes and len(model_root)==32 and
                pinned_admin_root!=model_root,
                "SEPARATE_SIGNED_ADMIN_ROOT_REQUIRED")
        self._admin_root=pinned_admin_root
        super().__init__(ledger_path,**kwargs)

    def _initialize(self):
        super()._initialize()
        db=self._db()
        try:
            db.executescript("""
              CREATE TABLE IF NOT EXISTS admin_commands (
                nonce TEXT PRIMARY KEY,
                command_sha TEXT UNIQUE NOT NULL,
                request_sha TEXT NOT NULL,
                root_sha TEXT NOT NULL
              );
              CREATE TABLE IF NOT EXISTS admin_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nonce TEXT UNIQUE NOT NULL,
                command_sha TEXT NOT NULL,
                event TEXT NOT NULL CHECK(event='SIGNED_ADMIN_REVOCATION_COMMITTED')
              );
            """)
        finally:
            db.close()

    def revoke(self,*args,**kwargs):
        raise BrokerDenied("UNSIGNED_ADMIN_REVOCATION_FORBIDDEN")

    def revoke_signed(self,envelope):
        # This is callable only in trusted host exec mode; never by worker IPC.
        nonce,cmd_sha=verify_admin_command(
            envelope,self._admin_root,self._root,self._clock())
        request_sha=envelope["statement"]["request_sha256"]
        db=self._db()
        try:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("INSERT INTO admin_commands VALUES (?,?,?,?)",
                           (nonce,cmd_sha,request_sha,
                            hashlib.sha256(self._admin_root).hexdigest()))
            except sqlite3.IntegrityError as e:
                raise BrokerDenied("ADMIN_COMMAND_NONCE_ALREADY_CONSUMED") from e
            try:
                db.execute("INSERT INTO revoked_requests VALUES"
                           " (?,'STOLEN_WORKER_SESSION',1)",(request_sha,))
            except sqlite3.IntegrityError as e:
                raise BrokerDenied("TARGET_ALREADY_REVOKED") from e
            db.execute("INSERT INTO revocation_audit(request_sha,event)"
                       " VALUES (?,'REVOCATION_COMMITTED')",(request_sha,))
            db.execute("INSERT INTO admin_audit(nonce,command_sha,event)"
                       " VALUES (?,?,'SIGNED_ADMIN_REVOCATION_COMMITTED')",
                       (nonce,cmd_sha))
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()
        return {"state":"REVOKED","request_sha256":request_sha,
                "admin_command_sha256":cmd_sha,"consumed_nonce":nonce,
                "signed_admin_events":1}

    def admin_status(self):
        db=self._db()
        try:
            cmds=db.execute("SELECT nonce,command_sha,request_sha,root_sha"
                            " FROM admin_commands").fetchall()
            audit=db.execute("SELECT nonce,command_sha,event"
                             " FROM admin_audit ORDER BY id").fetchall()
            revoked=db.execute("SELECT request_sha FROM revoked_requests").fetchall()
        finally:
            db.close()
        require(len(cmds)==len(audit)==len(revoked) and
                all((a[0],a[1])==(c[0],c[1]) and
                    a[2]=="SIGNED_ADMIN_REVOCATION_COMMITTED" and
                    c[2]==revoked[i][0] and
                    c[3]==hashlib.sha256(self._admin_root).hexdigest()
                    for i,(a,c) in enumerate(zip(audit,cmds))),
                "SIGNED_ADMIN_AUDIT_DATABASE_INTEGRITY_FAILED")
        return {"signed_commands":len(cmds),"audit_events":len(audit),
                "revocations":len(revoked)}
