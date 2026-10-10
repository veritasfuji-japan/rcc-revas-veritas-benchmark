"""Task15 offline proof-only governance root for admin-key lifecycle.

An independently pinned TEST governance signer authorizes enrollment, monotonic
rotation and terminal revocation of TEST administrator public keys. Both
lifecycle changes and admin-command use serialize in the same broker-owned
SQLite BEGIN IMMEDIATE decision boundary.

This is not independent real-world identity enrollment: the trusted host
configures the governance root and owns the SQLite/Docker runtime. Never
store real Provider credentials or expose a live sender.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import sqlite3

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from task15_mock_broker_authorization_boundary_v1 import (
    BrokerDenied, canonical, exact_request, require, sha
)
from task15_signed_admin_revocation_v1 import (
    SignedAdminRevocationBroker, verify_admin_command
)

RULE = "TASK15_GOVERNED_ADMIN_ROOT_LIFECYCLE_V1"
DOMAIN = "task15.offline.admin-root-lifecycle.v1"
OPERATIONS = {"ENROLL", "ROTATE", "REVOKE"}
FIELDS = {"domain", "operation", "epoch", "admin_root_hex",
          "previous_root_sha256", "nonce", "issued_at", "expires_at",
          "no_live_provider", "max_spend_micro_usd", "bank_effects"}
PLACEHOLDER_ROOT = bytes.fromhex(
    "b2e03c21f959c179e286e9a608402b13a7da2f94acc897c74d5e1f3c43fbba98"
)
NO_ROOT = ""
EVENT = "SIGNED_GOVERNANCE_ROOT_TRANSITION_COMMITTED"


def _hex(value, length):
    return (type(value) is str and len(value) == length and
            all(c in "0123456789abcdef" for c in value))


def verify_lifecycle_manifest(envelope, governance_root, model_root, now):
    require(type(governance_root) is bytes and len(governance_root) == 32 and
            type(model_root) is bytes and len(model_root) == 32 and
            governance_root != model_root and
            governance_root != PLACEHOLDER_ROOT,
            "SEPARATE_PINNED_GOVERNANCE_ROOT_REQUIRED")
    require(type(envelope) is dict and
            set(envelope) == {"statement", "signature_hex"},
            "EXACT_SIGNED_GOVERNANCE_ENVELOPE_REQUIRED")
    statement, signature = envelope["statement"], envelope["signature_hex"]
    require(type(statement) is dict and set(statement) == FIELDS,
            "EXACT_SIGNED_GOVERNANCE_STATEMENT_FIELDS_REQUIRED")
    require(statement["domain"] == DOMAIN and
            statement["operation"] in OPERATIONS and
            type(statement["epoch"]) is int and
            1 <= statement["epoch"] <= 2**31-1 and
            statement["no_live_provider"] is True and
            type(statement["max_spend_micro_usd"]) is int and
            statement["max_spend_micro_usd"] == 0 and
            statement["bank_effects"] is False,
            "GOVERNANCE_SCOPE_EPOCH_OR_BUDGET_DRIFT")
    root = statement["admin_root_hex"]
    must_revoke = statement["operation"] == "REVOKE"
    require((root == NO_ROOT if must_revoke else _hex(root, 64)) and
            (root == NO_ROOT or
             bytes.fromhex(root) not in (governance_root, model_root, PLACEHOLDER_ROOT)),
            "UNSAFE_GOVERNANCE_ADMIN_ROOT_VALUE")
    prev = statement["previous_root_sha256"]
    require(prev == NO_ROOT or _hex(prev, 64),
            "MALFORMED_PREVIOUS_ADMIN_ROOT_HASH")
    require(_hex(statement["nonce"], 64) and _hex(signature, 128),
            "MALFORMED_GOVERNANCE_NONCE_OR_SIGNATURE")
    require(type(now) is datetime and now.tzinfo is not None and
            now.utcoffset().total_seconds() == 0,
            "TRUSTED_GOVERNANCE_UTC_CLOCK_REQUIRED")
    try:
        issued = datetime.fromisoformat(statement["issued_at"])
        expires = datetime.fromisoformat(statement["expires_at"])
    except (TypeError, KeyError, ValueError) as exc:
        raise BrokerDenied("INVALID_GOVERNANCE_TIME_ENCODING") from exc
    require(issued.tzinfo is not None and expires.tzinfo is not None and
            issued.utcoffset().total_seconds() == 0 and
            expires.utcoffset().total_seconds() == 0 and
            issued <= now < expires and
            0 < (expires - issued).total_seconds() <= 300,
            "GOVERNANCE_MANIFEST_EXPIRED_FUTURE_OR_OVERLONG")
    try:
        Ed25519PublicKey.from_public_bytes(governance_root).verify(
            bytes.fromhex(signature), canonical(statement).encode("utf-8"))
    except (ValueError, InvalidSignature) as exc:
        raise BrokerDenied("INVALID_PINNED_GOVERNANCE_SIGNATURE") from exc
    return sha(envelope)


class GovernedAdminRootBroker(SignedAdminRevocationBroker):
    """Offline trusted core, not production IAM or Docker runtime.

    The parent TEST-admin root is a deliberately unusable placeholder. Every
    real signed-admin revocation is independently checked against the latest
    ACTIVE key loaded from the same durable SQLite transaction as revocation.
    """
    def __init__(self, ledger_path, *, pinned_governance_root, **kwargs):
        model_root = kwargs.get("pinned_operator_root")
        require(type(pinned_governance_root) is bytes and
                len(pinned_governance_root) == 32 and
                type(model_root) is bytes and len(model_root) == 32 and
                pinned_governance_root != model_root and
                pinned_governance_root != PLACEHOLDER_ROOT and
                model_root != PLACEHOLDER_ROOT,
                "INDEPENDENT_FROZEN_TEST_GOVERNANCE_ROOT_REQUIRED")
        self._governance_root = pinned_governance_root
        super().__init__(
            ledger_path, pinned_admin_root=PLACEHOLDER_ROOT, **kwargs
        )

    def _initialize(self):
        super()._initialize()
        db = self._db()
        try:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS governed_admin_roots (
                    epoch INTEGER PRIMARY KEY,
                    root_hex TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('ACTIVE','REVOKED')),
                    nonce TEXT NOT NULL UNIQUE,
                    signed_manifest_sha TEXT NOT NULL UNIQUE,
                    previous_root_sha TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS governed_admin_root_audit (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    epoch INTEGER NOT NULL UNIQUE,
                    operation TEXT NOT NULL,
                    signed_manifest_sha TEXT NOT NULL,
                    event TEXT NOT NULL CHECK(event='SIGNED_GOVERNANCE_ROOT_TRANSITION_COMMITTED')
                );
            """)
        finally:
            db.close()

    @staticmethod
    def _current(db):
        return db.execute(
            "SELECT epoch,root_hex,state FROM governed_admin_roots "
            "ORDER BY epoch DESC LIMIT 1"
        ).fetchone()

    def transition_signed(self, manifest):
        signature_sha = verify_lifecycle_manifest(
            manifest, self._governance_root, self._root, self._clock()
        )
        s = manifest["statement"]
        db = self._db()
        try:
            db.execute("BEGIN IMMEDIATE")
            last = self._current(db)
            if last is None:
                require(s["operation"] == "ENROLL" and
                        s["epoch"] == 1 and
                        s["previous_root_sha256"] == NO_ROOT,
                        "GOVERNANCE_FIRST_BOOTSTRAP_MANIFEST_REQUIRED")
            else:
                epoch, old_hex, state = last
                require(state == "ACTIVE", "TERMINAL_GOVERNANCE_REVOCATION")
                require(s["operation"] in ("ROTATE", "REVOKE") and
                        s["epoch"] == epoch + 1 and
                        s["previous_root_sha256"] ==
                        hashlib.sha256(bytes.fromhex(old_hex)).hexdigest(),
                        "GOVERNANCE_MONOTONIC_EPOCH_OR_PREDECESSOR_DRIFT")
                if s["operation"] == "ROTATE":
                    require(s["admin_root_hex"] != old_hex,
                            "GOVERNANCE_SAME_ADMIN_ROOT_ROTATION_FORBIDDEN")
            db.execute(
                "INSERT INTO governed_admin_roots VALUES (?,?,?,?,?,?)",
                (s["epoch"], s["admin_root_hex"],
                 "REVOKED" if s["operation"] == "REVOKE" else "ACTIVE",
                 s["nonce"], signature_sha, s["previous_root_sha256"])
            )
            db.execute(
                "INSERT INTO governed_admin_root_audit(epoch,operation,signed_manifest_sha,event)"
                " VALUES (?,?,?,?)", (s["epoch"], s["operation"], signature_sha, EVENT)
            )
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()
        return {"epoch": s["epoch"],
                "state": "REVOKED" if s["operation"] == "REVOKE" else "ACTIVE",
                "signed_manifest_sha256": signature_sha}

    def revoke_signed(self, envelope):
        db = self._db()
        try:
            # Acquire this write lock BEFORE reading current root and validating.
            # A signed ROTATE or REVOKE cannot race in after verification
            # but before the signed admin request is durably consumed.
            db.execute("BEGIN IMMEDIATE")
            current = self._current(db)
            require(current is not None and current[2] == "ACTIVE",
                    "NO_ACTIVE_GOVERNED_ADMIN_ROOT")
            epoch, root_hex, _ = current
            admin_root = bytes.fromhex(root_hex)
            nonce, command_sha = verify_admin_command(
                envelope, admin_root, self._root, self._clock())
            request_sha = envelope["statement"]["request_sha256"]
            try:
                db.execute("INSERT INTO admin_commands VALUES (?,?,?,?)",
                           (nonce, command_sha, request_sha,
                            hashlib.sha256(admin_root).hexdigest()))
            except sqlite3.IntegrityError as exc:
                raise BrokerDenied("ADMIN_COMMAND_NONCE_ALREADY_CONSUMED") from exc
            try:
                db.execute("INSERT INTO revoked_requests VALUES"
                           " (?,'STOLEN_WORKER_SESSION',1)", (request_sha,))
            except sqlite3.IntegrityError as exc:
                raise BrokerDenied("TARGET_ALREADY_REVOKED") from exc
            db.execute(
                "INSERT INTO revocation_audit(request_sha,event)"
                " VALUES (?,'REVOCATION_COMMITTED')", (request_sha,))
            db.execute(
                "INSERT INTO admin_audit(nonce,command_sha,event)"
                " VALUES (?,?,'SIGNED_ADMIN_REVOCATION_COMMITTED')",
                (nonce, command_sha))
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()
        return {"state": "REVOKED", "used_admin_epoch": epoch,
                "request_sha256": request_sha,
                "signed_admin_command_sha256": command_sha,
                "provider_calls": 0, "spend_usd": 0, "bank_effects": 0}

    def root_status(self):
        db = self._db()
        try:
            roots = db.execute(
                "SELECT epoch,root_hex,state,nonce,signed_manifest_sha,previous_root_sha"
                " FROM governed_admin_roots ORDER BY epoch"
            ).fetchall()
            audit = db.execute(
                "SELECT epoch,operation,signed_manifest_sha,event"
                " FROM governed_admin_root_audit ORDER BY seq"
            ).fetchall()
        finally:
            db.close()
        require(len(roots) == len(audit) and
                all(row[0] == i+1 and row[0] == event[0] and
                    row[4] == event[2] and event[3] == EVENT and
                    (row[2], event[1]) in
                    (("ACTIVE","ENROLL"),("ACTIVE","ROTATE"),("REVOKED","REVOKE"))
                    and (row[2] != "REVOKED" or i == len(roots)-1)
                    for i,(row,event) in enumerate(zip(roots,audit))),
                "GOVERNANCE_ROOT_EPOCH_OR_AUDIT_INTEGRITY_ERROR")
        require(len({r[3] for r in roots}) == len(roots) and
                len({r[4] for r in roots}) == len(roots),
                "GOVERNANCE_NONCE_OR_MANIFEST_REPLAY_IN_LEDGER")
        for i,row in enumerate(roots):
            previous = (NO_ROOT if i == 0 else
                        hashlib.sha256(bytes.fromhex(roots[i-1][1])).hexdigest())
            require(row[5] == previous, "GOVERNANCE_ROOT_HASH_CHAIN_DRIFT")
            if i == 0:
                require(row[2] == "ACTIVE" and audit[i][1] == "ENROLL",
                        "GOVERNANCE_GENESIS_DRIFT")
        return {"epochs":len(roots),"active_epoch":roots[-1][0] if roots and
                roots[-1][2]=="ACTIVE" else None,
                "terminally_revoked":bool(roots and roots[-1][2]=="REVOKED"),
                "events":[event[1] for event in audit],
                "admin_root_sha256":(
                   hashlib.sha256(bytes.fromhex(roots[-1][1])).hexdigest()
                   if roots and roots[-1][2] == "ACTIVE" else None)}
