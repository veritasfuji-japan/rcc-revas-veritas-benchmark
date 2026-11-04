"""Mock backend-only: synchronize Owner policy and one effect in SQLite.

This verifies synthetic signed Owner evidence *inside* the SQLite write
transaction that changes the mock effect counter and spent table. The trusted
CI root seeds and changes the synthetic owner policy. No external provider,
trusted wall-clock, real owner identity, independent trust root or
multi-database distributed transaction is claimed.
"""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

OWNER_DOMAIN = b"BEN_SYNTHETIC_OWNER_APPROVAL_V1\0"
OWNER_SCOPE = "BEN_RESEARCH_MOCK_ONLY"


def initialize(db, approved_statement_digest, need):
    """One-time test initialization, under mock backend UID."""
    need(type(approved_statement_digest) is str
         and len(approved_statement_digest) == 64, "BACKEND_OWNER_DIGEST")
    db.execute(
        "CREATE TABLE owner_policy (id INTEGER PRIMARY KEY, clock_tick INTEGER NOT NULL,"
        " revoked INTEGER NOT NULL, epoch INTEGER NOT NULL, statement_digest TEXT NOT NULL)")
    db.execute("INSERT INTO owner_policy VALUES (1,100,0,0,?)",
               (approved_statement_digest,))


def check_inside_transaction(db, approval, owner_key, issuer_key, request,
                             canonical, digest, need, op):
    """Require active write transaction; caller performs effect INSERT+UPDATE.

    BEGIN IMMEDIATE must be acquired BEFORE reading owner_policy, followed
    by the backend's effect INSERT/UPDATE and COMMIT on the SAME connection.
    """
    need(db.in_transaction, "BACKEND_OWNER_REQUIRES_TRANSACTION")
    need(type(owner_key) is bytes and len(owner_key) == 32
         and type(issuer_key) is bytes and len(issuer_key) == 32
         and owner_key != issuer_key, "BACKEND_OWNER_ISSUER_KEY_REUSE")
    need(type(approval) is dict and set(approval) == {"statement", "signature"},
         "BACKEND_OWNER_PROOF_SHAPE")
    stmt = approval["statement"]
    need(type(stmt) is dict and set(stmt) == {
        "scope", "operation_id", "request_sha256", "prestate_sha256",
        "valid_from_tick", "valid_until_tick"}, "BACKEND_OWNER_STATEMENT_SHAPE")
    lower, upper = stmt["valid_from_tick"], stmt["valid_until_tick"]
    need(type(lower) is int and type(upper) is int
         and 0 <= lower < upper <= 1_000_000, "BACKEND_OWNER_INTERVAL")
    need(stmt == {
        "scope": OWNER_SCOPE, "operation_id": op,
        "request_sha256": digest(request),
        "prestate_sha256": digest({"counter": 0, "revision": 0, "effect_count": 0}),
        "valid_from_tick": lower, "valid_until_tick": upper,
    }, "BACKEND_OWNER_EXACT_BINDING")
    signature = approval["signature"]
    need(type(signature) is str and len(signature) == 128, "BACKEND_OWNER_SIGNATURE")
    try:
        Ed25519PublicKey.from_public_bytes(owner_key).verify(
            bytes.fromhex(signature), OWNER_DOMAIN + canonical(stmt))
    except (InvalidSignature, ValueError):
        raise ValueError("BACKEND_OWNER_SIGNATURE") from None
    rows = db.execute(
        "SELECT clock_tick,revoked,epoch,statement_digest FROM owner_policy WHERE id=1"
    ).fetchall()
    need(len(rows) == 1, "BACKEND_OWNER_ROW")
    tick, revoked, epoch, statement_sha = rows[0]
    need(type(tick) is int and type(revoked) is int and type(epoch) is int
         and type(statement_sha) is str and epoch >= 0,
         "BACKEND_OWNER_ROW_TYPE")
    need(statement_sha == digest(stmt), "BACKEND_OWNER_UNENROLLED_STATEMENT")
    need(revoked == 0, "BACKEND_OWNER_REVOKED")
    need(lower <= tick < upper, "BACKEND_OWNER_EXPIRED")
    return {"statement_sha256": statement_sha, "epoch": epoch,
            "synthetic_tick": tick}
