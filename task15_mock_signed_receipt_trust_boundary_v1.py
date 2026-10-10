"""Offline pinned mock signing root for Task15 consequence receipt, NOT real provider.

Rule-of-One: this exact, opt-in mock reconciliation route must not promote
DISPATCH_UNKNOWN unless a matching mock-provider effect row AND an Ed25519
signature over its immutable scope verify under a pre-enrolled local test root.

A test-owned private key is generated at runtime (never stored or committed).
The public key is enrolled BEFORE any mock receipt arrives, then held as a
read-only expectation in the recovery object's own context. Neither is a real
third-party provider credential or production trust anchor.

Important scope: this gate wraps only the named mock route. Existing generic
LocalMockConsequence.reconcile can still be called by unrelated code. There is
no system-wide bypass-resistance claim or live trust-root assurance.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sqlite3

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from task15_mock_effect_unknown_reconcile_v1 import (
    LocalMockConsequence, canonical, sha,
)

RULE="TASK15_MOCK_SIGNED_RECEIPT_TRUST_BOUNDARY_V1"
PRIOR_RULE="TASK15_MOCK_EFFECT_UNKNOWN_RECONCILE_V1"
PREDECESSOR_MAIN="10ed8d1c5fd37e0712b3b33aa33cdec8b34620ce"
MOCK_ISSUER="OFFLINE_EPHEMERAL_SIMULATOR_NO_REAL_PROVIDER_IDENTITY"
MOCK_MODEL="gpt-4.1-mini-2025-04-14"
PROFILE="mock-receipt-ed25519-scope-bound-v1"

class MockTrustViolation(ValueError):
    pass

def require(ok, reason):
    if not ok:raise MockTrustViolation(reason)

def fp(pub):
    return hashlib.sha256(pub).hexdigest()

def hex64(s):
    return type(s) is str and len(s)==64 and all(c in "0123456789abcdef" for c in s)

class TestOnlyMockIssuer:
    """Ephemeral local simulator signer. It authenticates no real entity."""
    def __init__(self):
        self._private=Ed25519PrivateKey.generate()
        self.public_bytes=self._private.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.key_id=fp(self.public_bytes)

    def sign_for(self,sim):
        require(type(sim) is LocalMockConsequence
                and sim.state()["state"]=="DISPATCH_UNKNOWN"
                and sim.state()["dispatch_fences"]==1,
                "MOCK_ISSUER_REQUIRES_FENCED_OFFLINE_SOURCE")
        receipt=sim.mock_read_only_receipt()
        require(type(receipt) is dict,
                "NO_MOCK_EFFECT_RECORD_TO_ATTEST")
        statement={
            "profile":PROFILE,
            "issuer":MOCK_ISSUER,
            "key_id":self.key_id,
            "operation_id":sim.operation_id,
            "plan_sha256":sim.plan_sha,
            "predecessor_proof_sha256":sim.prior_sha,
            "model_snapshot":MOCK_MODEL,
            "mock_receipt_sha256":sha(receipt),
            "mock_receipt_kind":"MOCK_EFFECT_COMMITTED",
            "external_provider_authenticated":False,
            "external_effect_claimed":False,
        }
        signature=self._private.sign(canonical(statement).encode()).hex()
        return {"statement":statement,"signature_hex":signature}

class FrozenOfflineMockTrust:
    """One pre-enrolled local SQLite root; the constructor retains its pin."""
    def __init__(self,path,public_bytes,*,create):
        self.path=Path(path)
        require(type(public_bytes) is bytes and len(public_bytes)==32,
                "EXACT_ED25519_PUBLIC_KEY_BYTES_REQUIRED")
        self.expected_bytes=public_bytes
        self.key_id=fp(public_bytes)
        if create:
            require(not self.path.exists() and self.path.parent.is_dir(),
                    "FRESH_LOCAL_TRUST_ANCHOR_ENROLLMENT_REQUIRED")
            con=sqlite3.connect(self.path)
            try:
                con.execute("PRAGMA journal_mode=WAL")
                con.execute("PRAGMA synchronous=FULL")
                con.execute("CREATE TABLE keys(id TEXT PRIMARY KEY, pub BLOB NOT NULL,"
                            " profile TEXT NOT NULL, issuer TEXT NOT NULL)")
                con.execute("INSERT INTO keys VALUES (?,?,?,?)",
                            (self.key_id,public_bytes,PROFILE,MOCK_ISSUER))
                con.commit()
            finally:con.close()
        else:
            require(self.path.is_file(),"FROZEN_LOCAL_TRUST_ROOT_MISSING")
            self._read_pin()

    def _read_pin(self):
        con=sqlite3.connect("file:"+str(self.path.resolve())+"?mode=ro",uri=True)
        try:
            rows=con.execute("SELECT id,pub,profile,issuer FROM keys").fetchall()
        finally:con.close()
        require(len(rows)==1 and rows[0]==
                (self.key_id,self.expected_bytes,PROFILE,MOCK_ISSUER),
                "FROZEN_MOCK_TRUST_ROOT_CHANGED_OR_SELF_ATTESTED")
        return rows[0]

    def verify(self,envelope,sim):
        self._read_pin()
        require(type(envelope) is dict and
                set(envelope)=={"statement","signature_hex"},
                "EXACT_SIGNED_ENVELOPE_REQUIRED")
        st=envelope["statement"];h=envelope["signature_hex"]
        require(type(st) is dict and set(st)=={
            "profile","issuer","key_id","operation_id","plan_sha256",
            "predecessor_proof_sha256","model_snapshot","mock_receipt_sha256",
            "mock_receipt_kind","external_provider_authenticated",
            "external_effect_claimed"} and
            st["profile"]==PROFILE and
            st["issuer"]==MOCK_ISSUER and
            st["key_id"]==self.key_id and
            st["operation_id"]==sim.operation_id and
            st["plan_sha256"]==sim.plan_sha and
            st["predecessor_proof_sha256"]==sim.prior_sha and
            st["model_snapshot"]==MOCK_MODEL and
            st["mock_receipt_kind"]=="MOCK_EFFECT_COMMITTED" and
            st["external_provider_authenticated"] is False and
            st["external_effect_claimed"] is False and
            hex64(st["mock_receipt_sha256"]) and
            type(h) is str and len(h)==128 and
            all(c in "0123456789abcdef" for c in h),
            "SIGNED_MOCK_RECEIPT_SCOPE_OR_FORMAT_VIOLATION")
        receipt=sim.mock_read_only_receipt()
        require(receipt is not None and
                st["mock_receipt_sha256"]==sha(receipt),
                "SIGNED_RECEIPT_NOT_BOUND_TO_ACTUAL_MOCK_EFFECT_ROW")
        try:
            Ed25519PublicKey.from_public_bytes(self.expected_bytes).verify(
                bytes.fromhex(h),canonical(st).encode())
        except (ValueError,InvalidSignature) as exc:
            raise MockTrustViolation("MOCK_ED25519_SIGNATURE_INVALID") from exc
        return receipt

def attach_mock_signature(sim,envelope):
    """Test fixture inserts into the separate simulated-provider DB once."""
    require(type(sim) is LocalMockConsequence and
            sim.state()["state"]=="DISPATCH_UNKNOWN",
            "SIGNATURE_ATTACHMENT_REQUIRES_PENDING_MOCK_EFFECT")
    con=sqlite3.connect(sim.provider,timeout=20)
    try:
        con.execute("CREATE TABLE IF NOT EXISTS mock_signatures("
                    "operation_id TEXT PRIMARY KEY,"
                    "envelope_json TEXT NOT NULL, envelope_sha256 TEXT NOT NULL)")
        data=canonical(envelope)
        con.execute("INSERT INTO mock_signatures VALUES (?,?,?)",
                    (sim.operation_id,data,sha(envelope)))
        con.commit()
    except sqlite3.IntegrityError as exc:
        raise MockTrustViolation("DUPLICATE_MOCK_PROVIDER_SIGNATURE_REFUSED") from exc
    finally:con.close()

class BoundedSignedMockRecovery:
    """The ONLY specifically audited signed reconciliation entrypoint."""
    def __init__(self,sim,trust):
        require(type(sim) is LocalMockConsequence and
                type(trust) is FrozenOfflineMockTrust,
                "EXACT_OFFLINE_SIGNED_RECONCILIATION_ADAPTER_REQUIRED")
        self.sim=sim
        self.trust=trust

    def _provider_signed_row(self):
        con=sqlite3.connect("file:"+str(self.sim.provider.resolve())+"?mode=ro",uri=True)
        try:
            exists=con.execute("SELECT name FROM sqlite_master"
                               " WHERE type='table' AND name='mock_signatures'").fetchall()
            if not exists:return None
            rows=con.execute("SELECT operation_id,envelope_json,envelope_sha256"
                             " FROM mock_signatures").fetchall()
        finally:con.close()
        require(len(rows)<=1,"MULTIPLE_SIGNED_MOCK_RECEIPTS_FORBIDDEN")
        if not rows:return None
        op,serialized,digest=rows[0]
        require(op==self.sim.operation_id,"SIGNED_MOCK_OPERATION_ID_DRIFT")
        try: envelope=json.loads(serialized)
        except (TypeError,ValueError) as exc:
            raise MockTrustViolation("UNPARSABLE_SIGNED_MOCK_ENVELOPE") from exc
        require(serialized==canonical(envelope) and digest==sha(envelope),
                "SIGNED_MOCK_ENVELOPE_STORAGE_INTEGRITY_FAILURE")
        return envelope

    def reconcile(self):
        state=self.sim.state()
        require(state["state"]=="DISPATCH_UNKNOWN" and
                state["dispatch_fences"]==1,
                "ONLY_FENCED_UNKNOWN_MAY_HAVE_SIGNED_RECOVERY")
        # After even an unsuccessful read, no redispatch from this process.
        self.sim._local_dispatch_armed=False
        if self.sim.mock_read_only_receipt() is None:
            require(self._provider_signed_row() is None,
                    "SIGNATURE_WITHOUT_MOCK_EFFECT_IS_NOT_EVIDENCE")
            return "UNKNOWN"
        envelope=self._provider_signed_row()
        if envelope is None:
            return "UNKNOWN"
        receipt=self.trust.verify(envelope,self.sim)
        return self.sim.reconcile(receipt)

    def observation(self):
        state=self.sim.evidence()
        state["trust_root_key_id"]=self.trust.key_id
        state["signed_gate_only"]=True
        state["authenticated_external_provider"]=False
        state["production_effect_authenticity_proven"]=False
        return state
