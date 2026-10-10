"""Task15 compromised-worker synthetic key negative cases — offline-only proof.

Generic fast CI intentionally skips cryptography-based dedicated suite.
"""
from __future__ import annotations
import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timedelta,timezone
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

if os.environ.get("TASK15_STOLEN_SESSION_PROOF") != "1":
    raise unittest.SkipTest("Only the dedicated offline stolen-session revocation proof")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from task15_mock_broker_authorization_boundary_v1 import (
    BrokerDenied, canonical, exact_request, sha
)
from task15_stolen_session_revocation_fence_v1 import (
    RevocableMockAuthorizationBroker, REVOKED
)
from scripts.task15_session_challenge_broker_server_v1 import mac_hex

NOW = datetime(2026,10,10,12,0,tzinfo=timezone.utc)
SECRET = b"test-only-host-owned-FAKE-CLIENT-SECRET-00000000001"
STOLEN_SESSION_KEY = bytes(range(32))

def fixture():
    signer=Ed25519PrivateKey.generate()
    root=signer.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    request=exact_request()
    statement={
        "profile":request["profile"],
        "request_sha256":sha(request),
        "source_sha256":request["wire_source_sha256"],
        "max_calls":1,"max_total_spend_micro_usd":0,
        "no_live_provider":True,"no_bank_effects":True,
        "nonce":"a"*64,
        "issued_at":NOW.isoformat(),
        "expires_at":(NOW+timedelta(minutes=5)).isoformat()
    }
    grant={"statement":statement,
           "signature_hex":signer.sign(canonical(statement).encode()).hex()}
    return {"request":request,"approval":grant},signer,root

class StolenSessionRevocationTests(unittest.TestCase):
    def setUp(self):
        self.dir=tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.file=Path(self.dir.name)/"broker.sqlite3"
        self.envelope,self.signer,self.root=fixture()
        self.broker=self.open()

    def open(self,fail=False,root=None):
        return RevocableMockAuthorizationBroker(
            self.file,pinned_operator_root=self.root if root is None else root,
            synthetic_credential=SECRET,trusted_clock=lambda:NOW,
            mock_fail=fail)

    def revoke(self):
        return self.broker.revoke(sha(self.envelope["request"]))

    def expect_revoke_denial(self,broker=None,envelope=None):
        b=broker or self.broker
        with self.assertRaisesRegex(BrokerDenied,REVOKED):
            b.execute(copy.deepcopy(envelope or self.envelope))

    def test_01_compromised_session_mac_is_cryptographically_valid(self):
        nonce="ab"*32
        tag=mac_hex(STOLEN_SESSION_KEY,nonce,self.envelope)
        self.assertEqual(tag,mac_hex(STOLEN_SESSION_KEY,nonce,self.envelope))
        self.assertEqual(len(tag),64)

    def test_02_revoked_before_claim_denies_stolen_session(self):
        self.assertEqual(self.revoke()["state"],"REVOKED")
        self.expect_revoke_denial()
        self.assertEqual(self.broker.mock_calls,0)

    def test_03_revocation_durable_across_broker_restart(self):
        self.revoke()
        self.expect_revoke_denial(self.open())

    def test_04_revoke_idempotent_one_record(self):
        self.assertTrue(self.revoke()["new_revocation"])
        self.assertFalse(self.revoke()["new_revocation"])
        self.assertEqual(self.broker.revocation_status()["revocation_events"],1)

    def test_05_wrong_request_sha_cannot_revoke(self):
        with self.assertRaises(BrokerDenied):
            self.broker.revoke("0"*64)
        self.assertEqual(self.broker.revocation_status()["revoked_count"],0)

    def test_06_untrusted_envelope_cannot_revoke(self):
        malicious=copy.deepcopy(self.envelope)
        malicious["revoke"]=True
        with self.assertRaisesRegex(BrokerDenied,"ONLY_WORKER_PROPOSAL"):
            self.broker.execute(malicious)
        self.assertEqual(self.broker.revocation_status()["revoked_count"],0)

    def test_07_new_signature_same_request_still_revoked(self):
        self.revoke()
        copyenv=copy.deepcopy(self.envelope)
        copyenv["approval"]["statement"]["nonce"]="b"*64
        copyenv["approval"]["signature_hex"]=self.signer.sign(
            canonical(copyenv["approval"]["statement"]).encode()).hex()
        self.expect_revoke_denial(envelope=copyenv)

    def test_08_legitimate_worker_also_revoked(self):
        self.revoke()
        self.expect_revoke_denial()
        self.assertEqual(self.broker.status()["rows"],0)

    def test_09_stolen_grant_can_win_before_revocation_nonclaim(self):
        receipt=self.broker.execute(copy.deepcopy(self.envelope))
        self.assertEqual(receipt["state"],"MOCK_RECORDED")
        self.assertEqual(self.broker.mock_calls,1)
        self.revoke()
        self.expect_revoke_denial()
        self.assertEqual(self.broker.mock_calls,1)

    def test_10_single_use_even_when_stolen_key_has_valid_grant(self):
        self.broker.execute(self.envelope)
        with self.assertRaisesRegex(BrokerDenied,"ONE_SHOT"):
            self.broker.execute(self.envelope)
        self.assertEqual(self.broker.mock_calls,1)

    def test_11_replay_prevented_across_reopening(self):
        self.broker.execute(self.envelope)
        with self.assertRaisesRegex(BrokerDenied,"ONE_SHOT"):
            self.open().execute(self.envelope)

    def test_12_ambiguous_mock_delivery_cannot_retry(self):
        uncertain=self.open(fail=True)
        with self.assertRaises(RuntimeError):
            uncertain.execute(self.envelope)
        self.assertEqual(uncertain.status()["states"],["DISPATCH_UNKNOWN"])
        with self.assertRaisesRegex(BrokerDenied,"ONE_SHOT"):
            self.broker.execute(self.envelope)

    def test_13_unknown_can_be_revoked_without_erasing_claim(self):
        uncertain=self.open(fail=True)
        with self.assertRaises(RuntimeError):
            uncertain.execute(self.envelope)
        self.revoke()
        self.expect_revoke_denial()
        self.assertEqual(self.broker.status()["states"],["DISPATCH_UNKNOWN"])

    def test_14_revocation_audit_integrity_fail_closed(self):
        self.revoke()
        with sqlite3.connect(self.file) as db:
            db.execute("DELETE FROM revocation_audit")
        with self.assertRaisesRegex(BrokerDenied,"REVOCATION_AUDIT"):
            self.broker.revocation_status()

    def test_15_missing_ledger_does_not_silently_recreate(self):
        self.revoke()
        self.file.unlink()
        with self.assertRaises(BrokerDenied):
            self.broker.execute(self.envelope)

    def test_16_wrong_operator_root_grant_denied_before_claim(self):
        badroot=Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        with self.assertRaisesRegex(BrokerDenied,"INVALID_PINNED_OPERATOR_SIGNATURE"):
            self.open(root=badroot).execute(self.envelope)
        self.assertEqual(self.broker.status()["rows"],0)

    def test_17_invalid_signature_no_claim(self):
        x=copy.deepcopy(self.envelope)
        x["approval"]["signature_hex"]="0"*128
        with self.assertRaisesRegex(BrokerDenied,"INVALID_PINNED_OPERATOR_SIGNATURE"):
            self.broker.execute(x)
        self.assertEqual(self.broker.status()["rows"],0)

    def test_18_target_change_even_compromised_key_denied(self):
        x=copy.deepcopy(self.envelope)
        x["request"]["target"]["host"]="attacker.invalid"
        with self.assertRaisesRegex(BrokerDenied,"FROZEN_MODEL_SOURCE"):
            self.broker.execute(x)
        self.assertEqual(self.broker.mock_calls,0)

    def test_19_concurrent_32_revocations_only_one_audit(self):
        key=sha(self.envelope["request"])
        with ThreadPoolExecutor(max_workers=16) as pool:
            r=list(pool.map(lambda _:self.broker.revoke(key),range(32)))
        self.assertEqual(sum(x["new_revocation"] for x in r),1)
        self.assertEqual(self.broker.revocation_status()["revoked_count"],1)
        self.expect_revoke_denial()

    def test_20_32_concurrent_claims_after_revocation_all_denied(self):
        self.revoke()
        def worker(_):
            try:
                self.open().execute(self.envelope)
                return "ALLOWED"
            except BrokerDenied as exc:
                return str(exc)
        with ThreadPoolExecutor(max_workers=16) as pool:
            results=list(pool.map(worker,range(32)))
        self.assertEqual(results,[REVOKED]*32)
        self.assertEqual(self.broker.mock_calls,0)
        self.assertEqual(self.broker.status()["rows"],0)

if __name__=="__main__":
    unittest.main()
