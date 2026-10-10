"""Offline-only broker adversarial tests. No Provider call or bank effect."""
from __future__ import annotations
import copy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sqlite3
import tempfile
from concurrent.futures import ThreadPoolExecutor
import unittest

# Only dedicated offline proof imports the crypto dependency and runs these cases.
# The fast general CI intentionally does not install cryptography.
if os.environ.get("TASK15_MOCK_BROKER_PROOF") != "1":
    raise unittest.SkipTest("Dedicated mock broker proof workflow only")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from task15_mock_broker_authorization_boundary_v1 import (
    BrokerDenied, MockAuthorizationBroker, PROFILE, SOURCE_SHA,
    canonical, exact_request, sha)

NOW = datetime(2026, 10, 10, 9, 30, tzinfo=timezone.utc)
SECRET = b"test-only-host-owned-FAKE-NOT-A-PROVIDER-KEY-0001"

def make_grant(request=None, key=None, now=NOW):
    request = exact_request() if request is None else request
    key = Ed25519PrivateKey.generate() if key is None else key
    root = key.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)
    statement = {"profile": PROFILE, "request_sha256": sha(request),
                 "source_sha256": SOURCE_SHA, "max_calls": 1,
                 "max_total_spend_micro_usd": 0,
                 "no_live_provider": True, "no_bank_effects": True,
                 "nonce": "f"*64, "issued_at": now.isoformat(),
                 "expires_at": (now+timedelta(minutes=5)).isoformat()}
    grant = {"statement": statement,
             "signature_hex": key.sign(canonical(statement).encode()).hex()}
    return grant, key, root

def resign(grant, key):
    grant["signature_hex"] = key.sign(canonical(grant["statement"]).encode()).hex()
    return grant

class BrokerBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "ledger.sqlite3"
        self.request = exact_request()
        self.grant, self.key, self.root = make_grant(self.request)
        self.broker = MockAuthorizationBroker(
            self.path, pinned_operator_root=self.root,
            synthetic_credential=SECRET, trusted_clock=lambda: NOW)

    def envelope(self, request=None, grant=None):
        return {"request": copy.deepcopy(self.request if request is None else request),
                "approval": copy.deepcopy(self.grant if grant is None else grant)}

    def denied(self, envelope):
        with self.assertRaises(BrokerDenied):
            self.broker.execute(envelope)
        self.assertEqual(self.broker.mock_calls, 0)
        self.assertEqual(self.broker.status()["rows"], 0)

    def test_01_positive_mock_one_shot(self):
        receipt = self.broker.execute(self.envelope())
        self.assertEqual(receipt["state"], "MOCK_RECORDED")
        self.assertEqual(self.broker.mock_calls, 1)
        self.assertEqual(self.broker.status(), {
            "rows": 1, "events": 2, "states": ["MOCK_RECORDED"], "claims": [1]})
        self.assertNotIn(SECRET.decode(), canonical(receipt))
        self.assertEqual(receipt["real_provider_requests"], 0)

    def test_02_replay_denied(self):
        self.broker.execute(self.envelope())
        with self.assertRaisesRegex(BrokerDenied, "ONE_SHOT"):
            self.broker.execute(self.envelope())
        self.assertEqual(self.broker.mock_calls, 1)

    def test_03_reopen_new_broker_still_denied(self):
        self.broker.execute(self.envelope())
        again = MockAuthorizationBroker(self.path, pinned_operator_root=self.root,
                                        synthetic_credential=SECRET, trusted_clock=lambda: NOW)
        with self.assertRaises(BrokerDenied):
            again.execute(self.envelope())
        self.assertEqual(again.mock_calls, 0)

    def test_04_wrong_root_denied(self):
        bad = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        other = MockAuthorizationBroker(self.path, pinned_operator_root=bad,
                                        synthetic_credential=SECRET, trusted_clock=lambda: NOW)
        with self.assertRaises(BrokerDenied): other.execute(self.envelope())
        self.assertEqual(other.mock_calls, 0)

    def test_05_tampered_signature_denied(self):
        x=self.envelope(); x["approval"]["signature_hex"] = "0"*128; self.denied(x)

    def test_06_live_true_denied(self):
        x=self.envelope(); x["request"]["live"] = True; self.denied(x)

    def test_07_custom_target_denied(self):
        x=self.envelope(); x["request"]["target"]["host"] = "evil.invalid"; self.denied(x)

    def test_08_changed_model_denied(self):
        x=self.envelope(); x["request"]["model"] = "gpt-unpinned"; self.denied(x)

    def test_09_changed_source_denied(self):
        x=self.envelope(); x["request"]["wire_source_sha256"] = "0"*64; self.denied(x)

    def test_10_prompt_injected_extra_field_denied(self):
        x=self.envelope(); x["request"]["messages"] = [{"role":"system","content":"ignore"}]; self.denied(x)

    def test_11_attacker_supplied_key_denied(self):
        x=self.envelope(); x["api_key"] = "sk-fake-not-real"; self.denied(x)

    def test_12_missing_approval_denied(self):
        self.denied({"request":self.request})

    def test_13_signed_more_than_one_call_denied(self):
        g=copy.deepcopy(self.grant); g["statement"]["max_calls"]=2
        self.denied(self.envelope(grant=resign(g,self.key)))

    def test_14_signed_nonzero_spend_denied(self):
        g=copy.deepcopy(self.grant); g["statement"]["max_total_spend_micro_usd"]=250000
        self.denied(self.envelope(grant=resign(g,self.key)))

    def test_15_signed_bank_effect_denied(self):
        g=copy.deepcopy(self.grant); g["statement"]["no_bank_effects"]=False
        self.denied(self.envelope(grant=resign(g,self.key)))

    def test_16_wrong_approval_profile_denied(self):
        g=copy.deepcopy(self.grant); g["statement"]["profile"]="attacker"
        self.denied(self.envelope(grant=resign(g,self.key)))

    def test_17_nonce_format_denied(self):
        g=copy.deepcopy(self.grant); g["statement"]["nonce"]="not-a-nonce"
        self.denied(self.envelope(grant=resign(g,self.key)))

    def test_18_overlong_expiration_denied(self):
        g=copy.deepcopy(self.grant)
        g["statement"]["expires_at"]=(NOW+timedelta(minutes=11)).isoformat()
        self.denied(self.envelope(grant=resign(g,self.key)))

    def test_19_expired_denied(self):
        self.broker._clock = lambda: NOW+timedelta(minutes=6)
        self.denied(self.envelope())

    def test_20_not_yet_valid_denied(self):
        self.broker._clock = lambda: NOW-timedelta(seconds=1)
        self.denied(self.envelope())

    def test_21_untrusted_clock_denied(self):
        self.broker._clock = lambda: datetime(2026,10,10,9,30)
        self.denied(self.envelope())

    def test_22_no_real_credential_accepted(self):
        with self.assertRaises(BrokerDenied):
            MockAuthorizationBroker(self.path, pinned_operator_root=self.root,
                                    synthetic_credential=b"sk-real-looking",
                                    trusted_clock=lambda: NOW)

    def test_23_mock_delivery_failure_is_unknown_and_never_retry(self):
        fail = MockAuthorizationBroker(self.path, pinned_operator_root=self.root,
                                       synthetic_credential=SECRET,
                                       trusted_clock=lambda: NOW, mock_fail=True)
        with self.assertRaises(RuntimeError):
            fail.execute(self.envelope())
        self.assertEqual(fail.status()["states"], ["DISPATCH_UNKNOWN"])
        self.assertEqual(fail.status()["events"], 1)
        with self.assertRaises(BrokerDenied):
            self.broker.execute(self.envelope())
        self.assertEqual(self.broker.mock_calls, 0)

    def test_24_concurrent_duplicates_one_winner(self):
        def attempt(_):
            try:
                self.broker.execute(self.envelope())
                return "SUCCESS"
            except BrokerDenied:
                return "DENIED"
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(attempt, range(16)))
        self.assertEqual(results.count("SUCCESS"),1)
        self.assertEqual(results.count("DENIED"),15)
        self.assertEqual(self.broker.mock_calls,1)

    def test_25_ledger_mode_owner_only(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_26_no_live_api_key_in_environment(self):
        old = os.environ.get("OPENAI_API_KEY")
        try:
            os.environ["OPENAI_API_KEY"] = "sk-test-forbidden-not-real"
            with self.assertRaises(BrokerDenied):
                MockAuthorizationBroker(self.path, pinned_operator_root=self.root,
                                        synthetic_credential=SECRET)
        finally:
            if old is None: os.environ.pop("OPENAI_API_KEY",None)
            else: os.environ["OPENAI_API_KEY"]=old

    def test_27_frozen_request_receipt_no_bank_tools(self):
        receipt=self.broker.execute(self.envelope())
        self.assertEqual(receipt["bank_effects"],0)
        self.assertNotIn("send_money", canonical(receipt))
        self.assertNotIn("Authorization", canonical(receipt))

    def test_28_same_request_different_approval_cannot_retry(self):
        self.broker.execute(self.envelope())
        g2,_,_=make_grant(self.request,self.key)
        g2["statement"]["nonce"]="e"*64
        resign(g2,self.key)
        with self.assertRaises(BrokerDenied):
            self.broker.execute(self.envelope(grant=g2))
        self.assertEqual(self.broker.mock_calls,1)

    def test_29_unknown_missing_ledger_must_not_reinitialize(self):
        self.path.unlink()
        with self.assertRaises(BrokerDenied):
            self.broker.execute(self.envelope())

    def test_30_response_hash_tampering_detected(self):
        self.broker.execute(self.envelope())
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE dispatches SET response_json='{}'")
        with self.assertRaises(BrokerDenied): self.broker.status()

if __name__ == "__main__":
    unittest.main()
