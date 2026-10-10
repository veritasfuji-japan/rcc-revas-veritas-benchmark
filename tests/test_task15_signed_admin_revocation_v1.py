"""#285 independent synthetic administrator authorization negative unit tests.

The real trusted Docker admin command proof is separate. These cases never
send network traffic and require the dedicated offline proof env flag.
"""
from __future__ import annotations
import copy
from datetime import datetime,timedelta,timezone
from pathlib import Path
import secrets
import tempfile
import unittest
import os
if os.environ.get("TASK15_SIGNED_ADMIN_PROOF")!="1":
    raise unittest.SkipTest("Run only dedicated mock-only #285 signed admin suite")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from task15_mock_broker_authorization_boundary_v1 import BrokerDenied,canonical,exact_request,sha
from task15_signed_admin_revocation_v1 import (
    SignedAdminRevocationBroker,RULE,ACTION,DOMAIN
)
NOW=datetime(2026,10,10,12,30,tzinfo=timezone.utc)

def root(signer):
    return signer.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw)

class SignedAdminCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/"private.sqlite3"
        self.admin=Ed25519PrivateKey.generate()
        self.model=Ed25519PrivateKey.generate()
        self.broker=SignedAdminRevocationBroker(
          self.path,pinned_operator_root=root(self.model),
          pinned_admin_root=root(self.admin),
          synthetic_credential=b"test-only-host-owned-synthetic-revocation-credential",
          trusted_clock=lambda:NOW
        )
    def grant(self,signer=None,issued=None,expires=None,nonce=None):
        start=NOW-timedelta(minutes=1) if issued is None else issued
        end=NOW+timedelta(minutes=1) if expires is None else expires
        st={"domain":DOMAIN,"action":ACTION,
            "request_sha256":sha(exact_request()),
            "nonce":nonce or secrets.token_hex(32),
            "issued_at":start.isoformat(),
            "expires_at":end.isoformat(),
            "no_live_provider":True,
            "max_spend_micro_usd":0,"bank_effects":False}
        signature=(signer or self.admin).sign(canonical(st).encode()).hex()
        return {"statement":st,"signature_hex":signature}
    def resign(self,x):
        x["signature_hex"]=self.admin.sign(
            canonical(x["statement"]).encode()).hex()
        return x
    def bad(self,x,expected):
        with self.assertRaisesRegex(BrokerDenied,expected):
            self.broker.revoke_signed(x)
        self.assertEqual(self.broker.admin_status()["signed_commands"],0)
        self.assertEqual(self.broker.revocation_status()["revoked_count"],0)
    def test_01_valid_signed_admin_revokes(self):
        token=self.grant()
        result=self.broker.revoke_signed(token)
        self.assertEqual(result["admin_command_sha256"],sha(token))
        self.assertEqual(self.broker.admin_status()["signed_commands"],1)
    def test_02_unsigned_api_always_disabled(self):
        with self.assertRaisesRegex(BrokerDenied,"UNSIGNED_ADMIN"):
            self.broker.revoke(sha(exact_request()))
    def test_03_wrong_signature_key(self):
        self.bad(self.grant(signer=Ed25519PrivateKey.generate()),
                 "INVALID_INDEPENDENT_ADMIN_SIGNATURE")
    def test_04_same_model_signer_cannot_admin(self):
        self.bad(self.grant(signer=self.model),
                 "INVALID_INDEPENDENT_ADMIN_SIGNATURE")
    def test_05_tampered_target(self):
        x=self.grant();x["statement"]["request_sha256"]="0"*64
        self.bad(x,"ADMIN_COMMAND_ACTION_TARGET_OR_BUDGET_DRIFT")
    def test_06_tampered_budget(self):
        x=self.grant();x["statement"]["max_spend_micro_usd"]=1
        self.bad(self.resign(x),"ADMIN_COMMAND_ACTION_TARGET_OR_BUDGET_DRIFT")
    def test_07_tampered_action(self):
        x=self.grant();x["statement"]["action"]="EXECUTE_PROVIDER"
        self.bad(self.resign(x),"ADMIN_COMMAND_ACTION_TARGET_OR_BUDGET_DRIFT")
    def test_08_tampered_scope_bank_effect(self):
        x=self.grant();x["statement"]["bank_effects"]=True
        self.bad(self.resign(x),"ADMIN_COMMAND_ACTION_TARGET_OR_BUDGET_DRIFT")
    def test_09_expired_signed_admin(self):
        x=self.grant(issued=NOW-timedelta(minutes=4),
                     expires=NOW-timedelta(minutes=2))
        self.bad(x,"ADMIN_COMMAND_EXPIRED_FUTURE_OR_OVERLONG")
    def test_10_future_signed_admin(self):
        x=self.grant(issued=NOW+timedelta(minutes=1),
                     expires=NOW+timedelta(minutes=2))
        self.bad(x,"ADMIN_COMMAND_EXPIRED_FUTURE_OR_OVERLONG")
    def test_11_overlong_expiry(self):
        x=self.grant(issued=NOW-timedelta(minutes=1),
                     expires=NOW+timedelta(minutes=6))
        self.bad(x,"ADMIN_COMMAND_EXPIRED_FUTURE_OR_OVERLONG")
    def test_12_bad_nonce_encoding(self):
        x=self.grant();x["statement"]["nonce"]="!"*64
        self.bad(self.resign(x),"MALFORMED_ADMIN_COMMAND_NONCE")
    def test_13_missing_signature(self):
        x=self.grant();del x["signature_hex"]
        self.bad(x,"SIGNED_ADMIN_COMMAND_ENVELOPE_ONLY")
    def test_14_replay_denied_without_second_audit(self):
        x=self.grant()
        self.broker.revoke_signed(x)
        with self.assertRaisesRegex(BrokerDenied,"ADMIN_COMMAND_NONCE_ALREADY_CONSUMED"):
            self.broker.revoke_signed(x)
        self.assertEqual(self.broker.admin_status()["audit_events"],1)
    def test_15_second_fresh_valid_signed_revoke_denied(self):
        self.broker.revoke_signed(self.grant())
        with self.assertRaisesRegex(BrokerDenied,"TARGET_ALREADY_REVOKED"):
            self.broker.revoke_signed(self.grant())
        self.assertEqual(self.broker.admin_status()["signed_commands"],1)
    def test_16_admin_record_durable_across_reopen(self):
        self.broker.revoke_signed(self.grant())
        other=SignedAdminRevocationBroker(
            self.path,pinned_operator_root=root(self.model),
            pinned_admin_root=root(self.admin),
            synthetic_credential=b"test-only-host-owned-synthetic-revocation-credential",
            trusted_clock=lambda:NOW)
        self.assertEqual(other.admin_status()["signed_commands"],1)
        self.assertEqual(other.revocation_status()["revoked_count"],1)
    def test_17_reject_same_root_during_enrollment(self):
        with self.assertRaisesRegex(BrokerDenied,"SEPARATE_SIGNED_ADMIN_ROOT"):
            SignedAdminRevocationBroker(
              Path(self.temp.name)/"wrong.sqlite3",
              pinned_operator_root=root(self.model),
              pinned_admin_root=root(self.model),
              synthetic_credential=b"test-only-host-owned-synthetic-revocation-credential",
              trusted_clock=lambda:NOW)
    def test_18_fail_closed_admin_audit_tamper(self):
        import sqlite3
        self.broker.revoke_signed(self.grant())
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM admin_audit")
        with self.assertRaisesRegex(BrokerDenied,"SIGNED_ADMIN_AUDIT_DATABASE"):
            self.broker.admin_status()
if __name__=="__main__":
    unittest.main()
