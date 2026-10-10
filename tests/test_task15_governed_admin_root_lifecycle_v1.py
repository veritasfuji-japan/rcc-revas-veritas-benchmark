"""#286 exact bounded governed administrator TEST-root lifecycle cases.

No actual Provider send; no Docker IAM or live operator enrollment. Admin-key
root is signed only by a separate pre-pinned ephemeral TEST governance signer.
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timedelta,timezone
from pathlib import Path
import copy
import os
import secrets
import sqlite3
import tempfile
import unittest

if os.environ.get("TASK15_GOVERNED_ADMIN_ROOT_PROOF") != "1":
    raise unittest.SkipTest("Dedicated mock-only #286 governance root proof")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from task15_mock_broker_authorization_boundary_v1 import BrokerDenied,canonical,exact_request,sha
from task15_signed_admin_revocation_v1 import DOMAIN as ADMIN_DOMAIN,ACTION
from task15_governed_admin_root_lifecycle_v1 import (
    GovernedAdminRootBroker,DOMAIN,RULE
)

NOW=datetime(2026,10,10,12,30,tzinfo=timezone.utc)
SECRET=b"test-only-host-owned-governed-admin-root-fixture-000001"

def public(signer):
    return signer.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)

def make_root_manifest(signer,operation,epoch,new_root,previous="",now=NOW,
                       issued=None,expires=None):
    issued=issued or now-timedelta(minutes=1)
    expires=expires or now+timedelta(minutes=1)
    statement={"domain":DOMAIN,"operation":operation,"epoch":epoch,
               "admin_root_hex":new_root.hex() if new_root else "",
               "previous_root_sha256":previous,"nonce":secrets.token_hex(32),
               "issued_at":issued.isoformat(),"expires_at":expires.isoformat(),
               "no_live_provider":True,"max_spend_micro_usd":0,
               "bank_effects":False}
    return {"statement":statement,
            "signature_hex":signer.sign(canonical(statement).encode()).hex()}

def signed_admin(signer,now=NOW):
    stmt={"domain":ADMIN_DOMAIN,"action":ACTION,
          "request_sha256":sha(exact_request()),
          "nonce":secrets.token_hex(32),
          "issued_at":(now-timedelta(minutes=1)).isoformat(),
          "expires_at":(now+timedelta(minutes=1)).isoformat(),
          "no_live_provider":True,"max_spend_micro_usd":0,
          "bank_effects":False}
    return {"statement":stmt,"signature_hex":signer.sign(canonical(stmt).encode()).hex()}


class GovernedAdminRootLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/"ledger.sqlite3"
        self.gov=Ed25519PrivateKey.generate()
        self.model=Ed25519PrivateKey.generate()
        self.admin_a=Ed25519PrivateKey.generate()
        self.admin_b=Ed25519PrivateKey.generate()
        self.admin_c=Ed25519PrivateKey.generate()
        self.broker=self.open()

    def open(self):
        return GovernedAdminRootBroker(
            self.path,
            pinned_governance_root=public(self.gov),
            pinned_operator_root=public(self.model),
            synthetic_credential=SECRET,
            trusted_clock=lambda: NOW)

    def enroll(self,who=None):
        x=make_root_manifest(self.gov,"ENROLL",1,
                             public(who or self.admin_a))
        r=self.broker.transition_signed(x)
        self.assertEqual(r["epoch"],1)
        return x

    def rotate(self,from_key=None,to_key=None,epoch=2):
        from_key=from_key or self.admin_a
        to_key=to_key or self.admin_b
        x=make_root_manifest(self.gov,"ROTATE",epoch,public(to_key),
                             sha_root(public(from_key)))
        return self.broker.transition_signed(x)

    def deny_transition(self,token,expected):
        before=self.broker.root_status()
        with self.assertRaisesRegex(BrokerDenied,expected):
            self.broker.transition_signed(token)
        self.assertEqual(self.broker.root_status(),before)

    def test_01_cannot_revoke_without_enrollment(self):
        with self.assertRaisesRegex(BrokerDenied,"NO_ACTIVE_GOVERNED_ADMIN_ROOT"):
            self.broker.revoke_signed(signed_admin(self.admin_a))
    def test_02_cannot_revoke_unsigned(self):
        with self.assertRaisesRegex(BrokerDenied,"UNSIGNED_ADMIN_REVOCATION_FORBIDDEN"):
            self.broker.revoke(sha(exact_request()))
    def test_03_enroll_epoch_one(self):
        self.enroll()
        self.assertEqual(self.broker.root_status()["events"],["ENROLL"])
    def test_04_first_command_must_be_enroll(self):
        x=make_root_manifest(self.gov,"ROTATE",1,public(self.admin_a))
        self.deny_transition(x,"FIRST_BOOTSTRAP")
    def test_05_wrong_governance_key_denied(self):
        x=make_root_manifest(self.admin_c,"ENROLL",1,public(self.admin_a))
        self.deny_transition(x,"INVALID_PINNED_GOVERNANCE_SIGNATURE")
    def test_06_model_approval_key_cannot_enroll(self):
        x=make_root_manifest(self.model,"ENROLL",1,public(self.admin_a))
        self.deny_transition(x,"INVALID_PINNED_GOVERNANCE_SIGNATURE")
    def test_07_missing_signature_denied(self):
        x=make_root_manifest(self.gov,"ENROLL",1,public(self.admin_a))
        del x["signature_hex"]
        self.deny_transition(x,"EXACT_SIGNED_GOVERNANCE_ENVELOPE")
    def test_08_changed_root_without_resign_denied(self):
        x=make_root_manifest(self.gov,"ENROLL",1,public(self.admin_a))
        x["statement"]["admin_root_hex"]=public(self.admin_b).hex()
        self.deny_transition(x,"INVALID_PINNED_GOVERNANCE_SIGNATURE")
    def test_09_modified_action_denied(self):
        x=make_root_manifest(self.gov,"ENROLL",1,public(self.admin_a))
        x["statement"]["operation"]="ISSUE_REAL_PROVIDER_CREDENTIAL"
        self.deny_transition(x,"GOVERNANCE_SCOPE_EPOCH_OR_BUDGET_DRIFT")
    def test_10_spending_cannot_be_enabled(self):
        x=make_root_manifest(self.gov,"ENROLL",1,public(self.admin_a))
        x["statement"]["max_spend_micro_usd"]=1
        self.deny_transition(x,"GOVERNANCE_SCOPE_EPOCH_OR_BUDGET_DRIFT")
    def test_11_expired_governance_manifest(self):
        x=make_root_manifest(self.gov,"ENROLL",1,public(self.admin_a),
            issued=NOW-timedelta(minutes=4),expires=NOW-timedelta(minutes=2))
        self.deny_transition(x,"GOVERNANCE_MANIFEST_EXPIRED_FUTURE_OR_OVERLONG")
    def test_12_future_governance_manifest(self):
        x=make_root_manifest(self.gov,"ENROLL",1,public(self.admin_a),
            issued=NOW+timedelta(minutes=1),expires=NOW+timedelta(minutes=2))
        self.deny_transition(x,"GOVERNANCE_MANIFEST_EXPIRED_FUTURE_OR_OVERLONG")
    def test_13_overlong_governance_manifest(self):
        x=make_root_manifest(self.gov,"ENROLL",1,public(self.admin_a),
            issued=NOW-timedelta(minutes=1),expires=NOW+timedelta(minutes=6))
        self.deny_transition(x,"GOVERNANCE_MANIFEST_EXPIRED_FUTURE_OR_OVERLONG")
    def test_14_same_governance_root_cannot_be_enrolled_admin(self):
        x=make_root_manifest(self.gov,"ENROLL",1,public(self.gov))
        self.deny_transition(x,"UNSAFE_GOVERNANCE_ADMIN_ROOT_VALUE")
    def test_15_same_model_root_cannot_be_enrolled_admin(self):
        x=make_root_manifest(self.gov,"ENROLL",1,public(self.model))
        self.deny_transition(x,"UNSAFE_GOVERNANCE_ADMIN_ROOT_VALUE")
    def test_16_wrong_governance_root_at_constructor(self):
        with self.assertRaisesRegex(BrokerDenied,"INDEPENDENT_FROZEN_TEST_GOVERNANCE_ROOT_REQUIRED"):
            GovernedAdminRootBroker(
               Path(self.temp.name)/"bad.sqlite3",
               pinned_governance_root=public(self.model),
               pinned_operator_root=public(self.model),
               synthetic_credential=SECRET,trusted_clock=lambda:NOW)
    def test_17_same_enroll_manifest_replay(self):
        manifest=self.enroll()
        self.deny_transition(manifest,"MONOTONIC_EPOCH")
    def test_18_epoch_skip_and_wrong_previous_fails(self):
        self.enroll()
        wrong_epoch=make_root_manifest(self.gov,"ROTATE",3,public(self.admin_b),
                                       sha_root(public(self.admin_a)))
        self.deny_transition(wrong_epoch,"MONOTONIC_EPOCH")
        wrong_previous=make_root_manifest(self.gov,"ROTATE",2,public(self.admin_b),"f"*64)
        self.deny_transition(wrong_previous,"MONOTONIC_EPOCH")
    def test_19_admin_a_can_revoke_if_enrolled(self):
        self.enroll()
        outcome=self.broker.revoke_signed(signed_admin(self.admin_a))
        self.assertEqual(outcome["used_admin_epoch"],1)
        self.assertEqual(self.broker.revocation_status()["revoked_count"],1)
    def test_20_stale_admin_a_cannot_revoke_after_rotation(self):
        self.enroll()
        self.rotate()
        with self.assertRaisesRegex(BrokerDenied,"INVALID_INDEPENDENT_ADMIN_SIGNATURE"):
            self.broker.revoke_signed(signed_admin(self.admin_a))
        self.assertEqual(self.broker.revocation_status()["revoked_count"],0)
    def test_21_admin_b_can_revoke_after_rotation(self):
        self.enroll();self.rotate()
        result=self.broker.revoke_signed(signed_admin(self.admin_b))
        self.assertEqual(result["used_admin_epoch"],2)
        self.assertEqual(self.broker.revocation_status()["revoked_count"],1)
    def test_22_rotation_persistent_across_reopen(self):
        self.enroll();self.rotate()
        reopened=self.open()
        self.assertEqual(reopened.root_status()["active_epoch"],2)
        with self.assertRaisesRegex(BrokerDenied,"INVALID_INDEPENDENT_ADMIN_SIGNATURE"):
            reopened.revoke_signed(signed_admin(self.admin_a))
    def test_23_revoked_admin_root_blocks_all_admins(self):
        self.enroll();self.rotate()
        tomb=make_root_manifest(self.gov,"REVOKE",3,None,sha_root(public(self.admin_b)))
        self.broker.transition_signed(tomb)
        for who in (self.admin_a,self.admin_b,self.admin_c):
            with self.assertRaisesRegex(BrokerDenied,"NO_ACTIVE_GOVERNED_ADMIN_ROOT"):
                self.broker.revoke_signed(signed_admin(who))
        self.assertEqual(self.broker.root_status()["events"],["ENROLL","ROTATE","REVOKE"])
    def test_24_revocation_terminal_prevents_reenroll(self):
        self.enroll()
        self.broker.transition_signed(make_root_manifest(
            self.gov,"REVOKE",2,None,sha_root(public(self.admin_a))))
        self.deny_transition(make_root_manifest(
            self.gov,"ROTATE",3,public(self.admin_c),sha_root(public(self.admin_a))),
            "TERMINAL_GOVERNANCE_REVOCATION")
    def test_25_reuse_historic_admin_root_denied(self):
        self.enroll();self.rotate()
        x=make_root_manifest(self.gov,"ROTATE",3,public(self.admin_a),
                             sha_root(public(self.admin_b)))
        self.deny_transition(x,"HISTORIC_ADMIN_ROOT_REUSE_FORBIDDEN")
    def test_26_admin_command_replay_denied_after_rotation(self):
        self.enroll();self.rotate()
        token=signed_admin(self.admin_b)
        self.broker.revoke_signed(token)
        with self.assertRaisesRegex(BrokerDenied,"ADMIN_COMMAND_NONCE_ALREADY_CONSUMED"):
            self.broker.revoke_signed(token)
    def test_27_wrong_admin_cannot_write_any_revocation(self):
        self.enroll();self.rotate()
        with self.assertRaisesRegex(BrokerDenied,"INVALID_INDEPENDENT_ADMIN_SIGNATURE"):
            self.broker.revoke_signed(signed_admin(self.admin_c))
        self.assertEqual(self.broker.revocation_status()["revoked_count"],0)
    def test_28_concurrent_same_epoch_only_one_rotation(self):
        self.enroll()
        x=make_root_manifest(self.gov,"ROTATE",2,public(self.admin_b),
                             sha_root(public(self.admin_a)))
        def go(_):
            try:
                self.broker.transition_signed(x)
                return "OK"
            except BrokerDenied:
                return "DENIED"
        with ThreadPoolExecutor(max_workers=8) as pool:
            r=list(pool.map(go,range(16)))
        self.assertEqual(r.count("OK"),1)
        self.assertEqual(r.count("DENIED"),15)
        self.assertEqual(self.broker.root_status()["epochs"],2)
    def test_29_admin_revocation_is_atomic_before_mock_claim(self):
        self.enroll();self.rotate()
        self.broker.revoke_signed(signed_admin(self.admin_b))
        self.assertEqual(self.broker.status()["rows"],0)
        self.assertEqual(self.broker.mock_calls,0)
    def test_30_governance_audit_tamper_detected(self):
        self.enroll();self.rotate()
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM governed_admin_root_audit WHERE epoch=2")
        with self.assertRaisesRegex(BrokerDenied,"GOVERNANCE_ROOT_EPOCH_OR_AUDIT_INTEGRITY_ERROR"):
            self.broker.root_status()

def sha_root(value):
    import hashlib
    return hashlib.sha256(value).hexdigest()

if __name__=="__main__":
    unittest.main()
