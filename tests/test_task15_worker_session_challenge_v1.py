"""Offline adversarial fresh HMAC challenge tests; separate dedicated workflow."""
from __future__ import annotations
import copy
import hashlib
import hmac
import os
import tempfile
from pathlib import Path
import unittest
if os.environ.get("TASK15_WORKER_SESSION_PROOF")!="1":
    raise unittest.SkipTest("Dedicated offline task15 session-challenge proof only")
from scripts.task15_session_challenge_broker_server_v1 import (
    DOMAIN,mac_hex,load_secret,BrokerDenied
)
from task15_mock_broker_authorization_boundary_v1 import exact_request

KEY=bytes(range(32))
NONCE="a1"*32
ENVELOPE={"request":exact_request(),"approval":{"test_only":"grant"}}

class HmacSessionBoundaryTests(unittest.TestCase):
    def test_01_correct_hmac_deterministic(self):
        expected=hmac.new(KEY,DOMAIN+bytes.fromhex(NONCE)+
            hashlib.sha256(__import__("json").dumps(ENVELOPE,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).digest(),
            hashlib.sha256).hexdigest()
        self.assertEqual(mac_hex(KEY,NONCE,ENVELOPE),expected)
    def test_02_stale_nonce_differs(self):
        self.assertNotEqual(mac_hex(KEY,NONCE,ENVELOPE),mac_hex(KEY,"b2"*32,ENVELOPE))
    def test_03_wrong_key_differs(self):
        self.assertNotEqual(mac_hex(KEY,NONCE,ENVELOPE),mac_hex(b"\x00"*32,NONCE,ENVELOPE))
    def test_04_request_binding(self):
        x=copy.deepcopy(ENVELOPE);x["request"]["target"]["host"]="attacker.invalid"
        self.assertNotEqual(mac_hex(KEY,NONCE,ENVELOPE),mac_hex(KEY,NONCE,x))
    def test_05_approval_binding(self):
        x=copy.deepcopy(ENVELOPE);x["approval"]["test_only"]="tampered"
        self.assertNotEqual(mac_hex(KEY,NONCE,ENVELOPE),mac_hex(KEY,NONCE,x))
    def test_06_reordered_json_canonical(self):
        x={"approval":ENVELOPE["approval"],"request":ENVELOPE["request"]}
        self.assertEqual(mac_hex(KEY,NONCE,ENVELOPE),mac_hex(KEY,NONCE,x))
    def test_07_private_root_files_missing(self):
        with self.assertRaises(BrokerDenied):
            load_secret("/this-test-path-must-not-exist-28152",0o600)
    def test_08_file_mode_wrong(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"test";p.write_bytes(KEY);p.chmod(0o644)
            with self.assertRaises(BrokerDenied):load_secret(p,0o600)
    def test_09_token_requires_readonly_mode(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"token";p.write_bytes(KEY);p.chmod(0o600)
            with self.assertRaises(BrokerDenied):load_secret(p,0o444)
    def test_10_correct_private_file(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"credential";p.write_bytes(KEY);p.chmod(0o600)
            self.assertEqual(load_secret(p,0o600),KEY)
    def test_11_symlink_disallowed(self):
        with tempfile.TemporaryDirectory() as td:
            real=Path(td)/"real";real.write_bytes(KEY);real.chmod(0o600)
            link=Path(td)/"link";link.symlink_to(real)
            with self.assertRaises(BrokerDenied):load_secret(link,0o600)
    def test_12_test_token_not_leaked_by_hmac(self):
        self.assertNotIn(KEY.hex(),mac_hex(KEY,NONCE,ENVELOPE))
if __name__=="__main__":
    unittest.main()
