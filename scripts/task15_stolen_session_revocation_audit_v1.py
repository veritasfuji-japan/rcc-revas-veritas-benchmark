#!/usr/bin/env python3
"""Exact offline artifact for stolen worker-session and durable revocation V1.

Two durable independent SQLite states are archived:
- REVOKE_BEFORE_CLAIM: zero sink effects even with copied valid grant/key
- CLAIM_BEFORE_REVOKE: one mock effect can happen, never rolled back
No Provider sends, API keys, billing, bank effects or worker IPC integrations.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/"tests"))
os.environ["TASK15_STOLEN_SESSION_PROOF"]="1"
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from task15_mock_broker_authorization_boundary_v1 import (
    BrokerDenied,canonical,exact_request,sha
)
from task15_stolen_session_revocation_fence_v1 import (
    RULE,RevocableMockAuthorizationBroker,REVOKED
)
from test_task15_stolen_session_revocation_fence_v1 import (
    StolenSessionRevocationTests,STOLEN_SESSION_KEY,SECRET,NOW,fixture
)
from scripts.task15_session_challenge_broker_server_v1 import mac_hex

def require(ok,reason):
    if not ok:
        raise AssertionError(reason)

class TrackedResult(unittest.TextTestResult):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.records=[]
    def addSuccess(self,test):
        super().addSuccess(test)
        self.records.append((test.id(),"PASS",""))
    def addFailure(self,test,err):
        super().addFailure(test,err)
        self.records.append((test.id(),"FAIL",self._exc_info_to_string(err,test)[-800:]))
    def addError(self,test,err):
        super().addError(test,err)
        self.records.append((test.id(),"ERROR",self._exc_info_to_string(err,test)[-800:]))
    def addSkip(self,test,reason):
        super().addSkip(test,reason)
        self.records.append((test.id(),"SKIP",reason))

def inspect_and_copy(original,dest):
    with sqlite3.connect(original) as source:
        require(source.execute("PRAGMA integrity_check").fetchone()[0]=="ok",
                "SOURCE_SQLITE_INTEGRITY_FAIL")
        rows=source.execute("SELECT request_sha,approval_sha,state,claim_count,"
                            "response_sha,response_json FROM dispatches").fetchall()
        rev=source.execute("SELECT request_sha,reason,sequence"
                           " FROM revoked_requests ORDER BY request_sha").fetchall()
        audit=source.execute("SELECT request_sha,event FROM audit ORDER BY seq").fetchall()
        rev_audit=source.execute("SELECT request_sha,event FROM revocation_audit ORDER BY id").fetchall()
        with sqlite3.connect(dest) as target:
            source.backup(target)
    with sqlite3.connect(dest) as copied:
        require(copied.execute("PRAGMA integrity_check").fetchone()[0]=="ok",
                "ARCHIVED_SQLITE_INTEGRITY_FAIL")
    require(len(rev)==len(rev_audit)==1 and
            rev[0][1:] == ("STOLEN_WORKER_SESSION",1) and
            rev_audit[0] == (rev[0][0],"REVOCATION_COMMITTED"),
            "EXACT_SINGLE_DURABLE_REVOCATION_REQUIRED")
    return {
        "file":dest.name,
        "sqlite_sha256":hashlib.sha256(dest.read_bytes()).hexdigest(),
        "dispatch_rows":[list(x[:5]) for x in rows],
        "dispatch_audit":[list(x) for x in audit],
        "revocation_rows":[list(x) for x in rev],
        "revocation_audit":[list(x) for x in rev_audit],
        "response_sha256_verified":all(
            sha(json.loads(x[5]))==x[4] for x in rows if x[2]=="MOCK_RECORDED")
    }

def broker(path,root,fail=False):
    return RevocableMockAuthorizationBroker(
        path,pinned_operator_root=root,synthetic_credential=SECRET,
        trusted_clock=lambda:NOW,mock_fail=fail)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--output-dir",required=True,type=Path)
    args=ap.parse_args()
    out=args.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE and
            contract["predecessor_merged_main_sha"]==
            "384110807d7a5e418b06f06853f23f8c44739e32" and
            contract["real_provider_calls_authorized"] is False,
            "WRONG_BASE_OR_REAL_PROVIDER_SCOPE")
    require(not any(os.environ.get(x) for x in (
        "OPENAI_API_KEY","OPENAI_BASE_URL","ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY","GH_TOKEN","GITHUB_TOKEN"
    )),"LIVE_CREDENTIAL_IN_TEST_ENV")
    suite=unittest.TestLoader().loadTestsFromTestCase(StolenSessionRevocationTests)
    results=unittest.TextTestRunner(stream=sys.stdout,verbosity=2,
                                   resultclass=TrackedResult).run(suite)
    require(results.wasSuccessful() and len(results.records)==20 and
            all(r[1]=="PASS" for r in results.records),
            "TWENTY_EXACT_STOLEN_SESSION_NEGATIVE_CASES_REQUIRED")
    junit=ET.Element("testsuite",name=RULE,tests="20",failures="0",
                     errors="0",skipped="0")
    for name,result,detail in results.records:
        ET.SubElement(junit,"testcase",classname=RULE,name=name)
    ET.ElementTree(junit).write(out/"task15-stolen-session-junit.xml",
                               encoding="utf-8",xml_declaration=True)

    envelope,signer,root=fixture()
    public_stmt=envelope["approval"]["statement"]
    Ed25519PublicKey.from_public_bytes(root).verify(
        bytes.fromhex(envelope["approval"]["signature_hex"]),
        canonical(public_stmt).encode())
    nonce="bc"*32
    stolen_mac=mac_hex(STOLEN_SESSION_KEY,nonce,envelope)
    require(len(stolen_mac)==64 and
            stolen_mac==mac_hex(STOLEN_SESSION_KEY,nonce,envelope),
            "COPIED_KEY_CAN_COMPUTE_CURRENT_AUTHENTIC_TAG")

    with tempfile.TemporaryDirectory() as temp:
        revoked=broker(Path(temp)/"revoked.sqlite3",root)
        revoked.revoke(sha(envelope["request"]))
        try:
            revoked.execute(envelope)
        except BrokerDenied as exc:
            require(str(exc)==REVOKED,"REVOKED_GRANT_WRONG_DENIAL")
        else:
            raise AssertionError("REVOKED_BROKER_MOCK_SINK_EXECUTED")
        restarted=broker(revoked.ledger,root)
        try:
            restarted.execute(envelope)
        except BrokerDenied as exc:
            require(str(exc)==REVOKED,"RESTART_DID_NOT_PRESERVE_REVOCATION")
        else:
            raise AssertionError("RESTART_REVOCATION_FAILED")
        require(revoked.mock_calls==0 and restarted.mock_calls==0 and
                revoked.status()["rows"]==0,
                "PRECLAIM_REVOKE_MUST_LEAVE_ZERO_EFFECTS")
        archived_revoke=inspect_and_copy(
            revoked.ledger,out/"revoke-before-claim.sqlite3")
        require(archived_revoke["dispatch_rows"]==[] and
                archived_revoke["dispatch_audit"]==[],
                "PRECLAIM_REVOCATION_CANNOT_HAVE_DISPATCH_ROW")

        at_risk=broker(Path(temp)/"attack-before-revoke.sqlite3",root)
        # Deliberate disclosure of the bounded negative result:
        # a stolen session key plus a copied valid signed TEST grant can
        # win one already-authorized mock action BEFORE the revoke commits.
        receipt=at_risk.execute(envelope)
        require(receipt["state"]=="MOCK_RECORDED" and
                at_risk.mock_calls==1,"PRE_REVOCATION_ATTACK_MUST_SHOW_RISK")
        at_risk.revoke(sha(envelope["request"]))
        try:
            at_risk.execute(envelope)
        except BrokerDenied as exc:
            require(str(exc)==REVOKED,"POST_EFFECT_REVOCATION_NOT_ENFORCED")
        else:
            raise AssertionError("SECOND_MOCK_EFFECT_IN_STOLEN_KEY_SCENARIO")
        archived_risk=inspect_and_copy(
            at_risk.ledger,out/"claim-before-revoke.sqlite3")
        require(len(archived_risk["dispatch_rows"])==1 and
                archived_risk["dispatch_rows"][0][2]=="MOCK_RECORDED" and
                archived_risk["dispatch_rows"][0][3]==1 and
                len(archived_risk["dispatch_audit"])==2 and
                archived_risk["response_sha256_verified"],
                "PRE_REVOCATION_LIMIT_ONE_MOCK_EFFECT_NOT_CLOSED")

    evidence={
        "rule_of_one":RULE,
        "determination":"DURABLE_TRUSTED_SIDE_PRECLAIM_REVOKE_BLOCKS_NEW_MOCK_CLAIMS_NOT_COMPROMISE_PREVENTION",
        "predecessor_merged_main_sha":contract["predecessor_merged_main_sha"],
        "test_operator_root_hex":root.hex(),"signed_test_grant":envelope,
        "request_sha256":sha(envelope["request"]),
        "approval_sha256":sha(envelope["approval"]),
        "synthetic_stolen_key_sha256":hashlib.sha256(STOLEN_SESSION_KEY).hexdigest(),
        "synthetic_compromised_session_mac_hex":stolen_mac,
        "synthetic_challenge_hex":nonce,
        "unit_tests_pass":len(results.records),
        "preclaim_revocation":archived_revoke,
        "claim_first_risk":archived_risk,
        "real_provider_requests":0,"real_provider_spend_usd":0,
        "bank_effects":0,
        "independent_auditor_determination":"PENDING",
        "does_not_claim":"Worker key theft prevention, enrolled operator authority, or actual Docker IPC integration"
    }
    (out/"task15-stolen-session-evidence.json").write_text(
        json.dumps(evidence,sort_keys=True,indent=2)+"\n")
    (out/"task15-stolen-session-case-results.json").write_text(
        json.dumps({"cases":[{"name":a,"status":b} for a,b,_ in results.records]},
                   sort_keys=True,indent=2)+"\n")
    print("PASS_BOUNDED_STOLEN_SESSION_REVOCATION: 20/20; "+
          "REVOCATION_FIRST=0 EFFECTS; CLAIM_FIRST=1 MOCK EFFECT")
    print("REAL_PROVIDER_REQUESTS=0; SPEND_USD=0; BANK_EFFECTS=0")
    print("NOT_PROVEN: operator authorization, socket integration, host compromise resistance")

if __name__=="__main__":
    main()
