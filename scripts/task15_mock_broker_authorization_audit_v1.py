#!/usr/bin/env python3
"""Offline broker audit: 30 tests and two independently readable SQLite ledgers."""
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/"tests"))
from task15_mock_broker_authorization_boundary_v1 import (
    RULE, MockAuthorizationBroker, BrokerDenied, exact_request, sha
)
from test_task15_mock_broker_authorization_boundary_v1 import (
    SECRET, NOW, make_grant, BrokerBoundaryTests
)

def require(ok, reason):
    if not ok: raise AssertionError(reason)

class TrackedResult(unittest.TextTestResult):
    def __init__(self,*a,**k):
        super().__init__(*a,**k)
        self.records=[]
    def addSuccess(self,test):
        super().addSuccess(test)
        self.records.append((test.id(),"PASS",""))
    def addFailure(self,test,err):
        super().addFailure(test,err)
        self.records.append((test.id(),"FAIL",self._exc_info_to_string(err,test)[-1000:]))
    def addError(self,test,err):
        super().addError(test,err)
        self.records.append((test.id(),"ERROR",self._exc_info_to_string(err,test)[-1000:]))
    def addSkip(self,test,reason):
        super().addSkip(test,reason)
        self.records.append((test.id(),"SKIP",reason))

def dump_db(source, output):
    with sqlite3.connect(source) as src:
        with sqlite3.connect(output) as dst:
            src.backup(dst)
    with sqlite3.connect(output) as db:
        require(db.execute("PRAGMA integrity_check").fetchone()[0]=="ok",
                "ARCHIVED_SQLITE_INTEGRITY_FAILED")
        rows=db.execute("SELECT request_sha,approval_sha,state,claim_count,"
                        "response_sha,response_json FROM dispatches").fetchall()
        audit=db.execute("SELECT event FROM audit ORDER BY seq").fetchall()
    require(len(rows)==1,"EXACT_ONE_SQLITE_DISPATCH_REQUIRED")
    return {"file":output.name,"sha256":hashlib.sha256(output.read_bytes()).hexdigest(),
            "row":list(rows[0][:5]),"audit":[v[0] for v in audit]}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output-dir",required=True,type=Path)
    args=parser.parse_args()
    out=args.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE and
            contract["predecessor_merged_main_sha"]==
            "3d0a319931cd4f43a206cb3d1ac6b3d8e6b8384a" and
            contract["real_provider_calls_authorized"] is False,
            "CONTRACT_OR_SCOPE_DRIFT")
    require(not any(os.environ.get(x) for x in
                    ("OPENAI_API_KEY","OPENAI_BASE_URL","ANTHROPIC_API_KEY")),
            "PROVIDER_CREDENTIAL_PRESENT_IN_CI")
    suite=unittest.TestLoader().loadTestsFromTestCase(BrokerBoundaryTests)
    runner=unittest.TextTestRunner(stream=sys.stdout,verbosity=2,resultclass=TrackedResult)
    outcome=runner.run(suite)
    cases=outcome.records
    root=ET.Element("testsuite",name=RULE,tests=str(len(cases)),
                    failures=str(len(outcome.failures)),errors=str(len(outcome.errors)),
                    skipped=str(len(outcome.skipped)))
    for name,result,detail in cases:
        e=ET.SubElement(root,"testcase",classname=RULE,name=name)
        if result!="PASS":
            ET.SubElement(e,"failure",message=result).text=detail
    ET.ElementTree(root).write(out/"task15-mock-broker-junit.xml",
                               encoding="utf-8",xml_declaration=True)
    require(outcome.wasSuccessful() and len(cases)==30 and
            all(x[1]=="PASS" for x in cases), "EXACT_30_TESTS_MUST_PASS")
    request=exact_request();grant,key,root_pub=make_grant(request)
    evidence={"rule_of_one":RULE,"kind":"OFFLINE_TEST_ONLY_BROKER_AUTHORIZATION",
              "predecessor_merged_main_sha":contract["predecessor_merged_main_sha"],
              "test_only_operator_root_hex":root_pub.hex(),
              "signed_test_only_grant":grant,"exact_request":request,
              "request_sha256":sha(request),"approval_sha256":sha(grant),
              "junit_tests":len(cases),"real_provider_requests":0,
              "real_provider_spend_usd":0,"bank_effects":0}
    with tempfile.TemporaryDirectory() as t:
        ok=MockAuthorizationBroker(Path(t)/"positive.sqlite3",
                    pinned_operator_root=root_pub,synthetic_credential=SECRET,
                    trusted_clock=lambda:NOW)
        receipt=ok.execute({"request":request,"approval":grant})
        require(receipt["state"]=="MOCK_RECORDED" and
                receipt["real_provider_requests"]==0 and ok.mock_calls==1 and
                ok.status()["events"]==2,"VALID_OFFLINE_MOCK_ONE_SHOT_REQUIRED")
        evidence["positive"]=dump_db(ok.ledger,out/"broker-positive.sqlite3")
        with tempfile.TemporaryDirectory() as u:
            unknown=MockAuthorizationBroker(Path(u)/"unknown.sqlite3",
                       pinned_operator_root=root_pub,synthetic_credential=SECRET,
                       trusted_clock=lambda:NOW,mock_fail=True)
            try:
                unknown.execute({"request":request,"approval":grant})
            except RuntimeError:
                pass
            else:
                raise AssertionError("MOCK_AMBIGUOUS_DELIVERY_SHOULD_FAIL")
            require(unknown.status()["states"]==["DISPATCH_UNKNOWN"]
                    and unknown.mock_calls==1,
                    "AMBIGUOUS_DELIVERY_MUST_REMAIN_UNKNOWN")
            try:
                unknown.execute({"request":request,"approval":grant})
            except BrokerDenied:
                pass
            else:
                raise AssertionError("UNKNOWN_STATE_CANNOT_RETRY")
            evidence["unknown"]=dump_db(unknown.ledger,out/"broker-unknown.sqlite3")
    require(evidence["positive"]["row"][2]=="MOCK_RECORDED" and
            evidence["positive"]["row"][3]==1 and
            len(evidence["positive"]["audit"])==2 and
            evidence["unknown"]["row"][2]=="DISPATCH_UNKNOWN" and
            evidence["unknown"]["row"][3]==1 and
            len(evidence["unknown"]["audit"])==1,
            "RAW_SQLITE_WRONG_STATES")
    (out/"task15-mock-broker-evidence.json").write_text(
        json.dumps(evidence,indent=2,sort_keys=True)+"\n")
    (out/"task15-mock-broker-tests.json").write_text(
        json.dumps({"cases":[dict(name=a,result=b) for a,b,_ in cases]},
                   indent=2,sort_keys=True)+"\n")
    print("PASS_OFFLINE_BROKER_BOUNDARY: 30/30; sqlite=2; real calls=0")
    print("NOT_PROVEN: operator enrollment, OS separation, real effect sink")

if __name__=="__main__":
    main()
