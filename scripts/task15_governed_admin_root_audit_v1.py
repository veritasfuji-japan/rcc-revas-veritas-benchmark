#!/usr/bin/env python3
"""#286 independent offline governable admin-root epoch/rotation/revocation proof.

No Docker runtime or Provider wire is enabled. This is an isolated broker
core + durable SQLite evidence round only. Trusted ephemeral governance
signer is pinned at broker construction; real-human enrollment NOT proven.
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
os.environ["TASK15_GOVERNED_ADMIN_ROOT_PROOF"]="1"

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from task15_mock_broker_authorization_boundary_v1 import BrokerDenied,canonical,exact_request,sha
from task15_governed_admin_root_lifecycle_v1 import (
    RULE, GovernedAdminRootBroker
)
from test_task15_governed_admin_root_lifecycle_v1 import (
    GovernedAdminRootLifecycleTests,NOW,SECRET,public,
    make_root_manifest,signed_admin,sha_root
)

BASE="24a28ee3b6fd058f73fd519653d5c087b3515334"

def require(ok,reason):
    if not ok:raise AssertionError(reason)

class Collect(unittest.TextTestResult):
    def __init__(self,*args,**kw):
        super().__init__(*args,**kw);self.cases=[]
    def addSuccess(self,test):
        super().addSuccess(test)
        self.cases.append((test.id(),"PASS"))
    def addError(self,test,err):
        super().addError(test,err)
        self.cases.append((test.id(),"ERROR"))
    def addFailure(self,test,err):
        super().addFailure(test,err)
        self.cases.append((test.id(),"FAIL"))
    def addSkip(self,test,reason):
        super().addSkip(test,reason)
        self.cases.append((test.id(),"SKIP"))

def inspect_db(source,destination):
    with sqlite3.connect(source) as db:
        require(db.execute("PRAGMA integrity_check").fetchone()[0]=="ok",
                "SOURCE_SQLITE_CORRUPT")
        with sqlite3.connect(destination) as out:
            db.backup(out)
    with sqlite3.connect(destination) as db:
        require(db.execute("PRAGMA integrity_check").fetchone()[0]=="ok",
                "ARCHIVED_SQLITE_CORRUPT")
        tables={}
        for table in ("governed_admin_roots","governed_admin_root_audit",
                      "admin_commands","admin_audit","revoked_requests",
                      "revocation_audit","dispatches","audit"):
            rows=db.execute("SELECT * FROM "+table).fetchall()
            tables[table]=[list(x) for x in rows]
    return {"file":destination.name,
            "sqlite_sha256":hashlib.sha256(destination.read_bytes()).hexdigest(),
            "tables":tables,"sqlite_integrity":"ok"}

def verify_manifest(e,root):
    Ed25519PublicKey.from_public_bytes(root).verify(
        bytes.fromhex(e["signature_hex"]),
        canonical(e["statement"]).encode("utf-8"))

def new_broker(path,governance_root,model_root):
    return GovernedAdminRootBroker(
        path,pinned_governance_root=governance_root,
        pinned_operator_root=model_root,
        synthetic_credential=SECRET,trusted_clock=lambda:NOW)

def scenario(kind,out):
    gov=Ed25519PrivateKey.generate()
    model=Ed25519PrivateKey.generate()
    first=Ed25519PrivateKey.generate()
    second=Ed25519PrivateKey.generate()
    gov_root,model_root=public(gov),public(model)
    a,b=public(first),public(second)
    require(len({gov_root,model_root,a,b})==4,
            "ALL_FOUR_TEST_SIGNING_ROOTS_MUST_BE_DISTINCT")
    with tempfile.TemporaryDirectory(prefix="task15-governed-admin-root-") as td:
        path=Path(td)/"governed.sqlite3"
        broker=new_broker(path,gov_root,model_root)
        enrollment=make_root_manifest(gov,"ENROLL",1,a)
        rotation=make_root_manifest(gov,"ROTATE",2,b,sha_root(a))
        verify_manifest(enrollment,gov_root)
        verify_manifest(rotation,gov_root)
        broker.transition_signed(enrollment)
        broker.transition_signed(rotation)
        stale=signed_admin(first)
        verify_manifest(stale,a)
        with_expected="INVALID_INDEPENDENT_ADMIN_SIGNATURE"
        try:
            broker.revoke_signed(stale)
        except BrokerDenied as error:
            require(str(error)==with_expected,"STALE_ADMIN_DENIAL_CODE_MISMATCH")
        else:
            raise AssertionError("ROTATED_OLD_ADMIN_SIGNER_WAS_ACCEPTED")
        require(broker.revocation_status()["revoked_count"]==0,
                "OLD_ADMIN_SIGNER_MODIFIED_REVOCATION_STATE")
        fresh=signed_admin(second)
        verify_manifest(fresh,b)
        if kind=="rotate_then_authorize":
            record=broker.revoke_signed(fresh)
            require(record["state"]=="REVOKED" and
                    record["used_admin_epoch"]==2,
                    "FRESH_ENROLLED_ADMIN_DID_NOT_REVOKE")
            with_expected="ADMIN_COMMAND_NONCE_ALREADY_CONSUMED"
            try:
                broker.revoke_signed(fresh)
            except BrokerDenied as error:
                require(str(error)==with_expected,
                        "USED_SIGNED_ADMIN_NONCE_NOT_DENIED")
            else:
                raise AssertionError("SIGNED_ADMIN_NONCE_REPLAY_SUCCEEDED")
            terminal=None
        elif kind=="terminal_root_revocation":
            terminal=make_root_manifest(gov,"REVOKE",3,None,sha_root(b))
            verify_manifest(terminal,gov_root)
            broker.transition_signed(terminal)
            try:
                broker.revoke_signed(fresh)
            except BrokerDenied as error:
                require(str(error)=="NO_ACTIVE_GOVERNED_ADMIN_ROOT",
                        "REVOKED_ADMIN_ROOT_DID_NOT_FAIL_CLOSED")
            else:
                raise AssertionError("REVOKED_ROOT_ACCEPTED_ADMIN_COMMAND")
            require(broker.revocation_status()["revoked_count"]==0,
                    "TERMINAL_TEST_ROOT_REVOCATION_CREATED_TARGET_REVOCATION")
            record=None
        else:
            raise AssertionError("UNKNOWN_FROZEN_LIFECYCLE_SCENARIO")
        reopened=new_broker(path,gov_root,model_root)
        current=reopened.root_status()
        require(current["epochs"]==(3 if terminal else 2) and
                current["active_epoch"]==(None if terminal else 2) and
                current["terminally_revoked"]==bool(terminal),
                "DURABLE_GOVERNANCE_ROOT_STATUS_CHANGED_ON_RESTART")
        sqlite=inspect_db(path,out/(kind+".sqlite3"))
        tables=sqlite["tables"]
        require(len(tables["governed_admin_roots"])==
                len(tables["governed_admin_root_audit"])==
                current["epochs"],"GOVERNANCE_EPOCH_AUDIT_ROW_MISMATCH")
        require(len(tables["admin_commands"])==
                len(tables["admin_audit"])==
                len(tables["revoked_requests"])==
                len(tables["revocation_audit"])==
                (0 if terminal else 1),
                "SIGNED_ADMIN_REVOCATION_TRANSACTION_NOT_ATOMIC")
        require(len(tables["dispatches"])==len(tables["audit"])==0,
                "GOVERNANCE_CONTROL_MUST_NOT_DISPATCH_MODEL")
        if not terminal:
            row=tables["admin_commands"][0]
            require(row[0]==fresh["statement"]["nonce"] and
                    row[1]==sha(fresh) and
                    row[2]==sha(exact_request()) and
                    row[3]==sha_root(b),
                    "SIGNED_ADMIN_COMMAND_NOT_BOUND_TO_NEW_ACTIVE_ROOT")
        return {
            "scenario":kind,
            "predecessor_main_sha":BASE,
            "test_governance_root_hex":gov_root.hex(),
            "test_model_root_hex":model_root.hex(),
            "test_admin_a_root_hex":a.hex(),
            "test_admin_b_root_hex":b.hex(),
            "signed_root_enrollment":enrollment,
            "signed_root_rotation":rotation,
            "signed_root_revocation":terminal,
            "old_admin_signed_attempt":stale,
            "new_admin_signed_attempt":fresh,
            "successful_authorized_revocation":record,
            "stale_admin_denied":True,
            "terminal_root_denied_new_admin":bool(terminal),
            "reopened_status":current,
            "sqlite":sqlite,
            "synthetic_mock_calls":broker.mock_calls,
            "real_provider_requests":0,
            "real_provider_spend_usd":0,
            "bank_effects":0
        }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output-dir",required=True,type=Path)
    args=p.parse_args()
    out=args.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    contract=json.loads(
        (ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE and
            contract["predecessor_merged_main_sha"]==BASE and
            contract["real_provider_execution_authorized"] is False,
            "UNFROZEN_GOVERNANCE_SCOPE_OR_LIVE_EXECUTION")

    require(not any(os.environ.get(k) for k in (
        "OPENAI_API_KEY","OPENAI_BASE_URL","ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY","GH_TOKEN","GITHUB_TOKEN"
    )),"NO_REAL_PROVIDER_KEYS_IN_OFFLINE_PROOF")

    tests=unittest.TestLoader().loadTestsFromTestCase(
        GovernedAdminRootLifecycleTests)
    result=unittest.TextTestRunner(
        stream=sys.stdout,verbosity=2,resultclass=Collect).run(tests)
    require(result.wasSuccessful() and len(result.cases)==30 and
            all(status=="PASS" for _,status in result.cases),
            "THIRTY_ADVERSARIAL_GOVERNED_ROOT_CASES_REQUIRED")
    xml=ET.Element("testsuite",name=RULE,tests="30",
                   failures="0",errors="0",skipped="0")
    for name,_ in result.cases:
        ET.SubElement(xml,"testcase",classname=RULE,name=name)
    ET.ElementTree(xml).write(out/"task15-governed-admin-root-junit.xml",
                               encoding="utf-8",xml_declaration=True)

    scenarios=[
        scenario("rotate_then_authorize",out),
        scenario("terminal_root_revocation",out)
    ]
    require(all(s["synthetic_mock_calls"]==0 and
                s["real_provider_requests"]==0 for s in scenarios),
            "NO_MODEL_EFFECT_DURING_ADMIN_ROOT_LIFECYCLE")
    checks={
        "distinct_model_governance_and_admin_roots":True,
        "signature_and_manifest_scope_verified":True,
        "stale_admin_root_rejected":all(s["stale_admin_denied"] for s in scenarios),
        "new_root_accepts_exact_signed_revocation":
            scenarios[0]["successful_authorized_revocation"]["used_admin_epoch"]==2,
        "terminal_root_disables_subsequent_admin_signatures":
            scenarios[1]["terminal_root_denied_new_admin"],
        "db_evidence_integrity":all(s["sqlite"]["sqlite_integrity"]=="ok"
                                    for s in scenarios),
        "no_real_provider_billing_or_bank_effects":all(
            s["real_provider_requests"]==s["real_provider_spend_usd"]==
            s["bank_effects"]==0 for s in scenarios)
    }
    require(all(checks.values()),"FROZEN_ADMIN_ROOT_SCENARIO_ASSERTION_FAILED")
    evidence={
        "rule_of_one":RULE,
        "predecessor_merged_main_sha":BASE,
        "tests_passed":30,"scenario_assertions":checks,
        "scenarios":scenarios,
        "determination":"BOUNDED_TEST_GOVERNANCE_ROOT_LIFECYCLE_PROVED_ONLY_IN_TRUSTED_MOCK_BROKER_CORE",
        "real_provider_requests":0,"spend_usd":0,"bank_effects":0,
        "independent_auditor_determination":"PENDING",
        "not_proven":"Real administrator enrollment or production Docker/AF_UNIX root loading"
    }
    (out/"task15-governed-admin-root-evidence.json").write_text(
        json.dumps(evidence,sort_keys=True,indent=2)+"\n")
    print("PASS_BOUNDED_GOVERNED_ADMIN_ROOT: 30/30; 2/2 raw SQLite scenarios")
    print("REAL_PROVIDER_REQUESTS=0; SPEND_USD=0; BANK_EFFECTS=0")
    print("NOT_PRODUCTION_PROVEN: Real admin identity/IAM and Docker integration")
if __name__=="__main__":
    main()
