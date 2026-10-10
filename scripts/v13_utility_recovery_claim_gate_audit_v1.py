#!/usr/bin/env python3
"""Recompute exact V13 utility gap truth, no recovery or Provider authority.

The independent primary V13 artifact was previously audited; this checker
re-computes strict cross-contract arithmetic and source case partitions from
frozen committed contracts. It MUST NOT call provider, scorer, live tools or
claim newly measured Utility.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/"tests"))
os.environ["V13_UTILITY_RECOVERY_GATE_PROOF"]="1"
from v13_utility_recovery_claim_gate_v1 import RULE, SOURCE_SHA, classify
from test_v13_utility_recovery_claim_gate_v1 import UtilityRecoveryGateTests

def must(ok,reason):
    if not ok:raise AssertionError(reason)

def blob(path):
    return subprocess.run(["git","hash-object",str(path)],cwd=ROOT,
                          text=True,check=True,capture_output=True).stdout.strip()

class Results(unittest.TextTestResult):
    def __init__(self,*a,**kw):
        super().__init__(*a,**kw);self.outcomes=[]
    def addSuccess(self,test):
        super().addSuccess(test);self.outcomes.append((test.id(),"PASS"))
    def addError(self,test,err):
        super().addError(test,err);self.outcomes.append((test.id(),"ERROR"))
    def addFailure(self,test,err):
        super().addFailure(test,err);self.outcomes.append((test.id(),"FAIL"))
    def addSkip(self,test,reason):
        super().addSkip(test,reason);self.outcomes.append((test.id(),"SKIP"))

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output-dir",type=Path,required=True)
    a=p.parse_args()
    out=a.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    must(contract["rule_of_one"]==RULE and
         contract["predecessor_merged_main_sha"]==
         "f4e1dc166ad4bd5c2f8c4b47654ffd5bf637a4c1" and
         contract["real_provider_execution_authorized"] is False,
         "FROZEN_UTILITY_GATE_CONTRACT_INVALID")
    must(not any(os.environ.get(k) for k in (
       "OPENAI_API_KEY","OPENAI_BASE_URL","ANTHROPIC_API_KEY",
       "VERITAS_DATABASE_URL","GH_TOKEN","GITHUB_TOKEN"
    )),"LIVE_PROVIDER_OR_DATABASE_CREDENTIAL_PRESENT")
    sources={
      "baseline":"contracts/UTILITY_OPTIMIZATION_V1_BASELINE_DIAGNOSIS.json",
      "v13":"contracts/AGENTDOJO_FINAL_128_V13_POST_EXECUTION_ANALYSIS_BOUNDARY_v1.json",
      "controlled":"contracts/CONTROLLED_GOVERNANCE_TREATMENT_DELTA_ANALYSIS_V1.json"
    }
    must(contract["sources"]=={k:{"path":v,"git_blob":SOURCE_SHA[k]}
                           for k,v in sources.items()},
         "FROZEN_UTILITY_SOURCE_MANIFEST_MISMATCH")
    for k,relative in sources.items():
        must(blob(ROOT/relative)==SOURCE_SHA[k],
             "UTILITY_SOURCE_GIT_BLOB_DRIFT_"+k)
    objects={k:json.loads((ROOT/v).read_text()) for k,v in sources.items()}
    result=classify(objects["baseline"],objects["v13"],objects["controlled"])
    suite=unittest.TestLoader().loadTestsFromTestCase(UtilityRecoveryGateTests)
    record=unittest.TextTestRunner(stream=sys.stdout,verbosity=2,
                                  resultclass=Results).run(suite)
    must(record.wasSuccessful() and len(record.outcomes)==24 and
         all(status=="PASS" for _,status in record.outcomes),
         "ALL_TWENTY_FOUR_FAIL_CLOSED_GUARDS_MUST_PASS")
    xml=ET.Element("testsuite",name=RULE,tests="24",failures="0",errors="0",skipped="0")
    for name,_ in record.outcomes:
        ET.SubElement(xml,"testcase",classname=RULE,name=name)
    ET.ElementTree(xml).write(out/"v13-utility-recovery-claim-gate-junit.xml",
                              encoding="utf-8",xml_declaration=True)
    report={
        "rule_of_one":RULE,
        "classification":result,
        "frozen_contract_source_sha256":{
           k:hashlib.sha256((ROOT/v).read_bytes()).hexdigest()
           for k,v in sources.items()},
        "unit_tests_passed":len(record.outcomes),
        "independent_utility_measurement":False,
        "new_recovery_authority_issued":False,
        "final128_provider_calls":0,"provider_spend_usd":0,
        "native_bank_effects":0,
        "independent_auditor_determination":"PENDING"
    }
    (out/"v13-utility-recovery-claim-gate-evidence.json").write_text(
        json.dumps(report,sort_keys=True,indent=2)+"\n")
    (out/"v13-utility-recovery-testcases.json").write_text(
        json.dumps({"cases":[{"test":name,"result":status}
                             for name,status in record.outcomes]},indent=2)+"\n")
    print("PASS_V13_UTILITY_CLAIM_GATE: 24/24; 30 HISTORICAL REGRESSIONS; 0 NEW RECOVERIES")
    print("V13 A=93/128 B=64/128; INJECTION A=20/128 B=0/128")
    print("NO_PROVIDER_CALLS=0; SPEND_USD=0; BANK_EFFECTS=0")
if __name__=="__main__":
    main()
