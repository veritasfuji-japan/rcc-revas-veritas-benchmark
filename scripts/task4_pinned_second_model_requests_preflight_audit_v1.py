#!/usr/bin/env python3
"""Pure offline exact source-zip pinned second-request preflight/CI artifact."""
from __future__ import annotations
import argparse,json,os,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from task4_pinned_second_model_requests_preflight_v1 import (
    RULE,SOURCE_ZIP_SHA256,source_zip_manifest,prepare_two_unsent_second_model_requests
)
def need(ok,why):
    if not ok:raise AssertionError(why)
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--source-zip",type=Path,required=True)
    p.add_argument("--output-dir",type=Path,required=True)
    args=p.parse_args()
    out=args.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    cfg=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    need(cfg["rule_of_one"]==RULE and
         cfg["merged_predecessor_main"]=="a25fe47cc9b3452cf6baec277a662957acb4369a" and
         cfg["first_provider_authorization_consumed"] is True and
         cfg["additional_provider_requests_authorized"]==0 and
         cfg["expected_tests"]==29 and
         cfg["prior_native_source_zip_sha256"]==SOURCE_ZIP_SHA256,
         "STRICT_PREVIOUS_CONSENT_CONSUMED_OFFLINE_CONTRACT")
    need(not any(os.getenv(k) for k in (
       "OPENAI_API_KEY","TASK4_OPENAI_API_KEY","OPENAI_BASE_URL",
       "ANTHROPIC_API_KEY","VERITAS_DATABASE_URL",
       "GH_TOKEN","GITHUB_TOKEN")),
       "REAL_PROVIDER_SECRET_OR_GITHUB_TOKEN_NOT_ALLOWED")
    j=source_zip_manifest(args.source_zip.read_bytes())
    materialized=prepare_two_unsent_second_model_requests(j)
    junit=out/"task4-pinned-second-preflight-junit.xml"
    evidence=out/"task4-pinned-second-preflight-full-A-B-requests.json"
    for x in (junit,evidence):x.unlink(missing_ok=True)
    env=dict(os.environ)
    env.update({"TASK4_SECOND_SOURCE_ZIP":str(args.source_zip.resolve()),
       "TASK4_SECOND_OFFLINE_EVIDENCE":str(evidence),
       "TASK4_SECOND_REQUEST_PREFLIGHT_PROOF":"1",
       "PYTEST_ADDOPTS":"","PYTEST_DISABLE_PLUGIN_AUTOLOAD":"1",
       "OPENAI_API_KEY":"","TASK4_OPENAI_API_KEY":"","OPENAI_BASE_URL":"",
       "GH_TOKEN":"","GITHUB_TOKEN":""})
    proc=subprocess.run([sys.executable,"-m","pytest","-q","-o",
       "addopts=","tests/test_task4_pinned_second_model_requests_preflight_v1.py",
       "--junitxml",str(junit)],cwd=ROOT,env=env,text=True,capture_output=True)
    (out/"task4-pinned-second-preflight-tests.log").write_text(proc.stdout+proc.stderr)
    print(proc.stdout,end="")
    need(proc.returncode==0,"SECOND_REQUEST_SOURCE_PROOF_FAILED:"+
         (proc.stdout+proc.stderr)[-14000:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    need(len(cases)==29 and all(not any(z.find(x) is not None
         for x in ("failure","error","skipped")) for z in cases),
         "29_EXACT_SECOND_REQUEST_TESTS_REQUIRED")
    reread=json.loads(evidence.read_text())
    need(reread==materialized and
         reread["second_model_requests_authorized"]==0 and
         reread["second_model_requests_sent"]==0,
         "RAW_A_B_SECOND_QUERY_MISMATCH_OR_FALSE_PERMISSION")
    summary={
      "rule_of_one":RULE,
      "source_zip_sha256":SOURCE_ZIP_SHA256,
      "source_artifact_id":"11674688715",
      "dedicated_tests_passed":len(cases),
      "A_B_full_second_request_sha256":{
        arm:materialized["packets"][arm]["second_complete_request_sha256"]
        for arm in ("A","B")},
      "A_B_second_request_total":2,
      "second_model_requests_approved":0,
      "second_model_requests_dispatched":0,
      "real_model_attack_text_seen":False,
      "additional_provider_cost_usd":0,
      "new_final128_scores":0,
      "no_native_bank_effects":True,
      "independent_auditor_determination":"PENDING",
    }
    (out/"task4-pinned-second-preflight-summary.json").write_text(
        json.dumps(summary,sort_keys=True,indent=2)+"\n")
    print("PASS_PINNED_TWO_SECOND_MODEL_REQUESTS_OFFLINE: 29/29")
    print("AUTHORITY=NONE PROVIDER_CALLS=0 ADDITIONAL_SPEND_USD=0")
if __name__=="__main__":main()
