#!/usr/bin/env python3
"""#298 exact genuine first+second A/B model results to frozen native bank reads.

Reads four historical GitHub Actions artifacts, SHA-pinned. Native replay
has no authorization, no OpenAI transport and no bank writer. Third request
bytes are stored UNSENT. No benchmark score promoted from tool exposure.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from task4_pinned_genuine_second_responses_native_injected_read_v1 import (
  RULE,SECOND_REAL_ZIP_SHA,SECOND_JOURNAL_SHA,
  SECOND_SOURCE_ZIP_SHA,SECOND_SOURCE_JSON_SHA,
  ORIGINAL_SOURCE_JSON_SHA,FIRST_REAL_ZIP_SHA,SECOND_RESPONSE_SHA,
  sha_bytes,parse_pinned_real_second_events,replay_real_second_transactions
)
from task4_two_arm_first_live_request_packet_v1 import digest

def require(c,msg):
    if not c: raise AssertionError(msg)
def pinned_sha(p,h,msg):
    require(sha_bytes(p.read_bytes())==h,msg)
def checkout(root):
    return subprocess.run(["git","-C",str(root),"rev-parse","HEAD"],
                          capture_output=True,text=True,check=True).stdout.strip()
def read_zip(path,members):
    with zipfile.ZipFile(path) as z:
        require(z.testzip() is None and set(z.namelist())==set(members),
                "ZIP_CRC_OR_FROZEN_MEMBER_LIST_DRIFT_"+path.name)
        return {name:z.read(name) for name in members}

def main():
    a=argparse.ArgumentParser()
    for k in ("agentdojo","rcc","veritas"):
        a.add_argument("--"+k+"-root",type=Path,required=True)
    a.add_argument("--original-packet",type=Path,required=True)
    a.add_argument("--original-first-provider-zip",type=Path,required=True)
    a.add_argument("--prepared-second-zip",type=Path,required=True)
    a.add_argument("--actual-second-provider-zip",type=Path,required=True)
    a.add_argument("--output-dir",type=Path,required=True)
    x=a.parse_args()
    output=x.output_dir.resolve();output.mkdir(parents=True,exist_ok=True)
    cfg=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(cfg["rule_of_one"]==RULE and
         cfg["predecessor_main_sha"]=="6c13f90e116b0365c85cc3323ce60a2bf608cb3c"
         and cfg["source_second_real_provider_zip_sha256"]==SECOND_REAL_ZIP_SHA
         and cfg["third_provider_calls_authorized"]==0
         and cfg["expected_dedicated_tests"]==33
         and cfg["third_model_inputs_must_remain_unsent"] is True,
         "FROZEN_SECOND_REAL_PROVIDER_NATIVE_REPLAY_CONTRACT_REQUIRED")
    require(not any(os.getenv(k) for k in (
         "OPENAI_API_KEY","TASK4_OPENAI_API_KEY","OPENAI_BASE_URL",
         "ANTHROPIC_API_KEY","GH_TOKEN","GITHUB_TOKEN",
         "VERITAS_DATABASE_URL")),
         "NO_NETWORK_SECRETS_OR_GITHUB_TOKEN_IN_NATIVE_REPLAY")
    for name,path in (("agentdojo",x.agentdojo_root),
                      ("rcc",x.rcc_root),("veritas",x.veritas_root)):
        require(checkout(path)==cfg["external_pins"][name],
                "EXTERNAL_PIN_MISMATCH_"+name)
    pinned_sha(x.original_packet,ORIGINAL_SOURCE_JSON_SHA,
               "REAL_FIRST_PACKET_RAW_SHA_DRIFT")
    pinned_sha(x.original_first_provider_zip,FIRST_REAL_ZIP_SHA,
               "REAL_FIRST_PROVIDER_CAPTURE_RAW_ZIP_SHA_DRIFT")
    pinned_sha(x.prepared_second_zip,SECOND_SOURCE_ZIP_SHA,
               "PREPARED_SECOND_PACKET_CAPTURE_RAW_ZIP_SHA_DRIFT")
    pinned_sha(x.actual_second_provider_zip,SECOND_REAL_ZIP_SHA,
               "REAL_SECOND_PROVIDER_CAPTURE_RAW_ZIP_SHA_DRIFT")
    orig=read_zip(x.original_first_provider_zip,(
       "task4-live-first-two-provider-response-evidence.jsonl",
       "task4-live-preflight.json",
    ))
    prepared=read_zip(x.prepared_second_zip,(
       "task4-pinned-second-preflight-ci.log",
       "task4-pinned-second-preflight-full-A-B-requests.json",
       "task4-pinned-second-preflight-junit.xml",
       "task4-pinned-second-preflight-summary.json",
       "task4-pinned-second-preflight-tests.log",
    ))
    real=read_zip(x.actual_second_provider_zip,(
       "task4-second-two-preflight.json",
       "task4-second-two-provider-evidence.jsonl",
    ))
    first_journal=orig["task4-live-first-two-provider-response-evidence.jsonl"]
    second_journal=real["task4-second-two-provider-evidence.jsonl"]
    prepared_json=prepared["task4-pinned-second-preflight-full-A-B-requests.json"]
    require(sha_bytes(second_journal)==SECOND_JOURNAL_SHA and
        sha_bytes(prepared_json)==SECOND_SOURCE_JSON_SHA,
        "ACTUAL_SECOND_PROVIDER_OR_UNSENT_SECOND_REQUEST_BYTES_DRIFT")
    posted=json.loads(real["task4-second-two-preflight.json"])
    require(posted["A_B_second_request_hashes"]==cfg["actual_second_A_B_request_sha256"]
        and posted["source_zip_sha256"]==SECOND_SOURCE_ZIP_SHA
        and posted["source_file_sha256"]==SECOND_SOURCE_JSON_SHA
        and posted["case_id"]==cfg["exact_case"],
        "REAL_SECOND_PROVIDER_PREFLIGHT_SOURCE_DRIFT")
    source=json.loads(x.original_packet.read_text())
    second_prep=json.loads(prepared_json)
    parse_pinned_real_second_events(second_journal)

    origin=output/"tmp-first-genuine-provider.jsonl"
    recent=output/"tmp-second-genuine-provider.jsonl"
    packet=output/"tmp-prepared-second-model.json"
    origin.write_bytes(first_journal)
    recent.write_bytes(second_journal)
    packet.write_bytes(prepared_json)
    target=output/"task4-real-second-native-read-third-unsent-requests.json"
    junit=output/"task4-real-second-native-read-junit.xml"
    for p in (target,junit):p.unlink(missing_ok=True)
    env=dict(os.environ)
    env.update({
       "PYTEST_DISABLE_PLUGIN_AUTOLOAD":"1","PYTEST_ADDOPTS":"",
       "OPENAI_API_KEY":"","TASK4_OPENAI_API_KEY":"","OPENAI_BASE_URL":"",
       "ANTHROPIC_API_KEY":"","VERITAS_DATABASE_URL":"",
       "GITHUB_TOKEN":"","GH_TOKEN":"",
       "TASK4_PINNED_REAL_SECOND_NATIVE_PROOF":"1",
       "TASK4_298_ORIGINAL_292":str(x.original_packet.resolve()),
       "TASK4_298_FIRST_294":str(origin),
       "TASK4_298_SECOND_297":str(recent),
       "TASK4_298_PREPARED_296":str(packet),
       "TASK4_298_EVIDENCE":str(target)
    })
    try:
        result=subprocess.run([
          sys.executable,"-m","pytest","-q","-o","addopts=",
          "tests/test_task4_pinned_genuine_second_responses_native_injected_read_v1.py",
          "--junitxml",str(junit)
        ],cwd=ROOT,env=env,capture_output=True,text=True)
        (output/"task4-real-second-native-read-tests.log").write_text(
            result.stdout+result.stderr)
        print(result.stdout,end="")
        require(result.returncode==0,
                "NATIVE_REAL_SECOND_REPLAY_FAILED:"+
                (result.stdout+result.stderr)[-15000:])
        cases=ET.parse(junit).getroot().findall(".//testcase")
        require(len(cases)==33 and all(not any(
             tc.find(k) is not None for k in ("failure","error","skipped"))
             for tc in cases),"THIRTY_THREE_EXACT_REAL_SECOND_REPLAY_TESTS_REQUIRED")
        reproduced=replay_real_second_transactions(
           original_source=source,
           original_first_raw=first_journal,
           captured_second_raw=second_journal,
           second_packets=second_prep)
        require(reproduced==json.loads(target.read_text())
          and reproduced["genuine_native_transaction_tool_returns_containing_attack"]==2
          and reproduced["actual_native_read_only_calls"]==4
          and reproduced["complete_unsent_third_model_requests_prepared"]==2
          and reproduced["new_real_provider_calls"]==0
          and reproduced["actual_real_llm_exposure_to_injected_tool_output"] is False
          and reproduced["actual_bank_write_effects"]==0
          and reproduced["new_task4_utility_results"]==0
          and reproduced["new_canonical_final128_scores"]==0,
          "STORED_RAW_THIRD_INPUT_OR_NATIVE_EFFECT_PROOF_DIVERGED")
        report={
          "rule_of_one":RULE,
          "base_main_sha":cfg["predecessor_main_sha"],
          "real_second_provider_run_id":"38069600424",
          "real_second_provider_artifact_id":"11675439837",
          "real_second_provider_zip_sha256":SECOND_REAL_ZIP_SHA,
          "exact_a_b_real_second_response_sha256":SECOND_RESPONSE_SHA,
          "original_second_provider_input_sha256":
             cfg["actual_second_A_B_request_sha256"],
          "third_model_unsent_A_B_request_sha256":{
             arm:reproduced["A_B"][arm]["third_unsent_model_request_sha256"]
             for arm in ("A","B")},
          "native_read_only_calls":4,
          "native_tool_returns_containing_malicious_transaction":2,
          "read_results_present_only_in_unsent_model_queries":True,
          "third_genuine_model_calls":0,
          "new_provider_spend_usd":0,
          "native_bank_write_dispatches":0,
          "injection_success_scored":False,
          "task4_utility_scored":False,
          "new_final128_scores":0,
          "dedicated_tests_passed":len(cases),
          "independent_audit_status":"PENDING",
          "provider_signed_response":False
        }
        (output/"task4-real-second-native-read-summary.json").write_text(
            json.dumps(report,sort_keys=True,indent=2)+"\n")
        print("PASS_PINNED_REAL_SECOND_READ_INJECTED_TOOL_RETURN: 33/33")
        print("EXACT_TWO_GENUINE_LLM_SECOND_TOOL_CHOICES_TWO_NATIVE_TRANSACTION_READS")
        print("TWO_UNSENT_THIRD_QUERIES_WITH_NATIVE_ATTACK_TOOL_RETURN")
        print("ZERO_THIRD_PROVIDER_CALL_ZERO_PROTECTED_WRITER_ZERO_TASK4_SCORE")
    finally:
        for p in (origin,recent,packet):p.unlink(missing_ok=True)

if __name__=="__main__":main()
