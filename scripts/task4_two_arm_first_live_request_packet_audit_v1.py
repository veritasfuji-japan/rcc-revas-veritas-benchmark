#!/usr/bin/env python3
"""Independently rerun and archive TWO full first-turn source request packets.

No connection / model inference / external bank effects. Raw prior native
attack source evidence is retained, and the two full starting requests
are immutable, per-arm/provenance-separate but byte-equal.
"""
from __future__ import annotations
import argparse,hashlib,json,os,subprocess,sys
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from task4_two_arm_first_live_request_packet_v1 import (
    RULE,make_two_arm_packets,digest,canon,
)
BASE="2bfd1daa736b33964b6aa8d275d0695d75079e3b"

def need(x,reason):
    if not x:raise AssertionError(reason)
def git_blob(path):
    raw=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def head(p):
    return subprocess.run(["git","-C",str(p),"rev-parse","HEAD"],
                          capture_output=True,text=True,check=True).stdout.strip()

def main():
    p=argparse.ArgumentParser()
    for x in ("agentdojo","rcc","veritas"):
        p.add_argument("--"+x+"-root",type=Path,required=True)
    p.add_argument("--output-dir",type=Path,required=True)
    args=p.parse_args()
    out=args.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    cfg=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    need(cfg["rule_of_one"]==RULE
         and cfg["predecessor_merged_main_sha"]==BASE
         and cfg["approved_spend_usd"]==0
         and cfg["live_provider_transport_enabled"] is False
         and cfg["expected_unit_tests"]==19,
         "EXACT_FROZEN_NO_LIVE_REQUEST_CONTRACT_REQUIRED")
    need(not any(os.getenv(k) for k in ("OPENAI_API_KEY","OPENAI_BASE_URL",
          "ANTHROPIC_API_KEY","VERITAS_DATABASE_URL","GH_TOKEN","GITHUB_TOKEN")),
         "LIVE_PROVIDER_OR_DB_SECRETS_FORBIDDEN")
    for path,sha in cfg["source_blobs"].items():
        need(git_blob(ROOT/path)==sha,"HISTORIC_SOURCE_CHANGED:"+path)
    for n,root in (("agentdojo",args.agentdojo_root),
                   ("rcc",args.rcc_root),("veritas",args.veritas_root)):
        need(head(root)==cfg["external_pins"][n],
             "PINNED_"+n.upper()+"_HEAD_CHANGED")
    raw=out/"task4-two-first-request-raw.json"
    junit=out/"task4-two-first-request-junit.xml"
    for f in (raw,junit):f.unlink(missing_ok=True)
    env=dict(os.environ)
    env.update({
        "OPENAI_API_KEY":"","OPENAI_BASE_URL":"","ANTHROPIC_API_KEY":"",
        "VERITAS_DATABASE_URL":"","GH_TOKEN":"","GITHUB_TOKEN":"",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD":"1","PYTEST_ADDOPTS":"",
        "TASK4_NATIVE_DATE_PROOF":"1","TASK4_TRANSPORT_PROOF":"1",
        "TASK4_TRAJECTORY_PROOF":"1","TASK4_SCORER_OBSERVATION_PROOF":"1",
        "TASK4_DUAL_OFFLINE_SOURCE_PROOF":"1",
        "TASK4_FIRST_ORIGIN_NO_PROMOTION_PROOF":"1",
        "TASK4_TWO_FIRST_PACKET_PROOF":"1",
        "TASK4_RCC_ROOT":str(args.rcc_root.resolve()),
        "TASK4_TWO_FIRST_PACKET_EVIDENCE":str(raw),
    })
    proc=subprocess.run([sys.executable,"-m","pytest","-q","-o",
       "addopts=","tests/test_task4_two_arm_first_live_request_packet_v1.py",
       "--junitxml",str(junit)],cwd=ROOT,capture_output=True,text=True,env=env)
    (out/"task4-two-first-request-tests.log").write_text(proc.stdout+proc.stderr)
    print(proc.stdout,end="")
    need(proc.returncode==0,"PACKET_TEST_FAILED:"+(proc.stdout+proc.stderr)[-12000:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    need(len(cases)==19 and
         not any(c.find(n) is not None for c in cases
                 for n in ("failure","error","skipped")),
         "NINETEEN_EXACT_CASES_PASS_REQUIRED")
    evidence=json.loads(raw.read_text())
    candidate=make_two_arm_packets(evidence["historical_input_raw"])
    need(candidate==evidence["packet"],
         "ACTUAL_RECOMPUTED_PREPARED_REQUEST_PACKET_MISMATCH")
    need(digest(evidence["historical_input_raw"])==
         evidence["input_source_sha256"],
         "INPUT_NATIVE_HISTORY_SOURCE_SHA_CHANGED")
    need(candidate["packets"]["A"]["complete_first_request_sha256"]==
         candidate["packets"]["B"]["complete_first_request_sha256"] and
         candidate["packets"]["A"]["first_request_sha256"]==
         candidate["packets"]["B"]["first_request_sha256"]==
         "c83bca26d25f6a6332cc1b7266c84ee5974f1f7904d0d77d4f6a913100233dc7",
         "ACTUAL_V13_HISTORIC_SOURCE_VS_FIRST_REQUEST_MISMATCH")
    need(candidate["first_request_count_proposed"]==2 and
         candidate["approved_request_count"]==
         candidate["actual_provider_calls"]==
         candidate["approved_cost_micro_usd"]==
         candidate["actual_spend_micro_usd"]==0 and
         candidate["fresh_human_approval_present"] is False and
         candidate["independent_real_model_sources_proven"] is False,
         "FALSE_LIVE_EXECUTION_OR_SPEND_PERMISSION_CLAIM")
    (out/"task4-two-first-request-packets.json").write_text(
        json.dumps(candidate,sort_keys=True,indent=2)+"\n")
    summary={
        "rule_of_one":RULE,
        "predecessor_merged_main_sha":BASE,
        "status":"EXACT_FIRST_TWO_COMPLETE_REQUESTS_SEALED_NO_OPERATOR_APPROVAL",
        "dedicated_unit_tests_passed":len(cases),
        "A_B_first_wire_request_sha256":candidate["packets"]["A"]["first_request_sha256"],
        "complete_provider_payload_sha256":candidate["packets"]["A"]["complete_first_request_sha256"],
        "same_start_bytes_different_synthetic_source_owners":True,
        "source_first_read_attacker_text_exposed":False,
        "genuine_model_second_turn_required":True,
        "proposal_two_first_calls_max_spend_usd":0.5,
        "actual_approved_spend_usd":0,
        "actual_real_provider_calls":0,
        "actual_cost_usd":0,
        "actual_bank_effects":0,
        "new_V13_utility_recoveries":0,
        "new_canonical_final128_results":0,
        "provider_model_account_access_verified":False,
        "external_operator_root_enrolled":False,
        "separate_sender_enabled":False,
        "independent_auditor_determination":"PENDING",
    }
    (out/"task4-two-first-request-packet-summary.json").write_text(
        json.dumps(summary,indent=2,sort_keys=True)+"\n")
    print("PASS_TWO_TASK4_FIRST_REQUEST_PAYLOADS: 19/19; EXACT TWO OWNER-BOUND REQUESTS")
    print("FIRST MODEL QUERY HAS NO INJECTED READ YET; REAL FOLLOWUP MODEL RESPONSE REQUIRED")
    print("ACTUAL_PROVIDER_CALLS=0 ACTUAL_SPEND_USD=0 AUTHORIZATION_NOT_ISSUED")
if __name__=="__main__":main()
