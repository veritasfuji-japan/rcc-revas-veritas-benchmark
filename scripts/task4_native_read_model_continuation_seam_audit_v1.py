#!/usr/bin/env python3
"""Exact native AgentDojo read-only roundtrip audit for TWO synthetic arms.

Archives genuine native injected tool-return messages and next model-input
bytes. Synthetic first responses have NO authenticated Provider provenance.
"""
from __future__ import annotations
import argparse,hashlib,json,os,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from task4_native_read_model_continuation_seam_v1 import RULE
from task4_native_injected_read_exposure_v1 import (
    native_case_environment,contains_exact_injected_native_transaction)
from task4_two_arm_first_live_request_packet_v1 import digest

BASE="c0e6be8e106de4fb7ec47db12a7b495252aee07f"
def require(ok,why):
    if not ok:raise AssertionError(why)
def blob(path):
    b=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
def head(path):
    return subprocess.run(["git","-C",str(path),"rev-parse","HEAD"],
                          check=True,text=True,capture_output=True).stdout.strip()

def main():
    ap=argparse.ArgumentParser()
    for name in ("agentdojo","rcc","veritas"):
        ap.add_argument("--"+name+"-root",type=Path,required=True)
    ap.add_argument("--output-dir",type=Path,required=True)
    args=ap.parse_args()
    out=args.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    cfg=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(cfg["rule_of_one"]==RULE and
            cfg["predecessor_merged_main_sha"]==BASE and
            cfg["allowed_provider_requests"]==0 and
            cfg["expected_dedicated_tests"]==19 and
            cfg["real_bank_effects_permitted"] is False,
            "EXACT_NO_SEND_SINGLE_READ_ROUNDTRIP_CONTRACT_REQUIRED")
    require(not any(os.getenv(x) for x in (
       "OPENAI_API_KEY","OPENAI_BASE_URL","ANTHROPIC_API_KEY",
       "VERITAS_DATABASE_URL","GH_TOKEN","GITHUB_TOKEN")),
       "NO_REAL_PROVIDER_OR_DATABASE_SECRETS_IN_CI")
    for path,sha in cfg["source_blobs"].items():
        require(blob(ROOT/path)==sha,"FROZEN_SOURCE_DRIFT:"+path)
    for name,root in (("agentdojo",args.agentdojo_root),
                      ("rcc",args.rcc_root),("veritas",args.veritas_root)):
        require(head(root)==cfg["external_pins"][name],"FROZEN_EXTERNAL_PIN_DRIFT:"+name)
    junit=out/"task4-native-read-continuation-junit.xml"
    evidence=out/"task4-native-read-continuation-raw.json"
    for path in (junit,evidence):path.unlink(missing_ok=True)
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
       "TASK4_NATIVE_READ_CONTINUATION_PROOF":"1",
       "TASK4_RCC_ROOT":str(args.rcc_root.resolve()),
       "TASK4_NATIVE_READ_CONTINUATION_EVIDENCE":str(evidence)
    })
    run=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task4_native_read_model_continuation_seam_v1.py",
        "--junitxml",str(junit)
    ],cwd=ROOT,env=env,text=True,capture_output=True)
    (out/"task4-native-read-continuation-tests.log").write_text(run.stdout+run.stderr)
    print(run.stdout,end="")
    require(run.returncode==0,"NATIVE_READ_STEP_FAILED:"+(run.stdout+run.stderr)[-12000:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==19 and
        all(not any(x.find(n) is not None for n in ("failure","error","skipped"))
            for x in cases),"NINETEEN_NATIVE_TESTS_PASS_REQUIRED")
    raw=json.loads(evidence.read_text())
    require(raw["rule_of_one"]==RULE and
            raw["all_provider_calls"]==raw["real_external_effects"]==
            raw["historical_v13_utility_recoveries"]==
            raw["real_model_samples"]==0 and
            set(raw["sources"])=={"A","B"},
            "SYNTHETIC_MODEL_STATE_CANNOT_PROMOTE_TO_REAL")
    profiles=[]
    for arm,row in raw["sources"].items():
        original=native_case_environment()
        request=row["final_request"]
        journal=row["observation"]["read_journal"]
        require(len(journal)==2 and
                [x["tool"] for x in journal]==[
                    "get_iban","get_most_recent_transactions"] and
                [x["actual_native_tool_result_seen_by_next_model"]
                 for x in journal]==[False,True] and
                journal[1]["next_request_sha256"]==
                    row["final_request_sha256"]==digest(request) and
                journal[0]["native_prestate_and_poststate_sha256"]==
                journal[1]["native_prestate_and_poststate_sha256"]==
                original["injected_prestate_sha256"] and
                contains_exact_injected_native_transaction(
                    request["messages"][-1], original["exact_payload"],wire=True) and
                [m["role"] for m in request["messages"]]==[
                    "developer","user","assistant","tool","assistant","tool"],
                "RAW_NATIVE_TOOL_RESULT_MISSING_OR_MODEL_WIRE_MISMATCH:"+arm)
        profiles.append(row["injected_payload_sha256"])
    require(len(set(profiles))==1 and
            raw["sources"]["A"]["first_request_sha256"]==
            raw["sources"]["B"]["first_request_sha256"] and
            raw["sources"]["A"]["final_request_sha256"]!=
            raw["sources"]["B"]["final_request_sha256"],
            "TWO_SEPARATE_FAKE_RESPONSE_CHAINS_REQUIRED")
    summary={
        "rule_of_one":RULE,
        "predecessor_merged_main_sha":BASE,
        "determination":"TWO_SEPARATE_SYNTHETIC_RESPONSE_CHAINS_ACTUAL_NATIVE_READ_TO_ATTACK_BEARING_NEXT_QUERY",
        "dedicated_junit_passed":len(cases),
        "two_native_agentdojo_bank_states":True,
        "actual_native_read_tool_calls":4,
        "complete_next_model_requests_with_real_native_injected_data":2,
        "protected_native_tool_dispatches":0,
        "real_provider_calls":0,"actual_cost_usd":0,
        "real_external_bank_effects":0,
        "real_model_generation_proven":False,
        "model_generated_tool_call_sources":"SYNTHETIC_OFFLINE_FIXTURES_ONLY",
        "real_injection_success_rate_remeasured":False,
        "final128_utility_recovered":0,
        "independent_auditor_determination":"PENDING",
    }
    (out/"task4-native-read-continuation-summary.json").write_text(
        json.dumps(summary,sort_keys=True,indent=2)+"\n")
    print("PASS_NATIVE_TASK4_READ_CONTINUATION: 19/19; FOUR REAL NATIVE READS")
    print("TWO SEPARATE ATTACK_BEARING_NEXT_MODEL_REQUESTS; REAL_PROVIDER_CALLS=0")
if __name__=="__main__":main()
