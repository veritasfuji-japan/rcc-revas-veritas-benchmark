#!/usr/bin/env python3
"""#295 exact pinned REAL first Provider replies -> native AgentDojo get_iban.

No networking, provider client, new paid call, fresh approval, bank writer,
or next model completion. One-use tag must remain consumed and is never
altered. First genuine model turn captured on #294 is replayed only to
the safe native READ tool and then the model-compatible return is frozen.
"""
from __future__ import annotations
import argparse,hashlib,json,os,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from task4_pinned_real_first_replies_native_get_iban_v1 import (
    RULE,ORIGINAL_ARTIFACT_ZIP_SHA256,ORIGINAL_PACKET_SHA256,
    ORIGINAL_RUN_ID,parse_verified_original_events,
    replay_both_first_native_iban_reads,sha_bytes
)
from task4_two_arm_first_live_request_packet_v1 import digest
BASE="99812fe1fdbc627e582ec7935a429a852e22703d"

def require(ok,why):
    if not ok:raise AssertionError(why)
def blob(p):
    raw=p.read_bytes()
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def head(p):
    return subprocess.run(["git","-C",str(p),"rev-parse","HEAD"],
                          check=True,text=True,capture_output=True).stdout.strip()

def main():
    p=argparse.ArgumentParser()
    for x in ("agentdojo","rcc","veritas"):
        p.add_argument("--"+x+"-root",type=Path,required=True)
    p.add_argument("--captured-provider-zip",type=Path,required=True)
    p.add_argument("--original-packet-json",type=Path,required=True)
    p.add_argument("--output-dir",type=Path,required=True)
    args=p.parse_args()
    out=args.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    cfg=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(cfg["rule_of_one"]==RULE and
            cfg["predecessor_merged_main_sha"]==BASE and
            cfg["original_provider_artifact_zip_sha256"]==
                ORIGINAL_ARTIFACT_ZIP_SHA256 and
            cfg["original_request_packet_file_sha256"]==
                ORIGINAL_PACKET_SHA256 and
            cfg["additional_provider_calls_authorized"]==0 and
            cfg["expected_dedicated_tests"]==28 and
            cfg["send_next_request_authorized"] is False,
            "FROZEN_ONE_STEP_NO_MORE_PROVIDER_CONTRACT_REQUIRED")
    require(not any(os.getenv(x) for x in (
        "OPENAI_API_KEY","OPENAI_BASE_URL","TASK4_OPENAI_API_KEY",
        "ANTHROPIC_API_KEY","VERITAS_DATABASE_URL","GH_TOKEN","GITHUB_TOKEN")),
        "PROVIDER_CREDENTIALS_OR_NETWORK_GITHUB_TOKEN_NOT_ALLOWED_DURING_PROOF")
    for path,hashval in cfg["source_blobs"].items():
        require(blob(ROOT/path)==hashval,"HISTORIC_SOURCE_BLOB_CHANGED:"+path)
    for name,root in (("agentdojo",args.agentdojo_root),
                      ("rcc",args.rcc_root),("veritas",args.veritas_root)):
        require(head(root)==cfg["external_pins"][name],
                "FROZEN_EXTERNAL_GIT_HEAD_DRIFT:"+name)
    require(sha_bytes(args.captured_provider_zip.read_bytes())==
            ORIGINAL_ARTIFACT_ZIP_SHA256,
            "RAW_ACTUAL_PROVIDER_ZIP_SHA_NOT_PREVIOUSLY_AUDITED_CAPTURE")
    with zipfile.ZipFile(args.captured_provider_zip) as z:
        require(z.testzip() is None and set(z.namelist())=={
            "task4-live-first-two-provider-response-evidence.jsonl",
            "task4-live-preflight.json",
        },"FROZEN_294_ARTIFACT_MEMBER_OR_CRC_MISMATCH")
        event_bytes=z.read("task4-live-first-two-provider-response-evidence.jsonl")
        preflight=json.loads(z.read("task4-live-preflight.json"))
    require(sha_bytes(args.original_packet_json.read_bytes())==
            ORIGINAL_PACKET_SHA256,
            "FROZEN_292_SOURCE_JSON_FILE_CHANGED")
    packet=json.loads(args.original_packet_json.read_text())
    captures=parse_verified_original_events(event_bytes,packet["packets"])
    require(preflight["first_payload_sha256"]==
            captures["A"]["request_sha256"]==
            captures["B"]["request_sha256"] and
            preflight["expected_provider_calls"]==2 and
            preflight["source_artifact"]=="11672698922",
            "ORIGINAL_PRE_POST_RESPONSE_CAPTURE_WRONG_REQUEST_SOURCE")
    junit=out/"task4-real-first-native-iban-junit.xml"
    raw=out/"task4-real-first-native-iban-next-model-requests.json"
    for path in (junit,raw):path.unlink(missing_ok=True)
    env=dict(os.environ)
    env.update({
      "OPENAI_API_KEY":"","OPENAI_BASE_URL":"","TASK4_OPENAI_API_KEY":"",
      "ANTHROPIC_API_KEY":"","VERITAS_DATABASE_URL":"",
      "GH_TOKEN":"","GITHUB_TOKEN":"",
      "PYTEST_DISABLE_PLUGIN_AUTOLOAD":"1","PYTEST_ADDOPTS":"",
      "TASK4_NATIVE_DATE_PROOF":"1","TASK4_TRANSPORT_PROOF":"1",
      "TASK4_TRAJECTORY_PROOF":"1","TASK4_SCORER_OBSERVATION_PROOF":"1",
      "TASK4_DUAL_OFFLINE_SOURCE_PROOF":"1",
      "TASK4_FIRST_ORIGIN_NO_PROMOTION_PROOF":"1",
      "TASK4_TWO_FIRST_PACKET_PROOF":"1",
      "TASK4_NATIVE_READ_CONTINUATION_PROOF":"1",
      "TASK4_PINNED_REAL_FIRST_IBAN_PROOF":"1",
      "TASK4_RCC_ROOT":str(args.rcc_root.resolve()),
      "TASK4_295_ORIGINAL_PACKET_PATH":str(args.original_packet_json.resolve()),
      "TASK4_295_ORIGINAL_PROVIDER_JOURNAL_PATH":
          str((out/"tmp-original-provider-journal.jsonl").resolve()),
      "TASK4_PINNED_FIRST_IBAN_EVIDENCE":str(raw)
    })
    temp_path=Path(env["TASK4_295_ORIGINAL_PROVIDER_JOURNAL_PATH"])
    temp_path.write_bytes(event_bytes)
    try:
        run=subprocess.run([
            sys.executable,"-m","pytest","-q","-o","addopts=",
            "tests/test_task4_pinned_real_first_replies_native_get_iban_v1.py",
            "--junitxml",str(junit)
        ],cwd=ROOT,env=env,text=True,capture_output=True)
        (out/"task4-real-first-native-iban-tests.log").write_text(
            run.stdout+run.stderr)
        print(run.stdout,end="")
        require(run.returncode==0,
                "PINNED_REAL_FIRST_NATIVE_IBAN_FAILED:"+ (run.stdout+run.stderr)[-14000:])
        cases=ET.parse(junit).getroot().findall(".//testcase")
        require(len(cases)==28 and all(not any(row.find(x) is not None
                for x in ("failure","error","skipped")) for row in cases),
                "TWENTY_EIGHT_NATIVE_FIRST_RESPONSE_TESTS_REQUIRED")
        replay=replay_both_first_native_iban_reads(
            packet_source=packet,event_bytes=event_bytes)
        archived=json.loads(raw.read_text())
        require(replay==archived and
                replay["actual_native_iban_readonly_tools_executed"]==2 and
                replay["additional_real_provider_api_calls"]==0 and
                replay["native_attacked_transaction_read_exposure_to_real_model"] is False,
                "RAW_NATIVE_FIRST_READ_REPLAY_NOT_INDEPENDENTLY_REPRODUCIBLE")
        report={
          "rule_of_one":RULE,
          "predecessor_merged_main_sha":BASE,
          "original_provider_run":ORIGINAL_RUN_ID,
          "original_provider_capture_zip_sha256":ORIGINAL_ARTIFACT_ZIP_SHA256,
          "original_packet_file_sha256":ORIGINAL_PACKET_SHA256,
          "frozen_real_first_response_A_B_sha256":{
             arm:captures[arm]["provider_response_sha256"] for arm in ("A","B")},
          "replayed_real_first_response_native_readonly_calls":2,
          "full_next_unsent_model_inputs_A_B_sha256":{
             arm:replay["sources"][arm]["full_next_model_request_sha256"]
             for arm in ("A","B")},
          "source_provenance":"GITHUB_ACTIONS_DIRECT_TLS_CAPTURE_NOT_PROVIDER_SIGNED",
          "new_live_provider_calls":0,
          "new_model_spend_usd":0,
          "actual_bank_write_effects":0,
          "real_native_injected_transaction_tool_return_seen_by_model":False,
          "historical_v13_utility_recoveries":0,
          "new_canonical_final128_scored_cases":0,
          "dedicated_tests_passed":len(cases),
          "independent_auditor_determination":"PENDING",
        }
        (out/"task4-real-first-native-iban-summary.json").write_text(
             json.dumps(report,sort_keys=True,indent=2)+"\n")
        print("PASS_PINNED_REAL_FIRST_PROVIDER_2_NATIVE_IBAN: 28/28")
        print("TWO_REAL_MODEL_TOOL_CALL_IDS_BECAME_TWO_NATIVE_READ_RESULT_WIRES")
        print("ZERO_MORE_PROVIDER_CALLS ZERO_BANK_WRITES NO_ATTACK_READ_OR_SCORE")
    finally:
        temp_path.unlink(missing_ok=True)

if __name__=="__main__":main()
