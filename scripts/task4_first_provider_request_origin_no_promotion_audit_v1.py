#!/usr/bin/env python3
"""#291 exact pinned TEST-only first native provider query handoff audit.

Uses genuine native injected banking state + separate synthetic source histories.
NO OpenAI model, credential, external network, scoring benchmark, bank write.
"""
from __future__ import annotations
import argparse,hashlib,json,os,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from task4_first_provider_request_origin_no_promotion_v1 import (
    RULE,frozen_first_request_handoff,
)
BASE="5e194563645cda3a122021ed640676662408bf2d"
def must(ok,why):
    if not ok:raise AssertionError(why)
def blob(p):
    data=p.read_bytes()
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
def repo_head(path):
    return subprocess.run(["git","-C",str(path),"rev-parse","HEAD"],
                          text=True,capture_output=True,check=True).stdout.strip()

def main():
    p=argparse.ArgumentParser()
    for n in ("agentdojo","rcc","veritas"):
        p.add_argument("--"+n+"-root",required=True,type=Path)
    p.add_argument("--output-dir",type=Path,required=True)
    args=p.parse_args()
    out=args.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    cfg=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    must(cfg["rule_of_one"]==RULE and
         cfg["predecessor_merged_main_sha"]==BASE and
         cfg["real_provider_execution_authorized"] is False and
         cfg["expected_dedicated_tests"]==18,"EXACT_NONEXECUTABLE_CONTRACT_REQUIRED")
    must(not any(os.getenv(k) for k in (
       "OPENAI_API_KEY","OPENAI_BASE_URL","ANTHROPIC_API_KEY",
       "VERITAS_DATABASE_URL","GH_TOKEN","GITHUB_TOKEN",
       "AWS_SECRET_ACCESS_KEY","AWS_ACCESS_KEY_ID")),
       "NO_LIVE_PROVIDER_CREDENTIALS_IN_PROOF")
    for path,sha in cfg["source_blobs"].items():
        must(blob(ROOT/path)==sha,"HISTORICAL_SOURCE_BLOB_CHANGED:"+path)
    for name,root in (("agentdojo",args.agentdojo_root),
                      ("rcc",args.rcc_root),("veritas",args.veritas_root)):
        must(repo_head(root)==cfg["external_pins"][name],
             "PINNED_EXTERNAL_CODE_CHANGED_"+name)
    junit=out/"task4-first-origin-junit.xml"
    raw=out/"task4-first-origin-raw-histories.json"
    for f in (junit,raw): f.unlink(missing_ok=True)
    env=dict(os.environ)
    env.update({
        "OPENAI_API_KEY":"","OPENAI_BASE_URL":"","ANTHROPIC_API_KEY":"",
        "VERITAS_DATABASE_URL":"","GH_TOKEN":"","GITHUB_TOKEN":"",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD":"1","PYTEST_ADDOPTS":"",
        "TASK4_NATIVE_DATE_PROOF":"1","TASK4_TRANSPORT_PROOF":"1",
        "TASK4_TRAJECTORY_PROOF":"1","TASK4_SCORER_OBSERVATION_PROOF":"1",
        "TASK4_DUAL_OFFLINE_SOURCE_PROOF":"1",
        "TASK4_FIRST_ORIGIN_NO_PROMOTION_PROOF":"1",
        "TASK4_DUAL_OFFLINE_SOURCE_EVIDENCE":str(raw),
        "TASK4_FIRST_ORIGIN_RAW_EVIDENCE":str(raw),
        "TASK4_RCC_ROOT":str(args.rcc_root.resolve()),
    })
    trial=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task4_first_provider_request_origin_no_promotion_v1.py",
        "--junitxml",str(junit),
    ],cwd=ROOT,env=env,text=True,capture_output=True)
    (out/"task4-first-origin-tests.log").write_text(trial.stdout+trial.stderr)
    print(trial.stdout,end="")
    must(trial.returncode==0,"FIRST_ORIGIN_NEGATIVE_PROOF_FAILED:"+
         (trial.stdout+trial.stderr)[-13000:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    must(len(cases)==18 and not any(row.find(why) is not None
         for row in cases for why in ("failure","error","skipped")),
         "EIGHTEEN_PASS_WITHOUT_SKIP_REQUIRED")
    data=json.loads(raw.read_text())
    result=frozen_first_request_handoff(data["raw"])
    must(result["first_model_query_A_B_same_bytes"] is True and
         result["synthetic_source_provenance_distinct"] is True and
         result["allowed_live_provider_calls"]==
         result["allowed_real_spend_micro_usd"]==0 and
         all(r["provider_request_ever_issued"] is False and
             r["real_model_independent_sampling_observed"] is False
             for r in result["arms"].values()),
         "FAKE_MODEL_MUST_NOT_BE_PROMOTED_TO_LIVE")
    from task4_dual_offline_native_source_history_v1 import (
        validate_dual_offline_native_sources,
    )
    must(data["proof"]==validate_dual_offline_native_sources(data["raw"]),
         "RAW_SYNTHETIC_PREDECESSOR_PROOF_CHANGED")
    (out/"task4-first-origin-nonexecuting-handoff.json").write_text(
        json.dumps(result,sort_keys=True,indent=2)+"\n")
    summary={
       "rule_of_one":RULE,
       "predecessor_merged_main_sha":BASE,
       "determination":"FROZEN_FIRST_NATIVE_QUERY_ONLY_NO_SYNTHETIC_CONTINUATION_PROMOTION",
       "dedicated_junit_passed":len(cases),
       "exact_native_case":"banking:user_task_4:injection_task_0:direct",
       "two_synthetic_source_records_checked":True,
       "two_first_wire_requests_match":True,
       "distinct_test_client_identity_bound":True,
       "old_mock_postread_source_promotable_to_real_provider":False,
       "new_real_model_samples":0,
       "new_native_canonical_final128_case_scores":0,
       "historical_v13_utility_recoveries":0,
       "real_provider_calls":0,"spend_usd":0,"real_bank_effects":0,
       "independent_auditor_determination":"PENDING",
    }
    (out/"task4-first-origin-audit-summary.json").write_text(
        json.dumps(summary,indent=2,sort_keys=True)+"\n")
    print("PASS_TASK4_FIRST_PROVIDER_REQUEST_ORIGIN_NO_PROMOTION: 18/18")
    print("TWO TEST SOURCES; FIRST QUERY ONLY; THIRD REQUEST NOT AN AUTHENTIC PROVIDER CONTINUATION")
    print("REAL_PROVIDER_CALLS=0; SPEND_USD=0; HISTORICAL_V13_RECOVERIES=0")
if __name__=="__main__":main()
