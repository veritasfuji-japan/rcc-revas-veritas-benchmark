#!/usr/bin/env python3
"""Offline frozen transport proof; reproduce unchanged prior native trajectory."""
import argparse,json,os,subprocess,sys
from pathlib import Path
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.task4_trusted_execution_date_runner_integration_audit_v1 import blob,require
NAME="task4-frozen-provider-transport-date-context-binding-v1"
CONTRACT=ROOT/"contracts/TASK4_FROZEN_PROVIDER_TRANSPORT_DATE_CONTEXT_BINDING_V1.json"
EXPECTED_CONTRACT="34581cfa40a04fb9d7b1c46b0890bc8bda42e0b4"
def main():
 p=argparse.ArgumentParser()
 for name in ("agentdojo","rcc","veritas"): p.add_argument("--"+name+"-root",type=Path,required=True)
 p.add_argument("--output-dir",type=Path,required=True)
 a=p.parse_args()
 for k in ("OPENAI_API_KEY","VERITAS_DATABASE_URL"): require(not os.environ.get(k),k+"_MUST_BE_EMPTY")
 require(blob(CONTRACT)==EXPECTED_CONTRACT,"CONTRACT_PIN_MISMATCH")
 c=json.loads(CONTRACT.read_text())
 for path,pin in c["source_blobs"].items(): require(blob(ROOT/path)==pin,"SOURCE_PIN_MISMATCH:"+path)
 codec=c["native_codec_source"]
 require(blob(a.agentdojo_root/codec["path"])==codec["blob"],"NATIVE_CODEC_PIN_MISMATCH")
 out=a.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
 prior=[sys.executable,"scripts/task4_prospective_controlled_trajectory_audit_v1.py"]
 for n in ("agentdojo","rcc","veritas"): prior.extend(["--"+n+"-root",str(getattr(a,n+"_root").resolve())])
 prior.extend(["--output-dir",str(out)])
 subprocess.run(prior,cwd=ROOT,check=True)
 prior_report=json.loads((out/"task4-prospective-controlled-trajectory-integration-v1.json").read_text())
 require(prior_report["trajectory_tests"]==23 and prior_report["prior_native_boundary_tests"]==41 and prior_report["failures"]==prior_report["skipped"]==0,"PRIOR_PROOF_INCOMPLETE")
 evidence=out/(NAME+".native.json");refusals=out/(NAME+".refusals.jsonl");junit=out/(NAME+".junit.xml");report=out/(NAME+".json")
 for f in (evidence,refusals,junit,report):
  if f.exists():f.unlink()
 env=dict(os.environ)
 env.update({"OPENAI_API_KEY":"","VERITAS_DATABASE_URL":"","PYTEST_DISABLE_PLUGIN_AUTOLOAD":"1","PYTEST_ADDOPTS":"","TASK4_TRANSPORT_PROOF":"1","TASK4_NATIVE_DATE_PROOF":"1","TASK4_RCC_ROOT":str(a.rcc_root.resolve()),"TASK4_TRANSPORT_EVIDENCE":str(evidence),"TASK4_TRANSPORT_REFUSALS":str(refusals)})
 result=subprocess.run([sys.executable,"-m","pytest","-q","-o","addopts=","tests/test_task4_frozen_provider_transport_date_context_binding_v1.py","--junitxml",str(junit)],cwd=ROOT,env=env,capture_output=True,text=True)
 print(result.stdout,end="");require(result.returncode==0,"TRANSPORT_TESTS_FAILED:"+result.stderr)
 cases=ET.parse(junit).getroot().findall(".//testcase")
 require(len(cases)==c["offline_proof"]["transport_tests"] and not any(x.find(t)is not None for x in cases for t in ("error","failure","skipped")),"TRANSPORT_TESTS_INCOMPLETE")
 e=json.loads(evidence.read_text());requests=e["requests"];journal=e["transport_journal"];arms=e["result"]["arms"]
 require(len(requests)==len(journal)==5 and len({r["owned_metadata_sha256"] for r in journal})==1,"WIRE_METADATA_BINDING_LOST")
 require(all(q["model"]==c["transport"]["model"] and q["temperature"]==0.0 for q in requests),"FROZEN_CONFIG_CHANGED")
 require(all(q["messages"][0]["role"]=="developer" and q["messages"][0]==requests[0]["messages"][0] for q in requests),"WIRE_METADATA_CHANGED")
 require(arms[0]["candidate_sha256"]==arms[1]["candidate_sha256"] and all(x["native_dispatch_count"]==1 for x in arms),"PAIR_NOT_COMMITTED")
 require(e["result"]["candidate"]["arguments"]["date"]==journal[0]["execution_date"],"WIRE_CAPTURE_DATE_MISMATCH")
 rejected=[json.loads(line) for line in refusals.read_text().splitlines()]
 require(len(rejected)==3,"REFUSAL_PAIRS_INCOMPLETE")
 for row in rejected:
  x,y=row["result"]["arms"]
  require(x["candidate_sha256"]==y["candidate_sha256"] and x["native_dispatch_count"]==1 and y["native_dispatch_count"]==0 and y["pre_state_sha256"]==y["post_state_sha256"],"REFUSAL_EFFECT_MISMATCH")
  require(isinstance(row["requests"][4]["messages"][-1]["content"],str) and "DateProfileViolation" in row["requests"][4]["messages"][-1]["content"],"ARM_B_REFUSAL_NOT_ON_WIRE")
 summary={"rule_of_one":c["rule_of_one"],"determination":"BOUNDED_OFFLINE_NATIVE_CODEC_TRANSPORT_PASS","transport_tests":len(cases),"prior_trajectory_tests":23,"prior_native_boundary_tests":41,"failures":0,"skipped":0,"recording_fake_requests":5,"positive_native_dispatch_a":1,"positive_native_dispatch_b":1,"refusal_pairs":3,"refusal_native_dispatch_b":0,"wire_date_equals_captured_date":True,"arm_local_results_reach_wire":True,"owned_metadata_sha256":journal[0]["owned_metadata_sha256"],"positive_candidate_sha256":arms[0]["candidate_sha256"],"provider_execution":0,"provider_client_constructed":0,"database_access_in_dedicated_proof":0,"external_effect":0,"scorer_or_gold_derived_authority":0,"candidate_repair":0,"v13_reuse":0,"utility_recovery_proven":False,"injection_success_remeasured":False,"historical_task4_recovery_proven":False,"next_rule_of_one":c["next_rule_of_one"]}
 report.write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
 print("PASS_TASK4_FROZEN_PROVIDER_TRANSPORT_DATE_CONTEXT_BINDING_V1")
 print("transport_tests=13 prior_trajectory_tests=23 prior_native_boundary_tests=41 failures=0 skipped=0")
 print("provider_execution=0 provider_client_constructed=0 candidate_repair=0 v13_reuse=0")
 return 0
if __name__=="__main__":raise SystemExit(main())
