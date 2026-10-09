#!/usr/bin/env python3
"""Exact paired native scorer input extraction; no rubric, provider or canonical promotion."""
from __future__ import annotations
import argparse,hashlib,json,os,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
RULE="TASK15_OFFLINE_PAIRED_SCORER_INPUT_PROVENANCE_V1"
NAME="task15-offline-paired-scorer-input-provenance-v1"

def require(condition, reason):
    if not condition:raise ValueError(reason)

def blob(path):
    raw=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def main():
    ap=argparse.ArgumentParser()
    for key in ("agentdojo","rcc","veritas"):
        ap.add_argument("--"+key+"-root",required=True,type=Path)
    for key in ("replay-artifact","v13-artifact","output-dir"):
        ap.add_argument("--"+key,required=True,type=Path)
    args=ap.parse_args()
    require(not os.environ.get("OPENAI_API_KEY")
            and not os.environ.get("VERITAS_DATABASE_URL"),
            "CREDENTIALS_OR_DATABASE_PROHIBITED")
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE
            and contract["status"]=="IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI",
            "FROZEN_INPUT_PROJECTION_CONTRACT_REQUIRED")
    for p,h in contract["source_blobs"].items():
        require(blob(ROOT/p)==h,"BLOB_PIN_CHANGED:"+p)
    out=args.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    prior=subprocess.run([
        sys.executable,"scripts/task15_offline_paired_terminal_histories_audit_v1.py",
        "--agentdojo-root",str(args.agentdojo_root.resolve()),
        "--rcc-root",str(args.rcc_root.resolve()),
        "--veritas-root",str(args.veritas_root.resolve()),
        "--replay-artifact",str(args.replay_artifact.resolve()),
        "--v13-artifact",str(args.v13_artifact.resolve()),
        "--output-dir",str(out)],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(prior.stdout+prior.stderr)
    require(prior.returncode==0,"PR255_PREDECESSOR_REPLAY_FAILED:"+
            (prior.stdout+prior.stderr)[-9500:])
    old=json.loads((out/"task15-offline-paired-terminal-histories-v1.json").read_text())
    require(old["determination"]=="BOUNDED_OFFLINE_PAIRED_TERMINAL_TEXT_OBSERVED"
            and old["predecessor_tests"]==2302
            and old["new_tests"]==20
            and old["refusals"]==18
            and old["source_queries"]==3
            and old["terminal_queries"]==2
            and old["terminal_native_return_links"]==6
            and old["native_effects_ab"]==6
            and old["provider_calls"]==old["scorer_calls"]==0
            and old["native_task15_utility_measured"] is False,
            "EXACT_PR255_FROZEN_PROOF_CHANGED")
    positive=out/(NAME+".evidence.jsonl")
    denied=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for p in (positive,denied,junit):p.unlink(missing_ok=True)
    env.update({key:"1" for key in (
        "TASK15_PAIRED_SCORER_INPUT_PROOF",
        "TASK15_OFFLINE_PAIRED_TERMINAL_PROOF",
        "TASK15_OFFLINE_TERMINAL_NATIVE_PROOF",
        "TASK15_OFFLINE_CONTINUOUS_NATIVE_PROOF",
        "TASK15_MODEL_CALLID_RETURN_HISTORY_PROOF",
        "TASK15_NATIVE_MODEL_CAPTURE_PROOF",
        "TASK15_COMPOSED_NATIVE_RETURN_PROOF",
        "TASK15_COMPOSED_RUNNER_PROOF",
        "TASK15_NATIVE_ADDRESS_PROOF",
        "TASK15_EXACT_NATIVE_RETURN_PROOF",
        "TASK15_CONTROLLED_RENT_PROOF",
        "TASK15_RENT_DESIGN_PROOF",
        "TASK15_SCOPE_LINEAGE_PROOF",
        "TASK15_REFUND_DESIGN_PROOF",
        "TASK15_REFUND_METADATA_PROOF",
        "TASK15_REFUND_CORRELATION_PROOF",
    )})
    env["TASK15_RCC_ROOT"]=str(args.rcc_root.resolve())
    env["TASK15_PAIRED_SCORER_INPUT_EVIDENCE"]=str(positive)
    env["TASK15_PAIRED_SCORER_INPUT_REFUSALS"]=str(denied)
    tests=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task15_offline_paired_scorer_input_provenance_v1.py",
        "--junitxml",str(junit)],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".tests.log")).write_text(tests.stdout+tests.stderr)
    print(tests.stdout,end="")
    require(tests.returncode==0,"NEW_NATIVE_SCORER_INPUT_TEST_FAILED:"+
            (tests.stdout+tests.stderr)[-15000:])
    entries=ET.parse(junit).getroot().findall(".//testcase")
    require(len(entries)==contract["expected_tests"]
            and all(not any(e.find(n) is not None for n in
                            ("failure","error","skipped")) for e in entries),
            "EXACT_NEW_TEST_CARDINALITY_OR_RESULT_WRONG")
    positive_rows=[json.loads(x) for x in positive.read_text().splitlines()]
    refused=[json.loads(x) for x in denied.read_text().splitlines()]
    require(len(positive_rows)==1
            and len(refused)==contract["expected_negative_records"],
            "EXPECTED_SCORER_INPUT_PROVENANCE_EVIDENCE_ROWS")
    row=positive_rows[0]
    report=row["scorer_projection"]
    native=row["paired_terminal"]["paired_native_execution"]
    captured=row["paired_terminal"]["captured_source_history"]
    from task15_native_address_request_profile_issuance_v1 import sha
    from agentdojo.types import FunctionCall
    from agentdojo.task_suite.load_suites import get_suite
    from scripts.agentdojo_native_scorer_invocation_v0_1 import NativeScorerInput
    suite=get_suite("v1.2.2","banking")
    require(report["rule_of_one"]==RULE
            and report["determination"]=="OFFLINE_NATIVE_MODEL_OUTPUT_AND_FUNCTION_TRACE_PROJECTED"
            and report["canonical_case_id_match"] is False
            and report["noncanonical_local_design_case"] is True
            and report["canonical_final128_enrollment_proven"] is False
            and report["eligible_for_canonical_final128_scoring"] is False
            and report["source_history_generated_from_B_only"] is True
            and report["scorer_input_projection_count"]==2
            and report["native_function_trace_items"]==6
            and report["native_terminal_model_output_items"]==2
            and report["governed_native_commits_ab"]==6
            and report["provider_calls"]==report["scorer_calls"]==report["new_effect_dispatches"]==0
            and report["rubric_invoked"] is False
            and report["native_task15_utility_measured"] is False
            and report["injection_success_measured"] is False
            and report["final128_utility_recovery_proven"] is False
            and row["fixture_case_id"]==contract["local_fixture_case_id"]
            and report["source_paired_terminal_sha256"]==sha(row["paired_terminal"])
            and report["initial_native_state_sha256"]==sha(row["paired_terminal"]["paired_native_execution"]["completed_steps"][0]["arms"]["A"]["pre_environment"]) if "pre_environment" in native["completed_steps"][0]["arms"]["A"] else
                report["initial_native_state_sha256"]==native["initial_state_sha256"],
            "NOT_STRICT_LOCAL_UNSCORED_SOURCE")
    checked=0
    for arm in ("A","B"):
        rec=report["scorer_inputs"][arm]
        require(rec["case_id"]==contract["local_fixture_case_id"]
                and rec["arm"]==arm
                and rec["original_native_execution_sha256"]==sha(native)
                and len(rec["functions_stack_trace"])==3
                and len(rec["model_output"])==1
                and rec["model_output"][0]["type"]=="text"
                and sha(rec["pre_environment"])==native["initial_state_sha256"]
                and sha(rec["post_environment"])==native["completed_steps"][2]["arms"][arm]["post_state_sha256"],
                "SCORER_PREPOST_INPUT_WRONG")
        strict=NativeScorerInput(
            case_id=rec["case_id"],arm=arm,
            model_output=rec["model_output"],
            functions_stack_trace=[FunctionCall.model_validate(v)
                                  for v in rec["functions_stack_trace"]],
            pre_environment=suite.environment_type.model_validate(rec["pre_environment"]),
            post_environment=suite.environment_type.model_validate(rec["post_environment"]))
        require(len(strict.functions_stack_trace)==3
                and [v.id for v in strict.functions_stack_trace]==[
                    q["source_tool_call_id"] for q in captured["source_call_id_return_bindings"]]
                and strict.post_environment.model_dump(mode="json")==rec["post_environment"],
                "NATIVE_TYPED_SCORER_INPUT_NOT_REHYDRATABLE")
        checked+=1
    require(checked==2 and len(refused)==13,"SCORER_INPUT_REFUSAL_CARDINALITY_FAILED")
    result={
        "rule_of_one":RULE,
        "determination":"OFFLINE_NATIVE_MODEL_OUTPUT_AND_FUNCTION_TRACE_PROJECTED",
        "predecessor_tests":contract["expected_predecessor_tests"],
        "new_tests":len(entries),
        "negative_cases":len(refused),
        "native_scorer_input_arms":checked,
        "native_trace_items":6,
        "terminal_outputs":2,
        "rubric_invoked":False,
        "native_task15_utility_measured":False,
        "canonical_final128_enrollment_proven":False,
        "real_provider_calls":0,
        "scorer_calls":0,
        "real_external_effect_authenticated":False,
        "final128_utility_recovery_proven":False}
    (out/(NAME+".json")).write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("PASS_"+RULE)
    print("new_tests="+str(len(entries))+" refusals="+str(len(refused))+
          " projected_arms="+str(checked))
    return 0
if __name__=="__main__":
    raise SystemExit(main())
