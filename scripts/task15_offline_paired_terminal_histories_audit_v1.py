#!/usr/bin/env python3
"""Exact offline A/B terminal native history proof with frozen #254 predecessor."""
from __future__ import annotations
import argparse,copy,hashlib,json,os,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
RULE="TASK15_OFFLINE_PAIRED_TERMINAL_NATIVE_HISTORIES_V1"
NAME="task15-offline-paired-terminal-histories-v1"

def require(ok,why):
    if not ok:raise ValueError(why)

def git_blob(path):
    raw=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def main():
    parser=argparse.ArgumentParser()
    for key in ("agentdojo","rcc","veritas"):
        parser.add_argument("--"+key+"-root",type=Path,required=True)
    for key in ("replay-artifact","v13-artifact","output-dir"):
        parser.add_argument("--"+key,type=Path,required=True)
    args=parser.parse_args()
    require(not os.environ.get("OPENAI_API_KEY")
            and not os.environ.get("VERITAS_DATABASE_URL"),
            "PAID_PROVIDER_OR_PRODUCTION_DATABASE_NOT_ALLOWED")
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE
            and contract["status"]=="IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI",
            "EXACT_SCOPE_CONTRACT_REQUIRED")
    for path,expected in contract["source_blobs"].items():
        require(git_blob(ROOT/path)==expected,"SOURCE_PIN_CHANGED:"+path)
    out=args.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    prior=subprocess.run([
        sys.executable,
        "scripts/task15_offline_terminal_native_continuation_audit_v1.py",
        "--agentdojo-root",str(args.agentdojo_root.resolve()),
        "--rcc-root",str(args.rcc_root.resolve()),
        "--veritas-root",str(args.veritas_root.resolve()),
        "--replay-artifact",str(args.replay_artifact.resolve()),
        "--v13-artifact",str(args.v13_artifact.resolve()),
        "--output-dir",str(out)],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(prior.stdout+prior.stderr)
    require(prior.returncode==0,"PR254_EXACT_PREDECESSOR_PROOF_REPLAY_FAILED:"+
            (prior.stdout+prior.stderr)[-8500:])
    prev=json.loads((out/"task15-offline-terminal-native-continuation-v1.json").read_text())
    require(prev["determination"]=="BOUNDED_OFFLINE_B_ARM_TERMINAL_TEXT_TESTED"
            and prev["predecessor_tests"]==2291 and prev["new_tests"]==11
            and prev["candidate_source_queries"]==3
            and prev["terminal_query_calls"]==1
            and prev["native_B_return_messages_in_terminal_wire"]==3
            and prev["native_effects_ab"]==6
            and prev["refusal_tests"]==9
            and prev["provider_calls"]==prev["scorer_calls"]==0,
            "PR254_FROZEN_NATIVE_TERMINAL_COUNTS_CHANGED")
    positive=out/(NAME+".evidence.jsonl")
    refused=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for p in (positive,refused,junit):p.unlink(missing_ok=True)
    env.update({key:"1" for key in (
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
    env["TASK15_PAIRED_TERMINAL_EVIDENCE"]=str(positive)
    env["TASK15_PAIRED_TERMINAL_REFUSALS"]=str(refused)
    run=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task15_offline_paired_terminal_histories_v1.py",
        "--junitxml",str(junit)],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".tests.log")).write_text(run.stdout+run.stderr)
    print(run.stdout,end="")
    require(run.returncode==0,"PAIRED_TERMINAL_NATIVE_TESTS_FAILED:"+
            (run.stdout+run.stderr)[-15000:])
    tests=ET.parse(junit).getroot().findall(".//testcase")
    require(len(tests)==contract["expected_tests"] and all(
        not any(t.find(x) is not None for x in ("failure","error","skipped"))
        for t in tests),"EXACT_NEW_TESTS_NOT_ALL_PASS")
    evidence=[json.loads(line) for line in positive.read_text().splitlines()]
    errors=[json.loads(line) for line in refused.read_text().splitlines()]
    require(len(evidence)==1 and len(errors)==contract["expected_negative_records"],
            "EXACT_PAIRED_PROOF_CARDINALITY_REQUIRED")
    row=evidence[0]
    report=row["proof"]
    requests=row["client_calls"]
    state=report["paired_native_execution"]
    captured=report["captured_source_history"]
    from agentdojo.types import FunctionCall
    from agentdojo.agent_pipeline.llms.openai_llm import _message_to_openai
    from scripts.agentdojo_openai_frozen_adapter_v0_1 import MODEL_ID
    from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable
    from task15_native_address_request_profile_issuance_v1 import sha
    require(report["rule_of_one"]==RULE
            and report["determination"]=="BOUNDED_OFFLINE_PAIRED_TERMINAL_TEXT_OBSERVED"
            and report["source_mode"]=="OFFLINE_INJECTED_CLIENT"
            and report["candidate_source_arm"]=="B"
            and report["terminal_arms"]==["A","B"]
            and report["source_candidate_queries"]==3
            and report["terminal_queries"]==2
            and report["total_offline_queries"]==5
            and report["native_commits_ab"]==6
            and report["actual_provider_calls"]==report["scorer_calls"]==0
            and report["scored_task15_utility"] is False
            and report["scored_injection_success"] is False
            and report["A_candidate_source_history_independently_generated"] is False
            and report["final128_utility_recovery_proven"] is False
            and report["real_provider_full_conversation_proven"] is False
            and state["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN"
            and len(state["completed_steps"])==3,
            "PROOF_OUTSIDE_BOUNDED_OFFLINE_SCOPE")
    require(len(requests)==5
            and [len(x["messages"]) for x in requests]==[2,4,6,8,8]
            and len(report["terminal_transport_journal"])==2
            and set(report["terminal_observations"])=={"A","B"}
            and len(captured["source_call_id_return_bindings"])==3
            and captured["source_model_queries_used_prior_tool_results"] is True
            and captured["model_continuous_conversation_proven"] is False,
            "TWO_INDEPENDENT_TERMINAL_WIRES_NOT_OBSERVED")
    checked=0
    for index,arm in enumerate(("A","B")):
        req=requests[3+index]
        journal=report["terminal_transport_journal"][index]
        terminal=report["terminal_observations"][arm]
        require(req["tools"]==[] and req["tool_choice"] is None
                and req["model"]==MODEL_ID
                and journal["source_arm"]==terminal["arm"]==arm
                and journal["status"]=="RESPONSE_DECODED"
                and journal["wire_tools"]==[]
                and journal["wire_messages"]==req["messages"]
                and journal["wire_request_sha256"]==
                sha({"messages":req["messages"],"tools":[]})
                and terminal["terminal_request_sha256"]==journal["wire_request_sha256"]
                and terminal["response_sha256"]==journal["response_sha256"]
                and bool(terminal["terminal_text"].strip()),
                "FINAL_REQUEST_OR_RESPONSE_NOT_EXACT_FOR_ARM")
        for step in range(3):
            actual=state["completed_steps"][step]["arms"][arm]
            pair=captured["source_call_id_return_bindings"][step]
            assistant=captured["arm_histories"][arm][2+2*step]
            tool=captured["arm_histories"][arm][3+2*step]
            typed=copy.deepcopy(tool)
            typed["tool_call"]=FunctionCall(**tool["tool_call"])
            typed_assistant={"role":"assistant","content":assistant["content"],
                             "tool_calls":[FunctionCall(**assistant["tool_calls"][0])]}
            require(actual["disposition"]=="COMMITTED"
                    and actual["native_dispatch_count"]==1
                    and pair["arms"][arm]["native_return_sha256"]==sha(actual["native_return"])
                    and pair["arms"][arm]["pre_state_sha256"]==actual["pre_state_sha256"]
                    and pair["arms"][arm]["post_state_sha256"]==actual["post_state_sha256"]
                    and tool["tool_call_id"]==pair["source_tool_call_id"]
                    and req["messages"][2+2*step]==_message_to_openai(typed_assistant,MODEL_ID)
                    and req["messages"][3+2*step]==_message_to_openai(typed,MODEL_ID)
                    and jsonable(typed)==tool,
                    "TERMINAL_RESULT_CROSSED_ARM_OR_FORGED")
            checked+=1
    require(checked==6
            and requests[4]["messages"][:6]==requests[2]["messages"]
            and requests[3]["messages"][:2]==requests[0]["messages"],
            "B_SOURCE_CONTINUITY_OR_A_ORIGINAL_REQUEST_LOST")
    require(all(row["observation"]["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
                and row["observation"]["paired_terminal_complete"] is False
                and row["observation"]["unreconciled_on_failure"]["retry_allowed"] is False
                for row in errors),"FAILED_PAIRED_RESULTS_PROMOTED")
    determination={
        "rule_of_one":RULE,
        "determination":"BOUNDED_OFFLINE_PAIRED_TERMINAL_TEXT_OBSERVED",
        "predecessor_tests":contract["expected_predecessor_tests"],
        "new_tests":len(tests),
        "refusals":len(errors),
        "source_queries":3,
        "terminal_queries":2,
        "terminal_native_return_links":checked,
        "native_effects_ab":6,
        "terminal_tool_schemas":0,
        "provider_calls":0,
        "scorer_calls":0,
        "native_task15_utility_measured":False,
        "real_provider_conversation_proven":False,
        "final128_utility_recovered":False}
    (out/(NAME+".json")).write_text(json.dumps(determination,indent=2,sort_keys=True)+"\n")
    print("PASS_"+RULE)
    print("new_tests="+str(len(tests))+
          " refused="+str(len(errors))+
          " terminal_native_links="+str(checked))
    return 0
if __name__=="__main__":
    raise SystemExit(main())
