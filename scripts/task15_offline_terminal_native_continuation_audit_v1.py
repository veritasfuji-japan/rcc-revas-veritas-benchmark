#!/usr/bin/env python3
"""Provider-free exact B-arm governed native-history terminal text proof."""
from __future__ import annotations
import argparse,copy,hashlib,json,os,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
RULE="TASK15_OFFLINE_TERMINAL_NATIVE_CONTINUATION_V1"
NAME="task15-offline-terminal-native-continuation-v1"

def require(ok,reason):
    if not ok:raise ValueError(reason)

def blob(path):
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
            "NO_PROVIDER_CREDENTIAL_OR_PRODUCTION_DATABASE")
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE
            and contract["status"]=="IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI",
            "FROZEN_BOUNDED_TERMINAL_CONTRACT_REQUIRED")
    for path,digest in contract["source_blobs"].items():
        require(blob(ROOT/path)==digest,"PINNED_PREDECESSOR_OR_NEW_SOURCE_CHANGED:"+path)
    out=args.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    prior=subprocess.run([
        sys.executable,
        "scripts/task15_offline_continuous_native_history_audit_v1.py",
        "--agentdojo-root",str(args.agentdojo_root.resolve()),
        "--rcc-root",str(args.rcc_root.resolve()),
        "--veritas-root",str(args.veritas_root.resolve()),
        "--replay-artifact",str(args.replay_artifact.resolve()),
        "--v13-artifact",str(args.v13_artifact.resolve()),
        "--output-dir",str(out)],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(prior.stdout+prior.stderr)
    require(prior.returncode==0,"PR253_PREDECESSOR_REPLAY_FAILED:"+
            (prior.stdout+prior.stderr)[-9000:])
    old=json.loads((out/"task15-offline-continuous-native-history-v1.json").read_text())
    require(old["determination"]=="BOUNDED_OFFLINE_PRIOR_NATIVE_RETURN_SOURCE_CONSUMPTION_TESTED"
            and old["predecessor_tests"]==2282
            and old["new_tests"]==9
            and old["source_queries"]==3
            and old["native_source_prior_results_consumed"]==3
            and old["native_effects_ab"]==6
            and old["refusal_tests_with_evidence"]==7
            and old["provider_calls"]==0
            and old["full_model_conversation_proven"] is False,
            "PR253_FROZEN_BOUNDED_RESULT_CHANGED")
    positive=out/(NAME+".evidence.jsonl")
    refusals=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for p in (positive,refusals,junit):p.unlink(missing_ok=True)
    env.update({name:"1" for name in (
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
    env["TASK15_TERMINAL_NATIVE_EVIDENCE"]=str(positive)
    env["TASK15_TERMINAL_NATIVE_REFUSALS"]=str(refusals)
    test=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task15_offline_terminal_native_continuation_v1.py",
        "--junitxml",str(junit)],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".tests.log")).write_text(test.stdout+test.stderr)
    print(test.stdout,end="")
    require(test.returncode==0,"TERMINAL_NATIVE_TESTS_FAILED:"+
            (test.stdout+test.stderr)[-12000:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==contract["expected_tests"] and
            all(not any(x.find(n) is not None for n in
                        ("failure","error","skipped")) for x in cases),
            "EXACT_ELEVEN_TERMINAL_TESTS_REQUIRED")
    rows=[json.loads(s) for s in positive.read_text().splitlines()]
    failed=[json.loads(s) for s in refusals.read_text().splitlines()]
    require(len(rows)==1 and len(failed)==contract["expected_refusal_cases"],
            "EXACT_TERMINAL_PROOF_AND_REFUSAL_ROWS_REQUIRED")
    evidence=rows[0]
    proof=evidence["proof"]
    requests=evidence["client_wire_requests"]
    observation=evidence["terminal_observation"]
    from task15_native_address_request_profile_issuance_v1 import sha
    from scripts.agentdojo_openai_frozen_adapter_v0_1 import MODEL_ID
    from agentdojo.types import FunctionCall
    from agentdojo.agent_pipeline.llms.openai_llm import _message_to_openai
    from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable
    native=proof["composed_native_execution"]
    source=proof["candidate_history_proof"]
    journal=proof["terminal_transport_journal"]
    require(proof["rule_of_one"]==RULE
            and proof["determination"]=="BOUNDED_OFFLINE_B_ARM_TERMINAL_TEXT_TESTED"
            and proof["source_mode"]=="OFFLINE_INJECTED_CLIENT"
            and proof["source_arm_for_continuation"]=="B"
            and proof["source_model_candidate_queries"]==3
            and proof["terminal_model_queries"]==1
            and proof["total_offline_queries"]==4
            and proof["terminal_wire_message_count"]==8
            and proof["terminal_tool_schemas_exposed"]==0
            and proof["terminal_history_uses_all_three_actual_B_native_returns"] is True
            and proof["native_return_bindings"]==6
            and proof["post_terminal_native_dispatches"]==0
            and proof["model_provider_authenticated"] is False
            and proof["actual_provider_execution"] is False
            and proof["provider_calls"]==0
            and proof["scorer_calls"]==0
            and proof["automatic_retries"]==0
            and proof["external_effect_authenticated"] is False
            and proof["A_arm_terminal_answer_tested"] is False
            and proof["real_provider_full_conversation_proven"] is False
            and proof["Final128_utility_recovery_proven"] is False
            and type(proof["terminal_text"]) is str
            and bool(proof["terminal_text"].strip()),
            "TERMINAL_PROOF_PROMOTED_OR_OMITTED")
    require(len(requests)==4
            and [len(x["messages"]) for x in requests]==[2,4,6,8]
            and requests[3]["tools"]==[]
            and requests[3]["tool_choice"] is None
            and requests[3]["model"]==MODEL_ID
            and len(journal)==1
            and journal[0]["status"]=="RESPONSE_DECODED"
            and journal[0]["wire_messages"]==requests[3]["messages"]
            and proof["terminal_wire_request_sha256"]==
            sha({"messages":requests[3]["messages"],"tools":[]})
            and proof["terminal_response_sha256"]==
            journal[0]["response_sha256"]
            and observation["phase"]=="COMPLETE_OFFLINE_TERMINAL"
            and observation["complete_terminal_output"] is True
            and native["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN",
            "ACTUAL_TERMINAL_NATIVE_OPENAI_REQUEST_NOT_PROVEN")
    source_links=source["source_call_id_return_bindings"]
    require(len(source_links)==3
            and len(native["completed_steps"])==3
            and source["source_model_queries_used_prior_tool_results"] is True
            and source["model_continuous_conversation_proven"] is False,
            "PREVIOUS_SOURCE_CHAIN_NOT_PINNED")
    checked=0
    for step in range(3):
        pair=source_links[step]
        row=native["completed_steps"][step]
        tool=source["arm_histories"]["B"][3+2*step]
        assistant=source["arm_histories"]["B"][2+2*step]
        typed_tool=copy.deepcopy(tool)
        typed_tool["tool_call"]=FunctionCall(**tool["tool_call"])
        typed_assistant={"role":"assistant","content":assistant["content"],
                         "tool_calls":[FunctionCall(**assistant["tool_calls"][0])]}
        require(row["arms"]["B"]["disposition"]=="COMMITTED"
                and row["arms"]["B"]["native_dispatch_count"]==1
                and tool["tool_call_id"]==pair["source_tool_call_id"]
                and pair["arms"]["B"]["native_return_sha256"]==
                sha(row["arms"]["B"]["native_return"])
                and requests[3]["messages"][2+2*step]==
                _message_to_openai(typed_assistant,MODEL_ID)
                and requests[3]["messages"][3+2*step]==
                _message_to_openai(typed_tool,MODEL_ID)
                and jsonable(typed_tool)==tool
                and requests[3]["messages"][:2+2*step]==
                requests[step]["messages"],
                "TERMINAL_WIRE_DID_NOT_CONSUME_EXACT_THREE_GOVERNED_B_RETURNS")
        checked+=1
    require(checked==3 and all(x["observation"]["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
            and x["observation"]["complete_terminal_output"] is False
            and x["observation"]["unreconciled_on_failure"]["retry_allowed"] is False
            for x in failed),
            "ONE_SHOT_TERMINAL_REFUSAL_NOT_PROVEN")
    report={
        "rule_of_one":RULE,
        "determination":"BOUNDED_OFFLINE_B_ARM_TERMINAL_TEXT_TESTED",
        "predecessor_tests":contract["expected_predecessor_tests"],
        "new_tests":len(cases),
        "terminal_source_arm":"B",
        "candidate_source_queries":3,
        "terminal_query_calls":1,
        "native_B_return_messages_in_terminal_wire":checked,
        "native_effects_ab":6,
        "terminal_tools_exposed":0,
        "refusal_tests":len(failed),
        "provider_calls":0,
        "scorer_calls":0,
        "external_effect_authenticated":False,
        "A_arm_terminal_answer_tested":False,
        "real_provider_full_conversation_proven":False,
        "final128_utility_recovery_proven":False,
    }
    (out/(NAME+".json")).write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("PASS_"+RULE)
    print("prior="+str(contract["expected_predecessor_tests"])+" new="+str(len(cases))+
          " b_return_links="+str(checked)+" failures="+str(len(failed)))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
