#!/usr/bin/env python3
"""Exact provider-free proof: prior B native returns consumed by later offline source queries."""
from __future__ import annotations
import argparse,hashlib,json,os,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
RULE="TASK15_OFFLINE_CONTINUOUS_NATIVE_MODEL_HISTORY_REPLAY_V1"
NAME="task15-offline-continuous-native-history-v1"

def require(value,reason):
    if not value:raise ValueError(reason)

def blob(path):
    data=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()

def main():
    parser=argparse.ArgumentParser()
    for key in ("agentdojo","rcc","veritas"):
        parser.add_argument("--"+key+"-root",type=Path,required=True)
    for key in ("replay-artifact","v13-artifact","output-dir"):
        parser.add_argument("--"+key,type=Path,required=True)
    args=parser.parse_args()
    require(not os.environ.get("OPENAI_API_KEY") and
            not os.environ.get("VERITAS_DATABASE_URL"),"PROVIDER_OR_DATABASE_SECRET_FORBIDDEN")
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE and
            contract["status"]=="IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI",
            "FROZEN_OFFLINE_CONTINUITY_CONTRACT_REQUIRED")
    for path,digest in contract["source_blobs"].items():
        require(blob(ROOT/path)==digest,"SOURCE_BLOB_CHANGED:"+path)
    out=args.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    previous=subprocess.run([
        sys.executable,"scripts/task15_model_callid_native_return_history_audit_v1.py",
        "--agentdojo-root",str(args.agentdojo_root.resolve()),
        "--rcc-root",str(args.rcc_root.resolve()),
        "--veritas-root",str(args.veritas_root.resolve()),
        "--replay-artifact",str(args.replay_artifact.resolve()),
        "--v13-artifact",str(args.v13_artifact.resolve()),
        "--output-dir",str(out)],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(previous.stdout+previous.stderr)
    require(previous.returncode==0,"PR252_FROZEN_PROOF_REPLAY_FAILED:"+
            (previous.stdout+previous.stderr)[-9500:])
    old=json.loads((out/"task15-model-callid-native-return-history-v1.json").read_text())
    require(old["determination"]=="BOUNDED_OFFLINE_CALL_ID_TO_NATIVE_RETURN_HISTORY_TESTED"
            and old["new_tests"]==9 and old["predecessor_tests"]==2273
            and old["source_call_ids"]==3 and old["native_return_bindings"]==6
            and old["refused_cases"]==7 and old["actual_provider_calls"]==0
            and old["model_continuous_conversation_proven"] is False
            and old["model_queries_consumed_native_returns"] is False,
            "PREDECESSOR_SCOPE_OR_COUNTS_CHANGED")
    positive=out/(NAME+".evidence.jsonl")
    refusal=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for p in (positive,refusal,junit):p.unlink(missing_ok=True)
    env.update({key:"1" for key in (
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
    env["TASK15_CONTINUOUS_NATIVE_EVIDENCE"]=str(positive)
    env["TASK15_CONTINUOUS_NATIVE_REFUSALS"]=str(refusal)
    test=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task15_offline_continuous_native_history_v1.py",
        "--junitxml",str(junit)],
        cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".tests.log")).write_text(test.stdout+test.stderr)
    print(test.stdout,end="")
    require(test.returncode==0,"NEW_OFFLINE_CONTINUITY_TESTS_FAILED:"+
            (test.stdout+test.stderr)[-9500:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==contract["expected_tests"] and
            all(not any(x.find(k) is not None for k in
                        ("failure","error","skipped")) for x in cases),
            "NINE_EXACT_OFFLINE_TESTS_REQUIRED")
    entries=[json.loads(s) for s in positive.read_text().splitlines()]
    denied=[json.loads(s) for s in refusal.read_text().splitlines()]
    require(len(entries)==1 and len(denied)==contract["expected_refusal_cases"],
            "FROZEN_OFFLINE_CONTINUITY_EVIDENCE_MISSING")
    item=entries[0]
    result=item["proof"]
    native=item["native"]
    requests=item["model_transport_requests"]
    from task15_native_address_request_profile_issuance_v1 import sha
    from scripts.agentdojo_openai_frozen_adapter_v0_1 import MODEL_ID
    from agentdojo.types import FunctionCall
    from agentdojo.agent_pipeline.llms.openai_llm import _message_to_openai
    from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable
    import copy
    require(result["rule_of_one"]==RULE
            and result["source_mode"]=="OFFLINE_INJECTED_CLIENT"
            and result["source_model_queries_used_prior_tool_results"] is True
            and result["source_queries_are_sequential_native_history"] is True
            and result["bounded_offline_three_candidate_continuity_tested"] is True
            and result["source_arm_for_continuation"]=="B"
            and result["source_provider_authenticated"] is False
            and result["actual_provider_execution"] is False
            and result["model_continuous_conversation_proven"] is False
            and result["terminal_model_continuations"]==0
            and result["new_provider_calls"]==result["scorer_calls"]==0
            and native["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN"
            and result["composed_result_sha256"]==sha(native),
            "OFFLINE_BOUNDARY_WAS_PROMOTED_OR_UNPROVEN")
    queries=result["source_query_history_evidence"]
    links=result["source_call_id_return_bindings"]
    require(len(queries)==len(requests)==len(links)==3
            and [len(x) for x in requests]==contract["expected_exact_source_wire_message_counts"]
            and [len(x["previous_native_links"]) for x in queries]==contract["expected_consumed_previous_results"]
            and len(result["source_query_transport_journal"])==3,
            "EXPECTED_THREE_QUERY_HISTORY_CARDINALITY_CHANGED")
    consumed=0
    for step,(q,req,entry) in enumerate(zip(queries,requests,
                                             result["source_query_transport_journal"])):
        require(q["step"]==step and q["ordinal"]==(3,9,14)[step]
                and q["wire_message_count"]==len(req)
                and q["wire_messages_sha256"]==sha(req)
                and entry["wire_messages"]==req
                and len(req)==2+2*step,
                "SOURCE_TRANSPORT_DID_NOT_CONSUME_EXACT_PREFIX")
        for k in range(step):
            observed=native["completed_steps"][k]["arms"]["B"]
            tool=result["arm_histories"]["B"][3+2*k]
            assistant=result["arm_histories"]["B"][2+2*k]
            converted=copy.deepcopy(tool)
            converted["tool_call"]=FunctionCall(**tool["tool_call"])
            call_message={"role":"assistant","content":assistant["content"],
                          "tool_calls":[FunctionCall(**assistant["tool_calls"][0])]}
            require(req[2+2*k]==_message_to_openai(call_message,MODEL_ID)
                    and req[3+2*k]==_message_to_openai(converted,MODEL_ID)
                    and q["previous_native_links"][k]["native_return_sha256"]==sha(observed["native_return"])
                    and q["previous_native_links"][k]["candidate_sha256"]==observed["candidate_sha256"]
                    and tool["tool_call_id"]==links[k]["source_tool_call_id"]
                    and jsonable(converted)==tool,
                    "MODEL_REQUEST_OMITTED_OR_FORGED_PRIOR_B_NATIVE_RETURN")
            consumed+=1
    require(consumed==3 and len(native["completed_steps"])==3
            and all(x["arms"]["B"]["disposition"]=="COMMITTED"
                    for x in native["completed_steps"]),
            "MISSING_BOUNDED_OFFLINE_PRIOR_RESULT_CONSUMPTION")
    require(all(x["observation"]["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
                and x["observation"]["retry_allowed"] is False
                and x["observation"]["unreconciled_on_failure"]["completed_model_history"] is False
                for x in denied),
            "REFUSAL_PROMOTED_TO_CONTINUOUS_MODEL_PROOF")
    determination={
        "rule_of_one":RULE,
        "determination":"BOUNDED_OFFLINE_PRIOR_NATIVE_RETURN_SOURCE_CONSUMPTION_TESTED",
        "predecessor_tests":contract["expected_predecessor_tests"],
        "new_tests":len(cases),"source_queries":3,
        "native_source_prior_results_consumed":consumed,
        "native_effects_ab":6,
        "refusal_tests_with_evidence":len(denied),
        "provider_calls":0,
        "source_provider_authenticated":False,
        "model_saw_previous_native_results_in_later_queries":True,
        "full_model_conversation_proven":False,
        "terminal_answer_proven":False,
        "real_external_effect_authenticated":False,
        "final128_utility_recovery_proven":False,
        "independent_external_validation":False,
    }
    (out/(NAME+".json")).write_text(json.dumps(determination,indent=2,sort_keys=True)+"\n")
    print("PASS_"+RULE)
    print("new_tests="+str(len(cases))+" predecessor_tests="+str(contract["expected_predecessor_tests"]))
    print("source_queries="+str(len(requests))+" prior_results_consumed="+str(consumed)+" refusals="+str(len(denied)))
    return 0
if __name__=="__main__":raise SystemExit(main())
