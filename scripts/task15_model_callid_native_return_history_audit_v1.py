#!/usr/bin/env python3
"""Offline exact source tool-call IDs matched to actual governed native returns."""
from __future__ import annotations
import argparse,hashlib,json,os,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
RULE="TASK15_MODEL_CALL_ID_TO_NATIVE_TOOL_RETURN_HISTORY_V1"
NAME="task15-model-callid-native-return-history-v1"

def require(condition, reason):
    if not condition:raise ValueError(reason)

def blob(path):
    raw=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def main():
    parser=argparse.ArgumentParser()
    for name in ("agentdojo","rcc","veritas"):
        parser.add_argument("--"+name+"-root",type=Path,required=True)
    for name in ("replay-artifact","v13-artifact","output-dir"):
        parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args()
    require(not os.environ.get("OPENAI_API_KEY") and
            not os.environ.get("VERITAS_DATABASE_URL"),"NO_PROVIDER_DATABASE_CREDENTIALS")
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["status"]=="IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI"
            and contract["rule_of_one"]==RULE,"FROZEN_CALL_ID_PROOF_CONTRACT_REQUIRED")
    for path,hash_ in contract["source_blobs"].items():
        require(blob(ROOT/path)==hash_,"PINNED_SOURCE_CHANGED:"+path)
    out=args.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    prior=subprocess.run([
        sys.executable,"scripts/task15_composed_native_return_binding_audit_v1.py",
        "--agentdojo-root",str(args.agentdojo_root.resolve()),
        "--rcc-root",str(args.rcc_root.resolve()),
        "--veritas-root",str(args.veritas_root.resolve()),
        "--replay-artifact",str(args.replay_artifact.resolve()),
        "--v13-artifact",str(args.v13_artifact.resolve()),
        "--output-dir",str(out)],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(prior.stdout+prior.stderr)
    require(prior.returncode==0,"PR251_SOURCE_CHAIN_REPLAY_FAILED:"+
            (prior.stdout+prior.stderr)[-8000:])
    previous=json.loads((out/"task15-composed-native-return-binding-v1.json").read_text())
    require(previous["determination"]=="BOUNDED_COMPOSED_NATIVE_RETURN_BINDING_TESTED"
            and previous["new_tests"]==7
            and previous["predecessor_tests"]==2266
            and previous["success_native_return_bindings"]==6
            and previous["refusals"]==4
            and previous["real_provider_calls"]==0,
            "FROZEN_PR251_PROOF_CHANGED")
    positive=out/(NAME+".evidence.jsonl")
    refusal=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for f in (positive,refusal,junit):f.unlink(missing_ok=True)
    env.update({key:"1" for key in (
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
    env["TASK15_MODEL_CALLID_EVIDENCE"]=str(positive)
    env["TASK15_MODEL_CALLID_REFUSALS"]=str(refusal)
    tests=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task15_model_callid_native_return_history_v1.py",
        "--junitxml",str(junit)
    ],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".tests.log")).write_text(tests.stdout+tests.stderr)
    print(tests.stdout,end="")
    require(tests.returncode==0,"NEW_CALL_ID_NATIVE_RETURN_TEST_FAILED:"+
            (tests.stdout+tests.stderr)[-9000:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==contract["expected_tests"] and
            all(not any(t.find(n) is not None for n in ("skipped","failure","error"))
                for t in cases),"NEW_TEST_INCOMPLETE")
    evidence=[json.loads(s) for s in positive.read_text().splitlines()]
    errors=[json.loads(s) for s in refusal.read_text().splitlines()]
    require(len(evidence)==1 and len(errors)==contract["expected_refusal_tests"],
            "PROOF_ROW_CARDINALITY_CHANGED")
    item=evidence[0]
    proof=item["proof"]
    native=item["composed_native_execution"]
    require(proof["rule_of_one"]==RULE and proof["source_mode"]=="OFFLINE_INJECTED_CLIENT"
            and proof["new_provider_calls"]==0 and proof["scorer_calls"]==0
            and proof["source_provider_authenticated"] is False
            and proof["source_model_queries_used_prior_tool_results"] is False
            and proof["tool_messages_constructed_after_all_native_steps"] is True
            and proof["model_continuous_conversation_proven"] is False
            and proof["actual_provider_execution"] is False
            and proof["execution_effect_authenticated"] is False
            and proof["terminal_model_continuations"]==0,
            "INVALID_CONVERSATION_OR_PROVIDER_PROOF_PROMOTION")
    from task15_native_address_request_profile_issuance_v1 import sha,canonical
    require(len(proof["source_call_id_return_bindings"])==3 and
            all(len(proof["arm_histories"][arm])==8 for arm in ("A","B"))
            and native["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN"
            and proof["composed_result_sha256"]==sha(native),
            "COMPLETED_LOCAL_HISTORY_MISSING")
    verified=0
    ids=set()
    for step,binding in enumerate(proof["source_call_id_return_bindings"]):
        call_id=binding["source_tool_call_id"]
        require(call_id not in ids and call_id=="offline-native-"+str(step)
                and binding["step"]==step and binding["ordinal"]==(3,9,14)[step]
                and binding["candidate_sha256"]==native["completed_steps"][step]["candidate_sha256"],
                "WRONG_SOURCE_ID_OR_NATIVE_CANDIDATE")
        ids.add(call_id)
        for arm in ("A","B"):
            row=binding["arms"][arm]
            actual=native["completed_steps"][step]["arms"][arm]
            messages=proof["arm_histories"][arm]
            assistant,tool=messages[2+2*step:4+2*step]
            require(assistant["role"]=="assistant" and assistant["tool_calls"][0]["id"]==call_id
                    and tool["role"]=="tool" and tool["tool_call_id"]==call_id
                    and tool["tool_call"]==assistant["tool_calls"][0]
                    and tool["error"] is None
                    and sha(tool)==row["native_tool_message_sha256"]
                    and row["candidate_sha256"]==actual["candidate_sha256"]
                    and row["pre_state_sha256"]==actual["pre_state_sha256"]
                    and row["post_state_sha256"]==actual["post_state_sha256"]
                    and row["native_return_sha256"]==sha(actual["native_return"])
                    and row["native_dispatch_count"]==actual["native_dispatch_count"]==1,
                    "MODEL_TOOL_RESULT_NOT_GENUINELY_BOUND_TO_NATIVE_EFFECT")
            verified+=1
    require(verified==contract["expected_native_return_bindings"],
            "EXACT_NATIVE_LINK_COUNT_CHANGED")
    require(all(x["observation"]["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
                and x["observation"]["retry_allowed"] is False
                for x in errors),"REFUSAL_HISTORY_PROMOTION")
    report={"rule_of_one":RULE,
        "determination":"BOUNDED_OFFLINE_CALL_ID_TO_NATIVE_RETURN_HISTORY_TESTED",
        "predecessor_tests":contract["expected_predecessor_tests"],
        "new_tests":len(cases),"source_call_ids":len(ids),
        "native_return_bindings":verified,
        "refused_cases":len(errors),"actual_provider_calls":0,
        "model_continuous_conversation_proven":False,
        "model_queries_consumed_native_returns":False,
        "terminal_model_continuations":0,
        "external_effect_authenticated":False,
        "final128_utility_recovered":False,
        "independent_external_validation":False}
    (out/(NAME+".json")).write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("PASS_"+RULE)
    print("native_bindings="+str(verified)+" refusals="+str(len(errors)))
    return 0

if __name__=="__main__":raise SystemExit(main())
