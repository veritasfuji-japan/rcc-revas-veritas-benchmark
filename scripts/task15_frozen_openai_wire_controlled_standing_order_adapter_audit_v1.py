#!/usr/bin/env python3
"""Reproduce #225, independently link actual native evidence to frozen fake wire."""
from __future__ import annotations
import argparse
import importlib.metadata
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.task15_prospective_controlled_standing_order_trajectory_audit_v1 import blob,git,require,audit_pair
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable
from scripts.agentdojo_openai_frozen_adapter_v0_1 import MODEL_ID
from task15_standing_order_request_profile_issuance_v1 import sha
NAME="task15-frozen-openai-wire-controlled-standing-order-adapter-v1"
CONTRACT=ROOT/"contracts/TASK15_FROZEN_OPENAI_WIRE_CONTROLLED_STANDING_ORDER_ADAPTER_V1.json"
EXPECTED_CONTRACT="cbd52be4f3249b092c5ef4971e263d8282cf923d"

def audit_wire(row, *, positive, contract, codec, rcc_root):
    result,requests,journal=row["result"],row["requests"],row["transport_journal"]
    require(row["wire_rule_of_one"]==contract["rule_of_one"],"WIRE_RULE_CHANGED")
    prior_contract=ROOT/"contracts/TASK15_PROSPECTIVE_CONTROLLED_STANDING_ORDER_TRAJECTORY_V1.json"
    require(blob(prior_contract)==contract["trajectory_contract_blob"],"TRAJECTORY_CONTRACT_CHANGED")
    identity=audit_pair(jsonable(result),positive=positive,contract=json.loads(prior_contract.read_text()),rcc_root=rcc_root)
    require(len(requests)==len(journal)==5,"WIRE_QUERY_COUNT_CHANGED")
    require([x["phase"] for x in journal]==["COMMON_PREFIX"]*3+["CONTINUATION_A","CONTINUATION_B"],"WIRE_PHASES_CHANGED")
    require([x["ordinal"] for x in journal]==[0,1,2,3,3],"WIRE_ORDINALS_CHANGED")
    require(len({x["owned_messages_sha256"] for x in journal})==1 and
            len({x["native_tools_sha256"] for x in journal})==1,"WIRE_OWNED_BINDING_CHANGED")
    native=result["arms"][0]["messages"][:-2]
    histories=[native[:2],native[:4],native[:6]]+[arm["messages"][:-1] for arm in result["arms"]]
    for index,(q,j,messages) in enumerate(zip(requests,journal,histories)):
        require(set(q)=={"model","messages","tools","tool_choice","temperature"} and q["model"]==MODEL_ID and
                q["temperature"]==0.0 and q["tool_choice"]=="auto","FROZEN_REQUEST_CONFIG_CHANGED")
        def comparable(history):
            # Artifact JSON sorting loses dict insertion order; argument JSON
            # text may change key order on re-encoding. Compare parsed objects
            # only for this field; every other native wire field stays exact.
            value=copy.deepcopy(history)
            for message in value:
                for call in message.get("tool_calls",[]):
                    call["function"]["arguments"]=json.loads(call["function"]["arguments"])
            return value
        require(comparable(q["messages"])==comparable([codec._message_to_openai(m,MODEL_ID) for m in messages]),"WIRE_NOT_ACTUAL_NATIVE_HISTORY")
        require(q["messages"][:2]==requests[0]["messages"][:2] and q["messages"][0]["role"]=="developer" and
                q["messages"][1]["content"][0]["text"]==contract["prospective_original_request"],"WIRE_REQUEST_SOURCE_CHANGED")
        require(j["status"]=="RESPONSE_DECODED" and j["wire_messages"]==q["messages"] and j["wire_tools"]==q["tools"] and
                j["wire_request_sha256"]==sha({"messages":q["messages"],"tools":q["tools"]}) and
                j["native_tools_sha256"]==sha(q["tools"]),"WIRE_JOURNAL_HASH_MISMATCH")
        response=native[2] if index==0 else native[4] if index==1 else native[6] if index==2 else result["arms"][index-3]["messages"][-1]
        require(j["response_sha256"]==sha(jsonable(response)),"WIRE_RESPONSE_TO_NATIVE_CANDIDATE_LINKAGE_CHANGED")
    raw=requests[3]["messages"][-2]["tool_calls"][0]
    wire_arguments=json.loads(raw["function"]["arguments"])
    from agentdojo.task_suite.load_suites import get_suite
    rent=next(t for t in get_suite("v1.2.2","banking").tools if t.name=="update_scheduled_transaction")
    require(rent.parameters.model_validate(wire_arguments).model_dump(mode="json")==result["candidate"]["arguments"] and
            raw["function"]["name"]=="update_scheduled_transaction","WIRE_PROPOSAL_REPAIRED")
    allowed={"get_iban","get_balance","get_most_recent_transactions","get_scheduled_transactions","read_file","get_user_info","update_scheduled_transaction"}
    native_tools=[codec._function_to_openai(t) for t in get_suite("v1.2.2","banking").tools if t.name in allowed]
    require(all(q["tools"]==native_tools for q in requests),"WIRE_NOT_ACTUAL_NATIVE_TOOL_SCHEMAS")
    for q,arm in zip(requests[3:],result["arms"]):
        require(q["messages"][-1]["tool_call_id"]==raw["id"]=="wire-rent-2","WIRE_TOOL_RETURN_ID_CHANGED")
        if arm["native_dispatch_count"]==0:
            require(type(q["messages"][-1]["content"]) is str and q["messages"][-1]["content"].startswith("RentProfileViolation:"),"ACTUAL_REFUSAL_NOT_ON_WIRE")
    return {**identity,"wire_request_sha256s":[x["wire_request_sha256"] for x in journal],
            "owned_messages_sha256":journal[0]["owned_messages_sha256"],"native_tools_sha256":journal[0]["native_tools_sha256"]}

def restore(row):
    """Restore native FunctionCall objects; preserve the original request bytes."""
    from agentdojo.functions_runtime import FunctionCall
    for arm in row["result"]["arms"]:
        for message in arm["messages"]:
            if message.get("tool_calls"):
                message["tool_calls"]=[FunctionCall(**x) for x in message["tool_calls"]]
            if message.get("tool_call"):message["tool_call"]=FunctionCall(**message["tool_call"])
    return row

def audit_terminal_transports(rows, *, contract):
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite
    require(len(rows)==15 and {(r["fault_ordinal"],r["error_type"]) for r in rows}==
            {(i,e) for i in range(5) for e in ("RuntimeError","KeyboardInterrupt","SystemExit")},"TERMINAL_TRANSPORT_POPULATION_CHANGED")
    phases=["COMMON_PREFIX"]*3+["CONTINUATION_A","CONTINUATION_B"]
    native_transitions=0
    for row in rows:
        ordinal=row["fault_ordinal"];requests=row["requests"];journal=row["transport_journal"];arms=row["native_arms"]
        require(len(requests)==len(journal)==ordinal+1 and row["wire_closed"] is True and row["retry_requests"]==0,
                "FAILED_TRANSPORT_RETRIED")
        require([j["phase"] for j in journal]==phases[:ordinal+1] and
                [j["status"] for j in journal]==["RESPONSE_DECODED"]*ordinal+["FAILED_OR_CANCELLED"],"FAILED_TRANSPORT_PHASE_RECLASSIFIED")
        for q,j in zip(requests,journal):
            require(q["model"]==MODEL_ID and q["temperature"]==0.0 and q["tool_choice"]=="auto" and
                    q["messages"][:2]==[{"role":"developer","content":[{"type":"text","text":contract["system_message"]}]},
                    {"role":"user","content":[{"type":"text","text":contract["prospective_original_request"]}]}],"TERMINAL_REQUEST_SOURCE_CHANGED")
            require(j["wire_messages"]==q["messages"] and j["wire_tools"]==q["tools"] and
                    j["wire_request_sha256"]==sha({"messages":q["messages"],"tools":q["tools"]}),"TERMINAL_WIRE_HASH_CHANGED")
        require(len(arms)==max(0,ordinal-2),"COMPLETED_NATIVE_ARM_POPULATION_CHANGED")
        last=row["trajectory_journal"][-1]
        require(last["event"]=="TRAJECTORY_TERMINATED_WITHOUT_RETRY" and last["payload"]=={
            "error_type":row["error_type"],"returned_native_arm_results":len(arms),"completed_native_dispatches":len(arms),
            "later_arm_attempts_closed":ordinal>=3,"no_effect_or_rollback_claim":False},"PARTIAL_EFFECT_RECLASSIFIED")
        for index,arm in enumerate(arms):
            require(arm["arm"]==("A" if index==0 else "B") and arm["disposition"]=="COMMITTED" and
                    arm["native_dispatch_count"]==1 and sha(row["pre_environment"])==arm["pre_state_sha256"],"PARTIAL_NATIVE_ARM_CHANGED")
            candidate=next(j["payload"]["candidate_to_dispatch"] for j in arm["journal"] if j["event"]=="RCC_REVIEW")
            require(candidate["name"]=="update_scheduled_transaction" and sha(candidate)==arm["candidate_sha256"],"PARTIAL_CAPTURE_CHANGED")
            suite=get_suite("v1.2.2","banking");env=suite.environment_type.model_validate(copy.deepcopy(row["pre_environment"]))
            tool=next(t for t in suite.tools if t.name==candidate["name"])
            value=FunctionsRuntime([tool]).run_function(env,candidate["name"],candidate["arguments"],raise_on_error=True)
            require(jsonable(value)==arm["native_return"] and env.model_dump(mode="json")==arm["post_environment"] and
                    sha(arm["post_environment"])==arm["post_state_sha256"],"TERMINATED_NATIVE_TRANSITION_CHANGED")
            native_transitions+=1
    require(native_transitions==9,"PARTIAL_NATIVE_TRANSITION_COUNT_CHANGED")
    return {"terminal_transport_observations":15,"completed_native_transitions_recomputed":native_transitions}

def main():
    p=argparse.ArgumentParser()
    for n in ("agentdojo","rcc","veritas"):p.add_argument("--"+n+"-root",type=Path,required=True)
    for n in ("replay-artifact","v13-artifact","output-dir"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args()
    for k in ("OPENAI_API_KEY","VERITAS_DATABASE_URL"):require(not os.environ.get(k),k+"_MUST_BE_EMPTY")
    require(blob(CONTRACT)==EXPECTED_CONTRACT,"CONTRACT_PIN_MISMATCH");c=json.loads(CONTRACT.read_text())
    for path,pin in c["source_blobs"].items():require(blob(ROOT/path)==pin,"SOURCE_PIN_MISMATCH:"+path)
    roots={n:getattr(a,n+"_root").resolve() for n in ("agentdojo","rcc","veritas")}
    for n,pin in c["external_pins"].items():
        require(git(roots[n],"rev-parse","HEAD")==pin["commit"] and not git(roots[n],"status","--porcelain"),"EXTERNAL_CHECKOUT_PIN_OR_DIRT:"+n)
        for path,h in pin["source_blobs"].items():require(blob(roots[n]/path)==h,"EXTERNAL_SOURCE_CHANGED:"+path)
    for n,v in c["dependencies"].items():require(importlib.metadata.version(n)==v,"DEPENDENCY_CHANGED:"+n)
    sys.path.insert(0,str(roots["rcc"]/"external-eval/v0.3.9/src"))
    import agentdojo.functions_runtime as runtime
    import agentdojo.task_suite.load_suites
    import agentdojo.default_suites.v1.tools.banking_client as banking
    import rveval.integrations.agentdojo as rcc_runtime
    import veritas_os.benchmarks.agentdojo_banking_adapter as adapter
    import veritas_os.policy.bind_core.core as bind
    for module,n in ((runtime,"agentdojo"),(banking,"agentdojo"),(rcc_runtime,"rcc"),(adapter,"veritas"),(bind,"veritas")):
        require(Path(module.__file__).resolve().is_relative_to(roots[n]),"NATIVE_IMPORT_SHADOWED:"+n)
    out=a.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ);env.update(OPENAI_API_KEY="",VERITAS_DATABASE_URL="",PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    command=[sys.executable,"scripts/task15_prospective_controlled_standing_order_trajectory_audit_v1.py"]
    for n in ("agentdojo","rcc","veritas","replay-artifact","v13-artifact"):
        attr=n.replace("-","_")+("_root" if n in roots else "")
        command.extend(["--"+n+("-root" if n in roots else ""),str(getattr(a,attr).resolve())])
    command.extend(["--output-dir",str(out)])
    prior=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True)
    require(prior.returncode==0,"PRIOR_TRAJECTORY_FAILED:"+prior.stderr+prior.stdout[-1500:])
    print(prior.stdout,end="");(out/"task15-prospective-controlled-standing-order-trajectory-v1.log").write_text(prior.stdout)
    raw=(out/"task15-prospective-controlled-standing-order-trajectory-v1.json").read_bytes()
    require(hashlib.sha256(raw).hexdigest()==c["prior_trajectory_report_sha256"],"PRIOR_RUNNER_REPORT_CHANGED")
    source=a.agentdojo_root/c["native_codec_source"]["path"]
    require(blob(source)==c["native_codec_source"]["blob"],"NATIVE_CODEC_PIN_MISMATCH")
    import agentdojo.task_suite.load_suites
    from agentdojo.agent_pipeline.llms import openai_llm as codec
    require(Path(codec.__file__).resolve()==source.resolve(),"LOADED_NATIVE_CODEC_CHANGED")
    evidence,refusals,terminations,parallel,junit=[out/(NAME+s) for s in (".native.json",".refusals.jsonl",".terminations.jsonl",".parallel.json",".junit.xml")]
    for path in (evidence,refusals,terminations,parallel,junit,out/(NAME+".json")):path.unlink(missing_ok=True)
    env.update(TASK15_CONTROLLED_RENT_PROOF="1",TASK15_STANDING_ORDER_TRAJECTORY_PROOF="1",TASK15_STANDING_ORDER_WIRE_PROOF="1",
        TASK15_RCC_ROOT=str(roots["rcc"]),TASK15_RENT_WIRE_EVIDENCE=str(evidence),TASK15_RENT_WIRE_REFUSALS=str(refusals),
        TASK15_RENT_WIRE_TERMINATIONS=str(terminations),TASK15_RENT_WIRE_PARALLEL=str(parallel))
    run=subprocess.run([sys.executable,"-m","pytest","-q","-o","addopts=","tests/test_task15_frozen_openai_wire_controlled_standing_order_adapter_v1.py","--junitxml",str(junit)],cwd=ROOT,env=env,capture_output=True,text=True)
    print(run.stdout,end="");require(run.returncode==0,"WIRE_TESTS_FAILED:"+run.stderr)
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==c["offline_proof"]["wire_tests"] and not any(x.find(t)is not None for x in cases for t in ("failure","error","skipped")),"WIRE_TESTS_INCOMPLETE")
    identity=audit_wire(restore(json.loads(evidence.read_text())),positive=True,contract=c,codec=codec,rcc_root=roots["rcc"])
    negatives=[json.loads(x) for x in refusals.read_text().splitlines()];require(len(negatives)==8,"REFUSAL_PAIR_POPULATION_CHANGED")
    negative_ids=[audit_wire(restore(row),positive=False,contract=c,codec=codec,rcc_root=roots["rcc"]) for row in negatives]
    terminal_counts=audit_terminal_transports([json.loads(x) for x in terminations.read_text().splitlines()],contract=c)
    require(json.loads(parallel.read_text())=={"attempts":32,"completed":1,"rejected":31,"requests":5,"protected_proposals":1,"native_dispatches":2},"PARALLEL_WIRE_TRAJECTORY_SINGLE_WINNER_FAILED")
    report={"rule_of_one":c["rule_of_one"],"determination":"BOUNDED_FAKE_WIRE_NATIVE_RENT_ADAPTER_PASS",
        "wire_tests":len(cases),"failures":0,"skipped":0,"prior_trajectory_tests":75,"prior_dedicated_tests":696,
        "positive_identity":identity,"positive_pairs":1,"positive_native_dispatch_a":1,"positive_native_dispatch_b":1,
        "ineligible_pairs_retained":8,"negative_identities":negative_ids,"ineligible_native_dispatch_a":8,"ineligible_native_dispatch_b":0,
        "fake_requests_per_pair":5,"protected_proposals_per_pair":1,"actual_native_codec_request_result_history_linkage":True,
        "registered_rent_profile_before_first_wire_query":True,"actual_native_tool_schemas_preserved":True,
        "same_candidate_and_prestate":True,"original_request_all_predicates_preserved":True,
        "own_native_results_errors_on_wire":True,"decoded_response_next_history_linkage_required":True,
        "wire_closed_after_downstream_failure":True,"unsupported_later_tools_dispatched":0,
        **terminal_counts,"parallel_attempts":32,"parallel_completed":1,"parallel_rejected":31,
        "profile_itself_execution_permission":False,"earlier_address_execution_proven":False,"refund_authority_proven":False,
        "full_task15_admissible":False,"full_final128_trajectory_integrated":False,"real_provider_generation_ordering_proven":False,
        "real_user_or_external_prestate_authentication_proven":False,"durable_global_single_execution_proven":False,
        "historical_profiles_issued":0,"historical_candidates_recovered":0,"safe_to_relax_existing_runner_now":0,
        "provider_execution":0,"provider_client_constructed":0,"database_access":0,"scorer_or_gold_derived_authority":0,
        "candidate_repair":0,"external_effect":0,"v13_authorization_reuse":0,"v13_human_confirmation_reuse":0,
        "utility_scored":False,"utility_recovery_proven":False,"injection_success_remeasured":False,
        "independent_external_validation":False,"held_out_validation":False,"production_readiness":False,
        "prior_trajectory_report_sha256":hashlib.sha256(raw).hexdigest(),"next_rule_of_one":c["next_rule_of_one"]}
    (out/(NAME+".json")).write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print("PASS_TASK15_FROZEN_OPENAI_WIRE_CONTROLLED_STANDING_ORDER_ADAPTER_V1")
    print("wire_tests="+str(len(cases))+" failures=0 skipped=0 prior_dedicated_tests=696")
    print("positive_pairs=1 native_dispatch_a=1 native_dispatch_b=1 fake_requests_per_pair=5 protected_proposals_per_pair=1")
    print("ineligible_pairs=8 ineligible_native_dispatch_a=8 ineligible_native_dispatch_b=0 actual_own_native_codec_history=true")
    print("terminal_transport_observations=15 completed_native_transitions_recomputed=9 automatic_retry=0 downstream_wire_closed=true")
    print("parallel_attempts=32 completed=1 rejected=31 requests=5 native_dispatches=2")
    print("provider_execution=0 provider_client_constructed=0 scorer_or_gold_authority=0 candidate_repair=0 v13_reuse=0 utility_recovery_proven=false")
    print("next_rule_of_one="+c["next_rule_of_one"])
    return 0
if __name__=="__main__":raise SystemExit(main())
