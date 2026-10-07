#!/usr/bin/env python3
"""Reproduce #219, independently link actual native evidence to frozen fake wire."""
from __future__ import annotations
import argparse
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
from scripts.task15_prospective_controlled_address_trajectory_audit_v1 import blob,require,audit_pair
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable
from scripts.agentdojo_openai_frozen_adapter_v0_1 import MODEL_ID
from task15_native_address_request_profile_issuance_v1 import sha
NAME="task15-frozen-openai-wire-controlled-address-adapter-v1"
CONTRACT=ROOT/"contracts/TASK15_FROZEN_OPENAI_WIRE_CONTROLLED_ADDRESS_ADAPTER_V1.json"
EXPECTED_CONTRACT="04e43a9f9a1089c573d3f4d37f1ba85ff2190471"

def audit_wire(row, *, positive, contract, codec):
    result,requests,journal=row["result"],row["requests"],row["transport_journal"]
    identity=audit_pair(jsonable(result),positive=positive,contract=contract)
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
        require(j["status"]=="RESPONSE_DECODED" and j["wire_messages"]==q["messages"] and
                j["wire_request_sha256"]==sha({"messages":q["messages"],"tools":q["tools"]}) and
                j["native_tools_sha256"]==sha(q["tools"]),"WIRE_JOURNAL_HASH_MISMATCH")
        response=native[2] if index==0 else native[4] if index==1 else native[6] if index==2 else result["arms"][index-3]["messages"][-1]
        require(j["response_sha256"]==sha(jsonable(response)),"WIRE_RESPONSE_TO_NATIVE_CANDIDATE_LINKAGE_CHANGED")
    raw=requests[3]["messages"][-2]["tool_calls"][0]
    wire_arguments=json.loads(raw["function"]["arguments"])
    normalized={k:None for k in ("first_name","last_name","street","city")}
    normalized.update(wire_arguments)
    require(normalized==result["candidate"]["arguments"] and raw["function"]["name"]=="update_user_info","WIRE_PROPOSAL_REPAIRED")
    for q,arm in zip(requests[3:],result["arms"]):
        require(q["messages"][-1]["tool_call_id"]==raw["id"]=="wire-address-2","WIRE_TOOL_RETURN_ID_CHANGED")
        if arm["native_dispatch_count"]==0:
            require(type(q["messages"][-1]["content"]) is str and q["messages"][-1]["content"].startswith("AddressProfileViolation:"),"ACTUAL_REFUSAL_NOT_ON_WIRE")
    return {**identity,"wire_request_sha256s":[x["wire_request_sha256"] for x in journal],
            "owned_messages_sha256":journal[0]["owned_messages_sha256"],"native_tools_sha256":journal[0]["native_tools_sha256"]}

def main():
    p=argparse.ArgumentParser()
    for n in ("agentdojo","rcc","veritas"):p.add_argument("--"+n+"-root",type=Path,required=True)
    for n in ("replay-artifact","v13-artifact","output-dir"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args()
    for key in ("OPENAI_API_KEY","VERITAS_DATABASE_URL"):require(not os.environ.get(key),key+"_MUST_BE_EMPTY")
    require(blob(CONTRACT)==EXPECTED_CONTRACT,"CONTRACT_PIN_MISMATCH")
    c=json.loads(CONTRACT.read_text())
    for path,pin in c["source_blobs"].items():require(blob(ROOT/path)==pin,"SOURCE_PIN_MISMATCH:"+path)
    source=a.agentdojo_root/c["native_codec_source"]["path"]
    require(blob(source)==c["native_codec_source"]["blob"],"NATIVE_CODEC_PIN_MISMATCH")
    out=a.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ);env.update(OPENAI_API_KEY="",VERITAS_DATABASE_URL="",PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    command=[sys.executable,"scripts/task15_prospective_controlled_address_trajectory_audit_v1.py"]
    for n in ("agentdojo","rcc","veritas","replay-artifact","v13-artifact"):
        attr=n.replace("-","_")+("_root" if n in ("agentdojo","rcc","veritas") else "")
        command.extend(["--"+n+("-root" if n in ("agentdojo","rcc","veritas") else ""),str(getattr(a,attr).resolve())])
    command.extend(["--output-dir",str(out)])
    prior=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True)
    require(prior.returncode==0,"PRIOR_TRAJECTORY_FAILED:"+prior.stderr+prior.stdout[-2000:])
    print(prior.stdout,end="");(out/"task15-prospective-controlled-address-trajectory-v1.log").write_text(prior.stdout)
    raw=(out/"task15-prospective-controlled-address-trajectory-v1.json").read_bytes()
    require(hashlib.sha256(raw).hexdigest()==c["prior_trajectory_report_sha256"],"PRIOR_REPORT_CHANGED")
    evidence,refusals,junit=[out/(NAME+s) for s in (".native.json",".refusals.jsonl",".junit.xml")]
    for path in (evidence,refusals,junit,out/(NAME+".json")):path.unlink(missing_ok=True)
    env.update(TASK15_NATIVE_ADDRESS_PROOF="1",TASK15_ADDRESS_TRAJECTORY_PROOF="1",TASK15_ADDRESS_WIRE_PROOF="1",
               TASK15_RCC_ROOT=str(a.rcc_root.resolve()),TASK15_WIRE_EVIDENCE=str(evidence),TASK15_WIRE_REFUSALS=str(refusals))
    run=subprocess.run([sys.executable,"-m","pytest","-q","-o","addopts=","tests/test_task15_frozen_openai_wire_controlled_address_adapter_v1.py","--junitxml",str(junit)],cwd=ROOT,env=env,capture_output=True,text=True)
    print(run.stdout,end="");require(run.returncode==0,"WIRE_TESTS_FAILED:"+run.stderr)
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==32 and not any(x.find(t)is not None for x in cases for t in ("failure","error","skipped")),"WIRE_TESTS_INCOMPLETE")
    # Parent verified exact installed runtime sources; import that actual codec.
    import agentdojo.task_suite.load_suites
    from agentdojo.agent_pipeline.llms import openai_llm as codec
    require(Path(codec.__file__).resolve()==source.resolve(),"LOADED_CODEC_SOURCE_CHANGED")
    # Evidence uses native FunctionCall objects serialized as dictionaries.
    from agentdojo.functions_runtime import FunctionCall
    def restore(row):
        for arm in row["result"]["arms"]:
            for m in arm["messages"]:
                if m.get("tool_calls"):
                    m["tool_calls"]=[FunctionCall(**x) for x in m["tool_calls"]]
                if m.get("tool_call"):m["tool_call"]=FunctionCall(**m["tool_call"])
        return row
    positive=json.loads(evidence.read_text());negatives=[json.loads(x) for x in refusals.read_text().splitlines()]
    require(len(negatives)==6,"NEGATIVE_POPULATION_CHANGED")
    identity=audit_wire(restore(positive),positive=True,contract=c,codec=codec)
    negative_ids=[audit_wire(restore(row),positive=False,contract=c,codec=codec) for row in negatives]
    report={"rule_of_one":c["rule_of_one"],"determination":"BOUNDED_FAKE_WIRE_NATIVE_ADDRESS_ADAPTER_PASS","wire_tests":len(cases),
        "prior_trajectory_tests":40,"prior_native_runner_tests":65,"prior_profile_tests":101,"prior_mapping_tests":91,
        "failures":0,"skipped":0,"positive_pairs":1,"positive_dispatch_a":1,"positive_dispatch_b":1,"positive_identity":identity,
        "ineligible_pairs_retained":6,"ineligible_dispatch_a":6,"ineligible_dispatch_b":0,"negative_identities":negative_ids,
        "recording_fake_requests_per_pair":5,"same_candidate_and_immediate_state":True,"actual_native_codec_history_linkage":True,
        "owned_request_profile_before_first_wire_query":True,"native_schema_preserved":True,"provider_execution":0,
        "provider_client_constructed":0,"database_access_in_dedicated_proof":0,"scorer_or_gold_derived_authority":0,"candidate_repair":0,
        "v13_authorization_reuse":0,"v13_human_confirmation_reuse":0,"utility_scored":False,"utility_recovery_proven":False,
        "injection_success_remeasured":False,"historical_candidates_recovered":0,"full_task15_admissible":False,
        "real_provider_generation_ordering_proven":False,"full_final128_trajectory_integrated":False,"independent_external_validation":False,
        "held_out_validation":False,"production_readiness":False,"safe_to_relax_existing_runner_now":0,
        "prior_trajectory_report_sha256":hashlib.sha256(raw).hexdigest(),"next_rule_of_one":c["next_rule_of_one"]}
    (out/(NAME+".json")).write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("PASS_TASK15_FROZEN_OPENAI_WIRE_CONTROLLED_ADDRESS_ADAPTER_V1")
    print("wire_tests=32 prior_trajectory_tests=40 prior_native_runner_tests=65 failures=0 skipped=0")
    print("positive_pairs=1 ineligible_pairs_retained=6 actual_native_wire_history_linkage=true")
    print("provider_execution=0 provider_client_constructed=0 scorer_or_gold_authority=0 candidate_repair=0 v13_reuse=0")
    print("next_rule_of_one="+c["next_rule_of_one"])
    return 0
if __name__=="__main__":raise SystemExit(main())
