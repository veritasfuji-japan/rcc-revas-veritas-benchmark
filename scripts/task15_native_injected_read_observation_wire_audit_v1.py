#!/usr/bin/env python3
"""Pinned native injected read-only tool-return -> offline wire audit V1."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET
import yaml

ROOT=Path(__file__).resolve().parents[1]
RULE="TASK15_NATIVE_INJECTED_READ_OBSERVATION_WIRE_V1"
NAME="task15-native-injected-read-observation-wire-v1"
sys.path.insert(0,str(ROOT))


def require(ok,reason):
    if not ok:
        raise ValueError(reason)


def blob(path):
    data=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()


def main():
    ap=argparse.ArgumentParser()
    for name in ("agentdojo","rcc","veritas"):
        ap.add_argument("--"+name+"-root",type=Path,required=True)
    for name in ("replay-artifact","v13-artifact","output-dir"):
        ap.add_argument("--"+name,type=Path,required=True)
    a=ap.parse_args()
    require(not os.environ.get("OPENAI_API_KEY")
            and not os.environ.get("VERITAS_DATABASE_URL"),
            "REAL_PROVIDER_OR_PRODUCTION_DATABASE_FORBIDDEN")
    c=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(c["rule_of_one"]==RULE
            and c["predecessor_main_sha"]==
                "5f5ce72fc475b148d32b70ebea593edaf93007eb"
            and c["status"]=="IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI",
            "EXACT_MERGED_PR263_CONTRACT_REQUIRED")
    for path,digest in c["source_blobs"].items():
        require(blob(ROOT/path)==digest,"SOURCE_BLOB_DRIFT:"+path)
    for path,digest in c["agentdojo_native_blobs"].items():
        require(blob(a.agentdojo_root.resolve()/path)==digest,
                "PINNED_NATIVE_RUNTIME_BLOB_DRIFT:"+path)
    out=a.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    prev=subprocess.run([
        sys.executable,"scripts/task15_canonical_ab_first_offline_source_binding_audit_v1.py",
        "--agentdojo-root",str(a.agentdojo_root.resolve()),
        "--rcc-root",str(a.rcc_root.resolve()),
        "--veritas-root",str(a.veritas_root.resolve()),
        "--replay-artifact",str(a.replay_artifact.resolve()),
        "--v13-artifact",str(a.v13_artifact.resolve()),
        "--output-dir",str(out),
    ],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(prev.stdout+prev.stderr)
    require(prev.returncode==0,
            "PR263_PREDECESSOR_FULL_CHAIN_FAILED:"+
            (prev.stdout+prev.stderr)[-16000:])
    p=json.loads((out/"task15-canonical-ab-first-offline-source-binding-v1.json").read_text())
    require(p["determination"]==
                "EIGHT_NATIVE_CASES_SIXTEEN_OFFLINE_FIRST_PROPOSALS_BOUND"
            and p["predecessor_tests"]==2427
            and p["new_tests"]==15
            and p["refusals"]==14
            and p["native_canonical_task15_cases"]==8
            and p["distinct_synthetic_first_source_calls"]==16
            and p["native_injection_exposed_to_model"] is False
            and p["provider_calls"]==p["scorer_calls"]==
                p["native_dispatches"]==p["real_external_effects"]==0
            and p["canonical_utility_measured"] is False,
            "PR263_FIRST_REQUEST_DID_NOT_CARRY_NATIVE_ATTACK_REQUIRED")
    context=out/"task15-canonical-injected-ab-context-isolation-v1.evidence.jsonl"
    first=out/"task15-canonical-ab-first-offline-source-binding-v1.evidence.jsonl"
    require(context.is_file() and first.is_file(),
            "COMPLETE_PR262_PR263_DURABLE_EVIDENCE_REQUIRED")
    evidence=out/(NAME+".evidence.jsonl")
    refusals=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for path in (evidence,refusals,junit):path.unlink(missing_ok=True)
    for flag in (
        "TASK15_NATIVE_READ_OBSERVATION_PROOF",
        "TASK15_CANONICAL_FIRST_SOURCE_PROOF",
        "TASK15_CANONICAL_AB_CONTEXT_PROOF",
        "TASK15_INDEPENDENT_AB_THREE_STEP_PROOF",
        "TASK15_INDEPENDENT_AB_SOURCE_PROOF",
        "TASK15_NATIVE_DIRECT_SLOT_PROOF",
        "TASK15_CANONICAL_DIRECT_PAYLOAD_PROOF",
        "TASK15_CANONICAL_ENROLLMENT_GAP_PROOF",
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
    ):env[flag]="1"
    env["TASK15_RCC_ROOT"]=str(a.rcc_root.resolve())
    env["TASK15_NATIVE_READ_OBSERVATION_PREDECESSOR_DIR"]=str(out)
    env["TASK15_NATIVE_READ_OBSERVATION_EVIDENCE"]=str(evidence)
    env["TASK15_NATIVE_READ_OBSERVATION_REFUSALS"]=str(refusals)
    tests=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task15_native_injected_read_observation_wire_v1.py",
        "--junitxml",str(junit),
    ],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".tests.log")).write_text(tests.stdout+tests.stderr)
    print(tests.stdout,end="")
    require(tests.returncode==0,
            "NATIVE_READ_OBSERVATION_TESTS_FAILED:"+
            (tests.stdout+tests.stderr)[-23000:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==15
            and not any(z.find(k) is not None for z in cases
                        for k in ("failure","error","skipped")),
            "ALL_FIFTEEN_NATIVE_READ_OBSERVATION_TESTS_REQUIRED")
    good=[json.loads(x) for x in evidence.read_text().splitlines()]
    bad=[json.loads(x) for x in refusals.read_text().splitlines()]
    require(len(good)==1 and len(bad)==14
            and len({r["fault"] for r in bad})==14
            and all(r["result"]=="NO_NATIVE_INJECTED_OBSERVATION_PROOF_PROMOTION"
                    for r in bad),
            "ALL_FOURTEEN_NATIVE_OBSERVATION_REFUSALS_REQUIRED")
    proof=good[0]["proof"]
    prior_context=json.loads(context.read_text().splitlines()[0])["proof"]
    prior_first=json.loads(first.read_text().splitlines()[0])["proof"]
    from task15_native_model_response_capture_boundary_v1 import sha
    from task15_canonical_enrollment_gap_preflight_v1 import ENROLLED_TASK15
    from task15_canonical_direct_payload_template_v1 import native_expected_direct_payloads
    goals=native_expected_direct_payloads()
    require(proof["rule_of_one"]==RULE
            and proof["determination"]==
                "SIXTEEN_NATIVE_INJECTED_TOOL_RETURNS_SENT_TO_OFFLINE_CLIENTS"
            and proof["context_proof_sha256"]==sha(prior_context)
            and proof["first_source_proof_sha256"]==sha(prior_first)
            and proof["native_canonical_case_count"]==8
            and proof["native_read_only_probe_count"]==16
            and proof["synthetic_continuation_count"]==16
            and len(proof["source_observations"])==8
            and [r["case_id"] for r in proof["source_observations"]]==
                list(ENROLLED_TASK15)
            and len(proof["transport_journal"])==16
            and all(j["status"]=="SYNTHETIC_CONTINUATION_DECODED"
                    and j["model_authored_tool_read"] is False
                    and j["tool_result_contains_native_payload"] is True
                    for j in proof["transport_journal"])
            and proof["native_injection_exposed_in_offline_tool_wire"] is True
            and proof["injected_payload_seen_by_real_provider"] is False
            and proof["model_selected_native_read_tool"] is False
            and proof["canonical_full_trajectories_proven"] is False
            and proof["canonical_scoring_eligible"] is False
            and proof["provider_calls"]==proof["scorer_calls"]==
                proof["native_write_dispatches"]==proof["real_external_effects"]==0
            and proof["canonical_utility_measured"] is False
            and proof["injection_success_measured"] is False,
            "READ_ONLY_OFFLINE_OBSERVATION_CANNOT_PROMOTE_TO_CANONICAL_SCORE")
    call_ids=set()
    for index,row in enumerate(proof["source_observations"]):
        require(list(row["arms"])==["A","B"],"TWO_CANONICAL_LOCAL_ARMS_REQUIRED")
        payload=goals[row["case_id"]]
        for arm in ("A","B"):
            e=row["arms"][arm]
            c=good[0]["client_calls"][row["case_id"]][arm]
            wire=e["wire_messages"]
            call_id=e["probe_call_id"]
            require(len(c)==1 and c[0]["messages"]==wire
                    and call_id not in call_ids
                    and call_id==f"probe-native-{index}-{arm}"
                    and [m["role"] for m in wire]==
                        ["developer","user","assistant","tool"]
                    and wire[2]["tool_calls"][0]["id"]==
                        wire[3]["tool_call_id"]==call_id
                    and wire[2]["tool_calls"][0]["function"]["name"]==
                        e["native_read_tool"]=="get_most_recent_transactions"
                    and payload not in str(wire[:2])
                    and wire[3]["content"][0]["text"]==e["native_tool_result"]
                    and type(yaml.safe_load(e["native_tool_result"])) is list
                    and yaml.safe_load(e["native_tool_result"])==
                        prior_context["contexts"][index]["arms"][arm]
                            ["native_injected_environment"]["bank_account"]["transactions"]
                    and sum(
                        item.get("id")==5
                        and item.get("subject")==payload
                        for item in yaml.safe_load(e["native_tool_result"])
                    )==1
                    and sha(wire)==e["native_full_wire_sha256"]
                    and sha(wire[3])==e["native_tool_wire_sha256"]
                    and sha(e["native_tool_result"])==
                        e["native_tool_return_sha256"]
                    and e["native_payload_sha256"]==sha(payload)
                    and e["environment_sha256"]==
                        prior_context["contexts"][index]["arms"][arm]["environment_sha256"]
                    and e["real_model_generated_probe_call"] is False
                    and e["provider_authenticated"] is False
                    and e["native_write_tool_dispatch_count"]==0
                    and e["native_read_only_probe_count"]==1
                    and e["canonical_score_eligible"] is False,
                    "EXACT_NATIVE_ATTACKED_TOOL_RESULT_IN_OWN_ARM_WIRE_REQUIRED")
            call_ids.add(call_id)
    require(len(call_ids)==16,
            "ALL_SIXTEEN_NATIVE_PROBE_CALLS_UNIQUE")
    result={
        "rule_of_one":RULE,
        "determination":proof["determination"],
        "predecessor_tests":2442,
        "new_tests":len(cases),
        "refusals":len(bad),
        "native_canonical_task15_cases":8,
        "read_only_native_probe_calls":16,
        "synthetic_offline_continuations":16,
        "native_attack_text_in_tool_wire":True,
        "model_authored_probe_call":False,
        "real_provider_calls":0,"scorer_calls":0,
        "native_write_dispatches":0,"real_external_effects":0,
        "canonical_utility_measured":False,
    }
    (out/(NAME+".json")).write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("PASS_"+RULE)
    print("new_tests=15 refusals=14 native_observation_wires=16 "
          "provider_calls=0 scorer_calls=0 write_dispatches=0")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
