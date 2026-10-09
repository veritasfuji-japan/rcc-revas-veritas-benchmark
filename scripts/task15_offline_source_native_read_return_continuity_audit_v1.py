#!/usr/bin/env python3
"""Exact-HEAD native source-captured READ -> real return -> synthetic replay audit."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
RULE="TASK15_OFFLINE_SOURCE_NATIVE_READ_RETURN_CONTINUITY_V1"
NAME="task15-offline-source-native-read-return-continuity-v1"
sys.path.insert(0,str(ROOT))


def require(ok,reason):
    if not ok:
        raise ValueError(reason)


def blob(path):
    data=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()


def main():
    parser=argparse.ArgumentParser()
    for x in ("agentdojo","rcc","veritas"):
        parser.add_argument("--"+x+"-root",type=Path,required=True)
    for x in ("replay-artifact","v13-artifact","output-dir"):
        parser.add_argument("--"+x,type=Path,required=True)
    a=parser.parse_args()
    require(not os.environ.get("OPENAI_API_KEY")
            and not os.environ.get("VERITAS_DATABASE_URL"),
            "REAL_PROVIDER_OR_PRODUCTION_DB_NOT_ALLOWED")
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE
            and contract["predecessor_main_sha"]==
                "639d495fefc3ee6f026b2ee5cd8634635cdccaf7"
            and contract["status"]==
                "IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI",
            "EXACT_MERGED_PR264_FROZEN_CONTRACT_REQUIRED")
    for path,digest in contract["source_blobs"].items():
        require(blob(ROOT/path)==digest,"SOURCE_BLOB_DRIFT:"+path)
    for path,digest in contract["agentdojo_native_blobs"].items():
        require(blob(a.agentdojo_root.resolve()/path)==digest,
                "NATIVE_SOURCE_BLOB_DRIFT:"+path)
    out=a.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    previous=subprocess.run([
        sys.executable,"scripts/task15_native_injected_read_observation_wire_audit_v1.py",
        "--agentdojo-root",str(a.agentdojo_root.resolve()),
        "--rcc-root",str(a.rcc_root.resolve()),
        "--veritas-root",str(a.veritas_root.resolve()),
        "--replay-artifact",str(a.replay_artifact.resolve()),
        "--v13-artifact",str(a.v13_artifact.resolve()),
        "--output-dir",str(out),
    ],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(
        previous.stdout+previous.stderr)
    require(previous.returncode==0,
            "PR264_FULL_PREDECESSOR_PROOF_FAILED:"+
            (previous.stdout+previous.stderr)[-18000:])
    old=json.loads((out/"task15-native-injected-read-observation-wire-v1.json").read_text())
    require(old["determination"]==
                "SIXTEEN_NATIVE_INJECTED_TOOL_RETURNS_SENT_TO_OFFLINE_CLIENTS"
            and old["predecessor_tests"]==2442
            and old["new_tests"]==15
            and old["refusals"]==14
            and old["native_canonical_task15_cases"]==8
            and old["read_only_native_probe_calls"]==16
            and old["synthetic_offline_continuations"]==16
            and old["native_attack_text_in_tool_wire"] is True
            and old["model_authored_probe_call"] is False
            and old["real_provider_calls"]==old["scorer_calls"]==
                old["native_write_dispatches"]==
                old["real_external_effects"]==0
            and old["canonical_utility_measured"] is False,
            "ONLY_HARNESS_AUTHORED_PR264_READ_BOUNDARY_ACCEPTED")
    files={}
    for key,prefix in (
        ("contexts","task15-canonical-injected-ab-context-isolation-v1"),
        ("first","task15-canonical-ab-first-offline-source-binding-v1"),
        ("previous","task15-native-injected-read-observation-wire-v1"),
    ):
        file=out/(prefix+".evidence.jsonl")
        require(file.is_file(),"ALL_IMMUTABLE_PREDECESSOR_JSONL_REQUIRED:"+key)
        files[key]=json.loads(file.read_text().splitlines()[0])["proof"]
    evidence=out/(NAME+".evidence.jsonl")
    refusals=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for path in (evidence,refusals,junit):
        path.unlink(missing_ok=True)
    for flag in (
        "TASK15_OFFLINE_READ_CONTINUITY_PROOF",
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
    ):
        env[flag]="1"
    env["TASK15_RCC_ROOT"]=str(a.rcc_root.resolve())
    env["TASK15_OFFLINE_READ_CONTINUITY_PREDECESSOR_DIR"]=str(out)
    env["TASK15_OFFLINE_READ_CONTINUITY_EVIDENCE"]=str(evidence)
    env["TASK15_OFFLINE_READ_CONTINUITY_REFUSALS"]=str(refusals)
    tests=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task15_offline_source_native_read_return_continuity_v1.py",
        "--junitxml",str(junit),
    ],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".tests.log")).write_text(tests.stdout+tests.stderr)
    print(tests.stdout,end="")
    require(tests.returncode==0,
            "NEW_NATIVE_READ_SOURCE_CONTINUITY_TESTS_FAILED:"+
            (tests.stdout+tests.stderr)[-24000:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==15
            and not any(t.find(s) is not None for t in cases
                        for s in ("failure","error","skipped")),
            "EXACT_FIFTEEN_NEW_TESTS_AND_NO_SKIPS_REQUIRED")
    positive=[json.loads(line) for line in evidence.read_text().splitlines()]
    negative=[json.loads(line) for line in refusals.read_text().splitlines()]
    require(len(positive)==1 and len(negative)==14
            and len({r["fault"] for r in negative})==14
            and all(x["result"]==
                "NO_SOURCE_READ_RETURN_CONTINUITY_PROMOTION" for x in negative),
            "ALL_FOURTEEN_DISTINCT_UNPROMOTED_READ_FAULTS_REQUIRED")
    proof=positive[0]["proof"]
    from task15_native_model_response_capture_boundary_v1 import sha
    from task15_canonical_enrollment_gap_preflight_v1 import ENROLLED_TASK15
    from task15_canonical_direct_payload_template_v1 import native_expected_direct_payloads
    import yaml
    payloads=native_expected_direct_payloads()
    require(proof["rule_of_one"]==RULE
            and proof["determination"]==
                "SIXTEEN_SYNTHETIC_SOURCE_TO_NATIVE_READ_RETURNS_CONTINUOUS"
            and proof["context_proof_sha256"]==sha(files["contexts"])
            and proof["first_source_proof_sha256"]==sha(files["first"])
            and proof["prior_probe_proof_sha256"]==sha(files["previous"])
            and proof["canonical_task15_case_count"]==8
            and proof["separate_synthetic_source_clients"]==16
            and proof["source_proposal_count"]==proof["native_read_only_return_count"]==
                proof["offline_continuation_count"]==16
            and len(proof["source_returns"])==8
            and [r["case_id"] for r in proof["source_returns"]]==
                list(ENROLLED_TASK15)
            and len(proof["source_journal"])==16
            and all(x["status"]==
                "SYNTHETIC_SOURCE_READ_RETURN_CONTINUITY_CAPTURED"
                for x in proof["source_journal"])
            and proof["real_model_selected_read_count"]==
                proof["real_provider_calls"]==proof["scorer_calls"]==
                proof["native_write_dispatches"]==
                proof["real_external_effects"]==0
            and proof["full_canonical_trajectories_proven"] is False
            and proof["native_scorer_eligible"] is False
            and proof["final128_utility_measured"] is False
            and proof["injection_success_measured"] is False,
            "SYNTHETIC_READ_CONTINUITY_CANNOT_BE_REAL_MODEL_OR_CANONICAL_SCORE")
    seen=set()
    for index,row in enumerate(proof["source_returns"]):
        case=row["case_id"]
        require(list(row["arms"])==["A","B"],"TWO_ARMS_REQUIRED")
        for arm in ("A","B"):
            rec=row["arms"][arm]
            calls=positive[0]["client_calls"][case][arm]
            wire=rec["wire_messages"]
            call_id=rec["source_model_call_id"]
            ctx=files["contexts"]["contexts"][index]["arms"][arm]
            old=files["previous"]["source_observations"][index]["arms"][arm]
            parsed=yaml.safe_load(rec["native_tool_result"])
            require(len(calls)==2 and calls[1]["messages"]==wire
                    and call_id not in seen
                    and call_id==f"offline-source-read-{index}-{arm}"
                    and rec["case_id"]==case and rec["logical_arm"]==arm
                    and rec["initial_environment_sha256"]==ctx["environment_sha256"]
                    and rec["native_payload_sha256"]==sha(payloads[case])
                    and [x["role"] for x in wire]==
                        ["developer","user","assistant","tool"]
                    and calls[0]["messages"]==wire[:2]
                    and calls[1]["tools"]==[]
                    and sha({"messages":calls[0]["messages"],"tools":calls[0]["tools"]})==
                        rec["source_first_request_sha256"]
                    and wire[2]["tool_calls"][0]["id"]==
                        wire[3]["tool_call_id"]==call_id
                    and wire[2]["tool_calls"][0]["function"]["name"]==
                        rec["native_read_tool_name"]=="get_most_recent_transactions"
                    and wire[3]["content"][0]["text"]==rec["native_tool_result"]
                    and sha(rec["native_tool_result"])==
                        rec["native_tool_return_sha256"]==
                        old["native_tool_return_sha256"]
                    and sha(wire[3])==rec["native_tool_wire_sha256"]
                    and sha(wire)==rec["continuation_wire_sha256"]
                    and parsed==ctx["native_injected_environment"]["bank_account"]["transactions"]
                    and sum(x.get("id")==5 and
                            x.get("subject")==payloads[case]
                            for x in parsed)==1
                    and payloads[case] not in str(wire[:2])
                    and rec["read_tool_selected_by_offline_synthetic_client"] is True
                    and rec["read_tool_selected_by_authenticated_model"] is False
                    and rec["native_read_only_dispatches"]==1
                    and rec["governed_write_dispatches"]==0
                    and rec["scoring_eligible"] is False,
                    "EXACT_SOURCE_CALL_ID_TO_NATIVE_INJECTED_RETURN_LINK_FAILED")
            seen.add(call_id)
    require(len(seen)==16,"ALL_NATIVE_MODEL_SHAPED_READ_IDS_DISTINCT")
    result={
        "rule_of_one":RULE,
        "determination":proof["determination"],
        "predecessor_tests":2457,
        "new_tests":len(cases),
        "refusals":len(negative),
        "canonical_task15_cases":8,
        "synthetic_native_read_proposals":16,
        "native_read_only_returns":16,
        "synthetic_offline_continuations":16,
        "read_call_id_and_tool_return_identity_join":True,
        "authenticated_model_source":False,
        "real_provider_calls":0,"scorer_calls":0,
        "native_write_dispatches":0,"real_external_effects":0,
        "canonical_utility_measured":False,
    }
    (out/(NAME+".json")).write_text(
        json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("PASS_"+RULE)
    print("new_tests=15 refusals=14 source_read_returns=16 "
          "provider_calls=0 scorer_calls=0 native_writes=0")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
