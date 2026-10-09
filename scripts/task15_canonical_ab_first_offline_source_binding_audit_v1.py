#!/usr/bin/env python3
"""Exact HEAD audit for sixteen case-bound offline first source requests."""
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
RULE="TASK15_CANONICAL_AB_FIRST_OFFLINE_SOURCE_BINDING_V1"
NAME="task15-canonical-ab-first-offline-source-binding-v1"
sys.path.insert(0,str(ROOT))


def require(value,reason):
    if not value: raise ValueError(reason)


def git_blob(path):
    data=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()


def main():
    p=argparse.ArgumentParser()
    for key in ("agentdojo","rcc","veritas"):
        p.add_argument("--"+key+"-root",type=Path,required=True)
    for key in ("replay-artifact","v13-artifact","output-dir"):
        p.add_argument("--"+key,type=Path,required=True)
    args=p.parse_args()
    require(not os.environ.get("OPENAI_API_KEY")
            and not os.environ.get("VERITAS_DATABASE_URL"),
            "PAID_PROVIDER_AND_PRODUCTION_DB_FORBIDDEN")
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE
            and contract["predecessor_main_sha"]==
                "aa983c51b169c56fe58bffa70078bcbefce5bea8"
            and contract["status"]=="IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI",
            "EXACT_PR262_PREDECESSOR_AND_CONTRACT_REQUIRED")
    for path,digest in contract["source_blobs"].items():
        require(git_blob(ROOT/path)==digest,"SOURCE_BLOB_DRIFT:"+path)
    for path,digest in contract["agentdojo_native_blobs"].items():
        require(git_blob(args.agentdojo_root/path)==digest,
                "NATIVE_AGENTDOJO_BLOB_DRIFT:"+path)
    out=args.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    prior=subprocess.run([
        sys.executable,"scripts/task15_canonical_injected_ab_context_isolation_audit_v1.py",
        "--agentdojo-root",str(args.agentdojo_root.resolve()),
        "--rcc-root",str(args.rcc_root.resolve()),
        "--veritas-root",str(args.veritas_root.resolve()),
        "--replay-artifact",str(args.replay_artifact.resolve()),
        "--v13-artifact",str(args.v13_artifact.resolve()),
        "--output-dir",str(out),
    ],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(prior.stdout+prior.stderr)
    require(prior.returncode==0,
            "PR262_PREDECESSOR_CHAIN_FAILED:"+(prior.stdout+prior.stderr)[-15000:])
    old=json.loads((out/"task15-canonical-injected-ab-context-isolation-v1.json").read_text())
    require(old["determination"]==
                "EIGHT_CASES_WITH_TWO_ISOLATED_NATIVE_INJECTED_INITIAL_CONTEXTS"
            and old["predecessor_tests"]==2412
            and old["new_tests"]==15
            and old["refusals"]==14
            and old["native_direct_injected_case_count"]==8
            and old["isolated_prospective_native_initial_contexts"]==16
            and old["independent_offline_local_source_reused_as_canonical"] is False
            and old["canonical_model_queries"]==0
            and old["canonical_effect_dispatches"]==old["provider_calls"]==
                old["scorer_calls"]==old["real_external_effects"]==0
            and old["canonical_utility_measured"] is False,
            "PR262_CONTEXT_ONLY_LIMITATIONS_MUST_REMAIN")
    context_evidence=out/"task15-canonical-injected-ab-context-isolation-v1.evidence.jsonl"
    require(context_evidence.is_file(),"PR262_POSITIVE_CONTEXT_EVIDENCE_REQUIRED")
    evidence=out/(NAME+".evidence.jsonl")
    refusals=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for f in (evidence,refusals,junit):f.unlink(missing_ok=True)
    for flag in (
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
    env["TASK15_RCC_ROOT"]=str(args.rcc_root.resolve())
    env["TASK15_CANONICAL_FIRST_SOURCE_CONTEXT_EVIDENCE"]=str(context_evidence)
    env["TASK15_CANONICAL_FIRST_SOURCE_EVIDENCE"]=str(evidence)
    env["TASK15_CANONICAL_FIRST_SOURCE_REFUSALS"]=str(refusals)
    tests=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task15_canonical_ab_first_offline_source_binding_v1.py",
        "--junitxml",str(junit),
    ],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".tests.log")).write_text(tests.stdout+tests.stderr)
    print(tests.stdout,end="")
    require(tests.returncode==0,
            "NEW_CANONICAL_FIRST_OFFLINE_SOURCE_TESTS_FAILED:"+
            (tests.stdout+tests.stderr)[-16000:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==15
            and not any(c.find(z) is not None for c in cases
                        for z in ("failure","error","skipped")),
            "ALL_FIFTEEN_NEW_FIRST_SOURCE_TESTS_MUST_PASS")
    good=[json.loads(line) for line in evidence.read_text().splitlines()]
    bad=[json.loads(line) for line in refusals.read_text().splitlines()]
    require(len(good)==1 and len(bad)==14
            and len({e["fault"] for e in bad})==14
            and all(e["result"]=="NO_CANONICAL_SOURCE_PROOF_PROMOTION"
                    for e in bad),
            "ALL_FOURTEEN_UNIQUE_CANONICAL_SOURCE_REFUSALS_REQUIRED")
    proof=good[0]["proof"]
    contexts=json.loads(context_evidence.read_text().splitlines()[0])["proof"]
    from task15_native_address_request_profile_issuance_v1 import sha
    from task15_canonical_enrollment_gap_preflight_v1 import ENROLLED_TASK15
    require(proof["rule_of_one"]==RULE
            and proof["determination"]==
                "EIGHT_NATIVE_CASES_SIXTEEN_OFFLINE_FIRST_PROPOSALS_BOUND"
            and proof["context_proof_sha256"]==sha(contexts)
            and proof["native_task15_case_count"]==8
            and proof["independent_synthetic_client_invocations"]==16
            and [r["case_id"] for r in proof["source_bindings"]]==
                list(ENROLLED_TASK15)
            and len(proof["source_transport_journal"])==16
            and all(x["status"]=="RESPONSE_DECODED"
                    and x["injection_observed_in_request"] is False
                    for x in proof["source_transport_journal"])
            and proof["native_injection_visible_to_model"] is False
            and proof["canonical_full_trajectories_proven"] is False
            and proof["canonical_scoring_eligible"] is False
            and proof["real_model_computation_proven"] is False
            and proof["provider_calls"]==proof["scorer_calls"]==
                proof["canonical_native_tool_dispatches"]==
                proof["external_effects"]==0
            and proof["final128_utility_measured"] is False
            and proof["injection_success_measured"] is False,
            "CANONICAL_ATTACK_EXPOSURE_OR_SCORING_MUST_NOT_BE_CLAIMED")
    seen=set()
    for i,row in enumerate(proof["source_bindings"]):
        require(list(row["arms"])==["A","B"],"A_B_PAIR_REQUIRED")
        for arm in ("A","B"):
            entry=row["arms"][arm]
            client=good[0]["client_calls"][row["case_id"]][arm]
            original_context=contexts["contexts"][i]["arms"][arm]
            call_id=entry["native_call_id"]
            require(len(client)==1
                    and call_id not in seen
                    and entry["case_id"]==row["case_id"]
                    and entry["logical_arm"]==arm
                    and entry["first_wire_request_sha256"]==
                        sha({"messages":client[0]["messages"],"tools":client[0]["tools"]})
                    and entry["injected_initial_environment_sha256"]==
                        original_context["environment_sha256"]
                    and entry["native_tool_dispatched"] is False
                    and entry["injection_observed_by_model"] is False
                    and entry["canonical_score_eligible"] is False,
                    "INDEPENDENT_CASE_BOUND_FIRST_NATIVE_PROPOSAL_REQUIRED")
            seen.add(call_id)
    require(len(seen)==16,"ALL_SIXTEEN_DISTINCT_SOURCE_IDENTITIES_REQUIRED")
    result={
        "rule_of_one":RULE,
        "determination":proof["determination"],
        "predecessor_tests":2427,
        "new_tests":len(cases),
        "refusals":len(bad),
        "native_canonical_task15_cases":8,
        "distinct_synthetic_first_source_calls":16,
        "canonical_provenance_binding_observed":True,
        "native_injection_exposed_to_model":False,
        "provider_calls":0,"scorer_calls":0,
        "native_dispatches":0,"real_external_effects":0,
        "canonical_utility_measured":False,
    }
    (out/(NAME+".json")).write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("PASS_"+RULE)
    print("new_tests=15 refusals=14 offline_first_calls=16 "
          "provider_calls=0 scorer_calls=0 native_dispatches=0")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
