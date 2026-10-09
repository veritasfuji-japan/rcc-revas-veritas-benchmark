#!/usr/bin/env python3
"""Exact-HEAD prospective native Task15 A/B injected-context audit.

No canonical candidate generation, scorer, external model or effect; frozen
noncanonical source proof is present only as explicitly ineligible lineage.
"""
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
RULE="TASK15_CANONICAL_INJECTED_AB_CONTEXT_ISOLATION_V1"
NAME="task15-canonical-injected-ab-context-isolation-v1"
sys.path.insert(0,str(ROOT))


def require(ok,reason):
    if not ok:
        raise ValueError(reason)


def blob(path):
    data=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()


def main():
    p=argparse.ArgumentParser()
    for x in ("agentdojo","rcc","veritas"):
        p.add_argument("--"+x+"-root",type=Path,required=True)
    for x in ("replay-artifact","v13-artifact","output-dir"):
        p.add_argument("--"+x,type=Path,required=True)
    args=p.parse_args()
    require(not os.environ.get("OPENAI_API_KEY")
            and not os.environ.get("VERITAS_DATABASE_URL"),
            "PROVIDER_OR_PRODUCTION_DB_CREDENTIAL_FORBIDDEN")
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE
            and contract["predecessor_main_sha"]==
                "7e67402d7b3ee750b53f3a5c03b6caeed3d4d487"
            and contract["status"]=="IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI",
            "EXACT_PR261_MERGED_MAIN_PREDECESSOR_REQUIRED")
    for path,digest in contract["source_blobs"].items():
        require(blob(ROOT/path)==digest, "SOURCE_BLOB_CHANGED:"+path)
    for path,digest in contract["agentdojo_native_blobs"].items():
        require(blob(args.agentdojo_root/path)==digest,
                "PINNED_NATIVE_SOURCE_CHANGED:"+path)
    out=args.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    prev=subprocess.run([
        sys.executable,"scripts/task15_independent_ab_three_step_offline_native_history_audit_v1.py",
        "--agentdojo-root",str(args.agentdojo_root.resolve()),
        "--rcc-root",str(args.rcc_root.resolve()),
        "--veritas-root",str(args.veritas_root.resolve()),
        "--replay-artifact",str(args.replay_artifact.resolve()),
        "--v13-artifact",str(args.v13_artifact.resolve()),
        "--output-dir",str(out),
    ],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(prev.stdout+prev.stderr)
    require(prev.returncode==0,
            "PR261_FULL_PREDECESSOR_AUDIT_FAILED:"+
            (prev.stdout+prev.stderr)[-15000:])
    earlier=json.loads((out/"task15-independent-ab-three-step-offline-native-history-v1.json").read_text())
    require(earlier["determination"]==
                "TWO_ISOLATED_OFFLINE_THREE_STEP_MODEL_SOURCE_CHAINS_OBSERVED"
            and earlier["predecessor_tests"]==2397
            and earlier["new_tests"]==15
            and earlier["refusals"]==14
            and earlier["independent_synthetic_offline_source_queries"]==6
            and earlier["own_native_feedback_links"]==4
            and earlier["governed_local_dispatches"]==12
            and earlier["real_provider_calls"]==earlier["scorer_calls"]==
                earlier["real_external_effects"]==0
            and earlier["canonical_final128_utility_measured"] is False,
            "PR261_NONCANONICAL_SOURCE_SCOPE_MUST_REMAIN")
    native=json.loads((out/"task15-native-direct-attack-slot-application-v1.json").read_text())
    require(native["determination"]==
                "NATIVE_DIRECT_SLOTS_DISCOVERED_AND_LOCAL_ENVIRONMENTS_INJECTED"
            and native["canonical_task15_cases"]==8
            and native["canonical_roster_cases"]==128
            and native["provider_calls"]==native["scorer_calls"]==0,
            "PR259_NATIVE_SLOT_PREDECESSOR_MUST_REMAIN")

    source_evidence=out/"task15-independent-ab-three-step-offline-native-history-v1.evidence.jsonl"
    slot_evidence=out/"task15-native-direct-attack-slot-application-v1.evidence.jsonl"
    require(source_evidence.is_file() and slot_evidence.is_file(),
            "UPSTREAM_NATIVE_AND_MODEL_SOURCE_EVIDENCE_REQUIRED")
    evidence=out/(NAME+".evidence.jsonl")
    refusals=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for f in (evidence,refusals,junit):f.unlink(missing_ok=True)
    for flag in (
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
    env["TASK15_RCC_ROOT"]=str(args.rcc_root.resolve())
    env["TASK15_CANONICAL_AB_CONTEXT_SLOT_EVIDENCE"]=str(slot_evidence)
    env["TASK15_CANONICAL_AB_CONTEXT_SOURCE_EVIDENCE"]=str(source_evidence)
    env["TASK15_CANONICAL_AB_CONTEXT_EVIDENCE"]=str(evidence)
    env["TASK15_CANONICAL_AB_CONTEXT_REFUSALS"]=str(refusals)
    tests=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task15_canonical_injected_ab_context_isolation_v1.py",
        "--junitxml",str(junit),
    ],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".tests.log")).write_text(tests.stdout+tests.stderr)
    print(tests.stdout,end="")
    require(tests.returncode==0,
            "EIGHT_CANONICAL_CONTEXT_TESTS_FAILED:"+
            (tests.stdout+tests.stderr)[-18000:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==15
            and not any(t.find(x) is not None for t in cases
                        for x in ("failure","error","skipped")),
            "EXACT_FIFTEEN_CONTEXT_TEST_CASES_REQUIRED")
    good=[json.loads(l) for l in evidence.read_text().splitlines()]
    bad=[json.loads(l) for l in refusals.read_text().splitlines()]
    require(len(good)==1 and len(bad)==14
            and len({r["fault"] for r in bad})==14
            and all(r["result"]=="NO_CANONICAL_CONTEXT_OR_TRAJECTORY_PROMOTION"
                    for r in bad),
            "ALL_FOURTEEN_CONTEXT_ADMISSION_REFUSALS_REQUIRED")
    p=good[0]["proof"]
    from task15_native_address_request_profile_issuance_v1 import sha
    from task15_canonical_enrollment_gap_preflight_v1 import ENROLLED_TASK15
    require(p["rule_of_one"]==RULE
            and p["determination"]==
                "EIGHT_CASES_WITH_TWO_ISOLATED_NATIVE_INJECTED_INITIAL_CONTEXTS"
            and p["canonical_task15_case_count"]==8
            and p["prospective_initial_context_count"]==16
            and p["noncanonical_source_case_id"]==
                "banking:user_task_15:refund-design-v1"
            and p["noncanonical_offline_source_history_promoted_to_canonical"] is False
            and p["canonical_case_model_queries"]==0
            and p["canonical_candidate_dispatches"]==0
            and p["provider_calls"]==p["scorer_calls"]==p["real_external_effects"]==0
            and p["canonical_final128_utility_measured"] is False
            and p["canonical_injection_success_measured"] is False
            and [r["case_id"] for r in p["contexts"]]==list(ENROLLED_TASK15),
            "NO_FAKE_CANONICAL_MODEL_COMPLETION_OR_SCORE_ALLOWED")
    for r in p["contexts"]:
        arms=r["arms"]
        require(list(arms)==["A","B"]
                and r["verified_native_environment_sha256"]==
                    arms["A"]["environment_sha256"]==
                    arms["B"]["environment_sha256"]
                and sha(arms["A"]["native_injected_environment"])==
                    arms["A"]["environment_sha256"]
                and sha(arms["B"]["native_injected_environment"])==
                    arms["B"]["environment_sha256"]
                and r["native_slot_key"]=="injection_incoming_transaction"
                and all(arms[a]["source_candidate_generated_for_this_case"] is False
                        and arms[a]["canonical_enrollment_eligible"] is False
                        for a in ("A","B"))
                and r["canonical_case_executed"] is False
                and r["eligible_for_native_canonical_scoring"] is False,
                "INDEPENDENT_A_B_NATIVE_CONTEXT_BYTES_OR_CLAIMS_CHANGED")
    result={
        "rule_of_one":RULE,
        "determination":p["determination"],
        "predecessor_tests":2412,
        "new_tests":len(cases),
        "refusals":len(bad),
        "native_direct_injected_case_count":8,
        "isolated_prospective_native_initial_contexts":16,
        "independent_offline_local_source_reused_as_canonical":False,
        "canonical_model_queries":0,
        "canonical_effect_dispatches":0,
        "provider_calls":0,
        "scorer_calls":0,
        "real_external_effects":0,
        "canonical_utility_measured":False,
    }
    (out/(NAME+".json")).write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("PASS_"+RULE)
    print("new_tests=15 refusals=14 native_case_contexts=16 "
          "provider_calls=0 scorer_calls=0 canonical_queries=0")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
