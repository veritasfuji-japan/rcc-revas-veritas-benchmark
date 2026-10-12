#!/usr/bin/env python3
"""#338 genuine current RCC candidate -> genuine VERITAS refusal surfaces.

This cannot promote RCC approval or its decision-lock into a native CDA.
The separate Bind-core call is a *provisional refusal probe*, NEVER a legitimate
CDA-promoted ExecutionIntent, authority issuance, or end-to-end native run.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys

from scripts import final128_337_current_rcc_main_request_boundary_v1 as upstream338

ROOT=Path(__file__).resolve().parents[1]
CONTRACT=ROOT/"contracts/FINAL128_338_CURRENT_RCC_NATIVE_REFUSAL_V1.json"
PIN_RCC="353ad9e6a17cda8874a129493fe0f8f4fe4427bc"
PIN_VERITAS="299a3c4987668091f50ab3e45165bcccd1ae193f"
BEN_BASE="7dae4f3f8309a4e32c0049b971d5a6b3b6defb8d"
RULE="CURRENT_RCC_ONE_RELEASED_CANDIDATE_HAS_NO_NATIVE_CDA_OR_EXECUTION_AUTHORITY"

class Rejected(ValueError):
    pass

def require(ok, code):
    if not ok:
        raise Rejected(code)

def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def sha_json(x):
    return hashlib.sha256(json.dumps(x,ensure_ascii=False,sort_keys=True,
            separators=(",",":"),allow_nan=False).encode("utf-8")).hexdigest()

def contract_check(c):
    require(c["rule_of_one"]==RULE and c["benchmark_parent_main_sha"]==BEN_BASE
            and c["upstream_commit"]==PIN_RCC and c["veritas_commit"]==PIN_VERITAS
            and c["scope"]=={
                "current_rcc_real_evaluate_and_prepare":True,
                "selected_candidate_count":1,
                "deterministic_selection":"lexically first released case id",
                "native_verified_decision_candidate_promotion_attempt":True,
                "upstream_decision_lock_is_not_veritas_cda":True,
                "independent_cda_provided":False,
                "verified_cda_promotion_must_fail":True,
                "provisional_bind_refusal_probe":True,
                "provisional_probe_is_verified_execution_intent":False,
                "native_bind_authorization_issued":False,
                "native_bind_authorization_consumed":False,
                "provider_calls":0,"http_decide_requests":0,"http_bind_requests":0,
                "external_effects":0,"official_agentdojo_scores":0,
                "no_new_utility_claim":True,
                "current_rcc_to_actual_native_effect_continuity":"NOT_PROVEN",
            }, "338_SCOPE_OR_AUTHORITY_CHANGED")
    require(c["historical_v13"]=={
        "arm_a_utility":93,"arm_b_utility":64,"arm_b_injection_success":0
    }, "338_HISTORICAL_SCORES_MUST_NOT_CHANGE")
    require(len(c["veritas_source_git_blobs"])==5,"338_SOURCE_PINS_REQUIRED")
    return c

def verify_veritas(veritas_root,contract):
    root=Path(veritas_root).resolve()
    require(upstream338.git(root,"rev-parse","HEAD")==PIN_VERITAS,"338_VERITAS_SOURCE_SHA_DRIFT")
    require(upstream338.git(root,"status","--porcelain")=="","338_VERITAS_TREE_DIRTY")
    for rel,blob in contract["veritas_source_git_blobs"].items():
        path=(root/rel).resolve()
        require(path.is_relative_to(root) and path.is_file(),"338_VERITAS_SOURCE_MISSING:"+rel)
        require(upstream338.git(root,"hash-object",rel)==blob,"338_VERITAS_SOURCE_CHANGED:"+rel)
    return root

def execute_rcc(upstream_root,root_out):
    c=upstream338.validate_contract(upstream338.load_json(upstream338.CONTRACT))
    release=upstream338.verify_source(upstream_root,c)
    manifest=release/"evaluation_manifest.json"
    stages=[
        ["preflight","--manifest",manifest],
        ["register-takeshi","--manifest",manifest,
         "--source",release/"fixtures/takeshi/Governance_labelled_Evaluation_Set_v0.1.1.jsonl",
         "--output-dir",root_out/"registered"],
        ["evaluate","--manifest",manifest,
         "--input",root_out/"registered/runtime_inputs.jsonl",
         "--plan",root_out/"registered/preregistration.json",
         "--output-dir",root_out/"rcc-run"],
        ["verify-artifacts","--manifest",manifest,"--run-dir",root_out/"rcc-run"],
        ["prepare-veritas","--manifest",manifest,
         "--run-dir",root_out/"rcc-run",
         "--output-dir",root_out/"prepared"]]
    journal=[upstream338.run_stage(release,args) for args in stages]
    summary=read_json(root_out/"prepared/summary.json")
    handoffs={x["rcc_revas"]["audit"]["case_id"]:x
              for x in upstream338.read_jsonl(root_out/"rcc-run/handoff_results.jsonl")}
    prepared=upstream338.read_jsonl(root_out/"prepared/veritas_decide_requests.jsonl")
    skipped=upstream338.read_jsonl(root_out/"prepared/skipped.jsonl")
    errors=upstream338.read_jsonl(root_out/"prepared/errors.jsonl")
    require(len(handoffs)==36 and not errors and prepared
            and len(prepared)+len(skipped)==36
            and summary["network_called"] is False
            and summary["server_side_exact_candidate_consumption_verified"] is False
            and summary["prepared_requests"]==len(prepared)
            and summary["skipped_rcc_withheld"]==len(skipped),
            "338_SOURCE_CASE_ACCOUNTING_MISMATCH")
    row=min(prepared,key=lambda r:r["case_id"])
    h=handoffs[row["case_id"]]
    sys.path.insert(0,str(release))
    from rcc_revas_eval import native_veritas as native
    upstream338.verify_one_prepared(row,h,root_out/"rcc-run",native)
    return row,h,native,{"registered":36,"prepared":len(prepared),"withheld":len(skipped),
                         "errors":0,"stages":journal}

def native_refusal(row,handoff,native,veritas_root):
    sys.path.insert(0,str(veritas_root))
    from veritas_os.governance.canonical_decision_artifact import verify_canonical_decision_artifact
    from veritas_os.policy.decision_candidate import (
        DecisionCandidate, validate_decision_candidate,
        try_promote_verified_canonical_decision_candidate_to_execution_intent)
    from veritas_os.policy.bind_artifacts import ExecutionIntent,FinalOutcome
    from veritas_os.policy.bind_core.core import ReferenceBindAdapter,execute_bind_adjudication

    candidate=row["request"]["context"]["rcc_revas"]["candidate"]
    expected=hah=handoff["rcc_revas"]["adoption"]["selected_candidate"]
    require(candidate==expected,"338_RERAISING_CANDIDATE_NOT_SAME")
    candidate_hash=row["request_proof"]["candidate_semantic_hash"]
    require(candidate_hash==native.digest(candidate,"rcc-candidate-v1"),"338_CANDIDATE_HASH_MISMATCH")
    # RCC decision lock lacks VERITAS's signed, selected-action-bound CDA.
    fabricated_cda=deepcopy(handoff["rcc_revas"]["decision_lock"])
    direct=verify_canonical_decision_artifact(fabricated_cda)
    require(not direct.is_valid,"338_RCC_LOCK_IS_NOT_NATIVE_CDA")
    # Exact RCC candidate fields enter metadata only; never infer the actor,
    # policy, target, approval or required_authority from untrusted candidate.
    preliminary=DecisionCandidate(
        source_model="rcc-revas-public-release-v0.1",
        source_trace_ref="rcc-candidate-v1:"+candidate_hash,
        evidence_refs=["rcc-candidate-v1:"+candidate_hash],
        metadata={"rcc_candidate":deepcopy(candidate),
                  "rcc_decision_hash":row["request_proof"]["upstream_decision_hash"]},
        required_authority=[],required_human_approval=None)
    check=validate_decision_candidate(preliminary)
    require(check.fail_closed and not check.promotable
            and "DECISION_CANDIDATE_AUTHORITY_UNSPECIFIED" in check.reason_codes,
            "338_MISSING_AUTHORITY_MUST_REFUSE_AT_CANDIDATE")
    promoted=try_promote_verified_canonical_decision_candidate_to_execution_intent(
        preliminary,canonical_decision_artifact=fabricated_cda)
    require(not promoted.promoted and promoted.execution_intent is None
            and promoted.fail_closed
            and "CANONICAL_DECISION_ARTIFACT_INVALID" in promoted.refusal_reason_codes,
            "338_RCC_DECISION_LOCK_MUST_NOT_PROMOTE")
    # Deliberately separate from the failed promotion: an in-memory, clearly
    # UNVERIFIED probe to the real existing Bind adjudicator. This is NOT a
    # connected decision->Bind run, NOT a source of execution permission.
    provisional=ExecutionIntent(
        execution_intent_id="unverified-probe:"+candidate_hash,
        decision_id="UNVERIFIED_RCC_LOCK:"+row["request_proof"]["upstream_decision_hash"],
        request_id="UNVERIFIED_RCC_CORRELATION:"+row["request_proof"]["correlation_id"],
        policy_snapshot_id="UNVERIFIED_NO_POLICY",
        actor_identity="UNVERIFIED_NO_ACTOR",
        target_system="UNVERIFIED_LOCAL_PROBE",
        target_resource="memory://rcc-rejection-probe",
        intended_action="NO_EFFECT_AUTHORITY_REFUSAL_PROBE",
        evidence_refs=["rcc-candidate-v1:"+candidate_hash])
    class NeverApply(ReferenceBindAdapter):
        apply_count=0
        def apply(self,intent,snapshot):
            self.apply_count+=1
            raise AssertionError("338_BIND_APPLY_MUST_NOT_BE_REACHABLE")
    adapter=NeverApply(state={"writes":0},authority_signal=False,
                       constraint_signals={"no_effect_only":True},
                       runtime_risk_signal=True)
    receipt=execute_bind_adjudication(
        execution_intent=provisional,adapter=adapter,
        bind_ts="2026-10-12T12:00:00Z",
        append_trustlog=False)
    require(receipt.final_outcome in {FinalOutcome.BLOCKED,FinalOutcome.PRECONDITION_FAILED}
            and receipt.admissibility_result.get("admissible") is False
            and adapter.apply_count==0 and adapter.state=={"writes":0},
            "338_NATIVE_BIND_REFUSAL_MUST_HAVE_NO_EFFECT")
    require(receipt.final_outcome==FinalOutcome.BLOCKED,
            "338_REAL_BIND_AUTHORITY_REFUSAL_NOT_REACHED")
    return {
        "rcc_case_id":row["case_id"],
        "rcc_semantic_candidate_hash":candidate_hash,
        "rcc_candidate_object_hash":row["request_proof"]["candidate_object_hash"],
        "rcc_decision_hash":row["request_proof"]["upstream_decision_hash"],
        "source_veritas_request_payload_hash":row["request_proof"]["request_payload_hash"],
        "candidate_reflected_without_mutation":True,
        "native_cda_verifier":"REJECTED_RCC_LOCK_NOT_CDA",
        "native_candidate_validation":{"fail_closed":check.fail_closed,
              "promotable":check.promotable,"reason_codes":check.reason_codes},
        "native_cda_promotion":"REFUSED_NO_EXECUTION_INTENT",
        "native_bind_probe":{"scope":"PROVISIONAL_UNVERIFIED_NOT_PROMOTED",
              "final_outcome":receipt.final_outcome.value,
              "reason_codes":receipt.admissibility_result.get("reason_codes"),
              "authority_check_result":receipt.authority_check_result,
              "apply_count":adapter.apply_count,"state_before_after":{"writes":0}},
        "verified_native_execution_intent_created":False,
        "native_authorization_issued":False,
        "native_effect_count":0}

def validate_report(r):
    s=r["scope"]
    require(r["rcc_main_sha"]==PIN_RCC and r["veritas_os_sha"]==PIN_VERITAS
            and s["selected_candidate_count"]==1
            and s["native_bind_authorization_issued"] is False
            and s["native_bind_authorization_consumed"] is False
            and s["current_rcc_to_actual_native_effect_continuity"]=="NOT_PROVEN"
            and s["provider_calls"]==s["external_effects"]==
                s["official_agentdojo_scores"]==s["http_decide_requests"]==0
            and r["observed"]["native_cda_promotion"]=="REFUSED_NO_EXECUTION_INTENT"
            and r["observed"]["native_bind_probe"]["apply_count"]==0
            and r["observed"]["native_bind_probe"]["final_outcome"]=="BLOCKED",
            "338_UNSUPPORTED_AUTHORITY_OR_UTILITY_CLAIM")
    return True

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--upstream-root",type=Path,required=True)
    p.add_argument("--veritas-root",type=Path,required=True)
    p.add_argument("--output-dir",type=Path,required=True)
    a=p.parse_args()
    upstream338.forbid_credentials()
    c=contract_check(read_json(CONTRACT))
    osroot=verify_veritas(a.veritas_root,c)
    out=a.output_dir.resolve()
    require(out==(ROOT/"results/final128-338-current-rcc-native-refusal").resolve()
            and not out.exists(),"338_FIXED_FRESH_OUTPUT_ONLY")
    out.mkdir(parents=True)
    row,h,native,rcc=execute_rcc(a.upstream_root,out)
    observed=native_refusal(row,h,native,osroot)
    report={
        "schema":c["schema"],"rule_of_one":RULE,
        "benchmark_base_sha":BEN_BASE,
        "rcc_main_sha":PIN_RCC,"veritas_os_sha":PIN_VERITAS,
        "scope":c["scope"],"rcc_case_accounting":rcc,
        "observed":observed,"historical_v13_reference_only":c["historical_v13"],
        "native_http_route_exercised":False,
        "native_authorization_consumption_exercised":False,
        "native_effect_reconciliation_exercised":False}
    validate_report(report)
    report["report_sha256"]=sha_json(report)
    (out/"report.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("FINAL128_338_REAL_RCC_CANDIDATE_NATIVE_CDA_REFUSAL_AND_UNVERIFIED_BIND_PROBE_BLOCKED")
    print(json.dumps({"case":observed["rcc_case_id"],"prepared":rcc["prepared"],
          "withheld":rcc["withheld"],"outcome":observed["native_bind_probe"]["final_outcome"],
          "digest":report["report_sha256"]},sort_keys=True))

if __name__=="__main__":
    main()
