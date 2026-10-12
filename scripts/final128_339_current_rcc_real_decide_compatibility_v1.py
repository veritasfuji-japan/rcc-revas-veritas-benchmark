#!/usr/bin/env python3
"""#339: unchanged real RCC current-main request -> actual local VERITAS POST /v1/decide.

A native CDA can be structurally verified without proving that the exact RCC
candidate became the selected, promotable native execution candidate. Never
manufacture missing typed authority fields, review, an approval or a Bind permit.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from datetime import UTC,datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0,str(ROOT))
from scripts import final128_338_current_rcc_native_refusal_v1 as prev
from scripts import final128_337_current_rcc_main_request_boundary_v1 as upstream

CONTRACT_PATH=ROOT/"contracts/FINAL128_339_CURRENT_RCC_REAL_DECIDE_COMPATIBILITY_V1.json"
PIN_BASE="1b3d3a3d574a721a0e73513927b343b67f5aba19"
PIN_RCC="353ad9e6a17cda8874a129493fe0f8f4fe4427bc"
PIN_VERITAS="299a3c4987668091f50ab3e45165bcccd1ae193f"
FIXED_OUT=ROOT/"results/final128-339-current-rcc-real-decide"
RULE="EXERCISE_EXACT_RELEASED_RCC_REQUEST_AT_REAL_VERITAS_DECIDE_AND_AUDIT_NATIVE_CDA_CANDIDATE_BINDING"

class Refused(ValueError): pass

def require(condition,reason):
    if not condition: raise Refused(reason)

def json_digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),
        ensure_ascii=False,allow_nan=False).encode("utf-8")).hexdigest()

def contract_check(c):
    require(c["rule_of_one"]==RULE and c["benchmark_base_main_sha"]==PIN_BASE
        and c["upstream_rcc_sha"]==PIN_RCC and c["upstream_veritas_sha"]==PIN_VERITAS
        and c["selected_case_count"]==1 and c["request_mutation_allowed"] is False
        and c["route"]=="POST /v1/decide via in-process TestClient"
        and c["nonclaims"]=={
            "native_execution_intent_previously_established":False,
            "native_authorization_issued":False,"authorization_consumed":False,
            "native_bind_executed":False,"production_external_effect":False,
            "live_model_provider_calls":0,"physical_bank_prestate_proven":False,
            "official_final128_rescored":False,"end_to_end_same_candidate_proven":False,
        }
        and c["historic_v13"]=={"arm_a":93,"arm_b":64,"injection_success_b":0}
        and len(c["veritas_reference_proof_files"])==5,
        "339_SCOPE_DRIFT")
    return c

def verify_os(root,c):
    root=prev.verify_veritas(root,prev.contract_check(prev.read_json(prev.CONTRACT)))
    for rel,blob in c["veritas_reference_proof_files"].items():
        require(upstream.git(root,"hash-object",rel)==blob,"339_OS_PROOF_FILE_CHANGED:"+rel)
    return root

def selected_identity(request,response,verified_cda):
    """Observe all exact identity predicates; never equate echo with consumption."""
    context=request["context"]["rcc_revas"]
    candidate=context["candidate"]
    alt=request["alternatives"][0]
    chosen=response.get("chosen")
    expected_description=upstream.canon(candidate).decode("utf-8")
    matching_chosen=(type(chosen) is dict
        and chosen.get("id")==alt["id"]
        and chosen.get("description")==expected_description)
    action_evidence=None
    if verified_cda is not None:
        action_evidence=verified_cda.decision.selected_action_evidence
    return {
        "original_candidate_sha256":json_digest(candidate),
        "original_candidate_semantic_hash":context["candidate_semantic_hash"],
        "request_candidate_alternative_id":alt["id"],
        "request_description_exact_bytes_bound":alt["description"]==expected_description,
        "response_chosen_id":chosen.get("id") if type(chosen) is dict else None,
        "response_chosen_exact_candidate_description":bool(matching_chosen),
        "native_cda_selected_action_evidence_present":action_evidence is not None,
        "response_exact_native_candidate_selection_proven":bool(matching_chosen and action_evidence is not None),
    }

def validate_report(report):
    c=contract_check(prev.read_json(CONTRACT_PATH))
    require(report["scope"]==c["nonclaims"] and report["rcc_source_sha"]==PIN_RCC
        and report["veritas_source_sha"]==PIN_VERITAS
        and report["rcc_cases"]["prepared"]+report["rcc_cases"]["withheld"]==36
        and report["route"]["request_payload_exact"] is True
        and report["route"]["controlled_local_provider"] is True
        and report["route"]["real_api_route_called"] is True
        and report["route"]["real_decide_kernel_observed"] is True
        and report["route"]["synthetic_kms_sign_calls"]>0
        and report["route"]["synthetic_worm_put_calls"]>0
        and report["route"]["native_cda_verified"] is True
        and report["route"]["model_provider_network_calls"]==0
        and report["native_bind_invoked"] is False
        and report["actual_execution_effects"]==0,
        "339_CORE_ROUTE_OR_SCOPE_MISSING")
    linkage=report["linkage"]
    # An unrelated selected candidate cannot be reported as continuous:
    if not linkage["response_exact_native_candidate_selection_proven"]:
        require(report["verified_rcc_execution_intent"] is None
           and report["rcc_to_native_execution_intent_proven"] is False,
           "339_UNBOUND_NATIVE_EI_CLAIM")
    return True

def child(input_path,child_output,veritas_root):
    # This subprocess starts fresh; the native app reads process-global config.
    request=prev.read_json(input_path)
    source_hash=json_digest(request)
    req_context=request["context"]["rcc_revas"]
    require(len(request["alternatives"])==1
        and request["alternatives"][0]["id"]==
        "rcc-candidate:"+req_context["candidate_semantic_hash"],
        "339_UPSTREAM_REQUEST_ALTERNATIVE_CHANGED")
    require(request["alternatives"][0]["description"]==
            upstream.canon(req_context["candidate"]).decode("utf-8"),
            "339_REQUEST_CANDIDATE_BYTES_CHANGED")
    sys.path.insert(0,str(veritas_root))
    from scripts import run_decision_to_external_bind_poc as poc
    from veritas_os.core import pipeline
    from veritas_os.governance.canonical_decision_artifact import verify_canonical_decision_artifact
    from veritas_os.policy.decision_candidate import (
        validate_decision_candidate,try_promote_verified_canonical_decision_candidate_to_execution_intent)
    from veritas_os.policy.canonical_verified_decision_promotion import (
        build_canonical_verified_decision_promotion_packet, CanonicalVerifiedDecisionPromotionError)

    with tempfile.TemporaryDirectory(prefix="rcc339-native-route-") as name:
        runtime=Path(name)
        runtime.mkdir(exist_ok=True)
        poc._configure_environment(runtime,"test-"+secrets.token_urlsafe(24),
            base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
        key_id=poc._configure_secure_test_infrastructure(runtime,
            "test-"+secrets.token_urlsafe(32))
        signed_bundle=poc._configure_verified_policy_bundle(runtime)
        route_calls=[]
        def request_factory(bundle_dir):
            require(bundle_dir==signed_bundle,"339_POLICY_BUNDLE_DRIFT")
            payload=deepcopy(request)
            route_calls.append(json_digest(payload))
            return payload
        with (patch.object(poc,"_decision_request_fixture",side_effect=request_factory),
              patch.object(pipeline,"REPLAY_SOURCE_DIR",runtime/"replay-sources")):
            response,pipeline_ok,calls=poc._decide(
                aws_clients=poc._DeterministicAwsClients(
                    poc._DeterministicKmsClient(key_id),
                    poc._DeterministicObjectLockClient()),
                policy_bundle_dir=signed_bundle)
        require(route_calls==[source_hash],"339_NOT_EXACT_UPSTREAM_PAYLOAD")
        require(pipeline_ok is True,"339_REAL_NATIVE_KERNEL_NOT_EXERCISED")
        require(calls["kms_sign_calls"]>0 and calls["object_lock_put_calls"]>0,
                "339_REAL_NATIVE_KMS_WORM_SIGNING_PATH_NOT_OBSERVED")
        verification=verify_canonical_decision_artifact(response.get("canonical_decision_artifact"))
        require(verification.is_valid and verification.artifact is not None,
                "339_REAL_NATIVE_CDA_NOT_VALID")
        cda=verification.artifact
        linkage=selected_identity(request,response,cda)
        chosen=response.get("chosen")
        promotion_status="NO_SELECTED_NATIVE_CANDIDATE"
        promotion_reasons=[]
        genuine_intent=None
        genuine_promotion=None
        if isinstance(chosen,dict):
            try:
                promotion=try_promote_verified_canonical_decision_candidate_to_execution_intent(
                    chosen,canonical_decision_artifact=cda)
                promotion_status="PROMOTED_SCHEMA_ONLY" if promotion.promoted else "REFUSED"
                promotion_reasons=list(promotion.refusal_reason_codes)
                if promotion.promoted and linkage["response_exact_native_candidate_selection_proven"]:
                    intent=promotion.execution_intent
                    require(intent is not None,"339_PROMOTION_WITHOUT_INTENT")
                    genuine_intent=intent.to_dict()
                    try:
                        frozen=build_canonical_verified_decision_promotion_packet(
                            cda,chosen,promoted_at=datetime.now(UTC),ttl_seconds=300)
                        genuine_promotion=frozen.promotion_hash
                    except CanonicalVerifiedDecisionPromotionError:
                        genuine_intent=None
                        promotion_status="REFUSED_EXACT_PROMOTION_PACKET"
            except (TypeError,ValueError) as exc:
                promotion_status="REFUSED_INVALID_RESPONSE_CANDIDATE"
                promotion_reasons=[type(exc).__name__]
        # No authority is created even if a valid *schema-level* intent emerges.
        if not linkage["response_exact_native_candidate_selection_proven"]:
            genuine_intent=None
        report={
            "request_payload_exact":route_calls==[source_hash],
            "real_api_route_called":True,"real_decide_kernel_observed":pipeline_ok,
            "controlled_local_provider":True,
            "model_provider_network_calls":0,
            "synthetic_kms_sign_calls":calls["kms_sign_calls"],
            "synthetic_worm_put_calls":calls["object_lock_put_calls"],
            "native_cda_verified":True,
            "native_decision_id":cda.decision_id,
            "native_decision_hash":cda.decision_hash,
            "native_request_id":cda.request_id,
            "response_chosen_hash":json_digest(chosen) if isinstance(chosen,dict) else None,
            "request_exact_json_sha256":source_hash,
            "native_selected_evidence_present":cda.decision.selected_action_evidence is not None,
            "policy_evidence_verified":(cda.decision.policy_snapshot_evidence is not None
              and cda.decision.policy_snapshot_evidence.signature_verified is True),
            "candidate_promotion_status":promotion_status,
            "candidate_promotion_reasons":promotion_reasons,
            "exact_native_promotion_hash":genuine_promotion,
            "verified_rcc_execution_intent":genuine_intent,
            "linkage":linkage,
            "response_decision_status":response.get("decision_status"),
            "response_business_decision":response.get("business_decision"),
            "recovery_mode":"REJECT_ANY_MISSING_EVIDENCE_NOT_FABRICATE",
        }
    child_output.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf-8")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--upstream-root",type=Path)
    p.add_argument("--veritas-root",type=Path,required=True)
    p.add_argument("--output-dir",type=Path)
    p.add_argument("--child-input",type=Path)
    p.add_argument("--child-output",type=Path)
    a=p.parse_args()
    if a.child_input:
        child(a.child_input,a.child_output,a.veritas_root.resolve())
        return
    upstream.forbid_credentials()
    c=contract_check(prev.read_json(CONTRACT_PATH))
    osroot=verify_os(a.veritas_root,c)
    out=a.output_dir.resolve()
    require(out==FIXED_OUT.resolve() and not out.exists(),
            "339_FIXED_FRESH_EVIDENCE_DIR_REQUIRED")
    out.mkdir(parents=True)
    selected,h,native,rcc=prev.execute_rcc(a.upstream_root,out)
    request=selected["request"]
    require(request["context"]["rcc_revas"]["candidate"]==
            h["rcc_revas"]["adoption"]["selected_candidate"],
            "339_ORIGINAL_RCC_CANDIDATE_CHANGED")
    upstream.verify_one_prepared(selected,h,out/"rcc-run",native)
    input_path=out/"real-request.json"
    input_path.write_text(json.dumps(request,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    result_path=out/"native-decision.json"
    env=dict(os.environ)
    env["PYTHONPATH"]=str(osroot)+os.pathsep+str(ROOT)
    subprocess.run([sys.executable,str(Path(__file__).resolve()),
       "--child-input",str(input_path),"--child-output",str(result_path),
       "--veritas-root",str(osroot)],cwd=osroot,env=env,
       check=True,capture_output=True,text=True,timeout=180)
    native_report=prev.read_json(result_path)
    linkage=native_report.pop("linkage")
    verified_intent=native_report.pop("verified_rcc_execution_intent")
    report={
        "schema":c["schema"],"rule_of_one":RULE,
        "rcc_source_sha":PIN_RCC,"veritas_source_sha":PIN_VERITAS,
        "benchmark_base_sha":PIN_BASE,"selected_case_id":selected["case_id"],
        "rcc_cases":{"registered":36,"prepared":rcc["prepared"],"withheld":rcc["withheld"]},
        "rcc_selected_semantic_hash":selected["request_proof"]["candidate_semantic_hash"],
        "rcc_pre_state_hash":selected["request_proof"]["evaluation_pre_state_hash"],
        "route":native_report,"linkage":linkage,
        "verified_rcc_execution_intent":verified_intent,
        "rcc_to_native_execution_intent_proven":bool(
            linkage["response_exact_native_candidate_selection_proven"] and verified_intent is not None),
        "scope":c["nonclaims"],"native_bind_invoked":False,
        "actual_execution_effects":0,"historical_v13_reference_only":c["historic_v13"]
    }
    validate_report(report)
    report["report_sha256"]=json_digest(report)
    (out/"report.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("FINAL128_339_NATIVE_HTTP_CDA_INSPECTED_WITH_EXACT_RCC_REQUEST")
    print(json.dumps({"case":selected["case_id"],"rcc_prepared":rcc["prepared"],
          "native_cda":report["route"]["native_cda_verified"],
          "candidate_selected":linkage["response_exact_native_candidate_selection_proven"],
          "verified_rcc_intent":report["rcc_to_native_execution_intent_proven"],
          "report_sha256":report["report_sha256"]},sort_keys=True))

if __name__=="__main__":
    main()
