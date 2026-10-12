#!/usr/bin/env python3
"""#343: source-bound RCC → preissued offline voucher → actual native CDA and promotion.

The offline test issuer's signing key NEVER enters this code, its subprocess,
or CI. The native PoC still uses its own deterministic *synthetic* KMS/WORM
adapters for local CDA testing; this is not real operational authorization.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from datetime import datetime, UTC, timedelta
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
from scripts import final128_337_current_rcc_main_request_boundary_v1 as r337
from scripts import final128_338_current_rcc_native_refusal_v1 as r338
from scripts import final128_339_current_rcc_real_decide_compatibility_v1 as r339
from scripts import final128_341_rcc_signed_test_mandate_native_promotion_v1 as r341
from scripts import final128_342_offline_preissued_test_issuer_verifier_v1 as r342

CONTRACT=ROOT/"contracts/FINAL128_343_OFFLINE_VOUCHER_NATIVE_CDA_PROMOTION_V1.json"
OUT=ROOT/"results/final128-343-offline-native-cda-promotion"
MAIN="320b52ade0d346756a72f03c048fa072804207cd"
RULE="PINNED_PREISSUED_OFFLINE_TEST_ISSUER_RCCR_SOURCE_NATIVE_CDA_PROMOTION_SINGLE_LINEAGE"
LIMITS={
    "real_external_provider_calls":0,"real_external_effects":0,
    "native_v2_authorizations_issued":0,"native_v2_bind_calls":0,
    "native_authorization_consumptions":0,"real_human_approval_receipts":0,
    "actual_production_authority":False,
    "independent_business_issuer_verified":False,
    "independent_model_choice_verified":False,
    "official_final128_scores_recomputed":False,
}

class Refused(ValueError):
    pass

def require(ok,reason):
    if not ok:raise Refused(reason)

def read(p):
    return r342.unique_json(Path(p))

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode("utf-8")

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def contract_check(c):
    previous=r342.contract_check(r342.unique_json(r342.CONTRACT))
    require(type(c) is dict
      and c["schema"]=="veritas.final128.offline-voucher-to-native-cda-promotion.v1"
      and c["rule_of_one"]==RULE and c["base_main_sha"]==MAIN
      and c["rcc_sha"]==r339.PIN_RCC and c["veritas_sha"]==r339.PIN_VERITAS
      and c["source_case_id"]==previous["case_id"]
      and c["offline_voucher_sha256"]==previous["frozen_voucher_sha256"]
      and c["offline_public_key_sha256"]==previous["trust_anchor_public_key_sha256"]
      and c["issuer_private_key_generated_in_ci"] is False
      and c["issuer_signature_generated_in_ci"] is False
      and c["frozen_fixture_only"] is True
      and c["source_candidate_from_rcc"] is True
      and c["controlled_model_transcript_only"] is True
      and c["native_route"]=="POST /v1/decide"
      and c["require_independent_native_cda_verification"] is True
      and c["require_native_selected_action_hash_exact"] is True
      and c["require_native_promotion_packet_verification"] is True
      and c["must_reject_untrusted_rcc_without_offline_voucher"] is True
      and c["must_reject_wrong_scope_or_target"] is True
      and c["must_reject_expired_or_altered_voucher"] is True
      and c["never_treat_required_human_approval_as_granted"] is True
      and c["limits"]==LIMITS
      and c["historical_v13_reference_only"]=={
          "a_utility":93,"b_utility":64,"b_injection_success":0},
      "343_OFFLINE_TRUST_CONTRACT_OR_NONCLAIMS_DRIFT")
    return c

def verified_voucher_for_source(source,contract=None,voucher=None,*,at=None):
    c342=r342.contract_check(r342.unique_json(r342.CONTRACT))
    if contract is None:
        contract=contract_check(read(CONTRACT))
    else:
        contract_check(contract)
    if voucher is None:
        voucher=r342.unique_json(r342.VOUCHER)
    verified=r342.verify_voucher(voucher,c342,source,at=at,strict_frozen=True)
    require(verified["issuer_private_key_loaded"] is False
            and verified["signature_verified"] is True
            and verified["trust_anchor_pinned"] is True
            and verified["voucher_sha256"]==contract["offline_voucher_sha256"]
            and verified["issuer_public_key_sha256"]==contract["offline_public_key_sha256"],
            "343_OFFLINE_VOUCHER_TRUST_NOT_PROVEN")
    return verified

def mapped_test_candidate(source,verified):
    c342=r342.contract_check(r342.unique_json(r342.CONTRACT))
    return r342.offline_candidate(source,verified,c342)

def validate_source_and_candidate(source,original,verified):
    from veritas_os.policy.decision_candidate import (
        validate_decision_candidate,hash_decision_candidate)
    require(type(original) is dict
          and type(original.get("alternatives")) is list
          and len(original["alternatives"])==1
          and original["alternatives"][0]["description"]==r337.canon(source).decode("utf-8")
          and original["alternatives"][0]["id"]==
             "rcc-candidate:"+original["context"]["rcc_revas"]["candidate_semantic_hash"],
          "343_ORIGINAL_RCC_REQUEST_IDENTITY_LOST")
    baseline=r341.untrusted_candidate(source,digest(source))
    v=validate_decision_candidate(baseline)
    require(not v.promotable and v.fail_closed
       and "DECISION_CANDIDATE_AUTHORITY_UNSPECIFIED" in v.reason_codes
       and "DECISION_CANDIDATE_HUMAN_APPROVAL_UNCLEAR" in v.reason_codes,
       "343_UNVERIFIED_RCC_MUST_REMAIN_REFUSED")
    candidate=mapped_test_candidate(source,verified)
    valid=validate_decision_candidate(candidate)
    mandate=r342.contract_check(r342.unique_json(r342.CONTRACT))["mandate"]
    action=r341.verify_declared_action(source,mandate)
    require(valid.promotable and candidate.candidate_id==source["candidate_id"]
            and candidate.actor_identity==action["actor_identity"]
            and candidate.target_system==action["target_system"]
            and candidate.target_resource==action["target_resource"]
            and candidate.intended_action==action["canonical_action"]
            and candidate.action_type==action["action_class"]
            and candidate.required_authority==mandate["test_authority_grant"]
            and candidate.required_human_approval is True
            and candidate.metadata["real_world_authorization"] is False
            and candidate.metadata["rcc_original_candidate_sha256"]==digest(source)
            and candidate.metadata["offline_fixture_voucher_sha256"]==verified["voucher_sha256"],
            "343_TYPED_RCCR_ACTION_OR_TEST_SCOPE_MISMATCH")
    return candidate,hash_decision_candidate(candidate)

def build_derived_native_request(original,candidate):
    """Keep the original request *separate* from derived action option."""
    option={
        **candidate.to_dict(),
        "id":original["alternatives"][0]["id"],
        "title":original["alternatives"][0]["title"],
        "description":original["alternatives"][0]["description"],
        "score":1.0,
    }
    derived=deepcopy(original)
    derived["alternatives"]=[option]
    return derived,option

def controlled_transcript(option):
    # The response selects the option supplied to real native route; it
    # never creates any new signer, approval, or execution authority.
    result=json.dumps({"steps":[deepcopy(option)],
      "text":"Select the exact offline-verified synthetic governance action; no effects."},
      sort_keys=True,separators=(",",":"),ensure_ascii=False)
    return {"provider_mode":"controlled_test_only_no_external_provider",
            "response":{"content":result,"text":result}}

def negative_checks(source,voucher,c342):
    altered=deepcopy(source)
    altered["typed_action"]["target_resource"]="user:attacker"
    try:r342.verify_voucher(voucher,c342,altered)
    except r341.Refused:pass
    else:raise Refused("343_SOURCE_TARGET_SUBSTITUTION_ACCEPTED")

    altered=deepcopy(source)
    altered["typed_action"]["requested_scope"]=["role:owner"]
    try:r342.verify_voucher(voucher,c342,altered)
    except r341.Refused:pass
    else:raise Refused("343_SOURCE_SCOPE_SUBSTITUTION_ACCEPTED")

    altered=deepcopy(voucher)
    altered["payload"]["mandate"]["canonical_action"]="grant_unauthorized_scope"
    try:r342.verify_voucher(altered,c342,source)
    except r342.Refused:pass
    else:raise Refused("343_SIGNED_VOUCHER_MUTATION_ACCEPTED")

    before=r342.when(voucher["payload"]["not_before"])-timedelta(seconds=1)
    try:r342.verify_voucher(voucher,c342,source,at=before)
    except r342.Refused:pass
    else:raise Refused("343_NOT_YET_VALID_VOUCHER_ACCEPTED")

    expired=r342.when(voucher["payload"]["expires_at"])
    try:r342.verify_voucher(voucher,c342,source,at=expired)
    except r342.Refused:pass
    else:raise Refused("343_EXPIRED_VOUCHER_ACCEPTED")
    return True

def native_child(original_path,result_path,veritas_root):
    c=contract_check(read(CONTRACT))
    original=read(original_path)
    source=original["context"]["rcc_revas"]["candidate"]
    c342=r342.contract_check(r342.unique_json(r342.CONTRACT))
    voucher=r342.unique_json(r342.VOUCHER)
    require(source["candidate_id"]=="candidate:"+c["source_case_id"],
            "343_RCCR_CANDIDATE_CASE_ID_MISMATCH")
    negative_checks(source,voucher,c342)
    proof=verified_voucher_for_source(source,c,voucher)
    sys.path.insert(0,str(veritas_root))
    from scripts import run_decision_to_external_bind_poc as poc
    from veritas_os.core import pipeline,config as native_config
    from veritas_os.policy.decision_candidate import (
        hash_decision_candidate,
        try_promote_verified_canonical_decision_candidate_to_execution_intent)
    from veritas_os.policy.canonical_verified_decision_promotion import (
        build_canonical_verified_decision_promotion_packet,
        verify_canonical_verified_decision_promotion_packet)
    from veritas_os.governance.canonical_decision_artifact import verify_canonical_decision_artifact
    candidate,native_hash=validate_source_and_candidate(source,original,proof)
    derived,option=build_derived_native_request(original,candidate)
    derived_sha=digest(derived)
    transcript=controlled_transcript(option)

    with tempfile.TemporaryDirectory(prefix="rcc343-local-native-") as directory:
        runtime=Path(directory)
        poc._configure_environment(runtime,"test-"+secrets.token_urlsafe(24),
             base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"))
        key_id=poc._configure_secure_test_infrastructure(runtime,secrets.token_hex(32))
        bundle=poc._configure_verified_policy_bundle(runtime)
        native_config.cfg=native_config.VeritasConfig()
        require(native_config.cfg.api_secret_configured,
                "343_NATIVE_SECURE_RUNTIME_ENV_NOT_CONFIGURED")
        fixture=runtime/"transcript.json"
        fixture.write_text(json.dumps(transcript,sort_keys=True),encoding="utf-8")
        observed_requests=[]
        def derived_request(signed_policy_bundle):
            require(signed_policy_bundle==bundle,
                    "343_NATIVE_SIGNED_POLICY_SUBSTITUTED")
            observed_requests.append(digest(derived))
            return deepcopy(derived)
        with (patch.object(poc,"_decision_request_fixture",side_effect=derived_request),
              patch.object(poc,"FIXTURE_PATH",fixture),
              patch.object(pipeline,"REPLAY_SOURCE_DIR",runtime/"replay-sources")):
            response,kernel_ok,infra=poc._decide(
                aws_clients=poc._DeterministicAwsClients(
                    poc._DeterministicKmsClient(key_id),
                    poc._DeterministicObjectLockClient()),
                policy_bundle_dir=bundle)
        require(observed_requests==[derived_sha] and kernel_ok
                and infra["kms_sign_calls"]>0 and infra["object_lock_put_calls"]>0,
                "343_ACTUAL_NATIVE_DECIDE_KERNEL_CDA_SIGNING_NOT_OBSERVED")
        chosen=response.get("chosen")
        require(type(chosen) is dict
                and chosen.get("id")==option["id"]
                and chosen.get("description")==option["description"]
                and chosen.get("candidate_id")==source["candidate_id"]
                and chosen.get("actor_identity")==source["typed_action"]["actor_identity"]
                and chosen.get("target_resource")==source["typed_action"]["target_resource"],
                "343_ACTUAL_NATIVE_CHOSEN_NOT_EXACT_RCCR_SOURCE")
        checked=verify_canonical_decision_artifact(
            response.get("canonical_decision_artifact"))
        require(checked.is_valid and checked.artifact is not None,
                "343_NATIVE_CDA_VERIFICATION_FAILED")
        cda=checked.artifact
        action=cda.decision.selected_action_evidence
        policy=cda.decision.policy_snapshot_evidence
        require(action is not None and
                action.chosen_binding_sha256==cda.decision.chosen_binding.sha256
                and action.candidate_hash==native_hash
                and hash_decision_candidate(chosen)==native_hash
                and policy is not None and policy.signature_verified is True,
                "343_NATIVE_CDA_SELECTED_ACTION_OR_POLICY_LINEAGE_INCOMPLETE")
        promoted=try_promote_verified_canonical_decision_candidate_to_execution_intent(
            chosen,canonical_decision_artifact=cda)
        require(promoted.promoted and promoted.execution_intent is not None,
                "343_NATIVE_VERIFIED_CDA_SCHEMA_PROMOTION_FAILED")
        intent=promoted.execution_intent
        require(intent.actor_identity==source["typed_action"]["actor_identity"]
            and intent.target_system==source["typed_action"]["target_system"]
            and intent.target_resource==source["typed_action"]["target_resource"]
            and intent.intended_action==source["typed_action"]["canonical_action"]
            and intent.decision_id==cda.decision_id
            and intent.decision_hash==cda.decision_hash
            and intent.request_id==cda.request_id
            and intent.approval_context is None,
            "343_NATIVE_EI_SOURCE_OR_APPROVAL_ASSUMPTION_MISMATCH")
        packet=build_canonical_verified_decision_promotion_packet(
            cda,chosen,promoted_at=datetime.now(UTC),ttl_seconds=300)
        validated=verify_canonical_verified_decision_promotion_packet(packet)
        require(validated.promotion_hash==packet.promotion_hash
            and validated.candidate_hash==native_hash
            and validated.canonical_decision_hash==cda.decision_hash,
            "343_NATIVE_EXECUTION_INTENT_PACKET_VERIFICATION_FAILED")

        untrusted=r341.untrusted_candidate(source,digest(source))
        negative=try_promote_verified_canonical_decision_candidate_to_execution_intent(
            untrusted.to_dict(),canonical_decision_artifact=cda)
        require(not negative.promoted and negative.execution_intent is None,
                "343_UNTRUSTED_RCCR_CANDIDATE_PROMOTED_POST_CDA")
        changed=deepcopy(chosen)
        changed["target_resource"]="user:attacker"
        negative2=try_promote_verified_canonical_decision_candidate_to_execution_intent(
            changed,canonical_decision_artifact=cda)
        require(not negative2.promoted and negative2.execution_intent is None,
                "343_CHANGED_TARGET_PROMOTED_POST_CDA")

        result={
          "source_candidate_sha256":digest(source),
          "source_typed_action_sha256":digest(source["typed_action"]),
          "source_candidate_semantic_hash":original["context"]["rcc_revas"]["candidate_semantic_hash"],
          "original_request_sha256":digest(original),
          "derived_native_request_sha256":derived_sha,
          "derived_request_explicit_and_source_request_immutable":True,
          "offline_voucher_sha256":proof["voucher_sha256"],
          "offline_public_key_sha256":proof["issuer_public_key_sha256"],
          "offline_signature_verified":True,
          "offline_issuer_private_key_used":False,
          "offline_issuer_signature_minted_at_runtime":False,
          "offline_test_only":True,
          "negative_mutated_voucher_rejected":True,
          "negative_expired_or_early_voucher_rejected":True,
          "negative_source_scope_or_target_rejected":True,
          "untrusted_rcc_without_voucher_refused":True,
          "local_native_http_route_executed":True,
          "local_native_kernel_executed":kernel_ok,
          "controlled_model_only":True,
          "synthetic_kms_sign_calls":infra["kms_sign_calls"],
          "synthetic_worm_put_calls":infra["object_lock_put_calls"],
          "native_cda_verified":True,
          "native_cda_selected_action_verified":True,
          "native_cda_decision_id":cda.decision_id,
          "native_cda_decision_hash":cda.decision_hash,
          "native_cda_request_id":cda.request_id,
          "native_selected_action_candidate_hash":action.candidate_hash,
          "native_candidate_hash":native_hash,
          "native_execution_intent_schema_promotion":True,
          "native_execution_intent_decision_lineage_exact":True,
          "native_verified_promotion_packet":True,
          "native_verified_promotion_packet_hash":validated.promotion_hash,
          "native_verified_promotion_candidate_hash":validated.candidate_hash,
          "native_required_human_approval_not_granted":True,
          "untrusted_rcc_post_cda_refused":True,
          "tampered_native_candidate_post_cda_refused":True,
          "live_operator_authorization_proven":False,
          "real_external_effects":0,
        }
    result_path.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf-8")

def verify_report(report):
    c=contract_check(read(CONTRACT))
    x=report["observed"]
    required_true=(
       "derived_request_explicit_and_source_request_immutable",
       "offline_signature_verified","offline_test_only",
       "negative_mutated_voucher_rejected",
       "negative_expired_or_early_voucher_rejected",
       "negative_source_scope_or_target_rejected",
       "untrusted_rcc_without_voucher_refused",
       "local_native_http_route_executed","local_native_kernel_executed",
       "controlled_model_only","native_cda_verified",
       "native_cda_selected_action_verified",
       "native_execution_intent_schema_promotion",
       "native_execution_intent_decision_lineage_exact",
       "native_verified_promotion_packet",
       "native_required_human_approval_not_granted",
       "untrusted_rcc_post_cda_refused",
       "tampered_native_candidate_post_cda_refused",
    )
    require(report["schema"]==c["schema"] and report["rule_of_one"]==RULE
        and report["base_main_sha"]==MAIN
        and report["rcc_sha"]==r339.PIN_RCC
        and report["veritas_sha"]==r339.PIN_VERITAS
        and report["case_id"]==c["source_case_id"]
        and report["case_counts"]["registered"]==36
        and report["case_counts"]["prepared"]+report["case_counts"]["withheld"]==36
        and report["nonclaims"]==LIMITS
        and all(x[k] is True for k in required_true)
        and x["offline_voucher_sha256"]==c["offline_voucher_sha256"]
        and x["offline_public_key_sha256"]==c["offline_public_key_sha256"]
        and x["offline_issuer_private_key_used"] is False
        and x["offline_issuer_signature_minted_at_runtime"] is False
        and x["live_operator_authorization_proven"] is False
        and x["native_candidate_hash"]==x["native_selected_action_candidate_hash"]
        and x["native_candidate_hash"]==x["native_verified_promotion_candidate_hash"]
        and x["synthetic_kms_sign_calls"]>0
        and x["synthetic_worm_put_calls"]>0
        and x["real_external_effects"]==0,
        "343_OFFLINE_RCCR_NATIVE_CDA_PROMOTION_PROOF_FAIL_CLOSED")
    return True

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--upstream-root",type=Path)
    p.add_argument("--veritas-root",type=Path,required=True)
    p.add_argument("--output-dir",type=Path)
    p.add_argument("--child-original",type=Path)
    p.add_argument("--child-result",type=Path)
    a=p.parse_args()
    if a.child_original:
        native_child(a.child_original,a.child_result,a.veritas_root.resolve());return

    r337.forbid_credentials()
    c=contract_check(read(CONTRACT))
    osroot=r339.verify_os(
        a.veritas_root,r339.contract_check(r338.read_json(r339.CONTRACT_PATH)))
    out=a.output_dir.resolve()
    require(out==OUT.resolve() and not out.exists(),
            "343_FIXED_FRESH_OUT_REQUIRED")
    out.mkdir(parents=True)
    _first,_handoff,native,account=r338.execute_rcc(a.upstream_root,out)
    c342=r342.contract_check(r342.unique_json(r342.CONTRACT))
    selected=r341.selected_case(out,c342["mandate"])
    require(selected["case_id"]==c["source_case_id"],
            "343_OFFLINE_VOUCHER_CASE_ID_NOT_SOURCE_RELEASE")
    handoffs={row["rcc_revas"]["audit"]["case_id"]:row for row in
              r337.read_jsonl(out/"rcc-run/handoff_results.jsonl")}
    require(selected["case_id"] in handoffs,
            "343_RCC_ORIGINAL_HANDOFF_MISSING")
    r337.verify_one_prepared(selected,handoffs[selected["case_id"]],
                             out/"rcc-run",native)
    source=selected["request"]["context"]["rcc_revas"]["candidate"]
    require(source==handoffs[selected["case_id"]]["rcc_revas"]["adoption"]["selected_candidate"],
            "343_RCC_SELECTED_ORIGINAL_SOURCE_SUBSTITUTED")
    verified_voucher_for_source(source,c)
    original=out/"original-rcc-request.json"
    original.write_text(json.dumps(selected["request"],sort_keys=True,indent=2)+"\n",
                        encoding="utf-8")
    child_result=out/"native-offline-promotion.json"
    env=dict(os.environ)
    env["PYTHONPATH"]=str(osroot)+os.pathsep+str(ROOT)
    run=subprocess.run([sys.executable,str(Path(__file__).resolve()),
       "--child-original",str(original),"--child-result",str(child_result),
       "--veritas-root",str(osroot)],
       cwd=osroot,env=env,capture_output=True,text=True,timeout=240)
    if run.returncode:
        print("343_NATIVE_OFFLINE_INTEGRATION_CHILD_FAILED",file=sys.stderr)
        print(run.stderr[-9500:],file=sys.stderr)
        raise Refused("343_ACTUAL_NATIVE_DECIDE_PROMOTION_SUBPROCESS_FAILED")
    report={
       "schema":c["schema"],"rule_of_one":RULE,
       "base_main_sha":MAIN,
       "rcc_sha":r339.PIN_RCC,"veritas_sha":r339.PIN_VERITAS,
       "case_id":selected["case_id"],
       "case_counts":{"registered":36,"prepared":account["prepared"],
                      "withheld":account["withheld"]},
       "nonclaims":c["limits"],
       "observed":read(child_result),
       "historical_v13_reference_only":c["historical_v13_reference_only"],
       "issuer_trust_boundary":"PREISSUED_OFFLINE_AUTHOR_CONTROLLED_SYNTHETIC_FIXTURE_NOT_ENTERPRISE_AUTHORITY",
    }
    verify_report(report)
    report["report_sha256"]=digest(report)
    (out/"report.json").write_text(
        json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("FINAL128_343_OFFLINE_PREISSUED_RCCR_CDA_NATIVE_EI_PACKET_VERIFIED_NO_ISSUER_MINTING_NO_EFFECT")
    print(json.dumps({
      "case_id":report["case_id"],
      "offline_signature":True,"real_native_cda":True,
      "native_ei_packet":True,"issuer_private_key_in_ci":False,
      "real_operator_authority":False,
      "report_sha256":report["report_sha256"]},sort_keys=True))

if __name__=="__main__":
    main()
