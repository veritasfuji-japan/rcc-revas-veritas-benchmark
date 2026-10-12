#!/usr/bin/env python3
"""#340: strict source-candidate selection proof with controlled model decision only.

A controlled model transcript is made solely from the one real upstream RCC
candidate. It is an instrument, not a new authority or independent model proof.
The unmodified RCC request crosses the actual VERITAS /v1/decide API.
"""
from __future__ import annotations
import argparse,base64,hashlib,json,os,sys,secrets,subprocess,tempfile
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from scripts import final128_338_current_rcc_native_refusal_v1 as r338
from scripts import final128_339_current_rcc_real_decide_compatibility_v1 as r339
from scripts import final128_337_current_rcc_main_request_boundary_v1 as r337

CONTRACT=ROOT/"contracts/FINAL128_340_EXACT_RCC_SELECTED_CANDIDATE_LINEAGE_V1.json"
OUT=ROOT/"results/final128-340-exact-rcc-selected-candidate-lineage"
RULE="NATIVE_CDA_CHOSEN_MUST_MATCH_EXACT_RCC_SELECTED_OPTION_WITHOUT_NATIVE_AUTHORITY_PROMOTION"
BEN="ba2469ca35a19f4db7e62fe42975a0307213cafc"
class Refused(ValueError):pass

def ensure(ok,reason):
    if not ok:raise Refused(reason)

def read(path):return json.loads(Path(path).read_text(encoding="utf-8"))
def canon(value):return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(",",":"),allow_nan=False).encode("utf-8")
def sha(value):return hashlib.sha256(canon(value)).hexdigest()

def contract_check(c):
    ensure(c["rule_of_one"]==RULE and c["parent_main_sha"]==BEN
        and c["source_upstream_rcc_sha"]==r339.PIN_RCC
        and c["source_veritas_os_sha"]==r339.PIN_VERITAS
        and c["origin_candidate_mutation"] is False
        and c["native_chosen_must_match_original_rcc_candidate_id"] is True
        and c["native_chosen_must_match_original_rcc_candidate_canonical_description"] is True
        and c["require_verified_native_cda"] is True
        and c["require_selected_action_evidence"] is False
        and c["controlled_selector_can_create_execution_authority"] is False
        and c["control_provider_mode"]=="in-memory exact-origin-candidate transcription to controlled LLM seam"
        and c["nonclaims"]=={
            "real_model_calls":0,"real_external_effects":0,"native_bind_invocations":0,
            "native_authorization_issuance":0,"native_authorization_consumption":0,
            "official_final128_scoring":0,"production_authority":False,
            "actual_native_execution_intent_proven":False,
            "independent_model_selection_proven":False}
        and c["historical_v13"]=={"arm_a_utility":93,"arm_b_utility":64,
                                 "arm_b_injection_success":0},
        "340_CONTRACT_AUTHORITY_CLAIM_DRIFT")
    return c

def build_control_transcript(request):
    """No invented candidate or authority. Only select exactly the given alt."""
    ensure(set(request)=={"query","context","alternatives"} and len(request["alternatives"])==1,
           "340_SOURCE_REQUEST_SHAPE_CHANGED")
    alt=request["alternatives"][0]
    origin=request["context"]["rcc_revas"]["candidate"]
    ensure(alt["description"]==r337.canon(origin).decode("utf-8")
           and alt["id"]=="rcc-candidate:"+request["context"]["rcc_revas"]["candidate_semantic_hash"],
           "340_CONTROL_TRANSCRIPT_UNBOUND_TO_ORIGINAL")
    step={"id":alt["id"],"title":alt["title"],"description":alt["description"]}
    transcript=json.dumps({"steps":[step],"text":"Evaluate precisely the only presented RCC governance candidate; no execution."},
        ensure_ascii=False,separators=(",",":"))
    return {"provider_mode":"controlled_selected_original_rcc_candidate_only",
            "response":{"content":transcript,"text":transcript}}

def check_selection(request,chosen,cda):
    """Verify exact original option identity and CDA binding after native route."""
    from veritas_os.governance.canonical_decision_artifact import verify_canonical_decision_artifact
    ensure(type(chosen) is dict,"340_CHOSEN_NOT_OBJECT")
    cda_checked=verify_canonical_decision_artifact(cda)
    ensure(cda_checked.is_valid and cda_checked.artifact is not None,
           "340_NATIVE_CDA_INVALID")
    alt=request["alternatives"][0]
    origin=request["context"]["rcc_revas"]["candidate"]
    identity={
        "source_candidate_semantic_hash":request["context"]["rcc_revas"]["candidate_semantic_hash"],
        "candidate_raw_object_sha256":sha(origin),
        "source_alternative_id":alt["id"],
        "source_alternative_description_sha256":hashlib.sha256(alt["description"].encode("utf-8")).hexdigest(),
        "native_selected_id":chosen.get("id"),
        "native_selected_description_sha256":hashlib.sha256(str(chosen.get("description","")).encode("utf-8")).hexdigest(),
        "selected_id_exact":chosen.get("id")==alt["id"],
        "selected_canonical_description_exact":chosen.get("description")==alt["description"],
        "native_cda_verified":True,
        "native_cda_chosen_hash":cda_checked.artifact.decision.chosen_binding.sha256,
        "native_cda_decision_id":cda_checked.artifact.decision_id,
        "native_cda_decision_hash":cda_checked.artifact.decision_hash,
        "native_cda_selected_action_evidence":
             cda_checked.artifact.decision.selected_action_evidence is not None,
    }
    return identity,cda_checked.artifact

def child(source_path,output_path,veritas_root):
    request=read(source_path)
    expected_sha=sha(request)
    transcript=build_control_transcript(request)
    sys.path.insert(0,str(veritas_root))
    from scripts import run_decision_to_external_bind_poc as poc
    from veritas_os.core import pipeline
    from veritas_os.core import config as native_config
    from veritas_os.policy.decision_candidate import (
        try_promote_verified_canonical_decision_candidate_to_execution_intent)
    from veritas_os.governance.canonical_decision_artifact import verify_canonical_decision_artifact
    with tempfile.TemporaryDirectory(prefix="rcc340-local-veritas-") as temp:
        runtime=Path(temp)
        poc._configure_environment(runtime,"test-"+secrets.token_urlsafe(24),
            base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"))
        key_id=poc._configure_secure_test_infrastructure(runtime,secrets.token_hex(32))
        bundle=poc._configure_verified_policy_bundle(runtime)
        native_config.cfg=native_config.VeritasConfig()
        ensure(native_config.cfg.api_secret_configured,"340_NATIVE_SECRET_INVALID")
        source_transcript=runtime/"controlled-selection.json"
        source_transcript.write_text(json.dumps(transcript,sort_keys=True),encoding="utf-8")
        actual_requests=[]
        def original_request(current_bundle):
            ensure(current_bundle==bundle,"340_SIGNED_POLICY_BUNDLE_CHANGED")
            actual_requests.append(sha(request))
            return deepcopy(request)
        with (patch.object(poc,"_decision_request_fixture",side_effect=original_request),
              patch.object(poc,"FIXTURE_PATH",source_transcript),
              patch.object(pipeline,"REPLAY_SOURCE_DIR",runtime/"replay-sources")):
            response,pipeline_ok,calls=poc._decide(
                aws_clients=poc._DeterministicAwsClients(
                    poc._DeterministicKmsClient(key_id),
                    poc._DeterministicObjectLockClient()),
                policy_bundle_dir=bundle)
        ensure(actual_requests==[expected_sha],"340_REAL_HTTP_REQUEST_MUTATED")
        ensure(pipeline_ok and calls["kms_sign_calls"]>0
               and calls["object_lock_put_calls"]>0,"340_NATIVE_ROUTE_OR_CDA_PIPELINE_NOT_OBSERVED")
        identity,verified_cda=check_selection(request,response.get("chosen"),
            response.get("canonical_decision_artifact"))
        # Absolutely do not invent actor/target/human receipt/required authority.
        promotion=try_promote_verified_canonical_decision_candidate_to_execution_intent(
            response.get("chosen",{}),canonical_decision_artifact=verified_cda)
        ensure(not promotion.promoted and promotion.execution_intent is None,
               "340_UNEXPECTED_EXECUTION_INTENT_NEEDS_SEPARATE_AUTHORITY_PROOF")
        identity.update({
            "actual_http_route_exercised":True,
            "real_kernel_observed":True,
            "controlled_provider_transcript_hash":sha(transcript),
            "real_provider_network_requests":0,
            "synthetic_kms_sign_calls":calls["kms_sign_calls"],
            "synthetic_worm_put_calls":calls["object_lock_put_calls"],
            "native_promotion_result":"REFUSED_NO_EXECUTION_INTENT",
            "native_promotion_reasons":list(promotion.refusal_reason_codes),
            "native_actionability_status":response.get("actionability_status"),
            "native_decision_status":response.get("decision_status"),
            "native_business_decision":response.get("business_decision"),
        })
    output_path.write_text(json.dumps(identity,indent=2,sort_keys=True)+"\n",encoding="utf-8")

def verify_report(report):
    c=contract_check(read(CONTRACT))
    ensure(report["scope"]==c["nonclaims"] and report["parent_sha"]==BEN
           and report["origin_rcc_sha"]==r339.PIN_RCC
           and report["veritas_sha"]==r339.PIN_VERITAS
           and report["cases"]["registered"]==36
           and report["cases"]["prepared"]+report["cases"]["withheld"]==36
           and report["selected"]["native_cda_verified"]
           and report["selected"]["selected_id_exact"]
           and report["selected"]["selected_canonical_description_exact"]
           and report["selected"]["actual_http_route_exercised"]
           and report["selected"]["real_kernel_observed"]
           and report["selected"]["real_provider_network_requests"]==0
           and report["selected"]["native_promotion_result"]=="REFUSED_NO_EXECUTION_INTENT"
           and report["trusted_authority_issued"] is False
           and report["native_bind_invoked"] is False
           and report["real_external_effects"]==0
           and report["native_verified_execution_intent"] is None,
           "340_SELECTED_CANDIDATE_CONTINUITY_OR_AUTHORITY_SCOPE_NOT_PROVEN")
    return True

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--upstream-root",type=Path)
    p.add_argument("--veritas-root",type=Path,required=True)
    p.add_argument("--output-dir",type=Path)
    p.add_argument("--child-request",type=Path)
    p.add_argument("--child-result",type=Path)
    a=p.parse_args()
    if a.child_request:
        child(a.child_request,a.child_result,a.veritas_root.resolve());return
    r337.forbid_credentials()
    c=contract_check(read(CONTRACT))
    veritas_root=r339.verify_os(a.veritas_root,c if False else
        r339.contract_check(r338.read_json(r339.CONTRACT_PATH)))
    out=a.output_dir.resolve()
    ensure(out==OUT.resolve() and not out.exists(),"340_FIXED_FRESH_OUTPUT_REQUIRED")
    out.mkdir(parents=True)
    row,handoff,native,accounting=r338.execute_rcc(a.upstream_root,out)
    r337.verify_one_prepared(row,handoff,out/"rcc-run",native)
    request=row["request"]
    ensure(row["case_id"]==min(x["case_id"] for x in
        r337.read_jsonl(out/"prepared/veritas_decide_requests.jsonl")),
        "340_NOT_FIRST_RELEASED_CASE")
    ensure(request["context"]["rcc_revas"]["candidate"]==
        handoff["rcc_revas"]["adoption"]["selected_candidate"],
        "340_RCC_SELECTED_CANDIDATE_SUBSTITUTION")
    source_path=out/"exact-rcc-request.json"
    source_path.write_text(json.dumps(request,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    output_path=out/"native-selected.json"
    env=dict(os.environ)
    env["PYTHONPATH"]=str(veritas_root)+os.pathsep+str(ROOT)
    executed=subprocess.run([sys.executable,str(Path(__file__).resolve()),
         "--child-request",str(source_path),"--child-result",str(output_path),
         "--veritas-root",str(veritas_root)],
         cwd=veritas_root,env=env,capture_output=True,text=True,timeout=180)
    if executed.returncode:
        print("340_ACTUAL_NATIVE_CHILD_FAILED",file=sys.stderr)
        print(executed.stderr[-5000:],file=sys.stderr)
        raise Refused("340_ROUTE_CHILD_FAILED")
    selected=read(output_path)
    report={
        "schema":c["schema"],"rule_of_one":RULE,"parent_sha":BEN,
        "origin_rcc_sha":r339.PIN_RCC,"veritas_sha":r339.PIN_VERITAS,
        "case_id":row["case_id"],
        "cases":{"registered":36,"prepared":accounting["prepared"],
                 "withheld":accounting["withheld"]},
        "rcc_candidate_semantic_hash":row["request_proof"]["candidate_semantic_hash"],
        "original_request_sha256":sha(request),"selected":selected,
        "scope":c["nonclaims"],
        "trusted_authority_issued":False,"native_bind_invoked":False,
        "real_external_effects":0,"native_verified_execution_intent":None,
        "historical_v13_reference_only":c["historical_v13"],
        "selection_model":"CONTROLLED_TEST_TRANSCRIPT_NOT_INDEPENDENT_MODEL",
    }
    report["report_sha256"]=sha(report)
    (out/"report.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    verify_report(report)
    print("FINAL128_340_EXACT_RCC_ORIGIN_NATIVE_CDA_CHOSEN_BOUND_NO_AUTHORITY_ISSUED")
    print(json.dumps({"case":report["case_id"],"selected_id_exact":selected["selected_id_exact"],
            "selected_description_exact":selected["selected_canonical_description_exact"],
            "native_cda_verified":selected["native_cda_verified"],
            "native_promotion":selected["native_promotion_result"],
            "report_sha256":report["report_sha256"]},sort_keys=True))

if __name__=="__main__":main()
