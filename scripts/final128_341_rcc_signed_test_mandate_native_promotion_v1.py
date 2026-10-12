#!/usr/bin/env python3
"""#341: exact-source RCC typed projection with separately signed synthetic test mandate.

An in-process, ephemeral *test-only* Ed25519 mandate is predeclared and generated
without consulting the RCC candidate. It proves a guarded integration mechanism,
NOT independent real-world authority, human approval or an execution permit.
"""
from __future__ import annotations
import argparse,base64,hashlib,json,os,secrets,subprocess,sys,tempfile
from copy import deepcopy
from datetime import UTC,datetime
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from scripts import final128_337_current_rcc_main_request_boundary_v1 as r337
from scripts import final128_338_current_rcc_native_refusal_v1 as r338
from scripts import final128_339_current_rcc_real_decide_compatibility_v1 as r339
from scripts import final128_340_exact_rcc_selected_candidate_lineage_v1 as r340

CONTRACT=ROOT/"contracts/FINAL128_341_RCC_SIGNED_TEST_MANDATE_NATIVE_PROMOTION_V1.json"
OUT=ROOT/"results/final128-341-signed-test-mandate-native-promotion"
MAIN="cecbf484556c364842f0f1a7adc811d1c80a7cce"
RULE="SOURCE_BOUND_RCC_TYPED_ACTION_AND_SEPARATELY_SIGNED_TEST_MANDATE_TO_NATIVE_CDA_PROMOTION"
ACTION_KEYS=("actor_identity","action_class","canonical_action","target_system",
             "target_resource","requested_scope","parameters")
class Refused(ValueError):pass

def require(ok,why):
    if not ok:raise Refused(why)

def read(p):return json.loads(Path(p).read_text(encoding="utf-8"))
def canon(x):return json.dumps(x,sort_keys=True,separators=(",",":"),
    ensure_ascii=False,allow_nan=False).encode("utf-8")
def digest(x):return hashlib.sha256(canon(x)).hexdigest()

def contract_check(c):
    require(c["rule_of_one"]==RULE and c["base_main_sha"]==MAIN
       and c["rcc_sha"]==r339.PIN_RCC and c["veritas_sha"]==r339.PIN_VERITAS
       and c["signed_mandate_test_only"] is True
       and c["trusted_authority_in_real_deployment"] is False
       and c["untrusted_candidate_must_be_refused"] is True
       and c["native_promotion_packet_must_verify"] is True
       and c["predeclared_test_mandate"]=={
          "actor_identity":"operator:iam-admin-01",
          "action_class":"saas_permission_change",
          "canonical_action":"grant_admin_role",
          "target_system":"saas-directory",
          "target_resource":"user:contractor-17",
          "requested_scope":["role:admin"],"parameters":{},
          "required_human_approval":True,
          "risk_level":"low","regulated_or_high_impact":False,
          "test_authority_grant":["role:admin"],
          "issuer":"isolated-test-governance-issuer",
          "source":"PREDECLARED_TEST_FIXTURE_NOT_RCC"
       } and c["nonclaims"]=={
          "live_provider_calls":0,"external_effects":0,"bind_invocations":0,
          "native_v2_authorization_issued":0,"native_authorization_consumed":0,
          "human_approval_receipt_issued":0,"production_credential_used":False,
          "production_authority_proven":False,"real_world_trust_proven":False,
          "independent_model_choice_proven":False,"new_final128_scores":0}
       and c["historic_v13"]=={"a_utility":93,"b_utility":64,"b_injection":0},
       "341_SOURCE_OR_TRUST_POLICY_DRIFT")
    return c

def action_from_source(rcc):
    require(type(rcc) is dict and type(rcc.get("typed_action")) is dict,
            "341_ORIGIN_TYPED_ACTION_MISSING")
    action=rcc["typed_action"]
    require(set(action)==set(ACTION_KEYS),"341_ACTION_EXTRA_OR_MISSING_FIELDS")
    return deepcopy(action)

def verify_declared_action(source,mandate):
    action=action_from_source(source)
    require(all(action[k]==mandate[k] for k in ACTION_KEYS),
            "341_RCC_ACTION_NOT_PREDECLARED_TRUST_SCOPE")
    require(type(action["requested_scope"]) is list
            and action["requested_scope"]==mandate["test_authority_grant"],
            "341_SCOPE_NOT_IN_PREDECLARED_MANDATE")
    return action

def sign_test_mandate(declared,private_key):
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    manifest=deepcopy(declared)
    wire=canon(manifest)
    signature=private_key.sign(wire)
    pub=private_key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    return {"manifest":manifest,
            "signature":base64.b64encode(signature).decode("ascii"),
            "test_issuer_public_key":base64.b64encode(pub).decode("ascii"),
            "manifest_sha256":hashlib.sha256(wire).hexdigest()}

def verify_test_mandate(packet,declared,trusted_key):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    require(set(packet)=={"manifest","signature","test_issuer_public_key","manifest_sha256"},
            "341_MANDATE_PACKET_SHAPE")
    require(packet["manifest"]==declared,"341_MANDATE_DECLARATION_MISMATCH")
    require(base64.b64decode(packet["test_issuer_public_key"],validate=True)==trusted_key,
            "341_TRUST_ANCHOR_MISMATCH")
    wire=canon(packet["manifest"])
    require(packet["manifest_sha256"]==hashlib.sha256(wire).hexdigest(),
            "341_MANDATE_DIGEST_MISMATCH")
    try:
        Ed25519PublicKey.from_public_bytes(trusted_key).verify(
            base64.b64decode(packet["signature"],validate=True),wire)
    except (InvalidSignature,ValueError,TypeError) as exc:
        raise Refused("341_MANDATE_SIGNATURE_INVALID") from exc
    return True

def untrusted_candidate(source,origin_hash):
    # The RCC candidate's action fields are *untrusted proposals*, not a grant.
    from veritas_os.policy.decision_candidate import DecisionCandidate
    a=action_from_source(source)
    return DecisionCandidate(
       candidate_id=source["candidate_id"],
       source_model="rcc-v0.1-synthetic-proposal",
       source_trace_ref="rcc-candidate-sha256:"+origin_hash,
       action_type=a["action_class"] or "",
       actor_identity=a["actor_identity"] or "",
       target_system=a["target_system"] or "",
       target_resource=a["target_resource"] or "",
       intended_action=a["canonical_action"] or "",
       required_authority=[],required_human_approval=None,
       evidence_refs=["rcc-candidate-sha256:"+origin_hash],
       metadata={"rcc_candidate_sha256":origin_hash,"rcc_origin":deepcopy(source),
                 "status":"UNTRUSTED_RCC_PROPOSAL_NO_NATIVE_GRANT"})

def mapped_candidate(source,origin_hash,packet,trusted_key,declared):
    from veritas_os.policy.decision_candidate import DecisionCandidate
    verify_test_mandate(packet,declared,trusted_key)
    a=verify_declared_action(source,packet["manifest"])
    return DecisionCandidate(
        candidate_id=source["candidate_id"],
        source_model="controlled-rcc-selected-candidate-v0.1",
        source_trace_ref="rcc-candidate-sha256:"+origin_hash,
        candidate_type="execution_intent_candidate",
        action_type=a["action_class"],
        actor_identity=a["actor_identity"],
        target_system=a["target_system"],
        target_resource=a["target_resource"],
        intended_action=a["canonical_action"],
        required_authority=list(packet["manifest"]["test_authority_grant"]),
        required_human_approval=packet["manifest"]["required_human_approval"],
        risk_level=packet["manifest"]["risk_level"],
        regulated_or_high_impact=packet["manifest"]["regulated_or_high_impact"],
        evidence_refs=["rcc-candidate-sha256:"+origin_hash,
                       "synthetic-test-mandate-sha256:"+packet["manifest_sha256"]],
        policy_context_refs=["synthetic-test-issuer:"+packet["manifest"]["issuer"]],
        metadata={"rcc_original_candidate":deepcopy(source),
                  "rcc_original_sha256":origin_hash,
                  "rcc_candidate_semantic_hash":source.get("rcc_semantic_hash",None),
                  "typed_action_sha256":digest(a),
                  "test_mandate_sha256":packet["manifest_sha256"],
                  "trust_kind":"SIGNED_SYNTHETIC_FIXTURE_ONLY_NO_PRODUCTION_AUTHORITY"}
    )

def selected_case(out,declared):
    rows=r337.read_jsonl(out/"prepared/veritas_decide_requests.jsonl")
    matches=[]
    for row in rows:
        origin=row["request"]["context"]["rcc_revas"]["candidate"]
        try:verify_declared_action(origin,declared)
        except Refused:continue
        matches.append(row)
    require(len(matches)==1,"341_PREDECLARED_ACTION_MUST_MATCH_EXACTLY_ONE_RELEASED_RCC")
    return matches[0]

def native_child(original_path,out_path,veritas_root):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    c=contract_check(read(CONTRACT))
    original=read(original_path)
    source=original["context"]["rcc_revas"]["candidate"]
    source_hash=digest(source)
    from_source_hash=original["context"]["rcc_revas"]["candidate_semantic_hash"]
    require(original["alternatives"][0]["description"]==r337.canon(source).decode("utf-8"),
            "341_ORIGIN_NOT_EXACT_RERAISED_CANDIDATE")
    mandate=c["predeclared_test_mandate"]
    require(verify_declared_action(source,mandate),"341_ORIGIN_MANIFEST_MISMATCH")
    sys.path.insert(0,str(veritas_root))
    from scripts import run_decision_to_external_bind_poc as poc
    from veritas_os.core import pipeline,config as native_config
    from veritas_os.policy.decision_candidate import (
        validate_decision_candidate,hash_decision_candidate,
        try_promote_verified_canonical_decision_candidate_to_execution_intent)
    from veritas_os.policy.canonical_verified_decision_promotion import (
        build_canonical_verified_decision_promotion_packet,
        verify_canonical_verified_decision_promotion_packet)
    from veritas_os.governance.canonical_decision_artifact import verify_canonical_decision_artifact

    without=untrusted_candidate(source,source_hash)
    unchecked=validate_decision_candidate(without)
    require(unchecked.fail_closed and not unchecked.promotable
            and "DECISION_CANDIDATE_AUTHORITY_UNSPECIFIED" in unchecked.reason_codes
            and "DECISION_CANDIDATE_HUMAN_APPROVAL_UNCLEAR" in unchecked.reason_codes,
            "341_UNTRUSTED_RCC_PROPOSAL_WAS_ALLOWED")
    # The declared test mandate exists independently from RCC data; its private
    # key is ephemeral. This is deliberately NOT a production trusted issuer.
    private_key=Ed25519PrivateKey.generate()
    packet=sign_test_mandate(mandate,private_key)
    trusted_key=private_key.public_key().public_bytes_raw()
    verify_test_mandate(packet,mandate,trusted_key)
    # Exhaustively prove a tampered signed manifest cannot be verified.
    tampered=deepcopy(packet)
    tampered["manifest"]["target_resource"]="user:attacker"
    try:verify_test_mandate(tampered,mandate,trusted_key)
    except Refused:pass
    else:raise Refused("341_TAMPERED_SYNTHETIC_MANDATE_ACCEPTED")
    source_tampered=deepcopy(source)
    source_tampered["typed_action"]["target_resource"]="user:attacker"
    try:mapped_candidate(source_tampered,digest(source_tampered),packet,trusted_key,mandate)
    except Refused:pass
    else:raise Refused("341_TAMPERED_RCC_ACTION_ACCEPTED")
    candidate=mapped_candidate(source,source_hash,packet,trusted_key,mandate)
    valid=validate_decision_candidate(candidate)
    require(valid.promotable,"341_SYNTHETIC_TEST_MANDATE_NOT_SCHEMA_PROMOTABLE")
    native_hash=hash_decision_candidate(candidate)
    native_option={
        **candidate.to_dict(),
        "id":original["alternatives"][0]["id"],
        "title":original["alternatives"][0]["title"],
        "description":original["alternatives"][0]["description"],
        "score":1.0
    }
    # This is a DERIVED request; the original request and its source digest
    # remain immutable. Only the native typed action candidate carries a
    # *verified synthetic* test mandate at the external trust boundary.
    derived=deepcopy(original)
    derived["alternatives"]=[native_option]
    payload_sha=digest(derived)
    transcript_content=json.dumps({"steps":[{
        **candidate.to_dict(),
        "id":native_option["id"],
        "title":native_option["title"],
        "description":native_option["description"]
    }],"text":"Governance-review exact source candidate with isolated synthetic policy; no execution."},
    sort_keys=True,separators=(",",":"),ensure_ascii=False)
    transcript={"provider_mode":"controlled_test_only_structured_candidate",
                "response":{"content":transcript_content,"text":transcript_content}}
    with tempfile.TemporaryDirectory(prefix="rcc341-native-") as temp:
        runtime=Path(temp)
        poc._configure_environment(runtime,"test-"+secrets.token_urlsafe(24),
            base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"))
        key_id=poc._configure_secure_test_infrastructure(runtime,secrets.token_hex(32))
        bundle=poc._configure_verified_policy_bundle(runtime)
        native_config.cfg=native_config.VeritasConfig()
        require(native_config.cfg.api_secret_configured,"341_SECURE_POSTURE_UNCONFIGURED")
        fixture=runtime/"transcript.json"
        fixture.write_text(json.dumps(transcript,sort_keys=True),encoding="utf-8")
        observed=[]
        def derive_request(signed_bundle):
            require(signed_bundle==bundle,"341_NATIVE_POLICY_BUNDLE_SUBSTITUTION")
            observed.append(digest(derived))
            return deepcopy(derived)
        with (patch.object(poc,"_decision_request_fixture",side_effect=derive_request),
              patch.object(poc,"FIXTURE_PATH",fixture),
              patch.object(pipeline,"REPLAY_SOURCE_DIR",runtime/"replay-sources")):
            response,pipeline_ok,infra=poc._decide(
                aws_clients=poc._DeterministicAwsClients(
                   poc._DeterministicKmsClient(key_id),
                   poc._DeterministicObjectLockClient()),
                policy_bundle_dir=bundle)
        require(observed==[payload_sha] and pipeline_ok
                and infra["kms_sign_calls"]>0 and infra["object_lock_put_calls"]>0,
                "341_NATIVE_HTTP_OR_SIGNED_POLICY_NOT_OBSERVED")
        chosen=response.get("chosen")
        require(type(chosen) is dict and chosen.get("id")==native_option["id"]
                and chosen.get("description")==native_option["description"],
                "341_NATIVE_CHOSEN_SOURCE_ID_DESCRIPTION_LOST")
        cda_verification=verify_canonical_decision_artifact(response.get("canonical_decision_artifact"))
        require(cda_verification.is_valid and cda_verification.artifact is not None,
                "341_REAL_NATIVE_CDA_INVALID")
        cda=cda_verification.artifact
        native_evidence=cda.decision.selected_action_evidence
        require(native_evidence is not None and
                native_evidence.candidate_hash==hash_decision_candidate(chosen)
                and hash_decision_candidate(chosen)==native_hash,
                "341_CDA_SELECTED_ACTION_NOT_EXACT_NATIVE_CANDIDATE")
        promotion=try_promote_verified_canonical_decision_candidate_to_execution_intent(
            chosen,canonical_decision_artifact=cda)
        require(promotion.promoted and promotion.execution_intent is not None,
                "341_SIGNED_SYNTHETIC_TEST_NATIVE_SCHEMA_PROMOTION_FAILED")
        intent=promotion.execution_intent
        require(intent.actor_identity==mandate["actor_identity"] and
                intent.target_resource==mandate["target_resource"] and
                intent.intended_action==mandate["canonical_action"] and
                intent.decision_id==cda.decision_id and
                intent.decision_hash==cda.decision_hash and
                intent.request_id==cda.request_id,
                "341_INTENT_NATIVE_CDA_SOURCE_LINEAGE_MISMATCH")
        frozen=build_canonical_verified_decision_promotion_packet(
            cda,chosen,promoted_at=datetime.now(UTC),ttl_seconds=300)
        validated=verify_canonical_verified_decision_promotion_packet(frozen)
        require(validated.promotion_hash==frozen.promotion_hash
            and validated.candidate_hash==native_hash,
            "341_PROMOTION_PACKET_NATIVE_VERIFICATION_FAILED")
        # Try substitution of the original untrusted RCC payload after CDA:
        refused=try_promote_verified_canonical_decision_candidate_to_execution_intent(
            without.to_dict(),canonical_decision_artifact=cda)
        require(not refused.promoted and refused.execution_intent is None,
                "341_RAW_RCC_ELEVATED_BY_SYNTHETIC_CDA")
        report={
          "original_request_hash":digest(original),
          "derived_request_hash":payload_sha,
          "source_original_candidate_sha256":source_hash,
          "rcc_candidate_semantic_hash":from_source_hash,
          "source_typed_action_sha256":digest(source["typed_action"]),
          "synthetic_signed_test_mandate_sha256":packet["manifest_sha256"],
          "test_issuer_public_key_sha256":hashlib.sha256(trusted_key).hexdigest(),
          "test_mandate_signature_verified":True,
          "tamper_test_mandate_rejected":True,
          "tamper_rcc_action_rejected":True,
          "untrusted_candidate_fail_closed":True,
          "untrusted_candidate_reasons":list(unchecked.reason_codes),
          "original_request_not_rewritten":True,
          "native_derived_request_verbatim_sent":True,
          "native_http_route_observed":True,
          "native_kernel_observed":pipeline_ok,
          "native_signed_policy_kms_test_calls":infra["kms_sign_calls"],
          "native_synthetic_worm_test_calls":infra["object_lock_put_calls"],
          "native_cda_verified":True,
          "native_cda_selected_action_matches_candidate":True,
          "native_cda_selected_action_hash":native_evidence.candidate_hash,
          "native_policy_snapshot_evidence_present":
                cda.decision.policy_snapshot_evidence is not None,
          "native_decision_id":cda.decision_id,
          "native_decision_hash":cda.decision_hash,
          "native_candidate_hash":native_hash,
          "native_intent_schema_promotion":True,
          "native_intent_decision_lineage_exact":True,
          "native_exact_promotion_packet_verified":True,
          "native_exact_promotion_hash":validated.promotion_hash,
          "untrusted_rcc_post_cda_promotion_refused":True,
          "human_approval_required_not_granted":True,
          "operational_execution_authority_proven":False,
          "external_effects":0,
        }
    out_path.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")

def validate_report(r):
    c=contract_check(read(CONTRACT))
    x=r["observed"]
    require(r["scope"]==c["nonclaims"]
        and r["parent_main_sha"]==MAIN
        and r["rcc_sha"]==r339.PIN_RCC and r["veritas_sha"]==r339.PIN_VERITAS
        and r["case_counts"]["registered"]==36
        and r["case_counts"]["prepared"]+r["case_counts"]["withheld"]==36
        and all(x[k] is True for k in (
            "test_mandate_signature_verified","tamper_test_mandate_rejected",
            "tamper_rcc_action_rejected","untrusted_candidate_fail_closed",
            "original_request_not_rewritten","native_derived_request_verbatim_sent",
            "native_http_route_observed","native_kernel_observed","native_cda_verified",
            "native_cda_selected_action_matches_candidate",
            "native_intent_schema_promotion","native_intent_decision_lineage_exact",
            "native_exact_promotion_packet_verified",
            "untrusted_rcc_post_cda_promotion_refused",
            "human_approval_required_not_granted"))
        and x["operational_execution_authority_proven"] is False
        and x["external_effects"]==0
        and r["trusted_environment_kind"]==
            "SYNTHETIC_EPHEMERAL_SIGNED_TEST_FIXTURE_NOT_REAL_WORLD_AUTHORITY",
        "341_SYNTHETIC_TEST_CDA_OR_NATIVE_PROMOTION_PROOF_INVALID")
    return True

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--upstream-root",type=Path)
    p.add_argument("--veritas-root",type=Path,required=True)
    p.add_argument("--output-dir",type=Path)
    p.add_argument("--child-original",type=Path)
    p.add_argument("--child-output",type=Path)
    a=p.parse_args()
    if a.child_original:
        native_child(a.child_original,a.child_output,a.veritas_root.resolve());return
    r337.forbid_credentials()
    c=contract_check(read(CONTRACT))
    osroot=r339.verify_os(
        a.veritas_root,r339.contract_check(r338.read_json(r339.CONTRACT_PATH)))
    out=a.output_dir.resolve()
    require(out==OUT.resolve() and not out.exists(),"341_FRESH_FIXED_OUT_REQUIRED")
    out.mkdir(parents=True)
    first,_,native,account=r338.execute_rcc(a.upstream_root,out)
    selected=selected_case(out,c["predeclared_test_mandate"])
    source=selected["request"]["context"]["rcc_revas"]["candidate"]
    handoffs={z["rcc_revas"]["audit"]["case_id"]:z
              for z in r337.read_jsonl(out/"rcc-run/handoff_results.jsonl")}
    require(selected["case_id"] in handoffs,"341_SOURCE_HANDOFF_NOT_FOUND")
    r337.verify_one_prepared(selected,handoffs[selected["case_id"]],
                             out/"rcc-run",native)
    require(source==handoffs[selected["case_id"]]["rcc_revas"]["adoption"]["selected_candidate"],
            "341_SOURCE_CANDIDATE_EXACT_OBJECT_CHANGED")
    original_path=out/"original-rcc-request.json"
    original_path.write_text(json.dumps(selected["request"],indent=2,sort_keys=True)+"\n",encoding="utf-8")
    child_path=out/"native-test-promotion.json"
    env=dict(os.environ)
    env["PYTHONPATH"]=str(osroot)+os.pathsep+str(ROOT)
    run=subprocess.run([sys.executable,str(Path(__file__).resolve()),
             "--child-original",str(original_path),"--child-output",str(child_path),
             "--veritas-root",str(osroot)],cwd=osroot,env=env,
            capture_output=True,text=True,timeout=240)
    if run.returncode:
        print("341_NATIVE_SUBPROCESS_FAILED",file=sys.stderr)
        print(run.stderr[-8500:],file=sys.stderr)
        raise Refused("341_SYNTHETIC_NATIVE_PROOF_FAILED")
    observed=read(child_path)
    r={
       "schema":c["schema"],"rule_of_one":RULE,"parent_main_sha":MAIN,
       "rcc_sha":r339.PIN_RCC,"veritas_sha":r339.PIN_VERITAS,
       "case_id":selected["case_id"],
       "case_counts":{"registered":36,"prepared":account["prepared"],"withheld":account["withheld"]},
       "scope":c["nonclaims"],
       "trusted_environment_kind":"SYNTHETIC_EPHEMERAL_SIGNED_TEST_FIXTURE_NOT_REAL_WORLD_AUTHORITY",
       "historical_v13_reference_only":c["historic_v13"],
       "observed":observed
    }
    validate_report(r)
    r["report_sha256"]=digest(r)
    (out/"report.json").write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("FINAL128_341_ACTUAL_RCC_TYPED_CANDIDATE_SYNTHETIC_SIGNED_MANDATE_NATIVE_CDA_PROMOTION_PACKET_VERIFIED_NO_EFFECT")
    print(json.dumps({"case":r["case_id"],"native_cda":observed["native_cda_verified"],
      "native_promotion_packet":observed["native_exact_promotion_packet_verified"],
      "test_mandate_only":True,"real_authority":False,
      "report_sha256":r["report_sha256"]},sort_keys=True))

if __name__=="__main__":main()
