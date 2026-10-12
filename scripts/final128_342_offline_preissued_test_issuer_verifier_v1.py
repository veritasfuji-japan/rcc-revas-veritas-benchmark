#!/usr/bin/env python3
"""#342 offline-preissued synthetic issuer proof: no signing code or private key.

Rule of One: a pinned verifier trust root, fixed before handling any RCC candidate,
must reject an altered, expired, wrong-issuer, wrong-case, or wrong-scope voucher.
Even a valid fixture is only a synthetic *requirement*, not operational authority.
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
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts import final128_337_current_rcc_main_request_boundary_v1 as r337
from scripts import final128_338_current_rcc_native_refusal_v1 as r338
from scripts import final128_339_current_rcc_real_decide_compatibility_v1 as r339
from scripts import final128_341_rcc_signed_test_mandate_native_promotion_v1 as r341

CONTRACT = ROOT / "contracts/FINAL128_342_OFFLINE_PREISSUED_TEST_ISSUER_V1.json"
VOUCHER = ROOT / "fixtures/final128_342_offline_preissued_test_voucher_v1.json"
OUT = ROOT / "results/final128-342-offline-test-issuer-trust-anchor"
MAIN = "0f5879cc694a3d7e09141cdcb369297f1e7d9844"
RULE = "INDEPENDENT_PREISSUED_TEST_VOUCHER_PINNED_TRUST_ROOT_NO_INPROCESS_SIGNATURE_MINTING"
PUBLIC_SHA = "f0945df663c54edd3c9dc7033d1d8702975489175c02fbbc8d97c77ce4fca612"
PAYLOAD_SHA = "30e05dfbc88a604900b89e36b0d74387b25c5fd1a1d1b4e2e022a424f80afd46"
SIGNATURE_SHA = "148cbcc7ebd18c6d35473f51fe20246163a91a794544e3fd6b35409783325a0b"
VOUCHER_SHA = "93c40d0c25b2a019b253826cb3aaa362fc6d5c07465cd82396fd0e32a883e6bd"
DOMAIN = b"VERITAS_RCC_OFFLINE_TEST_ISSUER_V1\n"
EXPECTED_CASE = "fixture:30a220e37794e975131841bff70fc271e1a441b39efd95b93e45bc248b30ceef"

class Refused(ValueError):
    pass

def require(ok: bool, reason: str) -> None:
    if not ok:
        raise Refused(reason)

def unique_json(p: Path):
    def unique_pairs(items):
        result = {}
        for k, v in items:
            require(k not in result, "342_DUPLICATE_JSON_KEY")
            result[k] = v
        return result
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(Refused("342_NONFINITE_JSON")))

def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",",":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")

def hash_json(value):
    return hashlib.sha256(canon(value)).hexdigest()

def decoded(value: str) -> bytes:
    require(type(value) is str, "342_INVALID_BASE64_TYPE")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Refused("342_INVALID_BASE64") from exc

def when(value: str) -> datetime:
    require(type(value) is str and value.endswith("Z"), "342_TIMESTAMP_NOT_UTC")
    try:
        t = datetime.fromisoformat(value.replace("Z","+00:00"))
    except ValueError as exc:
        raise Refused("342_INVALID_TIMESTAMP") from exc
    require(t.utcoffset() == timedelta(0), "342_TIMESTAMP_NOT_UTC")
    return t

def contract_check(c):
    prev = r341.contract_check(r341.read(r341.CONTRACT))
    mandate = prev["predeclared_test_mandate"]
    require(
        c["rule_of_one"] == RULE and c["base_main_sha"] == MAIN
        and c["rcc_sha"] == r339.PIN_RCC and c["veritas_sha"] == r339.PIN_VERITAS
        and c["issuer_id"] == "offline-fixture-issuer-alpha"
        and c["issuer_key_id"] == "offline-fixture-alpha-ed25519-20261012"
        and c["audience"] == "veritas/rcc-revas-benchmark/final128"
        and c["case_id"] == EXPECTED_CASE
        and c["trust_anchor_public_key_b64"] == "p9BmwRqAUu+bxz2E+dUG1ZDKPGQOzWssJJ+XutFtEXY="
        and c["trust_anchor_public_key_sha256"] == PUBLIC_SHA
        and c["frozen_voucher_sha256"] == VOUCHER_SHA
        and c["frozen_payload_sha256"] == PAYLOAD_SHA
        and c["frozen_signature_sha256"] == SIGNATURE_SHA
        and c["signature_domain"] == "VERITAS_RCC_OFFLINE_TEST_ISSUER_V1\\n"
        and c["voucher_not_before"] == "2026-10-12T06:15:00Z"
        and c["voucher_expires_at"] == "2027-10-12T06:15:00Z"
        and c["mandate"] == mandate
        and c["issuer_key_private_in_repo"] is False
        and c["guardrails"] == {
          "require_wall_clock_validity":True,
          "trust_source":"FROZEN_PUBLIC_KEY_FROM_REPOSITORY_NOT_CANDIDATE",
          "test_only":True,
          "independent_legal_issuer":False,
          "real_world_authority":False,
          "untrusted_rcc_without_voucher_refused":True,
          "never_accept_embedded_candidate_public_keys":True,
          "never_derive_trust_from_rcc_outcome":True,
          "allow_voucher_reissue_in_ci":False,
        }
        and c["nonclaims"] == {
          "live_provider_calls":0,"real_external_effects":0,
          "native_v2_authorizations":0,"bind_dispatches":0,
          "human_approval_receipts":0,"real_enterprise_issuer_proven":False,
          "real_operator_separation_proven":False,
          "production_authority_proven":False,
          "independent_model_choice_proven":False,
          "official_final128_rescored":False,
        }
        and c["historic_v13"] == {"a_utility":93,"b_utility":64,"b_injection_success":0},
        "342_TRUST_ANCHOR_OR_SCOPE_CHANGED")
    key = decoded(c["trust_anchor_public_key_b64"])
    require(len(key)==32 and hashlib.sha256(key).hexdigest()==PUBLIC_SHA,
            "342_PINNED_PUBLIC_KEY_INVALID")
    return c

def signature_only_verify(voucher, key: bytes) -> None:
    """Verify signature over canonical signed payload, no candidate-provided key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    require(type(voucher) is dict and type(voucher.get("payload")) is dict,
            "342_INVALID_SIGNED_PAYLOAD")
    sig = decoded(voucher.get("signature_b64"))
    require(len(sig)==64 and len(key)==32, "342_SIGNATURE_OR_KEY_SIZE_INVALID")
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig, DOMAIN+canon(voucher["payload"]))
    except (InvalidSignature,ValueError,TypeError) as exc:
        raise Refused("342_OFFLINE_ISSUER_SIGNATURE_INVALID") from exc

def verify_voucher(voucher, c, source=None, *, at=None, strict_frozen=True):
    """The verifier never trusts a public key, issuer or scope supplied by RCC."""
    contract_check(c)
    require(type(voucher) is dict and set(voucher)=={
      "payload","signature_b64","signature_algorithm","issuer_key_id"},
      "342_VOUCHER_EXTRA_OR_MISSING_KEYS")
    p = voucher["payload"]
    require(type(p) is dict and set(p)=={
      "schema","issuer_id","issuer_key_id","audience","case_id","issued_at",
      "not_before","expires_at","purpose","mandate"},
      "342_SIGNED_PAYLOAD_KEYS_INVALID")
    require(voucher["signature_algorithm"]=="Ed25519"
      and voucher["issuer_key_id"]==c["issuer_key_id"]
      and p["issuer_key_id"]==c["issuer_key_id"]
      and p["issuer_id"]==c["issuer_id"]
      and p["audience"]==c["audience"]
      and p["case_id"]==c["case_id"]
      and p["schema"]=="veritas.rcc.offline-preissued-test-mandate.v1"
      and p["purpose"]=="offline-signed-synthetic-trust-fixture"
      and p["mandate"]==c["mandate"]
      and p["not_before"]==c["voucher_not_before"]
      and p["expires_at"]==c["voucher_expires_at"],
      "342_VOUCHER_ISSUER_OR_ACTION_SCOPE_MISMATCH")
    if strict_frozen:
        require(hash_json(voucher)==c["frozen_voucher_sha256"]
           and hash_json(p)==c["frozen_payload_sha256"]
           and hashlib.sha256(decoded(voucher["signature_b64"])).hexdigest()
                       ==c["frozen_signature_sha256"],
           "342_OFFLINE_FIXTURE_NOT_PINNED")
    key=decoded(c["trust_anchor_public_key_b64"])
    signature_only_verify(voucher,key)
    issued,nb,expiry = when(p["issued_at"]),when(p["not_before"]),when(p["expires_at"])
    moment=at if at is not None else datetime.now(UTC)
    require(moment.tzinfo is not None and moment.utcoffset()==timedelta(0),
            "342_VALIDATION_CLOCK_NOT_UTC")
    require(issued<=nb<=moment<expiry,"342_VOUCHER_NOT_YET_VALID_OR_EXPIRED")
    if source is not None:
        require(type(source) is dict
          and source["candidate_id"]=="candidate:"+c["case_id"],
          "342_VOUCHER_SOURCE_CANDIDATE_ID_MISMATCH")
        # Candidate identity never determines which key to trust.
        r341.verify_declared_action(source,p["mandate"])
    return {
       "issuer_id":p["issuer_id"],"key_id":p["issuer_key_id"],
       "case_id":p["case_id"],"valid_at":moment.isoformat(),
       "signature_verified":True,"trust_anchor_pinned":True,
       "issuer_private_key_loaded":False,
       "voucher_payload_sha256":hash_json(p),
       "voucher_sha256":hash_json(voucher),
       "issuer_public_key_sha256":hashlib.sha256(key).hexdigest(),
       "synthetic_fixture_only":True,
    }

def offline_candidate(source,verified,c):
    """Create a typed proposal after voucher verification; never mint grants."""
    from veritas_os.policy.decision_candidate import DecisionCandidate
    r341.verify_declared_action(source,c["mandate"])
    require(verified["signature_verified"] and verified["trust_anchor_pinned"]
            and verified["case_id"]==c["case_id"]
            and verified["voucher_sha256"]==c["frozen_voucher_sha256"],
            "342_OFFLINE_TRUST_NOT_VERIFIED")
    a=r341.action_from_source(source)
    origin_sha=hash_json(source)
    return DecisionCandidate(
       candidate_id=source["candidate_id"],
       source_model="RCC_OFFLINE_SIGNED_TEST_PROPOSAL_NOT_REAL_AUTHORITY",
       source_trace_ref="rcc-candidate-sha256:"+origin_sha,
       candidate_type="execution_intent_candidate",
       action_type=a["action_class"],actor_identity=a["actor_identity"],
       target_system=a["target_system"],target_resource=a["target_resource"],
       intended_action=a["canonical_action"],
       required_authority=list(c["mandate"]["test_authority_grant"]),
       required_human_approval=c["mandate"]["required_human_approval"],
       risk_level=c["mandate"]["risk_level"],
       regulated_or_high_impact=c["mandate"]["regulated_or_high_impact"],
       evidence_refs=["rcc-candidate-sha256:"+origin_sha,
                      "offline-preissued-test-voucher-sha256:"+verified["voucher_sha256"]],
       policy_context_refs=["test-only-offline-issuer:"+verified["issuer_id"]],
       metadata={"rcc_original_candidate_sha256":origin_sha,
                 "source_typed_action_sha256":hash_json(a),
                 "offline_fixture_voucher_sha256":verified["voucher_sha256"],
                 "authority_provenance":"OFFLINE_PREISSUED_SIGNED_TEST_FIXTURE_ONLY",
                 "real_world_authorization":False}
    )

def native_child(original_path,result_path,veritas_root):
    sys.path.insert(0,str(veritas_root))
    from veritas_os.policy.decision_candidate import (
       validate_decision_candidate,hash_decision_candidate)
    c=contract_check(unique_json(CONTRACT))
    voucher=unique_json(VOUCHER)
    original=unique_json(original_path)
    src=original["context"]["rcc_revas"]["candidate"]
    require(original["alternatives"][0]["description"]==r337.canon(src).decode("utf-8"),
            "342_RCC_CANDIDATE_CHANGED")
    require(original["alternatives"][0]["id"]==
            "rcc-candidate:"+original["context"]["rcc_revas"]["candidate_semantic_hash"],
            "342_RCC_OPTION_ID_CHANGED")
    baseline=r341.untrusted_candidate(src,hash_json(src))
    refused=validate_decision_candidate(baseline)
    require(not refused.promotable and refused.fail_closed
            and "DECISION_CANDIDATE_AUTHORITY_UNSPECIFIED" in refused.reason_codes,
            "342_UNSIGNED_RCC_AUTO_GRANTED")
    result=verify_voucher(voucher,c,src)
    candidate=offline_candidate(src,result,c)
    validation=validate_decision_candidate(candidate)
    require(validation.promotable and not validation.fail_closed,
            "342_VERIFIED_OFFLINE_TEST_CANDIDATE_NOT_SCHEMA_VALID")
    require(candidate.candidate_id==src["candidate_id"]
         and candidate.actor_identity==src["typed_action"]["actor_identity"]
         and candidate.target_system==src["typed_action"]["target_system"]
         and candidate.target_resource==src["typed_action"]["target_resource"]
         and candidate.intended_action==src["typed_action"]["canonical_action"],
            "342_NATIVE_ACTION_MISMATCH")
    result.update({
       "original_rcc_candidate_sha256":hash_json(src),
       "rcc_candidate_semantic_hash":original["context"]["rcc_revas"]["candidate_semantic_hash"],
       "source_typed_action_sha256":hash_json(src["typed_action"]),
       "origin_request_sha256":hash_json(original),
       "native_candidate_sha256":hash_decision_candidate(candidate),
       "native_schema_candidate_promotable_for_test":validation.promotable,
       "untrusted_without_voucher_refused":True,
       "original_action_identity_preserved":True,
       "human_approval_requirement_not_receipt":candidate.required_human_approval is True,
       "actual_cda_created_in_this_pr":False,
       "actual_execution_intent_created_in_this_pr":False,
       "native_bind_invoked":False,
       "real_issuer_authentication_proven":False,
       "real_external_effects":0,
    })
    result_path.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf-8")

def verify_report(report):
    c=contract_check(unique_json(CONTRACT))
    x=report["observation"]
    require(report["schema"]==c["schema"]
      and report["rule_of_one"]==RULE
      and report["base_main_sha"]==MAIN
      and report["rcc_sha"]==r339.PIN_RCC and report["veritas_sha"]==r339.PIN_VERITAS
      and report["case_id"]==EXPECTED_CASE
      and report["case_counts"]["registered"]==36
      and report["case_counts"]["prepared"]+report["case_counts"]["withheld"]==36
      and report["nonclaims"]==c["nonclaims"]
      and all(x[n] is True for n in (
         "signature_verified","trust_anchor_pinned","synthetic_fixture_only",
         "native_schema_candidate_promotable_for_test",
         "untrusted_without_voucher_refused","original_action_identity_preserved",
         "human_approval_requirement_not_receipt"))
      and x["issuer_private_key_loaded"] is False
      and x["actual_cda_created_in_this_pr"] is False
      and x["actual_execution_intent_created_in_this_pr"] is False
      and x["native_bind_invoked"] is False
      and x["real_issuer_authentication_proven"] is False
      and x["real_external_effects"]==0
      and x["issuer_public_key_sha256"]==PUBLIC_SHA
      and x["voucher_sha256"]==VOUCHER_SHA,
      "342_OFFLINE_ISSUER_TRUST_OR_SCOPE_PROOF_MISSING")
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
    c=contract_check(unique_json(CONTRACT))
    osroot=r339.verify_os(
        a.veritas_root,r339.contract_check(r338.read_json(r339.CONTRACT_PATH)))
    out=a.output_dir.resolve()
    require(out==OUT.resolve() and not out.exists(),"342_REQUIRES_FRESH_FIXED_EVIDENCE_DIR")
    out.mkdir(parents=True)
    _first,_handoff,native,account=r338.execute_rcc(a.upstream_root,out)
    selected=r341.selected_case(out,c["mandate"])
    require(selected["case_id"]==EXPECTED_CASE,"342_SIGNED_VOUCHER_CASE_REPLAY")
    handoffs={row["rcc_revas"]["audit"]["case_id"]:row for row in
              r337.read_jsonl(out/"rcc-run/handoff_results.jsonl")}
    require(selected["case_id"] in handoffs,"342_RCC_ORIGIN_HANDOFF_MISSING")
    r337.verify_one_prepared(selected,handoffs[selected["case_id"]],out/"rcc-run",native)
    require(selected["request"]["context"]["rcc_revas"]["candidate"]==
        handoffs[selected["case_id"]]["rcc_revas"]["adoption"]["selected_candidate"],
        "342_RCC_ORIGINAL_CANDIDATE_NOT_SAME_AS_RELEASE")
    source_path=out/"original-rcc-request.json"
    source_path.write_text(json.dumps(selected["request"],sort_keys=True,indent=2)+"\n",encoding="utf-8")
    child_result=out/"offline-trust-verification.json"
    env=dict(os.environ)
    env["PYTHONPATH"]=str(osroot)+os.pathsep+str(ROOT)
    run=subprocess.run([sys.executable,str(Path(__file__).resolve()),
       "--veritas-root",str(osroot),
       "--child-original",str(source_path),"--child-result",str(child_result)],
        cwd=osroot,env=env,capture_output=True,text=True,timeout=120)
    if run.returncode:
        print("342_NATIVE_VERIFIER_SUBPROCESS_FAILED",file=sys.stderr)
        print(run.stderr[-6500:],file=sys.stderr)
        raise Refused("342_NATIVE_VERIFICATION_DID_NOT_COMPLETE")
    report={
      "schema":c["schema"],"rule_of_one":RULE,"base_main_sha":MAIN,
      "rcc_sha":r339.PIN_RCC,"veritas_sha":r339.PIN_VERITAS,
      "case_id":selected["case_id"],
      "case_counts":{"registered":36,"prepared":account["prepared"],"withheld":account["withheld"]},
      "nonclaims":c["nonclaims"],"observation":unique_json(child_result),
      "historical_v13_reference_only":c["historic_v13"],
    }
    verify_report(report)
    report["report_sha256"]=hash_json(report)
    (out/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("FINAL128_342_PINNED_OFFLINE_TEST_ISSUER_VOUCHER_VERIFIED_SOURCE_BOUND_NO_MINTING")
    print(json.dumps({"case_id":report["case_id"],"offline_signature":True,
           "untrusted_refused":True,"test_candidate_schema":True,
           "production_authority":False,"actual_cda_created":False,
           "report_sha256":report["report_sha256"]},sort_keys=True))

if __name__=="__main__":
    main()
