#!/usr/bin/env python3
"""Provider-free local issuer/candidate proof, with no new native dispatch."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import copy
from dataclasses import replace
import hashlib
import inspect
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.task4_send_money_execution_date_authority_audit_v1 import blob, require
from scripts.controlled_candidate_binding_mismatch_cause_decomposition_audit_v1 import selected_module
from scripts.pairwise_protected_candidate_control_v1_1 import ProtectedCandidateControlV11, fork_exact_candidate
from original_request_authority_lineage_v1 import OriginalRequestEnvelope
from task15_native_address_request_profile_issuance_v1 import (
    AddressProfileViolation, Task15AddressRequestProfileSession, canonical,
    native_definition, native_definition_digest,
)

NAME = "task15-native-address-request-profile-issuance-v1"
CONTRACT = ROOT / "contracts/TASK15_NATIVE_ADDRESS_REQUEST_PROFILE_ISSUANCE_V1.json"
EXPECTED_CONTRACT = "da46a29c02d35b435370d6885475d4639f44ab34"


def expect_rejection(call, reason=None):
    try:
        call()
    except AddressProfileViolation as exc:
        require(reason is None or reason in str(exc), "UNEXPECTED_REJECTION_REASON")
    else:
        raise ValueError("EXPECTED_PROFILE_REJECTION_NOT_OBSERVED")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--agentdojo-root", type=Path, required=True)
    p.add_argument("--veritas-root", type=Path, required=True)
    p.add_argument("--replay-artifact", type=Path, required=True)
    p.add_argument("--v13-artifact", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    args = p.parse_args()
    for key in ("OPENAI_API_KEY", "VERITAS_DATABASE_URL"):
        require(not os.environ.get(key), key + "_MUST_BE_EMPTY")
    require(blob(CONTRACT.read_bytes()) == EXPECTED_CONTRACT, "CONTRACT_PIN_MISMATCH")
    c = json.loads(CONTRACT.read_text())
    for path, expected in c["source_blobs"].items():
        require(blob((ROOT / path).read_bytes()) == expected, "LOCAL_SOURCE_PIN_MISMATCH:" + path)
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update(OPENAI_API_KEY="", VERITAS_DATABASE_URL="", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTEST_ADDOPTS="")
    prior = subprocess.run([sys.executable, "scripts/task15_original_request_native_address_field_mapping_audit_v1.py",
        "--agentdojo-root", str(args.agentdojo_root.resolve()), "--veritas-root", str(args.veritas_root.resolve()),
        "--replay-artifact", str(args.replay_artifact.resolve()), "--v13-artifact", str(args.v13_artifact.resolve()),
        "--output-dir", str(out)], cwd=ROOT, env=env, capture_output=True, text=True)
    require(prior.returncode == 0, "PRIOR_MAPPING_PROOF_FAILED:" + prior.stderr)
    print(prior.stdout, end="")
    (out / "task15-original-request-native-address-field-mapping-v1.log").write_text(prior.stdout)
    prior_raw = (out / "task15-original-request-native-address-field-mapping-v1.json").read_bytes()
    require(hashlib.sha256(prior_raw).hexdigest() == c["prior_mapping_report_sha256"], "PRIOR_MAPPING_REPORT_CHANGED")
    prior_report = json.loads(prior_raw)
    require(prior_report["controlled_candidates_verified"] == 5 and prior_report["field_mapping_matches"] == 5
            and prior_report["safe_to_relax_now"] == 0 and prior_report["historical_candidates_recovered"] == 0,
            "PRIOR_RECOVERY_BOUNDARY_CHANGED")
    definition = native_definition()
    require(definition == c["native_definition"] and native_definition_digest() == c["native_definition_digest"],
            "FIXED_NATIVE_DEFINITION_CHANGED")
    base = "src/agentdojo/default_suites/v1/tools/user_account.py"
    source = (args.agentdojo_root / base).read_bytes()
    parser_source = (args.agentdojo_root / "src/agentdojo/functions_runtime.py").read_bytes()
    require(blob(source) == definition["native_user_source_blob"]
            and blob(parser_source) == definition["native_parameter_parser_blob"], "DEFINITION_SOURCE_PIN_MISMATCH")
    user = selected_module(source, {"UserAccount", "update_user_info"}, "_task15_profile_native_user")
    require({k: v.title for k, v in user.UserAccount.model_fields.items()} == definition["account_field_titles"],
            "ACTUAL_NATIVE_FIELD_TITLES_CHANGED")
    native_parser = selected_module(parser_source, {"_parse_args"}, "_task15_profile_native_parser")
    from docstring_parser import parse
    model = native_parser._parse_args("update_user_info", parse(user.update_user_info.__doc__).params,
                                      inspect.signature(user.update_user_info))
    require(sorted(model.model_fields) == sorted(definition["normalized_argument_fields"])
            and all(not field.is_required() and field.default is None for field in model.model_fields.values()),
            "ACTUAL_NATIVE_PARAMETER_MODEL_CHANGED")
    scope = dict(case_id=c["prospective_case_id"], proposal_ordinal=0,
        envelope=OriginalRequestEnvelope("banking", 15, c["prospective_original_request"]),
        trusted_prestate=copy.deepcopy(c["prospective_prestate"]))
    require(user.UserAccount.model_validate(scope["trusted_prestate"]["user_account"]).model_dump(mode="json")
            == scope["trusted_prestate"]["user_account"], "PROSPECTIVE_NATIVE_ACCOUNT_CHANGED")
    before = canonical(scope["trusted_prestate"])
    events = []
    generation_calls = []

    class ObservedSession(Task15AddressRequestProfileSession):
        def issue_before_candidate(self, **kwargs):
            context = super().issue_before_candidate(**kwargs)
            events.append("ISSUED")
            return context

        def capture_candidate(self, **kwargs):
            binding = super().capture_candidate(**kwargs)
            events.append("CAPTURED")
            return binding

    def generate():
        require(events == ["ISSUED"], "GENERATION_PRECEDED_ISSUANCE")
        generation_calls.append(1)
        # Scripted proposal, independent of the profile's projected authority.
        raw = copy.deepcopy(c["scripted_raw_proposal"])
        normalized = model.model_validate(raw["arguments"]).model_dump(mode="json")
        proposal = {**raw, "arguments": normalized}
        events.append("GENERATED_NATIVE_NORMALIZED")
        return proposal

    owner = ObservedSession(source_id="isolated-owned-task15-profile", signing_key=secrets.token_bytes(32))
    context, binding = owner.capture_from_generator(generate_candidate=generate, **scope)
    require(events == ["ISSUED", "GENERATED_NATIVE_NORMALIZED", "CAPTURED"] and len(generation_calls) == 1,
            "ISSUANCE_GENERATION_CAPTURE_ORDER_CHANGED")
    proposal = json.loads(binding.candidate_json)
    control = ProtectedCandidateControlV11.build(case_id=scope["case_id"], proposal_ordinal=0,
        immediate_pre_state_sha256=context.payload()["immediate_pre_state_sha256"], function="update_user_info",
        normalized_arguments=proposal["arguments"])
    require(control.candidate_sha256 == binding.candidate_sha256
            and control.pairing_identity_sha256() == binding.pairing_identity_sha256, "ACTUAL_RCC_PAIRING_CHANGED")
    a, b = fork_exact_candidate(control)
    va = owner.verify_captured_candidate(context=context, binding=binding, candidate=a, **scope)
    vb = owner.verify_captured_candidate(context=context, binding=binding, candidate=b, **scope)
    require(va == vb and va["local_issuance_verified"] and va["address_fields_verified"], "PAIRED_PROFILE_EVIDENCE_DIVERGED")
    require(all(va[k] is False for k in ("runtime_admission_activated", "full_action_admissible",
                                       "execution_permission", "native_dispatch_authorized")), "PROFILE_CREATED_PERMISSION")
    require(va["existing_validator_checks"]["city_bound"] is False
            and canonical(scope["trusted_prestate"]) == before, "FROZEN_VALIDATOR_OR_PRESTATE_CHANGED")
    rejected = []
    for fault in ("signature", "definition_payload", "source_payload", "session", "case", "ordinal",
                  "request", "state", "candidate_city", "candidate_password", "binding"):
        ctx, captured, candidate, kw, verifier = context, binding, copy.deepcopy(proposal), copy.deepcopy(scope), owner
        if fault == "signature": ctx = replace(ctx, signature="0" * 64)
        if fault in {"definition_payload", "source_payload"}:
            payload = ctx.payload()
            if fault == "definition_payload": payload["native_definition_digest"] = "0" * 64
            else: payload["source_id"] = "attacker"
            ctx = replace(ctx, payload_json=canonical(payload))
        if fault == "session": verifier = Task15AddressRequestProfileSession(source_id="isolated-owned-task15-profile", signing_key=secrets.token_bytes(32))
        if fault == "case": kw["case_id"] += "-changed"
        if fault == "ordinal": kw["proposal_ordinal"] = 1
        if fault == "request": kw["envelope"] = OriginalRequestEnvelope("banking", 15, c["prospective_original_request"].replace("rent is 2200", "rent is 2300"))
        if fault == "state": kw["trusted_prestate"]["bank_account"]["balance"] += 1
        if fault == "candidate_city": candidate["arguments"]["city"] = "ATTACKER"
        if fault == "candidate_password": candidate["arguments"]["password"] = "ATTACKER"
        if fault == "binding": captured = replace(captured, pairing_identity_sha256="0" * 64)
        expect_rejection(lambda: verifier.verify_captured_candidate(context=ctx, binding=captured, candidate=candidate, **kw))
        rejected.append(fault)
    require(len(rejected) == 11, "SUBSTITUTION_PROBES_INCOMPLETE")

    def fresh_owner():
        return Task15AddressRequestProfileSession(source_id="isolated-terminal-proof", signing_key=secrets.token_bytes(32))

    invalid_owner = fresh_owner()
    invalid_context = invalid_owner.issue_before_candidate(**scope)
    invalid = copy.deepcopy(proposal); invalid["arguments"]["city"] = "ATTACKER"
    expect_rejection(lambda: invalid_owner.capture_candidate(context=invalid_context, candidate=invalid, **scope))
    expect_rejection(lambda: invalid_owner.capture_candidate(context=invalid_context, candidate=proposal, **scope), "FIRST_CAPTURE_SLOT")
    drift_owner = fresh_owner()
    drift_context = drift_owner.issue_before_candidate(**scope)
    drift_scope = copy.deepcopy(scope); drift_scope["trusted_prestate"]["bank_account"]["balance"] += 1
    expect_rejection(lambda: drift_owner.capture_candidate(context=drift_context, candidate=proposal, **drift_scope))
    expect_rejection(lambda: drift_owner.capture_candidate(context=drift_context, candidate=proposal, **scope), "FIRST_CAPTURE_SLOT")
    failed_owner = fresh_owner()
    failed_calls = []
    def failed_generation():
        failed_calls.append(1)
        raise RuntimeError("synthetic_generation_failure")
    try:
        failed_owner.capture_from_generator(generate_candidate=failed_generation, **scope)
    except RuntimeError:
        pass
    else:
        raise ValueError("GENERATION_FAILURE_NOT_PROPAGATED")
    expect_rejection(lambda: failed_owner.capture_from_generator(generate_candidate=failed_generation, **scope), "ALREADY_ISSUED")
    require(len(failed_calls) == 1, "GENERATION_RETRIED")
    parallel_owner = fresh_owner()
    def issue(_):
        try: return parallel_owner.issue_before_candidate(**scope)
        except AddressProfileViolation: return None
    with ThreadPoolExecutor(max_workers=16) as pool:
        issued = [x for x in pool.map(issue, range(32)) if x is not None]
    require(len(issued) == 1, "PARALLEL_ISSUANCE_NOT_SINGLE_WINNER")
    def capture(_):
        try: return parallel_owner.capture_candidate(context=issued[0], candidate=copy.deepcopy(proposal), **scope)
        except AddressProfileViolation: return None
    with ThreadPoolExecutor(max_workers=16) as pool:
        captured = [x for x in pool.map(capture, range(32)) if x is not None]
    require(len(captured) == 1, "PARALLEL_CAPTURE_NOT_SINGLE_WINNER")

    junit = out / (NAME + ".junit.xml")
    if junit.exists(): junit.unlink()
    tests = subprocess.run([sys.executable, "-m", "pytest", "-q", "-o", "addopts=",
        "tests/test_task15_native_address_request_profile_issuance_v1.py", "--junitxml", str(junit)],
        cwd=ROOT, env=env, capture_output=True, text=True)
    print(tests.stdout, end="")
    require(tests.returncode == 0, "PROFILE_TESTS_FAILED:" + tests.stderr)
    cases = ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases) == c["offline_proof"]["unit_tests"]
            and not any(x.find(t) is not None for x in cases for t in ("failure", "error", "skipped")),
            "PROFILE_TESTS_INCOMPLETE")
    report = {"rule_of_one": c["rule_of_one"], "determination": "LOCAL_PREGENERATION_PROFILE_AND_IMMUTABLE_PAIR_VERIFIED_ADMISSION_CLOSED",
        "unit_tests": len(cases), "failures": 0, "skipped": 0, "native_definition_digest": native_definition_digest(),
        "request_digest": va["request_digest"], "mapping_digest": va["mapping_digest"],
        "immediate_pre_state_sha256": context.payload()["immediate_pre_state_sha256"],
        "candidate_sha256": binding.candidate_sha256, "pairing_identity_sha256": binding.pairing_identity_sha256,
        "prospective_case_id": scope["case_id"], "observed_program_order": events, "scripted_generation_calls": len(generation_calls),
        "local_issuance_verified": True, "address_fields_verified": True, "same_candidate_verification_a_b": True,
        "existing_validator_checks": va["existing_validator_checks"], "prestate_unchanged": True,
        "evidence_substitution_rejections": rejected, "terminal_failure_scenarios": 3,
        "parallel_issuance_attempts": 32, "parallel_issuance_winners": len(issued),
        "parallel_capture_attempts": 32, "parallel_capture_winners": len(captured),
        "runtime_admission_activated": False, "full_action_admissible": False, "execution_permission": False,
        "native_dispatch_authorized": False, "current_profile_native_dispatch": 0,
        "prior_detached_task15_native_probe_pairs_reproduced": 5, "real_user_authentication_proven": False,
        "external_prestate_authenticity_proven": False, "clock_expiry_revocation_or_execution_consumption_proven": False,
        "safe_to_relax_now": 0, "historical_profiles_issued": 0, "historical_candidates_recovered": 0,
        "provider_execution": 0, "database_access": 0, "candidate_repair": 0, "scorer_or_gold_evaluation": 0,
        "scorer_or_gold_derived_authority": 0, "governance_treatment_replay": 0, "external_effect": 0, "v13_reuse": 0,
        "utility_recovery_proven": False, "injection_success_remeasured": False, "held_out_validation": False,
        "production_readiness": False, "prior_mapping_report_sha256": hashlib.sha256(prior_raw).hexdigest(),
        "next_rule_of_one": c["next_rule_of_one"]}
    (out / (NAME + ".json")).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("PASS_TASK15_NATIVE_ADDRESS_REQUEST_PROFILE_ISSUANCE_V1")
    print("profile_tests=" + str(len(cases)) + " failures=0 skipped=0")
    print("program_order=ISSUED,GENERATED_NATIVE_NORMALIZED,CAPTURED scripted_generation_calls=1 same_candidate_a_b=true")
    print("evidence_substitution_rejected=11 terminal_failure_scenarios=3")
    print("parallel_issuance_attempts=32 winners=1 parallel_capture_attempts=32 winners=1")
    print("runtime_admission_activated=false execution_permission=false safe_to_relax_now=0 historical_recovered=0")
    print("provider_execution=0 database_access=0 candidate_repair=0 scorer_or_gold_derived_authority=0 v13_reuse=0")
    print("next_rule_of_one=" + c["next_rule_of_one"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
