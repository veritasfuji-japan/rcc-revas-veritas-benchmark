#!/usr/bin/env python3
"""Prove a narrow address representation without activating admission."""
from __future__ import annotations

import argparse
import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.task4_send_money_execution_date_authority_audit_v1 import blob, require
from scripts.controlled_candidate_binding_mismatch_cause_decomposition_audit_v1 import (
    canonical, prompt_fields, record_fields, selected_module, sha, task_id, verify_pair,
)
from original_request_authority_lineage_v1 import OriginalRequestEnvelope
from task15_original_request_native_address_field_mapping_v1 import (
    POLICY_ID, assess_task15_native_address_fields, derive_task15_native_address_mapping,
)

NAME = "task15-original-request-native-address-field-mapping-v1"
CONTRACT = ROOT / "contracts/TASK15_ORIGINAL_REQUEST_NATIVE_ADDRESS_FIELD_MAPPING_V1.json"
EXPECTED_CONTRACT = "acbb923fc776306deac86506ec43589c3e18f36a"


def verify_scope(row, records, models, prompts, user, envelope, contract):
    require(task_id(row) == 15 and row["function"] == "update_user_info", "ADDRESS_SCOPE_REQUIRED")
    mapping = derive_task15_native_address_mapping(envelope)
    require(envelope.digest == contract["original_request_digest"]
            and mapping.mapping_digest == contract["mapping_digest"], "OWNED_REQUEST_OR_POLICY_IDENTITY_CHANGED")
    fields = user.UserAccount.model_fields
    require(set(fields) == {"first_name", "last_name", "street", "city", "password"}
            and fields["street"].title == "Street of the user"
            and fields["city"].title == "City of the user", "NATIVE_ADDRESS_SCHEMA_CHANGED")
    pre, checks, failed = verify_pair(row, records, models, prompts)
    require(failed == ["city_bound"], "FROZEN_BINDING_FAILURE_CHANGED")
    assessment = assess_task15_native_address_fields(
        envelope=envelope, tool_name=row["function"], arguments=row["arguments"])
    require(assessment.field_mapping_matches and not assessment.execution_permission
            and not assessment.runtime_admission_activated, "MAPPING_OR_CLOSED_ADMISSION_CHANGED")
    return pre, mapping, assessment, checks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--agentdojo-root", type=Path, required=True)
    parser.add_argument("--veritas-root", type=Path, required=True)
    parser.add_argument("--replay-artifact", type=Path, required=True)
    parser.add_argument("--v13-artifact", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    for key in ("OPENAI_API_KEY", "VERITAS_DATABASE_URL"):
        require(not os.environ.get(key), key + "_MUST_BE_EMPTY")
    require(blob(CONTRACT.read_bytes()) == EXPECTED_CONTRACT, "CONTRACT_PIN_MISMATCH")
    contract = json.loads(CONTRACT.read_text())
    for path, expected in contract["source_blobs"].items():
        require(blob((ROOT / path).read_bytes()) == expected, "SOURCE_PIN_MISMATCH:" + path)
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update(OPENAI_API_KEY="", VERITAS_DATABASE_URL="",
               PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTEST_ADDOPTS="")
    # Exact previous diagnosis includes external source/artifact closure and the
    # actual frozen route. Its native probes are also detached, not dispatch.
    previous = subprocess.run([
        sys.executable, "scripts/controlled_candidate_binding_mismatch_cause_decomposition_audit_v1.py",
        "--agentdojo-root", str(args.agentdojo_root.resolve()),
        "--veritas-root", str(args.veritas_root.resolve()),
        "--replay-artifact", str(args.replay_artifact.resolve()),
        "--v13-artifact", str(args.v13_artifact.resolve()), "--output-dir", str(out),
    ], cwd=ROOT, env=env, capture_output=True, text=True)
    require(previous.returncode == 0, "PRIOR_DIAGNOSIS_FAILED:" + previous.stderr)
    print(previous.stdout, end="")
    (out / "controlled-candidate-binding-mismatch-cause-decomposition-v1.log").write_text(previous.stdout)
    prior_raw = (out / "controlled-candidate-binding-mismatch-cause-decomposition-v1.json").read_bytes()
    require(hashlib.sha256(prior_raw).hexdigest() == contract["prior_diagnosis_report_sha256"],
            "PRIOR_DIAGNOSIS_REPORT_CHANGED")
    prior = json.loads(prior_raw)
    require(prior["controlled_cases"] == 22 and prior["safe_to_relax_now"] == 0
            and prior["historical_candidates_recovered"] == 0, "PRIOR_RECOVERY_BOUNDARY_CHANGED")
    for label, path in (("replay", args.replay_artifact), ("v13", args.v13_artifact)):
        require(hashlib.sha256(path.read_bytes()).hexdigest() == contract["artifacts"][label]["zip_sha256"],
                "ARTIFACT_ZIP_MISMATCH:" + label)
    with zipfile.ZipFile(args.replay_artifact) as z:
        replay_raw = z.read(contract["artifacts"]["replay"]["member"])
    with zipfile.ZipFile(args.v13_artifact) as z:
        source_raw = z.read(contract["artifacts"]["v13"]["member"])
    for label, raw in (("replay", replay_raw), ("v13", source_raw)):
        require(hashlib.sha256(raw).hexdigest() == contract["artifacts"][label]["member_sha256"],
                "ARTIFACT_MEMBER_MISMATCH:" + label)
    records = record_fields([json.loads(line) for line in source_raw.splitlines() if line])
    rows = [row for row in json.loads(replay_raw)["rows"]
            if task_id(row) == 15 and row["arm_B"]["disposition"] == "VERITAS_BLOCKED"]
    require(len(rows) == 5 and [r["case_id"] for r in rows] == contract["frozen_case_ids"],
            "FROZEN_ADDRESS_CASE_SET_CHANGED")
    base = "src/agentdojo/default_suites/"
    sources = {}
    for path, expected in contract["agentdojo_source_blobs"].items():
        raw = (args.agentdojo_root / path).read_bytes()
        require(blob(raw) == expected, "NATIVE_SOURCE_PIN_MISMATCH:" + path)
        sources[path] = raw
    prompts = prompt_fields(sources[base + "v1/banking/user_tasks.py"], {15})
    overrides = prompt_fields(sources[base + "v1_1_1/banking/user_tasks.py"], {15})
    require(set(overrides) == {15} and not prompt_fields(sources[base + "v1_2_2/banking/user_tasks.py"], {15}),
            "EFFECTIVE_PROMPT_VERSION_CHAIN_CHANGED")
    prompts.update(overrides)
    require(prompts[15] == contract["original_request"], "EFFECTIVE_OWNED_REQUEST_CHANGED")
    envelope = OriginalRequestEnvelope("banking", 15, prompts[15])
    mapping = derive_task15_native_address_mapping(envelope)
    require(mapping.source_components() == contract["explicit_address_components"]
            and mapping.native_fields() == contract["native_field_projection"]
            and POLICY_ID == contract["mapping_policy_id"], "ADDRESS_MAPPING_POLICY_CHANGED")
    user = selected_module(sources[base + "v1/tools/user_account.py"],
                           {"UserAccount", "update_user_info"}, "_task15_address_native_user")
    native_parser = selected_module(sources["src/agentdojo/functions_runtime.py"],
                                    {"_parse_args"}, "_task15_address_native_parser")
    from docstring_parser import parse
    models = {"update_user_info": native_parser._parse_args(
        "update_user_info", parse(user.update_user_info.__doc__).params, inspect.signature(user.update_user_info))}
    case_evidence = []
    for row in rows:
        pre, mapped, assessment, old_checks = verify_scope(
            row, records, models, prompts, user, envelope, contract)
        require(set(pre["user_account"]) == set(user.UserAccount.model_fields), "EXACT_NATIVE_ACCOUNT_REQUIRED")
        candidate_before = canonical(row["arguments"])
        state_before = canonical(pre)
        expected = copy.deepcopy(pre)
        expected["user_account"].update(mapped.native_fields())
        afters = []
        deltas = []
        for clone in ("A", "B"):
            detached = copy.deepcopy(pre)
            account = user.UserAccount.model_validate(detached["user_account"])
            require(account.model_dump(mode="json") == pre["user_account"], "ACCOUNT_NORMALIZATION_CHANGED_PRESTATE")
            result = user.update_user_info(account, **row["arguments"])
            detached["user_account"] = account.model_dump(mode="json")
            require(detached == expected, "NATIVE_EFFECT_OUTSIDE_EXACT_ADDRESS_PROJECTION")
            require(result == {k: expected["user_account"][k] for k in ("first_name", "last_name", "street", "city")},
                    "NATIVE_RETURN_CHANGED_UNRELATED_FIELDS")
            delta = {k: {"before": pre["user_account"][k], "after": detached["user_account"][k]}
                     for k in pre["user_account"] if pre["user_account"][k] != detached["user_account"][k]}
            require(set(delta).issubset({"street", "city"}), "NAME_OR_PASSWORD_EFFECT")
            afters.append(sha(detached)); deltas.append(delta)
        require(afters[0] == afters[1] and deltas[0] == deltas[1]
                and canonical(pre) == state_before and canonical(row["arguments"]) == candidate_before,
                "NATIVE_PROBE_PAIR_OR_IMMUTABILITY_VIOLATION")
        case_evidence.append({"case_id": row["case_id"], "source_arm": row["source_arm"],
            "source_request_digest": envelope.digest, "mapping_digest": mapped.mapping_digest,
            "candidate_sha256": row["candidate_sha256"], "pairing_identity_sha256": row["pairing_identity_sha256"],
            "immediate_pre_state_sha256": row["immediate_pre_state_sha256"],
            "arguments_unchanged": True, "mapping_checks": dict(assessment.checks),
            "field_mapping_matches": True, "frozen_checks_unchanged": old_checks,
            "historical_b_disposition": "VERITAS_BLOCKED", "historical_recovery_proven": False,
            "detached_clone_a_post_state_sha256": afters[0], "detached_clone_b_post_state_sha256": afters[1],
            "observed_native_delta": deltas[0], "names_password_and_other_environment_preserved": True,
            "runtime_admission_activated": False, "execution_permission": False})
    # Every substitution check completes before reaching a native probe.
    rejected = []
    for fault in ("candidate_city", "candidate_street", "candidate_name", "extra_password",
                  "pairing_identity", "arm_prestate", "source_call", "source_request", "native_city_title"):
        row, lookup, owned = copy.deepcopy(rows[0]), records, envelope
        if fault == "candidate_city": row["arguments"]["city"] = "Boston"
        if fault == "candidate_street": row["arguments"]["street"] = "ATTACKER"
        if fault == "candidate_name": row["arguments"]["first_name"] = "ATTACKER"
        if fault == "extra_password": row["arguments"]["password"] = "ATTACKER"
        if fault == "pairing_identity": row["pairing_identity_sha256"] = "0" * 64
        if fault == "arm_prestate": row["arm_B"]["pre_state_sha256"] = "0" * 64
        if fault == "source_call":
            lookup = copy.deepcopy(records)
            lookup[row["case_id"], row["source_arm"]]["functions_stack_trace"][row["source_trace_index"]]["args"]["city"] = "Boston"
        if fault == "source_request":
            owned = OriginalRequestEnvelope("banking", 15, prompts[15].replace("New York", "Boston"))
        title = user.UserAccount.model_fields["city"].title
        if fault == "native_city_title": user.UserAccount.model_fields["city"].title = "Arbitrary text"
        try:
            verify_scope(row, lookup, models, prompts, user, owned, contract)
        except ValueError:
            rejected.append(fault)
        else:
            raise ValueError("EVIDENCE_SUBSTITUTION_ACCEPTED:" + fault)
        finally:
            user.UserAccount.model_fields["city"].title = title
    require(len(rejected) == 9, "ADDRESS_EVIDENCE_REJECTION_PROBES_INCOMPLETE")
    junit = out / (NAME + ".junit.xml")
    if junit.exists(): junit.unlink()
    tests = subprocess.run([sys.executable, "-m", "pytest", "-q", "-o", "addopts=",
        "tests/test_task15_original_request_native_address_field_mapping_v1.py", "--junitxml", str(junit)],
        cwd=ROOT, env=env, capture_output=True, text=True)
    print(tests.stdout, end="")
    require(tests.returncode == 0, "ADDRESS_MAPPING_TESTS_FAILED:" + tests.stderr)
    cases = ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases) == contract["offline_proof"]["unit_tests"]
            and not any(x.find(t) is not None for x in cases for t in ("failure", "error", "skipped")),
            "ADDRESS_MAPPING_TESTS_INCOMPLETE")
    report = {"rule_of_one": contract["rule_of_one"],
        "determination": "BOUNDED_REQUEST_TO_NATIVE_ADDRESS_FIELD_PROJECTION_VERIFIED_ADMISSION_CLOSED",
        "mapping_policy_id": POLICY_ID, "original_request_digest": envelope.digest,
        "mapping_digest": mapping.mapping_digest, "explicit_address_components": mapping.source_components(),
        "native_field_projection": mapping.native_fields(), "unit_tests": len(cases), "failures": 0, "skipped": 0,
        "controlled_candidates_verified": 5, "field_mapping_matches": 5, "paired_detached_native_probes": 5,
        "address_native_function_invocations": 10, "rows": case_evidence, "evidence_substitution_rejections": rejected,
        "prior_detached_native_probes": {"schedule_pairs": 3, "city_variants": 3},
        "native_city_title": "City of the user", "region_and_postal_code_retained_in_evidence": True,
        "native_region_and_postal_code_storage": False, "complete_postal_address_storage_proven": False,
        "original_request_authentication_proven": False, "pre_generation_request_context_issued": False,
        "existing_validator_resolver_and_runner_unchanged": True, "runtime_admission_activated": False,
        "execution_permission": False, "safe_to_relax_now": 0, "historical_candidates_recovered": 0,
        "provider_execution": 0, "database_access": 0, "scorer_or_gold_evaluation": 0,
        "scorer_or_gold_derived_authority": 0, "candidate_repair": 0, "governance_treatment_replay": 0,
        "external_effect": 0, "v13_reuse": 0, "utility_recovery_proven": False,
        "injection_success_remeasured": False, "held_out_validation": False, "production_readiness": False,
        "prior_diagnosis_report_sha256": hashlib.sha256(prior_raw).hexdigest(),
        "next_rule_of_one": contract["next_rule_of_one"]}
    (out / (NAME + ".json")).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("PASS_TASK15_ORIGINAL_REQUEST_NATIVE_ADDRESS_FIELD_MAPPING_V1")
    print("mapping_tests=" + str(len(cases)) + " failures=0 skipped=0")
    print("controlled_candidates=5 mapping_matches=5 paired_detached_native_probes=5 address_native_function_invocations=10")
    print("evidence_substitution_rejected=9 names_password_other_environment_preserved=5")
    print("runtime_admission_activated=false execution_permission=false safe_to_relax_now=0 historical_recovered=0")
    print("provider_execution=0 database_access=0 scorer_or_gold_derived_authority=0 candidate_repair=0 v13_reuse=0")
    print("next_rule_of_one=" + contract["next_rule_of_one"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
