#!/usr/bin/env python3
"""Decompose frozen binding failures without repairing or admitting candidates.

Only original PROMPT fields, native model/tool bodies and parameter parsing are
selected from AgentDojo. No task methods, scorer, gold or provider are invoked.
Native probes operate on detached accounts, outside governance/dispatch.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import copy
from decimal import Decimal
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import types
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.task4_send_money_execution_date_authority_audit_v1 import blob, require
from scripts.pairwise_protected_candidate_control_v1_1 import ProtectedCandidateControlV11
from agentdojo_constraint_resolver_v0_1 import (
    FRIEND_IBAN, _latest_incoming_amount, _task2_rent_update_from_prestate,
    _task11_apple_purchase_from_prestate, _task13_address_from_prestate, validate_candidate,
)
from original_request_authority_lineage_v1 import (
    OriginalRequestEnvelope, derive_task15_request_authority, validate_task15_from_original_request,
)

NAME = "controlled-candidate-binding-mismatch-cause-decomposition-v1"
CONTRACT = ROOT / "contracts/CONTROLLED_CANDIDATE_BINDING_MISMATCH_CAUSE_DECOMPOSITION_V1.json"
EXPECTED_CONTRACT = "814773b2ce98881b603f320ba9c5b847e1d671fe"
TARGETS = {2, 3, 11, 13, 15}
PROTECTED = {"send_money", "schedule_transaction", "update_scheduled_transaction", "update_password", "update_user_info"}
READ_ONLY = {"get_iban", "get_balance", "get_most_recent_transactions", "get_scheduled_transactions", "read_file", "get_user_info"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def task_id(row):
    return int(row["case_id"].split(":")[1].removeprefix("user_task_"))


def prompt_fields(source, targets):
    """Evaluate only string literals and a bounded class-local f-string name."""
    result = {}
    for cls in ast.parse(source).body:
        if not isinstance(cls, ast.ClassDef) or cls.name not in {f"UserTask{x}" for x in targets}:
            continue
        scalars = {t.id: n.value.value for n in cls.body if isinstance(n, ast.Assign)
                   and isinstance(n.value, ast.Constant) and type(n.value.value) is str
                   for t in n.targets if isinstance(t, ast.Name)}
        fields = [n.value for n in cls.body if isinstance(n, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == "PROMPT" for t in n.targets)]
        require(len(fields) == 1, "SINGLE_PROMPT_FIELD_REQUIRED")
        field = fields[0]
        if isinstance(field, ast.Constant) and type(field.value) is str:
            prompt = field.value
        else:
            require(isinstance(field, ast.JoinedStr), "UNSUPPORTED_PROMPT_EXPRESSION")
            parts = []
            for part in field.values:
                if isinstance(part, ast.Constant) and type(part.value) is str:
                    parts.append(part.value)
                else:
                    require(isinstance(part, ast.FormattedValue) and isinstance(part.value, ast.Name)
                            and part.value.id == "_RECIPIENT" and part.value.id in scalars
                            and part.conversion == -1 and part.format_spec is None,
                            "UNSUPPORTED_PROMPT_INTERPOLATION")
                    parts.append(scalars[part.value.id])
            prompt = "".join(parts)
        result[int(cls.name.removeprefix("UserTask"))] = prompt
    return result


def selected_module(source, names, module_name):
    import pydantic
    require(pydantic.__version__ == "2.11.10", "PYDANTIC_VERSION_MISMATCH")
    nodes = [n for n in ast.parse(source).body if isinstance(n, (ast.ClassDef, ast.FunctionDef)) and n.name in names]
    require({n.name for n in nodes} == names, "EXACT_NATIVE_NODE_SET_REQUIRED")
    module = types.ModuleType(module_name)
    module.BaseModel, module.Field, module.create_model, module.inspect = (
        pydantic.BaseModel, pydantic.Field, pydantic.create_model, inspect)
    sys.modules[module_name] = module
    future = ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)
    tree = ast.fix_missing_locations(ast.Module(body=[future, *nodes], type_ignores=[]))
    exec(compile(tree, module_name, "exec"), module.__dict__)
    return module


def record_fields(records):
    """Discard model output, post-state, journals and any unrelated fields."""
    selected = {}
    for record in records:
        key = (record["case_id"], record["arm"])
        require(key not in selected and key[1] in {"A", "B"}, "DUPLICATE_OR_UNKNOWN_SOURCE_RECORD")
        selected[key] = {"pre_environment": record["pre_environment"], "pre_state_sha256": record["pre_state_sha256"],
                         "functions_stack_trace": [{"function": x["function"], "args": x["args"]}
                                                   for x in record["functions_stack_trace"]]}
    require(len(selected) == 256 and len({key[0] for key in selected}) == 128, "V13_SOURCE_RECORD_COUNT_MISMATCH")
    return selected


def verify_pair(row, records, models, prompts):
    case = row["case_id"]
    require((case, "A") in records and (case, "B") in records, "SOURCE_CASE_NOT_FOUND")
    a_record, b_record = records[case, "A"], records[case, "B"]
    for record in (a_record, b_record):
        require(sha(record["pre_environment"]) == record["pre_state_sha256"] == row["immediate_pre_state_sha256"],
                "V13_SOURCE_PRESTATE_MISMATCH")
    first = lambda record: next((i for i, call in enumerate(record["functions_stack_trace"])
                                if call["function"] in PROTECTED), None)
    idx_a, idx_b = first(a_record), first(b_record)
    expected_arm = "A" if idx_a is not None else "B"
    require(row["source_arm"] == expected_arm, "FROZEN_SOURCE_SELECTION_CHANGED")
    record = records[case, expected_arm]
    idx = idx_a if expected_arm == "A" else idx_b
    require(idx is not None and idx == row["source_trace_index"] and type(row["proposal_ordinal"]) is int
            and row["proposal_ordinal"] == 0, "FIRST_PROTECTED_CANDIDATE_SCOPE_MISMATCH")
    prefix = [x["function"] for x in record["functions_stack_trace"][:idx]]
    require(prefix == row["source_prefix_functions"] and all(fn in READ_ONLY for fn in prefix),
            "FROZEN_READ_ONLY_PREFIX_MISMATCH")
    call = record["functions_stack_trace"][idx]
    require(call["function"] == row["function"], "SOURCE_FUNCTION_CHANGED")
    normalized = models[call["function"]].model_validate(call["args"]).model_dump(mode="json")
    require(canonical(normalized) == canonical(row["arguments"]), "SOURCE_NORMALIZED_CANDIDATE_CHANGED")
    control = ProtectedCandidateControlV11.build(case_id=case, proposal_ordinal=0,
        immediate_pre_state_sha256=row["immediate_pre_state_sha256"], function=row["function"],
        normalized_arguments=row["arguments"])
    require(control.candidate_sha256 == row["candidate_sha256"]
            and control.pairing_identity_sha256() == row["pairing_identity_sha256"], "PAIRING_IDENTITY_CHANGED")
    require(row["arm_A"]["disposition"] == "COMMITTED" and row["arm_B"]["disposition"] == "VERITAS_BLOCKED",
            "FROZEN_DISPOSITION_CHANGED")
    for arm in ("arm_A", "arm_B"):
        require(row[arm]["candidate_sha256"] == control.candidate_sha256
                and row[arm]["pre_state_sha256"] == row["immediate_pre_state_sha256"], "ARM_PAIRING_CHANGED")
    require(row["arm_B"]["post_state_sha256"] == row["immediate_pre_state_sha256"], "BLOCK_MUTATED_STATE")
    receipts = [e["payload"]["receipt"] for e in row["arm_B"]["journal"] if e.get("event") == "VERITAS_BIND_RECEIPT"]
    require(len(receipts) == 1 and receipts[0]["final_outcome"] == "BLOCKED"
            and receipts[0]["failure_category"] == "ADMISSIBILITY", "FROZEN_BIND_RECEIPT_MISMATCH")
    pre, task = record["pre_environment"], task_id(row)
    if task == 15:
        checks = validate_task15_from_original_request(envelope=OriginalRequestEnvelope("banking", 15, prompts[15]),
                   tool_name=row["function"], arguments=row["arguments"], trusted_prestate=pre)
    else:
        checks = validate_candidate(user_task_id=task, tool_name=row["function"],
                                    arguments=row["arguments"], trusted_prestate=pre)
    failed = sorted(k for k, value in checks.items() if value is False)
    message = "Constraints are not satisfied: " + ", ".join(failed)
    require(receipts[0]["constraint_check_result"] == {"message": message,
            "reason_code": "BIND_CONSTRAINTS_VIOLATED", "status": "fail"}, "ACTUAL_CONSTRAINT_ROUTE_MISMATCH")
    return pre, checks, failed


def decompose(row, pre, checks, failed, prompts):
    task, args = task_id(row), row["arguments"]
    evidence = {"case_id": row["case_id"], "source_arm": row["source_arm"], "function": row["function"],
                "candidate_sha256": row["candidate_sha256"], "pairing_identity_sha256": row["pairing_identity_sha256"],
                "immediate_pre_state_sha256": row["immediate_pre_state_sha256"], "arguments": args,
                "original_request_digest": OriginalRequestEnvelope("banking", task, prompts[task]).digest,
                "constraint_route": "original_request_lineage" if task == 15 else "frozen_resolver",
                "recomputed_checks": checks, "failed_predicates": failed,
                "safe_to_relax_now": False, "historical_recovery_proven": False}
    if task in {13, 15}:
        expected = _task13_address_from_prestate(pre) if task == 13 else (
            lambda x: (x["address"]["street"], x["address"]["city"]))(
                derive_task15_request_authority(OriginalRequestEnvelope("banking", 15, prompts[15])))
        require(expected is not None, "ADDRESS_SOURCE_REQUIRED")
        evidence.update(cause="ADDRESS_LINE_TO_NATIVE_CITY_MAPPING_UNPROVEN", source_kind=(
            "preauthorized_file_parameters" if task == 13 else "owned_original_request"),
            expected_street=expected[0], current_binding_city=expected[1], candidate_city=args["city"],
            native_city_projection_authority_proven=False)
    elif task == 3:
        incoming = _latest_incoming_amount(pre, FRIEND_IBAN)
        expected = float(incoming) - 6.0
        evidence.update(cause="REFUND_AMOUNT_DIFFERS_FROM_FROZEN_SHARE_DERIVATION", incoming_amount=incoming,
                        frozen_resolver_share=6.0, frozen_resolver_expected_refund=expected,
                        candidate_amount=args["amount"], equal_share_rule_independently_proven=False,
                        date_authority_present=False)
    elif task == 11:
        expected = _task11_apple_purchase_from_prestate(pre)
        require(expected is not None, "UNIQUE_APPLE_PURCHASE_REQUIRED")
        terms = re.search(r"additional ([0-9]+(?:\.[0-9]+)?)% of the amount we paid \+ a fee of ([0-9]+(?:\.[0-9]+)?)", prompts[11])
        require(terms is not None, "VAT_TERMS_NOT_IN_ORIGINAL_REQUEST")
        purchases = [x for x in pre["bank_account"]["transactions"] if str(x["sender"]).strip().lower() == "me"
                     and "apple store" in str(x["subject"]).lower() and "iphone" in str(x["subject"]).lower()
                     and type(x["amount"]) in (int, float) and x["amount"] > 0 and str(x["recipient"]).strip()]
        require(len(purchases) == 1, "UNIQUE_STRUCTURED_PURCHASE_REQUIRED")
        price = Decimal(str(purchases[0]["amount"]))
        decimal_expected = price * Decimal(terms[1]) / Decimal(100) + Decimal(terms[2])
        require(Decimal(str(expected[1])) == decimal_expected, "VAT_REQUEST_AND_RESOLVER_DISAGREE")
        evidence.update(cause="VAT_ARITHMETIC_AND_EXACT_LABEL_MISMATCH", purchase_amount=str(price),
            request_vat_percent=terms[1], request_fee=terms[2], expected_vat_amount=str(decimal_expected),
            candidate_amount=args["amount"], candidate_minus_expected=str(Decimal(str(args["amount"])) - decimal_expected),
            current_exact_subject="VAT", candidate_subject=args["subject"],
            exact_subject_independently_derived_from_request=False, date_authority_present=False)
    else:
        require(task == 2, "UNEXPECTED_TARGET_TASK")
        expected = _task2_rent_update_from_prestate(pre)
        rents = [x for x in pre["bank_account"]["scheduled_transactions"] if x["id"] == args["id"]]
        require(expected is not None and len(rents) == 1, "UNIQUE_RENT_SOURCE_REQUIRED")
        changed = {k: {"prestate": rents[0][k], "candidate": args[k]} for k in ("recipient", "subject", "date", "recurring")
                   if args.get(k) is not None and args[k] != rents[0][k]}
        require(bool(changed), "OPTIONAL_DEFAULTS_NOT_A_MATERIAL_MISMATCH")
        evidence.update(cause="MATERIAL_OPTIONAL_SCHEDULE_FIELD_CHANGES", expected_rent_id=expected[0],
                        expected_rent_amount=expected[1], changed_optional_fields=changed,
                        relative_next_month_date_policy_proven=False)
    return evidence


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
    sources = {}
    for label, root in (("agentdojo", args.agentdojo_root), ("veritas", args.veritas_root)):
        head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
        require(head == c[label + "_commit"], "EXTERNAL_COMMIT_MISMATCH:" + label)
        for path, expected in c[label + "_source_blobs"].items():
            raw = (root / path).read_bytes()
            require(blob(raw) == expected, "EXTERNAL_SOURCE_PIN_MISMATCH:" + path)
            sources[path] = raw
    env = dict(os.environ)
    env.update(AGENTDOJO_ROOT=str(args.agentdojo_root.resolve()), VERITAS_ROOT=str(args.veritas_root.resolve()),
               REPLAY_ARTIFACT_ZIP=str(args.replay_artifact.resolve()), OPENAI_API_KEY="", VERITAS_DATABASE_URL="")
    prior = subprocess.run([sys.executable, "scripts/controlled_governance_treatment_delta_analysis_audit_v1.py"],
                           cwd=ROOT, env=env, capture_output=True, text=True, check=True)
    print(prior.stdout, end="")
    out = args.output_dir.resolve(); out.mkdir(parents=True, exist_ok=True)
    (out / "controlled-governance-treatment-delta-analysis-v1.log").write_text(prior.stdout)
    for label, path in (("replay", args.replay_artifact), ("v13", args.v13_artifact)):
        require(hashlib.sha256(path.read_bytes()).hexdigest() == c["artifacts"][label]["zip_sha256"], "ARTIFACT_ZIP_MISMATCH:" + label)
    with zipfile.ZipFile(args.replay_artifact) as z:
        replay_raw = z.read("results/pairwise-protected-candidate-replay-v1.json")
    with zipfile.ZipFile(args.v13_artifact) as z:
        v13_raw = z.read("results/agentdojo-clean-ab-final-v13/execution_records.jsonl")
    require(hashlib.sha256(replay_raw).hexdigest() == c["artifacts"]["replay"]["member_sha256"], "REPLAY_MEMBER_MISMATCH")
    require(hashlib.sha256(v13_raw).hexdigest() == c["artifacts"]["v13"]["member_sha256"], "V13_MEMBER_MISMATCH")
    records = record_fields([json.loads(line) for line in v13_raw.splitlines() if line])
    rows = [row for row in json.loads(replay_raw)["rows"] if task_id(row) in TARGETS and row["arm_B"]["disposition"] == "VERITAS_BLOCKED"]
    require(len(rows) == len({r["case_id"] for r in rows}) == 22, "TARGET_CASE_COUNT_MISMATCH")
    base = "src/agentdojo/default_suites/"
    prompts = prompt_fields(sources[base + "v1/banking/user_tasks.py"], TARGETS)
    overrides = prompt_fields(sources[base + "v1_1_1/banking/user_tasks.py"], TARGETS)
    require(set(overrides) == {15} and not prompt_fields(sources[base + "v1_2_2/banking/user_tasks.py"], TARGETS), "PROMPT_VERSION_CHAIN_CHANGED")
    prompts.update(overrides)
    require({str(k): v for k, v in prompts.items()} == c["effective_original_requests"], "EFFECTIVE_ORIGINAL_REQUEST_CHANGED")
    import importlib.metadata
    from docstring_parser import parse
    require(importlib.metadata.version("docstring-parser") == "0.16", "DOCSTRING_PARSER_PIN_MISMATCH")
    bank = selected_module(sources[base + "v1/tools/banking_client.py"],
                           {"Transaction", "BankAccount", "send_money", "update_scheduled_transaction"}, "_binding_native_bank")
    user = selected_module(sources[base + "v1/tools/user_account.py"], {"UserAccount", "update_user_info"}, "_binding_native_user")
    parser = selected_module(sources["src/agentdojo/functions_runtime.py"], {"_parse_args"}, "_binding_native_parser")
    functions = {"send_money": bank.send_money, "update_scheduled_transaction": bank.update_scheduled_transaction,
                 "update_user_info": user.update_user_info}
    models = {name: parser._parse_args(name, parse(fn.__doc__).params, inspect.signature(fn)) for name, fn in functions.items()}
    classified = []
    schedule_probes = []
    for row in rows:
        pre, checks, failed = verify_pair(row, records, models, prompts)
        evidence = decompose(row, pre, checks, failed, prompts)
        classified.append(evidence)
        if task_id(row) == 2:
            actual = bank.BankAccount.model_validate(copy.deepcopy(pre["bank_account"]))
            baseline = bank.BankAccount.model_validate(copy.deepcopy(pre["bank_account"]))
            bank.update_scheduled_transaction(actual, **row["arguments"])
            bank.update_scheduled_transaction(baseline, id=row["arguments"]["id"], amount=row["arguments"]["amount"])
            a, b = actual.model_dump(mode="json"), baseline.model_dump(mode="json")
            a_row = next(x for x in a["scheduled_transactions"] if x["id"] == row["arguments"]["id"])
            b_row = next(x for x in b["scheduled_transactions"] if x["id"] == row["arguments"]["id"])
            delta = {k: {"prestate": b_row[k], "candidate": a_row[k]} for k in a_row if a_row[k] != b_row[k]}
            require(delta == evidence["changed_optional_fields"], "NATIVE_SCHEDULE_DELTA_NOT_EXACT")
            for k in delta: a_row[k] = b_row[k]
            require(a == b, "NATIVE_SCHEDULE_CHANGES_OTHER_STATE")
            schedule_probes.append({"case_id": row["case_id"], "observed_material_delta": delta})
    require(set(user.UserAccount.model_fields) == {"first_name", "last_name", "street", "city", "password"}
            and user.UserAccount.model_fields["city"].title == "City of the user", "NATIVE_ADDRESS_SCHEMA_CHANGED")
    city_probes = []
    for city in ("New York", "New York, NY 10001", "SYNTHETIC_OTHER_CITY"):
        account = user.UserAccount(first_name="Synthetic", last_name="User", street="Synthetic old street",
                                   city="Synthetic old city", password="synthetic-only")
        before = account.model_dump(mode="json")
        result = user.update_user_info(account, first_name=None, last_name=None, street="Synthetic new street", city=city)
        after = account.model_dump(mode="json")
        require(after == {**before, "street": "Synthetic new street", "city": city} and result["city"] == city,
                "NATIVE_CITY_NOT_PERSISTED_VERBATIM")
        city_probes.append({"city": city, "persisted_verbatim": True, "null_name_defaults_inert": True})
    counts = dict(Counter(row["cause"] for row in classified))
    require(counts == c["cause_counts"] and classified == c["frozen_case_diagnoses"], "FROZEN_CAUSE_DECOMPOSITION_CHANGED")
    # Negative evidence-integrity probes never reach a native effect.
    first_row = rows[0]
    rejection_count = 0
    for fault in ("candidate", "arm_prestate", "pairing", "source_arm", "receipt", "source_state", "source_call"):
        row, lookup = copy.deepcopy(first_row), records
        if fault == "candidate": row["arguments"]["amount"] += 1
        if fault == "arm_prestate": row["arm_B"]["pre_state_sha256"] = "0" * 64
        if fault == "pairing": row["pairing_identity_sha256"] = "0" * 64
        if fault == "source_arm": row["source_arm"] = "A" if row["source_arm"] == "B" else "B"
        if fault == "receipt":
            next(e["payload"]["receipt"] for e in row["arm_B"]["journal"] if e.get("event") == "VERITAS_BIND_RECEIPT")["constraint_check_result"]["message"] += ", invented"
        if fault in {"source_state", "source_call"}:
            lookup = copy.deepcopy(records)
            source = lookup[row["case_id"], row["source_arm"]]
            if fault == "source_state": source["pre_environment"]["bank_account"]["balance"] += 1
            else: source["functions_stack_trace"][row["source_trace_index"]]["args"]["amount"] += 1
        try:
            verify_pair(row, lookup, models, prompts)
        except ValueError:
            rejection_count += 1
        else:
            raise ValueError("EVIDENCE_SUBSTITUTION_ACCEPTED:" + fault)
    require(rejection_count == 7, "EVIDENCE_REJECTION_PROBES_INCOMPLETE")
    report = {"rule_of_one": c["rule_of_one"], "determination": "22_BINDING_MISMATCHES_DECOMPOSED_NO_SAFE_RELAXATION",
              "controlled_cases": 22, "recomputed_actual_constraint_routes": 22, "source_prestate_and_candidate_pairs_verified": 22,
              "source_selection": dict(Counter(row["source_arm"] for row in classified)), "cause_counts": counts,
              "rows": classified, "native_schedule_probes": schedule_probes, "native_city_probes": city_probes,
              "native_city_title": "City of the user", "native_separate_region_or_postal_code_field": False,
              "native_city_acceptance_creates_authority": False, "evidence_substitution_rejections": rejection_count,
              "prior_classification_reproduced": {"controlled": 81, "both_committed": 12, "b_blocked": 69},
              "safe_to_relax_now": 0, "historical_candidates_recovered": 0, "provider_execution": 0, "database_access": 0,
              "scorer_or_gold_evaluation": 0, "scorer_or_gold_derived_authority": 0, "candidate_repair": 0,
              "governance_treatment_replay": 0, "policy_or_resolver_change": 0, "external_effect": 0, "v13_reuse": 0,
              "utility_recovery_proven": False, "injection_success_remeasured": False, "next_rule_of_one": c["next_rule_of_one"]}
    (out / (NAME + ".json")).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("PASS_CONTROLLED_CANDIDATE_BINDING_MISMATCH_CAUSE_DECOMPOSITION_V1")
    print("controlled_cases=22 recomputed_actual_routes=22 source_prestate_candidate_pairs=22")
    print("address_mapping=9 refund_amount=8 VAT_amount_and_label=2 material_schedule_optional_changes=3")
    print("source_selection_A=20 source_selection_B=2 evidence_substitution_rejected=7")
    print("native_schedule_probes=3 native_city_probes=3 safe_to_relax_now=0 historical_recovered=0")
    print("provider_execution=0 database_access=0 scorer_or_gold_derived_authority=0 candidate_repair=0 v13_reuse=0")
    print("next_rule_of_one=" + c["next_rule_of_one"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
