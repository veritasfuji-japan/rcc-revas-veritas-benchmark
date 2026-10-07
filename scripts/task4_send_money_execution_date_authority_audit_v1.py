#!/usr/bin/env python3
"""Offline, source-pinned Task4 date semantics and unresolved authority audit.

Only PROMPT literals are selected from task source. No task class, gold method,
scorer, provider, database, or full AgentDojo pipeline is imported or invoked.
The native probes execute selected, unmodified banking models/functions against
isolated synthetic accounts; this is not a governance replay or an allow proof.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import types
import zipfile
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "contracts/TASK4_SEND_MONEY_EXECUTION_DATE_AUTHORITY_V1.json"
EXPECTED_CONTRACT_BLOB = "27df2d5fb3d6eb75ec173a9273b0bc6834fd0c1c"


def blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def selected_native_module(source: bytes) -> types.ModuleType:
    """Compile exact source bodies; omit only unrelated module imports/nodes."""
    import pydantic
    require(pydantic.__version__ == "2.11.10", "PYDANTIC_VERSION_MISMATCH")
    selected = {"Transaction", "BankAccount", "next_id", "get_iban", "send_money", "schedule_transaction"}
    tree = ast.parse(source)
    nodes = [n for n in tree.body if isinstance(n, (ast.ClassDef, ast.FunctionDef)) and n.name in selected]
    require({n.name for n in nodes} == selected, "NATIVE_NODE_SET_MISMATCH")
    send = next(n for n in nodes if n.name == "send_money")
    reads = [n for n in ast.walk(send) if isinstance(n, ast.Name) and n.id == "date" and isinstance(n.ctx, ast.Load)]
    require(len(reads) == 1, "DATE_HAS_ADDITIONAL_NATIVE_USES")
    constructors = [n for n in ast.walk(send) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "Transaction"]
    require(len(constructors) == 1, "TRANSACTION_CONSTRUCTOR_MISMATCH")
    dates = [kw.value for kw in constructors[0].keywords if kw.arg == "date"]
    require(len(dates) == 1 and dates[0] is reads[0], "DATE_NOT_EXACT_LEDGER_FIELD")
    module = types.ModuleType("_task4_pinned_native_date_probe")
    module.BaseModel = pydantic.BaseModel
    module.Field = pydantic.Field
    sys.modules[module.__name__] = module
    # Future annotations avoid evaluating Depends, which is annotation-only in
    # these functions. Their bodies, models and Pydantic validation are intact.
    future = ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)
    selected_tree = ast.fix_missing_locations(ast.Module(body=[future, *nodes], type_ignores=[]))
    exec(compile(selected_tree, "pinned-banking-client-date-probe", "exec"), module.__dict__)
    return module


def native_probes(source: bytes) -> dict:
    native = selected_native_module(source)
    dates = ["2001-01-02", "2040-02-03", "2099-12-31", "not-a-calendar-date", ""]
    projections = []
    returned = []
    for date in dates:
        account = native.BankAccount(balance=100, iban="SYNTHETIC_SENDER", transactions=[], scheduled_transactions=[])
        before = account.model_dump(mode="json")
        result = native.send_money(account, "SYNTHETIC_RECIPIENT", 7.0, "Synthetic refund probe", date)
        after = account.model_dump(mode="json")
        require(len(after["transactions"]) == 1, "NATIVE_APPEND_COUNT")
        transaction = after["transactions"][0]
        require(transaction["date"] == date, "DATE_NOT_PERSISTED_EXACTLY")
        require(transaction["recurring"] is False, "SEND_MONEY_RECURRING_CHANGED")
        require(after["scheduled_transactions"] == before["scheduled_transactions"], "SEND_MONEY_SCHEDULED_STATE_CHANGED")
        require(after["balance"] == before["balance"] and after["iban"] == before["iban"], "NATIVE_OTHER_STATE_CHANGED")
        projected = copy.deepcopy(after)
        del projected["transactions"][0]["date"]
        projections.append(projected)
        returned.append(result)
    require(all(x == projections[0] for x in projections), "DATE_CHANGES_NON_DATE_NATIVE_STATE")
    require(all(x == returned[0] for x in returned), "DATE_CHANGES_NATIVE_RETURN")
    # A separate native scheduling probe prevents extending this result to the
    # schedule_transaction tool used by Task6.
    account = native.BankAccount(balance=100, iban="SYNTHETIC_SENDER", transactions=[], scheduled_transactions=[])
    native.schedule_transaction(account, "SYNTHETIC_RECIPIENT", 7.0, "Synthetic schedule probe", "2040-02-03", True)
    require(not account.transactions and len(account.scheduled_transactions) == 1, "SCHEDULE_TOOL_BOUNDARY_MISMATCH")
    return {
        "send_money_probes": len(dates),
        "schedule_boundary_probes": 1,
        "date_persisted_exactly": True,
        "non_date_state_equal": True,
        "native_return_equal": True,
        "scheduled_state_unchanged_by_send_money": True,
        "invalid_and_empty_date_strings_accepted_by_native": True,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--agentdojo-root", type=Path, required=True)
    p.add_argument("--replay-artifact", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    require(not os.environ.get("OPENAI_API_KEY"), "OPENAI_API_KEY_MUST_BE_EMPTY")
    require(not os.environ.get("VERITAS_DATABASE_URL"), "VERITAS_DATABASE_URL_MUST_BE_EMPTY")
    raw_contract = CONTRACT_PATH.read_bytes()
    require(blob(raw_contract) == EXPECTED_CONTRACT_BLOB, "TASK4_CONTRACT_BLOB_MISMATCH")
    c = json.loads(raw_contract)
    require(c["rule_of_one"] == "TASK4_SEND_MONEY_EXECUTION_DATE_AUTHORITY_V1", "RULE_OF_ONE_MISMATCH")
    for path, expected in c["local_source_blobs"].items():
        require(blob((ROOT / path).read_bytes()) == expected, "LOCAL_SOURCE_BLOB_MISMATCH:" + path)
    head = subprocess.run(["git", "-C", str(args.agentdojo_root), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    require(head == c["agentdojo_commit"], "AGENTDOJO_COMMIT_MISMATCH")
    sources = {}
    for path, expected in c["agentdojo_source_blobs"].items():
        raw = (args.agentdojo_root / path).read_bytes()
        require(blob(raw) == expected, "AGENTDOJO_SOURCE_BLOB_MISMATCH:" + path)
        sources[path] = raw

    # Select only Task4's original instruction literal, never its methods.
    task_tree = ast.parse(sources["src/agentdojo/default_suites/v1/banking/user_tasks.py"])
    task4 = next(n for n in task_tree.body if isinstance(n, ast.ClassDef) and n.name == "UserTask4")
    prompts = [n.value.value for n in task4.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "PROMPT" for t in n.targets) and isinstance(n.value, ast.Constant)]
    require(prompts == [c["original_request"]], "TASK4_ORIGINAL_REQUEST_MISMATCH")
    for version in ("v1_1_1", "v1_2_2"):
        tree = ast.parse(sources[f"src/agentdojo/default_suites/{version}/banking/user_tasks.py"])
        require(not any(isinstance(n, ast.ClassDef) and n.name == "UserTask4" for n in tree.body), "TASK4_VERSION_OVERRIDE")
    suite_tree = ast.parse(sources["src/agentdojo/default_suites/v1/banking/task_suite.py"])
    native_imports = [n for n in suite_tree.body if isinstance(n, ast.ImportFrom) and n.module == "agentdojo.default_suites.v1.tools.banking_client"]
    require(len(native_imports) == 1 and any(a.name == "send_money" and a.asname is None for a in native_imports[0].names), "BANKING_NATIVE_TOOL_IMPORT_MISMATCH")
    tool_lists = [n.value for n in suite_tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "TOOLS" for t in n.targets)]
    require(len(tool_lists) == 1 and isinstance(tool_lists[0], ast.List) and "send_money" in [n.id for n in tool_lists[0].elts if isinstance(n, ast.Name)], "BANKING_NATIVE_TOOL_NOT_REGISTERED")

    # Version selection deep-copies the same registered native tool list. Read
    # only this method's AST and exercise it on a sentinel object, never a suite
    # instance that could evaluate task/scoring methods.
    suite_core_tree = ast.parse(sources["src/agentdojo/task_suite/task_suite.py"])
    suite_class = next(n for n in suite_core_tree.body if isinstance(n, ast.ClassDef) and n.name == "TaskSuite")
    new_version = next(n for n in suite_class.body if isinstance(n, ast.FunctionDef) and n.name == "get_new_version")
    namespace = {"copy": copy}
    future = ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)
    selected = ast.fix_missing_locations(ast.Module(body=[future, new_version], type_ignores=[]))
    exec(compile(selected, "pinned-task-suite-version-method", "exec"), namespace)
    sentinel = types.SimpleNamespace(tools=["send_money_sentinel"], benchmark_version=(1, 0, 0))
    newer = namespace["get_new_version"](sentinel, (1, 2, 2))
    require(newer.tools == sentinel.tools and newer.benchmark_version == (1, 2, 2) and newer is not sentinel, "NATIVE_TOOL_VERSION_INHERITANCE_MISMATCH")

    # The actual, unchanged frozen Task4 resolver remains fail-closed even
    # when recipient/amount bindings pass. These synthetic date values supply
    # no new authority, and never come from score/gold/corpus success labels.
    spec = importlib.util.spec_from_file_location("_task4_frozen_resolver", ROOT / "agentdojo_constraint_resolver_v0_1.py")
    require(spec is not None and spec.loader is not None, "FROZEN_RESOLVER_IMPORT_FAILURE")
    resolver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(resolver)
    synthetic_prestate = {"bank_account": {"transactions": [{"sender": "GB29NWBK60161331926819", "amount": 7.0}]}}
    for synthetic_date in ("2001-01-02", "2040-02-03", "not-a-calendar-date", ""):
        checks = resolver.validate_candidate(user_task_id=4, tool_name="send_money", arguments={"recipient": "GB29NWBK60161331926819", "amount": 7.0, "subject": "Synthetic refund probe", "date": synthetic_date}, trusted_prestate=synthetic_prestate)
        require(checks["recipient_bound"] and checks["amount_bound"], "TASK4_SYNTHETIC_BINDING_SETUP_FAILURE")
        require(checks["date_authority_present"] is False and checks["supported_profile"] is False, "TASK4_EXISTING_DATE_GATE_RELAXED")

    artifact_bytes = args.replay_artifact.read_bytes()
    require(hashlib.sha256(artifact_bytes).hexdigest() == c["source_replay"]["artifact_zip_sha256"], "REPLAY_ARTIFACT_DIGEST_MISMATCH")
    with zipfile.ZipFile(args.replay_artifact) as archive:
        result_bytes = archive.read("results/pairwise-protected-candidate-replay-v1.json")
    require(hashlib.sha256(result_bytes).hexdigest() == c["source_replay"]["result_json_sha256"], "REPLAY_RESULT_DIGEST_MISMATCH")
    result = json.loads(result_bytes)
    rows = [r for r in result["rows"] if r["case_id"].split(":")[1] == "user_task_4"]
    require(len(rows) == 8 and len({r["case_id"] for r in rows}) == 8, "TASK4_CASE_COUNT_MISMATCH")
    observed = []
    for row in rows:
        require(row["function"] == "send_money", "TASK4_TOOL_MISMATCH")
        require(row["arm_A"]["disposition"] == "COMMITTED" and row["arm_B"]["disposition"] == "VERITAS_BLOCKED", "TASK4_DISPOSITION_MISMATCH")
        for arm in ("arm_A", "arm_B"):
            require(row[arm]["candidate_sha256"] == row["candidate_sha256"], "TASK4_CANDIDATE_PAIRING_MISMATCH")
            require(row[arm]["pre_state_sha256"] == row["immediate_pre_state_sha256"], "TASK4_PRESTATE_PAIRING_MISMATCH")
        require(row["arm_B"]["post_state_sha256"] == row["arm_B"]["pre_state_sha256"], "TASK4_BLOCK_MUTATED_STATE")
        payload = {"kind": "tool_call", "name": row["function"], "arguments": row["arguments"], "content": None, "metadata": {}}
        candidate_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        require(candidate_hash == row["candidate_sha256"], "TASK4_RCC_CANDIDATE_HASH_MISMATCH")
        receipts = [e["payload"]["receipt"] for e in row["arm_B"]["journal"] if e.get("event") == "VERITAS_BIND_RECEIPT"]
        require(len(receipts) == 1, "TASK4_BIND_RECEIPT_COUNT")
        require(receipts[0]["constraint_check_result"]["message"] == "Constraints are not satisfied: date_authority_present, supported_profile", "TASK4_FAILED_PREDICATES_MISMATCH")
        observed.append({"case_id": row["case_id"], "candidate_sha256": candidate_hash, "immediate_pre_state_sha256": row["immediate_pre_state_sha256"], "candidate_date": row["arguments"]["date"]})
    require(observed == c["frozen_task4_candidates"], "TASK4_FROZEN_CANDIDATES_MISMATCH")
    dates = dict(Counter(r["candidate_date"] for r in observed))
    require(dates == c["candidate_date_distribution"], "TASK4_DATE_DISTRIBUTION_MISMATCH")

    probe_result = native_probes(sources["src/agentdojo/default_suites/v1/tools/banking_client.py"])
    report = {
        "schema_version": "veritas.task4-send-money-execution-date-authority-report.v1",
        "rule_of_one": c["rule_of_one"],
        "native_semantics": probe_result,
        "native_semantics_determination": "DATE_PERSISTED_AS_LEDGER_METADATA_NOT_DISPATCH_SCHEDULE",
        "authority_recovery_determination": "NOT_PROVEN_NO_INDEPENDENT_TRUSTED_DATE_BINDING",
        "frozen_candidate_count": len(observed),
        "candidate_date_distribution": dates,
        "safe_to_relax_now": 0,
        "unchanged_resolver_fail_closed_synthetic_probes": 4,
        "governance_treatment_replay": 0,
        "provider_execution": 0,
        "database_access": 0,
        "scorer_or_gold_evaluation": 0,
        "scorer_or_gold_used_for_authority": 0,
        "candidate_repair": 0,
        "policy_or_resolver_change": 0,
        "external_effect": 0,
        "next_rule_of_one": c["next_rule_of_one"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("PASS_TASK4_SEND_MONEY_EXECUTION_DATE_AUTHORITY_V1")
    print("PASS_TASK4_EXACT_SOURCE_AND_REPLAY_PINS")
    print("PASS_TASK4_8_UNMODIFIED_PAIRED_CANDIDATES")
    print("PASS_TASK4_NATIVE_DATE_IS_PERSISTED_METADATA_NOT_DISPATCH_SCHEDULE")
    print("PASS_TASK4_ARBITRARY_NATIVE_DATE_ACCEPTANCE_IS_NOT_AUTHORITY")
    print("authority_recovery=NOT_PROVEN")
    print("safe_to_relax_now=0")
    print("native_send_money_synthetic_probes=5")
    print("native_schedule_boundary_synthetic_probes=1")
    print("provider_execution=0 database_access=0 external_effect=0")
    print("next_rule_of_one=" + c["next_rule_of_one"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
