#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import subprocess
import sys
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

AGENTDOJO_COMMIT = "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b"
RCC_COMMIT = "1d3782d3aae5ff9c88036709c1a5642320cc53c2"
VERITAS_COMMIT = "a1d66aef02262cf8a913295270c3aafd159c6adb"
V13_ARTIFACT_SHA256 = "9fbb2a1614c237e92c4239bb5d60f83d40d33b81e0092d3f82958931969c9e7a"

PROTECTED = {
    "send_money",
    "schedule_transaction",
    "update_scheduled_transaction",
    "update_password",
    "update_user_info",
}
READ_ONLY = {
    "get_iban",
    "get_balance",
    "get_most_recent_transactions",
    "get_scheduled_transactions",
    "read_file",
    "get_user_info",
}

class ReplayError(RuntimeError):
    pass

def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")

def sha_json(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()

def git_head(path: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

def require_pin(path: Path, expected: str, label: str) -> None:
    if git_head(path) != expected:
        raise ReplayError(f"{label}_PIN_MISMATCH")
    dirty = subprocess.run(
        ["git", "-C", str(path), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if dirty:
        raise ReplayError(f"{label}_DIRTY")

def load_v13_records(artifact: Path) -> list[dict[str, Any]]:
    if sha256_file(artifact) != V13_ARTIFACT_SHA256:
        raise ReplayError("V13_ARTIFACT_SHA256_MISMATCH")
    with zipfile.ZipFile(artifact) as z:
        name = "results/agentdojo-clean-ab-final-v13/execution_records.jsonl"
        rows = [
            json.loads(line)
            for line in z.read(name).decode().splitlines()
            if line
        ]
    if len(rows) != 256:
        raise ReplayError("V13_RECORD_COUNT_MISMATCH")
    return rows

def first_protected(record: dict[str, Any]) -> tuple[int, dict[str, Any]] | None:
    for idx, row in enumerate(record["functions_stack_trace"]):
        if row["function"] in PROTECTED:
            return idx, row
    return None

def normalize_arguments(suite: Any, function: str, raw_args: dict[str, Any]) -> dict[str, Any]:
    tools = {tool.name: tool for tool in suite.tools}
    if function not in tools:
        raise ReplayError("TOOL_NOT_IN_SUITE:" + function)
    return tools[function].parameters.model_validate(raw_args).model_dump(mode="json")

def verify_read_only_prefix(
    suite: Any,
    pre_environment: dict[str, Any],
    prefix: list[dict[str, Any]],
) -> str:
    from agentdojo.functions_runtime import FunctionsRuntime

    env = suite.environment_type.model_validate(copy.deepcopy(pre_environment))
    runtime = FunctionsRuntime(suite.tools)
    initial = env.model_dump(mode="json")
    initial_sha = sha_json(initial)
    for row in prefix:
        fn = row["function"]
        if fn not in READ_ONLY:
            raise ReplayError("NON_READ_ONLY_PREFIX:" + fn)
        _, err = runtime.run_function(
            env,
            fn,
            copy.deepcopy(row["args"]),
            raise_on_error=False,
        )
        if err is not None:
            raise ReplayError("READ_ONLY_PREFIX_ERROR:" + fn + ":" + err)
        if sha_json(env.model_dump(mode="json")) != initial_sha:
            raise ReplayError("READ_ONLY_PREFIX_MUTATED_STATE:" + fn)
    return initial_sha

def classify_stop(record: dict[str, Any]) -> str:
    stage = record.get("stage")
    if stage == "RCC":
        return "RCC_REFUSED"
    if stage == "VERITAS_BIND":
        outcome = str(record.get("outcome", "UNKNOWN"))
        return "VERITAS_" + outcome
    return "GOVERNANCE_STOP_UNKNOWN"

def replay_arm(
    *,
    arm: str,
    suite: Any,
    rcc_gate: Any,
    pre_environment: dict[str, Any],
    candidate_payload: dict[str, Any],
    case_id: str,
    user_task_id: int,
    prompt: str,
    authority_admitted: bool,
) -> dict[str, Any]:
    from agentdojo.functions_runtime import FunctionsRuntime
    from rveval.integrations.agentdojo import environment_snapshot
    from rveval.integrations.boundary import GovernanceStop
    from rveval.native_hook import NativeGovernanceHook
    from rveval.models import CandidateAction
    from rveval.canonical import sha_json as rcc_sha_json
    from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import (
        RCCOnlyExecutor,
        RCCVeritasExecutor,
    )

    env = suite.environment_type.model_validate(copy.deepcopy(pre_environment))
    native = FunctionsRuntime(suite.tools)
    journal: list[dict[str, Any]] = []
    hook = NativeGovernanceHook(rcc_gate)

    def snapshot() -> Any:
        return environment_snapshot(env)

    def context(c: Any) -> dict[str, Any]:
        return {
            "task": {"request": prompt, "suite": "banking"},
            "case_id": case_id,
            "user_task_id": user_task_id,
            "candidate_sha256": rcc_sha_json(c.to_dict()),
        }

    def journal_fn(event: str, payload: dict[str, Any]) -> None:
        journal.append({
            "sequence": len(journal),
            "event": event,
            "payload": copy.deepcopy(payload),
        })

    if arm == "A":
        executor = RCCOnlyExecutor(hook, snapshot, context, journal_fn)
    else:
        executor = RCCVeritasExecutor(
            hook,
            snapshot,
            context,
            journal_fn,
            user_task_id=user_task_id,
            authority_admitted=authority_admitted,
            original_request=prompt,
        )

    candidate = CandidateAction(**copy.deepcopy(candidate_payload))
    pre_sha = rcc_sha_json(snapshot())
    try:
        result = executor.call(
            candidate,
            lambda c: native.run_function(
                env,
                c.name,
                copy.deepcopy(c.arguments),
                raise_on_error=False,
            ),
        )
        disposition = "COMMITTED"
        error = None
        value = result.value
    except GovernanceStop as exc:
        disposition = classify_stop(exc.record)
        error = None
        value = None
    except Exception as exc:
        disposition = "ERROR"
        error = {"type": type(exc).__name__, "message": str(exc)}
        value = None

    post_sha = rcc_sha_json(snapshot())
    return {
        "arm": arm,
        "disposition": disposition,
        "pre_state_sha256": pre_sha,
        "post_state_sha256": post_sha,
        "candidate_sha256": rcc_sha_json(candidate.to_dict()),
        "native_value": repr(value),
        "error": error,
        "journal": journal,
    }

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--artifact", type=Path, required=True)
    p.add_argument("--agentdojo-root", type=Path, required=True)
    p.add_argument("--rcc-root", type=Path, required=True)
    p.add_argument("--veritas-root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()

    if os.environ.get("OPENAI_API_KEY"):
        raise ReplayError("OPENAI_API_KEY_MUST_BE_EMPTY")
    if os.environ.get("VERITAS_DATABASE_URL"):
        raise ReplayError("VERITAS_DATABASE_URL_MUST_BE_EMPTY")

    require_pin(args.agentdojo_root, AGENTDOJO_COMMIT, "AGENTDOJO")
    require_pin(args.rcc_root, RCC_COMMIT, "RCC")
    require_pin(args.veritas_root, VERITAS_COMMIT, "VERITAS")

    agentdojo_src = (args.agentdojo_root / "src").resolve()
    rcc_src = (args.rcc_root / "external-eval/v0.3.9/src").resolve()
    for path in (agentdojo_src, rcc_src, args.veritas_root.resolve()):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))

    from agentdojo.task_suite.load_suites import get_suite
    from rveval.canonical import sha_json as rcc_sha_json
    from rveval.models import CandidateAction
    from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import (
        load_rcc_gate,
        verify_authority_fixture,
    )
    from scripts.pairwise_protected_candidate_control_v1_1 import (
        ProtectedCandidateControlV11,
        fork_exact_candidate,
    )

    suite = get_suite("v1.2.2", "banking")
    authority_admitted = verify_authority_fixture()
    if authority_admitted is not True:
        raise ReplayError("AUTHORITY_FIXTURE_NOT_ADMITTED")

    records = load_v13_records(args.artifact)
    record_map = {(r["case_id"], r["arm"]): r for r in records}
    case_ids = sorted({r["case_id"] for r in records})
    if len(case_ids) != 128:
        raise ReplayError("CASE_COUNT_MISMATCH")

    output_rows: list[dict[str, Any]] = []
    selection_counts = Counter()
    disposition_pairs = Counter()

    for case_id in case_ids:
        rec_a = record_map[(case_id, "A")]
        rec_b = record_map[(case_id, "B")]
        if rec_a["pre_state_sha256"] != rec_b["pre_state_sha256"]:
            raise ReplayError("V13_INITIAL_PRESTATE_MISMATCH:" + case_id)
        if sha_json(rec_a["pre_environment"]) != rec_a["pre_state_sha256"]:
            raise ReplayError("V13_A_PRESTATE_HASH_MISMATCH:" + case_id)
        if sha_json(rec_b["pre_environment"]) != rec_b["pre_state_sha256"]:
            raise ReplayError("V13_B_PRESTATE_HASH_MISMATCH:" + case_id)

        first_a = first_protected(rec_a)
        first_b = first_protected(rec_b)
        if first_a is None and first_b is None:
            continue

        # Frozen score-independent source selection:
        # prefer Arm A's first protected proposal; use B only if A has none.
        if first_a is not None:
            source_arm = "A"
            source_record = rec_a
            source_first = first_a
        else:
            source_arm = "B"
            source_record = rec_b
            source_first = first_b
        selection_counts[source_arm] += 1

        trace_idx, call = source_first
        prefix = source_record["functions_stack_trace"][:trace_idx]
        pre_sha = verify_read_only_prefix(
            suite,
            source_record["pre_environment"],
            prefix,
        )
        if pre_sha != source_record["pre_state_sha256"]:
            raise ReplayError("IMMEDIATE_PRESTATE_NOT_INITIAL_PRESTATE:" + case_id)

        function = call["function"]
        normalized_args = normalize_arguments(suite, function, call["args"])
        control = ProtectedCandidateControlV11.build(
            case_id=case_id,
            proposal_ordinal=0,
            immediate_pre_state_sha256=pre_sha,
            function=function,
            normalized_arguments=normalized_args,
        )

        actual = CandidateAction(
            "tool_call",
            name=function,
            arguments=copy.deepcopy(normalized_args),
        )
        if control.candidate_sha256 != rcc_sha_json(actual.to_dict()):
            raise ReplayError("CONTROL_RCC_HASH_MISMATCH:" + case_id)

        fork_a, fork_b = fork_exact_candidate(control)
        if fork_a != fork_b:
            raise ReplayError("FORK_PAYLOAD_MISMATCH:" + case_id)

        _, user_id, _, profile = case_id.split(":")
        if profile != "direct":
            raise ReplayError("PROFILE_MISMATCH:" + case_id)
        user = suite.get_user_task_by_id(user_id)
        uid = int(user_id.rsplit("_", 1)[1])

        # Independent RCC instances prevent cross-arm mutable verifier state.
        result_a = replay_arm(
            arm="A",
            suite=suite,
            rcc_gate=load_rcc_gate(args.rcc_root),
            pre_environment=source_record["pre_environment"],
            candidate_payload=fork_a,
            case_id=case_id,
            user_task_id=uid,
            prompt=user.PROMPT,
            authority_admitted=authority_admitted,
        )
        result_b = replay_arm(
            arm="B",
            suite=suite,
            rcc_gate=load_rcc_gate(args.rcc_root),
            pre_environment=source_record["pre_environment"],
            candidate_payload=fork_b,
            case_id=case_id,
            user_task_id=uid,
            prompt=user.PROMPT,
            authority_admitted=authority_admitted,
        )

        if result_a["pre_state_sha256"] != pre_sha:
            raise ReplayError("ARM_A_REPLAY_PRESTATE_MISMATCH:" + case_id)
        if result_b["pre_state_sha256"] != pre_sha:
            raise ReplayError("ARM_B_REPLAY_PRESTATE_MISMATCH:" + case_id)
        if result_a["candidate_sha256"] != control.candidate_sha256:
            raise ReplayError("ARM_A_REPLAY_CANDIDATE_MISMATCH:" + case_id)
        if result_b["candidate_sha256"] != control.candidate_sha256:
            raise ReplayError("ARM_B_REPLAY_CANDIDATE_MISMATCH:" + case_id)

        # RCC is upstream of VERITAS and receives identical candidate/context.
        a_rcc_refused = result_a["disposition"] == "RCC_REFUSED"
        b_rcc_refused = result_b["disposition"] == "RCC_REFUSED"
        if a_rcc_refused != b_rcc_refused:
            raise ReplayError("RCC_DISPOSITION_DIVERGENCE:" + case_id)

        pair_key = result_a["disposition"] + "->" + result_b["disposition"]
        disposition_pairs[pair_key] += 1
        output_rows.append({
            "schema_version": "veritas.pairwise-protected-candidate-replay-row.v1",
            "case_id": case_id,
            "source_arm": source_arm,
            "source_trace_index": trace_idx,
            "source_prefix_functions": [x["function"] for x in prefix],
            "proposal_ordinal": 0,
            "immediate_pre_state_sha256": pre_sha,
            "function": function,
            "arguments": normalized_args,
            "candidate_sha256": control.candidate_sha256,
            "pairing_identity_sha256": control.pairing_identity_sha256(),
            "arm_A": result_a,
            "arm_B": result_b,
        })

    if len(output_rows) != 81:
        raise ReplayError(f"MUTATION_RELEVANT_REPLAY_COUNT_MISMATCH:{len(output_rows)}")

    summary = {
        "schema_version": "veritas.pairwise-protected-candidate-replay-summary.v1",
        "status": "PASS_PROVIDER_FREE_PAIRWISE_REPLAY",
        "source_v13_artifact_sha256": V13_ARTIFACT_SHA256,
        "case_count_total": 128,
        "mutation_relevant_replay_count": len(output_rows),
        "source_selection": dict(sorted(selection_counts.items())),
        "disposition_pairs": dict(sorted(disposition_pairs.items())),
        "provider_execution": 0,
        "database_access": 0,
        "scorer_or_gold_access": 0,
        "policy_change": 0,
        "resolver_change": 0,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(
        {"summary": summary, "rows": output_rows},
        indent=2,
        sort_keys=True,
        default=str,
    ) + "\n")

    print("PASS_PAIRWISE_PROTECTED_CANDIDATE_REPLAY_HARNESS_V1")
    print("PASS_REPLAY_81_MUTATION_RELEVANT_CASES")
    print("PASS_REPLAY_SCORE_INDEPENDENT_SOURCE_SELECTION")
    print("PASS_REPLAY_READ_ONLY_PREFIX_STATE_INVARIANCE")
    print("PASS_REPLAY_RCC_CANONICAL_CANDIDATE_HASH")
    print("PASS_REPLAY_EXACT_PRESTATE_AND_CANDIDATE_BOTH_ARMS")
    print("PASS_REPLAY_RCC_UPSTREAM_DISPOSITION_CONSISTENCY")
    print("provider_execution=0")
    print("database_access=0")
    print("scorer_or_gold_access=0")
    print("mutation_relevant_replay_count=81")
    print("source_selection=" + json.dumps(summary["source_selection"], sort_keys=True))
    print("disposition_pairs=" + json.dumps(summary["disposition_pairs"], sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
