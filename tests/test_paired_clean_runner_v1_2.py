from __future__ import annotations

import ast
import json
import os
from pathlib import Path

import pytest

import paired_clean_runner_v1_1 as v11
import paired_clean_runner_v1_2 as runner
import run_joint_benchmark_v0_2 as bind_runner


def test_v1_1_remains_frozen() -> None:
    assert v11.RUNNER_VERSION == "paired-clean-v1.1.0"


def test_v1_2_preserves_frozen_evaluation_inputs() -> None:
    assert runner.RUNNER_VERSION == "paired-clean-v1.2.0"
    assert runner.CONTRACT_SHA256 == v11.CONTRACT_SHA256
    assert runner.DATASET_SHA256 == v11.DATASET_SHA256
    assert runner.RCC_COMMIT == v11.RCC_COMMIT
    assert runner.RCC_ARCHIVE_SHA256 == v11.RCC_ARCHIVE_SHA256
    assert runner.VERITAS_COMMIT == v11.VERITAS_COMMIT
    assert runner.CASE_COUNT == 36
    assert runner.DIVERGENCES == v11.DIVERGENCES


def _load_case(case_id: str) -> dict:
    data = json.loads(
        Path("fixtures/Governance_labelled_Evaluation_Set_v0.1.1.json").read_text()
    )
    return next(case for case in data["cases"] if case["case_id"] == case_id)


def _candidate_from_case(case: dict) -> dict:
    action = case["input"]["action_context"]
    return {
        "candidate_id": f"candidate:fixture:{case['case_id'].lower()}",
        "typed_action": {
            "actor_identity": action["actor_identity"],
            "action_class": action["action_class"],
            "canonical_action": action["canonical_action"],
            "target_system": action["target_system"],
            "target_resource": action["target_resource"],
            "requested_scope": action["requested_scope"],
        },
        "binding": {"object_id": action["subject"]},
    }


def _runtime_response(case_id: str) -> dict:
    digest = "1" * 64
    return {
        "request_id": f"runtime-request:{case_id.lower()}",
        "canonical_decision_artifact": {
            "decision_id": "cda:v1:sha256:" + digest,
            "decision_hash": digest,
            "decision_ts": "2030-01-01T00:00:00.000000Z",
        },
    }


def _run_native_gate(case_id: str) -> dict:
    veritas_env = os.environ.get("VERITAS_REPO")
    if not veritas_env:
        pytest.skip("frozen VERITAS checkout is provided by the v1.2 pin workflow")
    veritas = Path(veritas_env)
    case = runner.treatment_case(_load_case(case_id))
    candidate = _candidate_from_case(case)
    profile = json.loads(Path("fixtures/Bind_Profile_v0.2.json").read_text())
    native, funcs = bind_runner.load_native(veritas)
    gate, _ = runner.native_gate(
        case, veritas, _runtime_response(case_id), candidate, profile, native, funcs
    )
    return gate


def test_required_path_uses_contract_bound_requirement_satisfaction() -> None:
    gate = _run_native_gate("GOV-A01")
    assert gate["native_handoff_status"] == "READY_FOR_GUARDED_PROMOTION"
    assert gate["native_bind_gate_invoked"] is True
    assert gate["native_bind_gate_outcome"] == bind_runner.BIND_PASS
    assert gate["native_human_approval_required"] is True
    assert gate["native_human_approval_requirement_state"] == "REQUIRED"
    assert (
        gate["native_human_approval_satisfaction_state"]
        == "SATISFIED_BY_VERIFIED_HUMAN_APPROVAL_LINKAGE"
    )
    assert gate["native_human_approval_linkage_used"] is True
    assert gate["native_human_approval_reference_count"] == 1
    assert gate["native_human_approval_created"] is False


def test_not_required_path_reaches_gate_without_fabricated_approval() -> None:
    gate = _run_native_gate("GOV-A04")
    assert gate["native_handoff_status"] == "READY_FOR_GUARDED_PROMOTION"
    assert gate["native_bind_gate_invoked"] is True
    assert gate["native_bind_gate_outcome"] == bind_runner.BIND_PASS
    assert gate["native_human_approval_required"] is False
    assert gate["native_human_approval_requirement_state"] == "NOT_REQUIRED_BY_ACTION_CONTRACT"
    assert (
        gate["native_human_approval_satisfaction_state"]
        == "SATISFIED_AS_NOT_REQUIRED_BY_ACTION_CONTRACT"
    )
    assert gate["native_human_approval_linkage_used"] is False
    assert gate["native_human_approval_reference_count"] == 0
    assert gate["native_human_approval_created"] is False


def test_v1_2_treatment_helpers_do_not_read_ground_truth() -> None:
    source = Path("paired_clean_runner_v1_2.py").read_text()
    tree = ast.parse(source)
    treatment = {
        "candidate_matches_case",
        "post_decide",
        "require_response_candidate",
        "rebind_runtime_handoff_identity",
        "bind_handoff",
        "build_testbed_action_contract",
        "execute_native_chain_v1_2",
        "native_gate",
    }
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in treatment:
            text = ast.get_source_segment(source, node) or ""
            assert "ground_truth" not in text, node.name


def test_v1_2_parser_defaults_to_separate_output_namespace() -> None:
    args = runner.build_parser().parse_args(
        ["--upstream-repo", "/tmp/rcc", "--veritas-repo", "/tmp/veritas"]
    )
    assert args.preflight is False
    assert args.testbed_run is False
    assert args.scored_run is False
    assert args.output_dir == Path("results/paired-clean-v1_2")
    assert args.remediation_ack_confirmation is None
