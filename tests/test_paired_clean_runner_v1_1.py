from __future__ import annotations

import ast
import json
import os
from pathlib import Path

import pytest

import paired_clean_runner_v1 as frozen_v1
import paired_clean_runner_v1_1 as runner


def test_original_v1_remains_frozen() -> None:
    assert frozen_v1.RUNNER_VERSION == "paired-clean-v1.0.1"


def test_v1_1_preserves_frozen_evaluation_inputs() -> None:
    assert runner.RUNNER_VERSION == "paired-clean-v1.1.0"
    assert runner.CONTRACT_SHA256 == frozen_v1.CONTRACT_SHA256
    assert runner.DATASET_SHA256 == frozen_v1.DATASET_SHA256
    assert runner.RCC_COMMIT == frozen_v1.RCC_COMMIT
    assert runner.RCC_ARCHIVE_SHA256 == frozen_v1.RCC_ARCHIVE_SHA256
    assert runner.VERITAS_COMMIT == frozen_v1.VERITAS_COMMIT
    assert runner.CASE_COUNT == 36
    assert runner.DIVERGENCES == frozen_v1.DIVERGENCES


def _handoff(*, approval: bool = True) -> dict:
    return {
        "source_decision": {
            "request_id": "req-gov-a01",
            "canonical_decision_id": "synthetic-decision",
            "canonical_decision_hash": "sha256:synthetic",
            "canonical_decision_ts": "2030-01-01T00:00:00Z",
        },
        "decision_lineage": {"decision_id": "synthetic-decision"},
        "trustlog_lineage": {
            "verified": True,
            "request_id": "req-gov-a01",
            "artifact_ref": "trustlog-GOV-A01",
            "chain_hash": "sha256:synthetic-trust",
        },
        "replay_lineage": {
            "verified": True,
            "request_id": "req-gov-a01",
            "artifact_ref": "replay-GOV-A01",
            "artifact_hash": "sha256:synthetic-replay",
        },
        "human_approval_evidence": (
            {"candidate_ref": "candidate-gov-a01"} if approval else None
        ),
    }


def _response() -> dict:
    return {
        "request_id": "runtime-request-123",
        "canonical_decision_artifact": {
            "decision_id": "cda:v1:sha256:" + "1" * 64,
            "decision_hash": "2" * 64,
            "decision_ts": "2026-09-23T03:00:00.000000Z",
        },
    }


def _candidate() -> dict:
    return {"candidate_id": "candidate:fixture:exact-rcc-id"}


def test_runtime_rebinding_updates_all_request_lineage_ids() -> None:
    handoff = _handoff()
    runner.rebind_runtime_handoff_identity(handoff, _response(), _candidate())

    expected = "runtime-request-123"
    assert handoff["source_decision"]["request_id"] == expected
    assert handoff["trustlog_lineage"]["request_id"] == expected
    assert handoff["replay_lineage"]["request_id"] == expected
    assert handoff["source_decision"]["canonical_decision_id"] == (
        "cda:v1:sha256:" + "1" * 64
    )
    assert handoff["decision_lineage"]["decision_id"] == (
        "cda:v1:sha256:" + "1" * 64
    )


def test_runtime_rebinding_updates_approval_candidate_reference() -> None:
    handoff = _handoff(approval=True)
    runner.rebind_runtime_handoff_identity(handoff, _response(), _candidate())
    assert handoff["human_approval_evidence"]["candidate_ref"] == (
        "candidate:fixture:exact-rcc-id"
    )


def test_runtime_rebinding_does_not_invent_approval_evidence() -> None:
    handoff = _handoff(approval=False)
    runner.rebind_runtime_handoff_identity(handoff, _response(), _candidate())
    assert handoff["human_approval_evidence"] is None


def test_canonical_replay_lineage_original_decision_is_rebound_when_present() -> None:
    handoff = _handoff()
    handoff["replay_lineage"].update(
        {
            "format_version": "canonical-replay-handoff-lineage/v1",
            "original_decision_id": "synthetic-decision",
            "original_decision_hash": "sha256:synthetic",
            "original_decision_ts": "2030-01-01T00:00:00Z",
        }
    )
    runner.rebind_runtime_handoff_identity(handoff, _response(), _candidate())
    replay = handoff["replay_lineage"]
    assert replay["original_decision_id"] == "cda:v1:sha256:" + "1" * 64
    assert replay["original_decision_hash"] == "sha256:" + "2" * 64
    assert replay["original_decision_ts"] == "2026-09-23T03:00:00.000000Z"


def test_scored_execution_requires_explicit_counterparty_ack_confirmation() -> None:
    with pytest.raises(runner.RunnerError, match="counterparty remediation ACK"):
        runner.require_remediation_ack(None)
    with pytest.raises(runner.RunnerError, match="counterparty remediation ACK"):
        runner.require_remediation_ack("wrong")
    runner.require_remediation_ack(runner.REMEDIATION_ACK_CONFIRMATION)


def test_v1_1_treatment_helpers_do_not_read_ground_truth() -> None:
    source = Path("paired_clean_runner_v1_1.py").read_text()
    tree = ast.parse(source)
    treatment = {
        "candidate_matches_case",
        "post_decide",
        "require_response_candidate",
        "rebind_runtime_handoff_identity",
        "bind_handoff",
        "native_gate",
    }
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in treatment:
            text = ast.get_source_segment(source, node) or ""
            assert "ground_truth" not in text, node.name


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


def test_rebound_handoff_reaches_frozen_validator_ready_state() -> None:
    veritas = Path(os.environ["VERITAS_REPO"])
    case = runner.treatment_case(_load_case("GOV-A01"))
    candidate = _candidate_from_case(case)
    handoff, flags = runner.bind_handoff(
        case, veritas, _runtime_response(case["case_id"]), candidate
    )

    native = runner.handoff_runner.load_native_veritas(veritas)
    context = runner.handoff_runner.build_context(handoff, native, flags)
    validated = native["validate"](
        handoff, context, runner.handoff_runner.EVALUATED_AT
    ).to_dict()

    assert validated["status"] == "READY_FOR_GUARDED_PROMOTION", validated
    runtime_request_id = _runtime_response(case["case_id"])["request_id"]
    assert handoff["source_decision"]["request_id"] == runtime_request_id
    assert handoff["trustlog_lineage"]["request_id"] == runtime_request_id
    assert handoff["replay_lineage"]["request_id"] == runtime_request_id
    assert handoff["human_approval_evidence"]["candidate_ref"] == candidate["candidate_id"]


def test_v1_1_parser_defaults_to_no_execution_and_separate_output_path() -> None:
    args = runner.build_parser().parse_args(
        ["--upstream-repo", "/tmp/rcc", "--veritas-repo", "/tmp/veritas"]
    )
    assert args.preflight is False
    assert args.testbed_run is False
    assert args.scored_run is False
    assert args.output_dir == Path("results/paired-clean-v1_1")
    assert args.remediation_ack_confirmation is None


def test_historical_scored_run_flag_is_disabled_for_v1_1() -> None:
    args = runner.build_parser().parse_args(
        [
            "--upstream-repo", "/tmp/rcc",
            "--veritas-repo", "/tmp/veritas",
            "--scored-run",
        ]
    )
    assert args.scored_run is True
    assert args.testbed_run is False
