from __future__ import annotations

import ast
import socket
from pathlib import Path

import pytest

import paired_clean_runner_v1 as runner


def test_frozen_identity_constants() -> None:
    assert runner.CONTRACT_SHA256 == "532958fc9371fb34e550fb2a108868c64e87a980833dd46e8a92c7a133d9ae1f"
    assert runner.DATASET_SHA256 == "1e6ea7f9366876b4cbf041cc0841ab72bd58d6f561ff78553deb6645e5bf2a88"
    assert runner.RCC_COMMIT == "805cd5ff17e431cf50a3dafa7f78a60a704613b9"
    assert runner.RCC_ARCHIVE_SHA256 == "4c736357ab93a8f4b5027b94c20340b973c760de1a0027df30bb53d3d10f47d8"
    assert runner.VERITAS_COMMIT == "b39961b003179aea70e320a57cb000f56a81951e"
    assert runner.CASE_COUNT == 36
    assert runner.DIVERGENCES == ("GOV-H06", "GOV-H07", "GOV-D08")


def test_effects_are_all_fail_closed() -> None:
    assert runner.EFFECTS
    assert all(value is False for value in runner.EFFECTS.values())


def test_candidate_pairing_ignores_ground_truth() -> None:
    case = {
        "input": {
            "action_context": {
                "actor_identity": "actor:a",
                "action_class": "payment",
                "canonical_action": "submit_payment",
                "target_system": "ledger",
                "target_resource": "payment:1",
                "requested_scope": ["payment:submit"],
                "subject": "payment:1",
            }
        },
        "ground_truth": {"expected_decision": "DENY"},
    }
    candidate = {
        "typed_action": {
            "actor_identity": "actor:a",
            "action_class": "payment",
            "canonical_action": "submit_payment",
            "target_system": "ledger",
            "target_resource": "payment:1",
            "requested_scope": ["payment:submit"],
        },
        "binding": {"object_id": "payment:1"},
    }
    assert runner.candidate_matches_case(candidate, case)
    case["ground_truth"]["expected_decision"] = "ALLOW"
    assert runner.candidate_matches_case(candidate, case)


def test_candidate_semantic_drift_is_rejected() -> None:
    case = {
        "input": {
            "action_context": {
                "actor_identity": "actor:a",
                "action_class": "payment",
                "canonical_action": "submit_payment",
                "target_system": "ledger",
                "target_resource": "payment:1",
                "requested_scope": ["payment:submit"],
                "subject": "payment:1",
            }
        }
    }
    candidate = {
        "typed_action": {
            "actor_identity": "actor:a",
            "action_class": "payment",
            "canonical_action": "submit_payment",
            "target_system": "ledger",
            "target_resource": "payment:DIFFERENT",
            "requested_scope": ["payment:submit"],
        },
        "binding": {"object_id": "payment:1"},
    }
    assert not runner.candidate_matches_case(candidate, case)


def test_network_guard_blocks_socket_connect() -> None:
    s = socket.socket()
    try:
        with runner.block_network():
            with pytest.raises(runner.RunnerError, match="network dispatch prohibited"):
                s.connect(("127.0.0.1", 1))
    finally:
        s.close()


def test_treatment_helpers_do_not_read_ground_truth() -> None:
    source = Path("paired_clean_runner_v1.py").read_text()
    tree = ast.parse(source)
    treatment = {
        "candidate_matches_case",
        "post_decide",
        "require_response_candidate",
        "bind_handoff",
        "native_gate",
    }
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in treatment:
            text = ast.get_source_segment(source, node) or ""
            assert "ground_truth" not in text, node.name


def test_scored_execution_is_opt_in() -> None:
    args = runner.build_parser().parse_args(
        ["--upstream-repo", "/tmp/rcc", "--veritas-repo", "/tmp/veritas"]
    )
    assert args.preflight is False
    assert args.scored_run is False
    assert args.runner_commit is None
    assert args.acknowledged_contract_sha256 is None


def test_canonical_hash_is_order_stable() -> None:
    a = {"b": 2, "a": {"y": 2, "x": 1}}
    b = {"a": {"x": 1, "y": 2}, "b": 2}
    assert runner.canonical(a) == runner.canonical(b)
    assert runner.sha_json(a) == runner.sha_json(b)
