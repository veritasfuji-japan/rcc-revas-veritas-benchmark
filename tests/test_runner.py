import copy
import json
from pathlib import Path

import pytest

import bootstrap_package
import run_joint_benchmark as runner


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "fixtures/Governance_labelled_Evaluation_Set_v0.1.1.json"
JSONL_DATASET = ROOT / "fixtures/Governance_labelled_Evaluation_Set_v0.1.1.jsonl"


def _template() -> dict:
    provenance_paths = [
        "source_decision.request_id",
        "source_decision.canonical_decision_id",
        "source_decision.canonical_decision_hash",
        "source_decision.canonical_decision_ts",
        "candidate.actor_identity",
        "candidate.target_system",
        "candidate.target_resource",
        "candidate.canonical_action",
        "candidate_hash",
        "trustlog_lineage",
        "replay_lineage",
        "policy_lineage",
        "authority_requirement",
        "authority_evidence",
        "human_approval_requirement",
        "human_approval_evidence",
        "expected_state",
    ]
    return {
        "input": {
            "source_decision": {},
            "decision_lineage": {},
            "provenance": [
                {
                    "field_path": path,
                    "value": None,
                    "verification_status": "UNVERIFIED",
                }
                for path in provenance_paths
            ],
            "handoff_status": "READY_FOR_GUARDED_PROMOTION",
            "refusal_reason_codes": [],
        }
    }


def test_staged_archive_has_required_sha256() -> None:
    raw = bootstrap_package._load_archive()

    assert runner.hashlib.sha256(raw).hexdigest() == (
        "b3b0e074c28c30714224157c6b4f8a5dc9a15f5c03e973c058efcd44b8e5c379"
    )


def test_dataset_is_pinned_and_jsonl_matches() -> None:
    data = runner.load_dataset(DATASET)
    jsonl_cases = [
        json.loads(line)
        for line in JSONL_DATASET.read_text(encoding="utf-8").splitlines()
    ]

    assert jsonl_cases == data["cases"]
    assert all(
        case["ground_truth"]["execution_authorized"] is False
        for case in data["cases"]
    )
    assert all(
        case["ground_truth"]["external_effect_must_occur"] is False
        for case in data["cases"]
    )
    assert data["distribution"]["case_count"] == len(data["cases"])
    for case in data["cases"]:
        content = dict(case)
        expected_hash = content.pop("case_sha256")
        assert runner.sha256_json(content) == expected_hash


def test_dataset_hash_verification_cannot_be_disabled(tmp_path: Path) -> None:
    changed = tmp_path / "changed.json"
    changed.write_bytes(DATASET.read_bytes() + b"\n")

    with pytest.raises(runner.RunnerError, match="SHA-256 mismatch"):
        runner.load_dataset(changed)
    with pytest.raises(SystemExit):
        runner.build_parser().parse_args(["--skip-dataset-hash-check"])


def test_ground_truth_labels_are_not_treatment_inputs(tmp_path: Path) -> None:
    vector = tmp_path / (
        "docs/en/architecture/test-vectors/decision-to-bind-handoff-v1/vector-01.json"
    )
    vector.parent.mkdir(parents=True)
    vector.write_text(json.dumps(_template()), encoding="utf-8")
    case = runner.load_dataset(DATASET)["cases"][10]
    relabelled = copy.deepcopy(case)
    relabelled["ground_truth"]["expected_handoff_state"] = "INVALID"
    relabelled["ground_truth"]["expected_reason_codes"] = ["SECRET_LABEL"]

    handoff, flags = runner.build_handoff(case, tmp_path)
    relabelled_handoff, relabelled_flags = runner.build_handoff(relabelled, tmp_path)

    assert handoff == relabelled_handoff
    assert flags == relabelled_flags
    assert "SECRET_LABEL" not in json.dumps(relabelled_handoff)


def test_path_a_adoption_does_not_confer_execution_authority() -> None:
    case = runner.load_dataset(DATASET)["cases"][0]

    result = runner.path_a_proxy(case)

    assert result["aggregate_decision"] == "ALLOW"
    assert result["semantic_scope"] == (
        "UPSTREAM_ADOPTION_PROXY_NOT_EXECUTION_AUTHORITY"
    )
    assert result["execution_authority_conferred"] is False
