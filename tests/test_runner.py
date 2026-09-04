import copy
import json
from pathlib import Path

import pytest

import run_joint_benchmark as runner


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "fixtures/Governance_labelled_Evaluation_Set_v0.1.1.json"
JSONL_DATASET = ROOT / "fixtures/Governance_labelled_Evaluation_Set_v0.1.1.jsonl"
PINNED_ARTIFACT_SHA256 = {
    "contracts/VERITAS_Canonical_Benchmark_Contract_v0.1.json": (
        "a1352dc3cea28da07ca4799e1587b45616376521021e88c724c753fb60738628"
    ),
    "contracts/VERITAS_Benchmark_Runtime_Manifest_v0.1.json": (
        "edefe64da6ab0980ff94fdc62086933b4ce79860e352472f92873d6e0ac310d8"
    ),
    "contracts/RCC_REVAS_VERITAS_Field_Contract_v0.2.json": (
        "47de8bc99999d7f2d7791f51f6afa046e50f56b5777123374e1d43c00a4496fa"
    ),
    "fixtures/Governance_labelled_Evaluation_Set_v0.1.1.json": (
        "1e6ea7f9366876b4cbf041cc0841ab72bd58d6f561ff78553deb6645e5bf2a88"
    ),
}


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


def test_committed_artifacts_have_required_sha256() -> None:
    for relative_path, expected_sha256 in PINNED_ARTIFACT_SHA256.items():
        assert runner.sha256_file(ROOT / relative_path) == expected_sha256


def test_package_manifest_integrity() -> None:
    manifest_path = ROOT / "PACKAGE_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = {entry["path"]: entry for entry in manifest["files"]}

    assert set(PINNED_ARTIFACT_SHA256) <= set(entries)
    for relative_path, entry in entries.items():
        artifact = ROOT / relative_path
        assert artifact.stat().st_size == entry["bytes"]
        assert runner.sha256_file(artifact) == entry["sha256"]


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
