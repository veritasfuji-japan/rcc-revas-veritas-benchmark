import copy
import hashlib
import inspect
import json
from pathlib import Path

import pytest

import run_joint_benchmark_v0_2 as runner

ROOT = Path(__file__).resolve().parents[1]


def _fake_stages(tamper=False):
    stages = []
    for index, name in enumerate(runner.STAGES):
        def build(previous_packet=None, case_id=None, _index=index, **kwargs):
            body = {"packet_id": f"packet-{_index}", "index": _index,
                    "previous": previous_packet}
            body["packet_hash"] = hashlib.sha256(
                json.dumps(body, sort_keys=True).encode()
            ).hexdigest()
            if _index == len(runner.STAGES) - 1:
                body["outcome"] = runner.BIND_PASS
            return body

        def verify(packet, _index=index, **kwargs):
            body = dict(packet)
            actual = body.pop("packet_hash")
            body.pop("outcome", None)
            expected = hashlib.sha256(
                json.dumps(body, sort_keys=True).encode()
            ).hexdigest()
            return actual == expected and not (tamper and _index == 19)

        stages.append({"name": name, "build": build, "verify": verify})
    return stages


def _fixture():
    profile = json.loads((ROOT / "fixtures/Bind_Profile_v0.2.json").read_text())
    case = json.loads(
        (ROOT / "fixtures/Governance_labelled_Evaluation_Set_v0.1.1.json").read_text()
    )["cases"][0]
    return runner.treatment_fixture(case, profile)


def test_v01_dataset_and_persisted_evidence_are_immutable() -> None:
    assert runner.sha256_file(
        ROOT / "fixtures/Governance_labelled_Evaluation_Set_v0.1.1.json"
    ) == runner.PINNED_DATASET_SHA256
    evidence = ROOT / "evidence/native-v0.1"
    assert evidence.is_dir()
    assert not any(path.is_symlink() for path in evidence.rglob("*"))


def test_ground_truth_cannot_influence_treatment_inputs() -> None:
    data = json.loads(
        (ROOT / "fixtures/Governance_labelled_Evaluation_Set_v0.1.1.json").read_text()
    )
    case = data["cases"][0]
    relabelled = copy.deepcopy(case)
    relabelled["ground_truth"] = {"expected_decision": "SECRET_LABEL"}
    profile = json.loads((ROOT / "fixtures/Bind_Profile_v0.2.json").read_text())
    assert runner.treatment_fixture(case, profile) == runner.treatment_fixture(
        relabelled, profile
    )


def test_non_ready_result_never_invokes_bind_gate() -> None:
    case = {"case_id": "stop", "ground_truth": {
        "expected_bind_gate_outcome": runner.BIND_FAIL}}
    row = runner.base_result(case, {"status": "INVALID"})
    assert row["bind_chain_reached"] is False
    assert row["native_bind_gate_invoked"] is False


def test_profile_is_non_routable_secretless_and_non_effecting() -> None:
    profile = json.loads((ROOT / "fixtures/Bind_Profile_v0.2.json").read_text())
    assert profile["endpoint"]["host"].endswith(".example.invalid")
    assert profile["endpoint"]["routable"] is False
    assert profile["credential_reference"]["secret_present"] is False
    forbidden = ("password", "private_key", "access_token", "client_secret")
    assert not any(key in json.dumps(profile).lower() for key in forbidden)
    assert all(value is False for value in profile["effects"].values())


def test_production_runner_has_no_test_helper_imports() -> None:
    source = inspect.getsource(runner)
    assert "veritas_os.tests" not in source
    assert "from tests" not in source
    assert "import tests" not in source


def test_supported_ready_fixture_reaches_and_reverifies_gate() -> None:
    packet, verified = runner.execute_native_chain(
        {"handoff_status": "READY_FOR_GUARDED_PROMOTION"},
        _fixture(), _fake_stages(),
    )
    assert packet["outcome"] == runner.BIND_PASS
    assert verified == list(runner.STAGES)
    assert verified[-1] == "live_adapter_dry_run_bind_authorization_gate_review"


def test_tampered_gate_packet_is_rejected() -> None:
    with pytest.raises(runner.BenchmarkError, match="native verification failed"):
        runner.execute_native_chain(
            {"handoff_status": "READY_FOR_GUARDED_PROMOTION"},
            _fixture(), _fake_stages(tamper=True),
        )


def test_approval_not_required_never_fabricates_approval() -> None:
    data = json.loads(
        (ROOT / "fixtures/Governance_labelled_Evaluation_Set_v0.1.1.json").read_text()
    )
    case = next(c for c in data["cases"] if not c["input"]
                ["governance_fixture"]["approval_required"])
    profile = json.loads((ROOT / "fixtures/Bind_Profile_v0.2.json").read_text())
    fixture = runner.treatment_fixture(case, profile)
    assert fixture["human_approval_reference_bundle"] is None


def test_every_effect_and_authority_flag_is_false() -> None:
    assert runner.EFFECT_FLAGS
    assert all(value is False for value in runner.EFFECT_FLAGS.values())
    assert "live_adapter" not in vars(runner)
