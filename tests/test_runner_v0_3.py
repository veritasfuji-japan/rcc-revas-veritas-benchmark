import copy
import hashlib
import inspect
import json
from pathlib import Path

import pytest

import run_joint_benchmark_v0_3 as runner

ROOT = Path(__file__).resolve().parents[1]


def _fake_stages(tamper=False):
    functions = {}
    for index, spec in enumerate(runner.STAGE_SPECS):
        def build(_index=index, **kwargs):
            body = {
                "packet_id": f"packet-{_index}",
                "index": _index,
                "inputs": sorted(kwargs),
                "execution_intent_id": "execution-intent:test:v0.3",
                "execution_intent": {
                    "actor_identity": "agent:test",
                    "target_system": "billing",
                    "target_resource": "invoices:read",
                    "intended_action": "invoices.read",
                },
                "adapter_contract_id": "adapter-contract:test:v0.3",
                "endpoint_candidate": {
                    "endpoint_candidate_id": "endpoint:test:v0.3",
                    "target_system": "billing",
                    "target_resource_scope": "invoices:read",
                    "endpoint_environment": "benchmark",
                    "endpoint_purpose": "dry-run",
                },
                "credential_reference": {
                    "credential_reference_id": "credential-ref:test:v0.3",
                    "target_system": "billing",
                    "target_resource_scope": "invoices:read",
                    "credential_purpose": "dry-run",
                },
            }
            if _index == 6:
                body["planned_steps"] = [{
                    "step_id": "dry-run-step:v1:1:describe-target",
                    "ordinal": 1,
                    "planned_adapter_method": "describe_target",
                    "expected_output_ref": "expected:describe-target",
                    "refusal_if_missing_later": "refuse-if-missing",
                }]
            if "endpoint_candidate" in kwargs:
                body["endpoint_candidate"] = kwargs["endpoint_candidate"]
            if "credential_reference" in kwargs:
                body["credential_reference"] = kwargs["credential_reference"]
            if "authority_evidence_reference_bundle" in kwargs:
                body["authority_evidence_reference_bundle"] = (
                    kwargs["authority_evidence_reference_bundle"]
                )
            module = runner.STAGE_SPECS[_index].module
            if module == "human_approval_requirement_resolution":
                required = bool(
                    kwargs["action_contract"]["human_approval_rules"]["required"]
                )
                body["required_human_approval"] = required
                body["requirement_state"] = (
                    "REQUIRED"
                    if required
                    else "NOT_REQUIRED_BY_ACTION_CONTRACT"
                )
            if module == (
                "live_adapter_dry_run_human_approval_requirement_satisfaction"
            ):
                required = bool(
                    kwargs["action_contract"]["human_approval_rules"]["required"]
                )
                body["requirement_satisfaction_state"] = (
                    "SATISFIED_BY_VERIFIED_HUMAN_APPROVAL_LINKAGE"
                    if required
                    else "SATISFIED_AS_NOT_REQUIRED_BY_ACTION_CONTRACT"
                )
            body["packet_hash"] = hashlib.sha256(
                json.dumps(body, sort_keys=True).encode()
            ).hexdigest()
            if _index == len(runner.STAGE_SPECS) - 1:
                body.update({
                    "gate_review_state": runner.BIND_PASS,
                    "live_adapter_dry_run_bind_authorization_gate_review_id": "gate-1",
                    "live_adapter_dry_run_bind_authorization_gate_review_hash": "sha256:gate",
                })
            return body

        def verify(packet, _index=index):
            return not (
                tamper and _index == len(runner.STAGE_SPECS) - 1
            )

        functions[spec.builder] = build
        functions[spec.verifier] = verify

    functions.update({
        "_adapter_methods": ("describe_target",),
        "_prohibited_during_selection": (),
        "_adapter_effect_profile": {},
        "_descriptor_scope_limitations": (),
        "_result_limitations": ("NOT_LIVE_RESULT",),
        "_endpoint_snapshot_hash": lambda value: "0" * 64,
        "_credential_policy_snapshot_hash": lambda value: "0" * 64,
        "_final_acknowledgements": (),
        "_final_outcomes": (
            "ACCEPTED_FOR_FUTURE_BIND_AUTHORIZATION_GATE_REVIEW",
            "REJECTED_FOR_FUTURE_BIND_AUTHORIZATION_GATE_REVIEW",
        ),
        "_gate_acknowledgements": (),
        "_gate_outcomes": (runner.BIND_PASS, runner.BIND_FAIL),
        "_ActionClassContract": lambda **kwargs: kwargs,
    })
    return functions

def _fixture():
    profile = json.loads((ROOT / "fixtures/Bind_Profile_v0.3.json").read_text())
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
    run = evidence / "run-33929723868"
    provenance = json.loads(
        (run / "ARTIFACT_PROVENANCE.json").read_text(encoding="utf-8")
    )
    for name, recorded in provenance["persisted_files"].items():
        assert runner.sha256_file(run / name) == recorded["sha256"]


def test_ground_truth_cannot_influence_treatment_inputs() -> None:
    data = json.loads(
        (ROOT / "fixtures/Governance_labelled_Evaluation_Set_v0.1.1.json").read_text()
    )
    case = data["cases"][0]
    relabelled = copy.deepcopy(case)
    relabelled["ground_truth"] = {"expected_decision": "SECRET_LABEL"}
    profile = json.loads((ROOT / "fixtures/Bind_Profile_v0.3.json").read_text())
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
    profile = json.loads((ROOT / "fixtures/Bind_Profile_v0.3.json").read_text())
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
    packet, verified, approval_meta = runner.execute_native_chain(
        {"handoff_status": "READY_FOR_GUARDED_PROMOTION"},
        object(), _fixture(), _fake_stages(),
    )
    assert packet["gate_review_state"] == runner.BIND_PASS
    assert verified == list(runner.STAGES)
    assert approval_meta["required_human_approval"] is True
    assert approval_meta["requirement_state"] == "REQUIRED"
    assert approval_meta["human_approval_linkage_invoked"] is True
    assert verified[-1] == "live_adapter_dry_run_bind_authorization_gate_review"


def test_not_required_ready_fixture_reaches_gate_without_approval_linkage() -> None:
    data = json.loads(
        (ROOT / "fixtures/Governance_labelled_Evaluation_Set_v0.1.1.json").read_text()
    )
    case = next(
        c for c in data["cases"]
        if not c["input"]["governance_fixture"]["approval_required"]
    )
    profile = json.loads((ROOT / "fixtures/Bind_Profile_v0.3.json").read_text())
    fixture = runner.treatment_fixture(case, profile)
    packet, verified, approval_meta = runner.execute_native_chain(
        {"handoff_status": "READY_FOR_GUARDED_PROMOTION"},
        object(), fixture, _fake_stages(),
    )

    assert packet["gate_review_state"] == runner.BIND_PASS
    assert approval_meta["required_human_approval"] is False
    assert approval_meta["requirement_state"] == "NOT_REQUIRED_BY_ACTION_CONTRACT"
    assert approval_meta["human_approval_linkage_invoked"] is False
    assert (
        "live_adapter_dry_run_human_approval_linkage" not in verified
    )
    assert (
        "live_adapter_dry_run_human_approval_requirement_satisfaction"
        in verified
    )


def test_tampered_gate_packet_is_rejected() -> None:
    with pytest.raises(runner.BenchmarkError, match="native verification failed"):
        runner.execute_native_chain(
            {"handoff_status": "READY_FOR_GUARDED_PROMOTION"},
            object(), _fixture(), _fake_stages(tamper=True),
        )


def test_guarded_promotion_receives_exact_native_context_arguments() -> None:
    functions = _fake_stages()
    name = "build_guarded_promotion_eligibility_packet"
    original = functions[name]
    captured = {}

    def capture(**kwargs):
        captured.update(kwargs)
        return original(**kwargs)

    functions[name] = capture
    runner.execute_native_chain({}, object(), _fixture(), functions)
    assert "trusted_context" in captured
    assert "validation_context" not in captured
    assert "evaluated_at" in captured
    assert "issued_at" in captured


def test_pre_bind_validation_receives_formation_packet() -> None:
    functions = _fake_stages()
    name = "build_execution_intent_pre_bind_validation_packet"
    original = functions[name]
    captured = {}

    def capture(**kwargs):
        captured.update(kwargs)
        return original(**kwargs)

    functions[name] = capture
    runner.execute_native_chain({}, object(), _fixture(), functions)
    assert "formation_packet" in captured
    assert "execution_intent_packet" not in captured


def test_harness_programming_error_propagates() -> None:
    functions = _fake_stages()

    def broken(**kwargs):
        raise TypeError("bad native wiring")

    functions[runner.STAGE_SPECS[4].builder] = broken
    with pytest.raises(TypeError, match="bad native wiring"):
        runner.execute_native_chain({}, object(), _fixture(), functions)


def test_packet_dict_supports_pydantic_v2_packets() -> None:
    class Packet:
        def model_dump(self, *, mode):
            assert mode == "json"
            return {"native": True}

    assert runner.packet_dict(Packet()) == {"native": True}


def test_approval_not_required_never_fabricates_approval() -> None:
    data = json.loads(
        (ROOT / "fixtures/Governance_labelled_Evaluation_Set_v0.1.1.json").read_text()
    )
    case = next(c for c in data["cases"] if not c["input"]
                ["governance_fixture"]["approval_required"])
    profile = json.loads((ROOT / "fixtures/Bind_Profile_v0.3.json").read_text())
    fixture = runner.treatment_fixture(case, profile)
    assert fixture["human_approval_reference_bundle"] is None


def test_every_effect_and_authority_flag_is_false() -> None:
    assert runner.EFFECT_FLAGS
    assert all(value is False for value in runner.EFFECT_FLAGS.values())
    assert "live_adapter" not in vars(runner)
