#!/usr/bin/env python3
"""RCC/REVAS × VERITAS native Bind-chain benchmark v0.2.

This harness only builds and verifies dry-run review artifacts.  It deliberately
contains no adapter, transport, credential-resolution, or dispatch operation.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib
import json
import platform
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import run_joint_benchmark as handoff_runner

RUNNER_VERSION = "0.2.0"
PINNED_VERITAS_COMMIT = "4a794e31b26c28e43eb1bb8e6a2474f511c5bd7c"
PINNED_DATASET_SHA256 = handoff_runner.PINNED_DATASET_SHA256
PINNED_PROFILE_SHA256 = "75f2a33134fa014fb90f0810f9c6773d4786d91e428fa1b75a5955d54fcb0884"
PINNED_CONTRACT_SHA256 = "081e1a3f8069eaa336f8c1a0f5c7d7151206e9dd670207726906236c8bc1c08f"
PINNED_RUNTIME_SHA256 = "257919474e0c6477213ed611b1537e01f7460861543ac2c9b968430ce0d4ea22"
BIND_PASS = "PASSED_FOR_FUTURE_BIND_AUTHORIZATION_ARTIFACT"
BIND_FAIL = "FAILED_FOR_FUTURE_BIND_AUTHORIZATION_ARTIFACT"
EFFECT_FLAGS = {
    "real_bind_invoked": False,
    "bind_authorization_created": False,
    "execution_authority_created": False,
    "bind_receipt_created": False,
    "request_dispatched": False,
    "credential_material_accessed": False,
    "authorization_header_constructed": False,
    "network_used": False,
    "external_effect_occurred": False,
}
STAGE_SYMBOLS = (
    ("guarded_promotion_eligibility", "build_guarded_promotion_eligibility_packet", "verify_guarded_promotion_eligibility_packet"),
    ("execution_intent_formation_readiness", "build_execution_intent_formation_readiness_packet", "verify_execution_intent_formation_readiness_packet"),
    ("canonical_execution_intent_formation", "build_canonical_execution_intent_formation_packet", "verify_canonical_execution_intent_formation_packet"),
    ("execution_intent_pre_bind_validation", "build_execution_intent_pre_bind_validation_packet", "verify_execution_intent_pre_bind_validation_packet"),
    ("canonical_bind_preflight_adjudication", "build_canonical_bind_preflight_adjudication_packet", "verify_canonical_bind_preflight_adjudication_packet"),
    ("bind_adapter_contract_selection", "build_bind_adapter_contract_selection_packet", "verify_bind_adapter_contract_selection_packet"),
    ("adapter_dry_run_plan", "build_adapter_dry_run_plan_packet", "verify_adapter_dry_run_plan_packet"),
    ("adapter_dry_run_result", "build_adapter_dry_run_fixture_result_packet", "verify_adapter_dry_run_fixture_result_packet"),
    ("reference_adapter_rehearsal", "build_reference_adapter_in_memory_rehearsal_packet", "verify_reference_adapter_in_memory_rehearsal_packet"),
    ("live_adapter_dry_run_readiness", "build_live_adapter_dry_run_request_readiness_packet", "verify_live_adapter_dry_run_request_readiness_packet"),
    ("live_adapter_dry_run_request", "build_live_adapter_dry_run_request_packet", "verify_live_adapter_dry_run_request_packet"),
    ("live_adapter_dry_run_dispatch_readiness", "build_live_adapter_dry_run_dispatch_readiness_packet", "verify_live_adapter_dry_run_dispatch_readiness_packet"),
    ("live_adapter_dry_run_endpoint_allowlist", "build_live_adapter_dry_run_endpoint_allowlist_evaluation_packet", "verify_live_adapter_dry_run_endpoint_allowlist_evaluation_packet"),
    ("live_adapter_dry_run_credential_authorization", "build_live_adapter_dry_run_credential_authorization_evaluation_packet", "verify_live_adapter_dry_run_credential_authorization_evaluation_packet"),
    ("live_adapter_dry_run_operator_dispatch_review", "build_live_adapter_dry_run_operator_dispatch_review_packet", "verify_live_adapter_dry_run_operator_dispatch_review_packet"),
    ("live_adapter_dry_run_bind_pre_dispatch_review", "build_live_adapter_dry_run_bind_pre_dispatch_review_packet", "verify_live_adapter_dry_run_bind_pre_dispatch_review_packet"),
    ("live_adapter_dry_run_authority_evidence_linkage", "build_live_adapter_dry_run_authority_evidence_linkage_review_packet", "verify_live_adapter_dry_run_authority_evidence_linkage_review_packet"),
    ("live_adapter_dry_run_human_approval_linkage", "build_live_adapter_dry_run_human_approval_linkage_review_packet", "verify_live_adapter_dry_run_human_approval_linkage_review_packet"),
    ("live_adapter_dry_run_final_bind_authorization_readiness", "build_live_adapter_dry_run_final_bind_authorization_readiness_packet", "verify_live_adapter_dry_run_final_bind_authorization_readiness_packet"),
    ("live_adapter_dry_run_bind_authorization_gate_review", "build_live_adapter_dry_run_bind_authorization_gate_review_packet", "verify_live_adapter_dry_run_bind_authorization_gate_review_packet"),
)


class BenchmarkError(RuntimeError):
    """An integrity or native-contract error (not a scientific mismatch)."""


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def packet_dict(packet: Any) -> dict[str, Any]:
    if isinstance(packet, dict):
        return copy.deepcopy(packet)
    if hasattr(packet, "model_dump"):
        return packet.model_dump(mode="json")
    if hasattr(packet, "to_dict"):
        return packet.to_dict()
    raise BenchmarkError(f"native packet has no to_dict(): {type(packet)!r}")


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def verify_inputs(root: Path, veritas_repo: Path | None = None) -> dict[str, Any]:
    pins = {
        "dataset": (root / "fixtures/Governance_labelled_Evaluation_Set_v0.1.1.json", PINNED_DATASET_SHA256),
        "bind_profile": (root / "fixtures/Bind_Profile_v0.2.json", PINNED_PROFILE_SHA256),
        "contract": (root / "contracts/VERITAS_Canonical_Benchmark_Contract_v0.2.json", PINNED_CONTRACT_SHA256),
        "runtime_manifest": (root / "contracts/VERITAS_Benchmark_Runtime_Manifest_v0.2.json", PINNED_RUNTIME_SHA256),
    }
    for name, (path, expected) in pins.items():
        actual = sha256_file(path)
        if actual != expected:
            raise BenchmarkError(f"{name} SHA-256 mismatch: {actual}")
    state: dict[str, Any] = {name + "_sha256": digest for name, (_, digest) in pins.items()}
    if veritas_repo is not None:
        state["veritas_commit"] = _git(veritas_repo, "rev-parse", "HEAD")
        state["veritas_repo_dirty"] = bool(_git(veritas_repo, "status", "--porcelain"))
        if state["veritas_commit"] != PINNED_VERITAS_COMMIT:
            raise BenchmarkError("wrong VERITAS commit")
        if state["veritas_repo_dirty"]:
            raise BenchmarkError("dirty VERITAS checkout")
    return state


@dataclass(frozen=True)
class StageSpec:
    name: str
    build: Callable[..., Any]
    verify: Callable[..., Any]


def load_native(veritas_repo: Path) -> tuple[dict[str, Any], tuple[StageSpec, ...]]:
    if str(veritas_repo) not in sys.path:
        sys.path.insert(0, str(veritas_repo))
    handoff = handoff_runner.load_native_veritas(veritas_repo)
    stages = []
    for module_name, builder_name, verifier_name in STAGE_SYMBOLS:
        module = importlib.import_module(f"veritas_os.policy.{module_name}")
        try:
            stages.append(StageSpec(
                module_name,
                getattr(module, builder_name),
                getattr(module, verifier_name),
            ))
        except AttributeError as exc:
            raise BenchmarkError(
                f"pinned native symbol missing: {module_name}.{exc.name}"
            ) from exc
    return handoff, tuple(stages)


def treatment_fixture(case: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    """Construct treatment data without ever reading ``ground_truth``."""
    action = case["input"]["action_context"]
    governance = case["input"]["governance_fixture"]
    case_id = case["case_id"]
    contract_id = profile["adapter_contract"]["adapter_contract_id"]
    return {
        "case_id": case_id,
        "actor": action.get("actor_identity"),
        "actor_identity": action.get("actor_identity"),
        "target_system": action.get("target_system"),
        "target_resource": action.get("target_resource"),
        "adapter_contract_id": contract_id,
        "adapter_contract_descriptor": copy.deepcopy(profile["adapter_contract"]),
        "endpoint_candidate": copy.deepcopy(profile["endpoint"]),
        "endpoint_allowlist_snapshot": {
            "allowed_hosts": [profile["endpoint"]["host"]], "synthetic_only": True,
        },
        "credential_reference": copy.deepcopy(profile["credential_reference"]),
        "credential_policy_snapshot": {"reference_only": True, "material_access_allowed": False},
        "approval_required": bool(governance.get("approval_required")),
        "authority_evidence_reference_bundle": {
            "kind": "METADATA_REFERENCE_ONLY", "case_id": case_id,
            "creates_authority_evidence": False,
        },
        "human_approval_reference_bundle": (
            {"kind": "METADATA_REFERENCE_ONLY", "case_id": case_id,
             "creates_human_approval": False}
            if governance.get("approval_required") else None
        ),
        "operator_review_decision": "APPROVE_DRY_RUN_REVIEW_ONLY",
        "bind_pre_dispatch_review_decision": "APPROVE_DRY_RUN_REVIEW_ONLY",
        "fixture_step_results": copy.deepcopy(profile["fixture_step_results"]),
        "reference_rehearsal_fixture": copy.deepcopy(
            profile["reference_rehearsal_fixture"]
        ),
        "final_bind_authorization_readiness_review_decision": (
            "READY_FOR_BIND_AUTHORIZATION_GATE_REVIEW_NOT_AUTHORIZED"
        ),
        "bind_authorization_gate_review_decision": (
            "PASS_FOR_FUTURE_BIND_AUTHORIZATION_ARTIFACT_NOT_AUTHORIZED"
        ),
        "timestamps": list(profile["fixed_timestamps_utc"]),
        **EFFECT_FLAGS,
    }


def execute_native_chain(
    handoff: dict[str, Any], trusted_context: Any, fixture: dict[str, Any],
    stages: tuple[StageSpec, ...],
) -> tuple[dict[str, Any], list[str]]:
    """Build and independently verify every native prerequisite in order."""
    stage = {spec.name: spec for spec in stages}
    timestamps = [datetime.fromisoformat(value.replace("Z", "+00:00"))
                  for value in fixture["timestamps"]]
    verified_names = []

    def verified(name: str, packet: Any) -> Any:
        result = stage[name].verify(packet)
        if result is False or (hasattr(result, "valid") and not result.valid):
            raise BenchmarkError(f"native verification failed: {name}")
        verified_names.append(name)
        return packet

    eligibility = verified("guarded_promotion_eligibility", stage[
        "guarded_promotion_eligibility"].build(
            handoff, trusted_context, timestamps[0], timestamps[1]
        ))
    intent_readiness = verified("execution_intent_formation_readiness", stage[
        "execution_intent_formation_readiness"].build(
            eligibility_packet=eligibility, checked_at=timestamps[2]
        ))
    execution_intent = verified("canonical_execution_intent_formation", stage[
        "canonical_execution_intent_formation"].build(
            readiness_packet=intent_readiness, formed_at=timestamps[3]
        ))
    fixture["execution_intent_id"] = execution_intent.execution_intent_id
    fixture["execution_intent_hash"] = execution_intent.execution_intent_hash
    pre_bind = verified("execution_intent_pre_bind_validation", stage[
        "execution_intent_pre_bind_validation"].build(
            execution_intent_packet=execution_intent,
            checked_at=timestamps[4],
        ))
    preflight = verified("canonical_bind_preflight_adjudication", stage[
        "canonical_bind_preflight_adjudication"].build(
            pre_bind_validation_packet=pre_bind,
            adjudicated_at=timestamps[5],
        ))
    selection = verified("bind_adapter_contract_selection", stage[
        "bind_adapter_contract_selection"].build(
            bind_preflight_adjudication_packet=preflight,
            adapter_contract_descriptor=fixture["adapter_contract_descriptor"],
            selected_at=timestamps[6],
        ))
    plan = verified("adapter_dry_run_plan", stage["adapter_dry_run_plan"].build(
        adapter_contract_selection_packet=selection,
        planned_at=timestamps[7],
    ))
    dry_run_result = verified("adapter_dry_run_result", stage[
        "adapter_dry_run_result"].build(
            dry_run_plan_packet=plan,
            fixture_step_results=fixture["fixture_step_results"],
            evaluated_at=timestamps[8],
        ))
    rehearsal = verified("reference_adapter_rehearsal", stage[
        "reference_adapter_rehearsal"].build(
            dry_run_fixture_result_packet=dry_run_result,
            reference_rehearsal_fixture=fixture["reference_rehearsal_fixture"],
            rehearsed_at=timestamps[9],
        ))
    request_readiness = verified("live_adapter_dry_run_readiness", stage[
        "live_adapter_dry_run_readiness"].build(
            reference_adapter_rehearsal_packet=rehearsal,
            checked_at=timestamps[10],
        ))
    request = verified("live_adapter_dry_run_request", stage[
        "live_adapter_dry_run_request"].build(
            request_readiness_packet=request_readiness,
            endpoint_candidate=fixture["endpoint_candidate"],
            credential_reference=fixture["credential_reference"],
            created_at=timestamps[11],
        ))
    dispatch_readiness = verified("live_adapter_dry_run_dispatch_readiness", stage[
        "live_adapter_dry_run_dispatch_readiness"].build(
            live_adapter_dry_run_request_packet=request,
            checked_at=timestamps[12],
        ))
    allowlist = verified("live_adapter_dry_run_endpoint_allowlist", stage[
        "live_adapter_dry_run_endpoint_allowlist"].build(
            dispatch_readiness_packet=dispatch_readiness,
            endpoint_allowlist_snapshot=fixture["endpoint_allowlist_snapshot"],
            evaluated_at=timestamps[13],
        ))
    credential = verified("live_adapter_dry_run_credential_authorization", stage[
        "live_adapter_dry_run_credential_authorization"].build(
            endpoint_allowlist_evaluation_packet=allowlist,
            credential_policy_snapshot=fixture["credential_policy_snapshot"],
            evaluated_at=timestamps[14],
        ))
    operator = verified("live_adapter_dry_run_operator_dispatch_review", stage[
        "live_adapter_dry_run_operator_dispatch_review"].build(
            credential_authorization_evaluation_packet=credential,
            operator_review_decision=fixture["operator_review_decision"],
            reviewed_at=timestamps[15],
        ))
    pre_dispatch = verified("live_adapter_dry_run_bind_pre_dispatch_review", stage[
        "live_adapter_dry_run_bind_pre_dispatch_review"].build(
            operator_dispatch_review_packet=operator,
            bind_pre_dispatch_review_decision=fixture[
                "bind_pre_dispatch_review_decision"],
            reviewed_at=timestamps[16],
        ))
    authority = verified("live_adapter_dry_run_authority_evidence_linkage", stage[
        "live_adapter_dry_run_authority_evidence_linkage"].build(
            bind_pre_dispatch_review_packet=pre_dispatch,
            authority_evidence_reference_bundle=fixture[
                "authority_evidence_reference_bundle"],
            reviewed_at=timestamps[17],
        ))
    approval = verified("live_adapter_dry_run_human_approval_linkage", stage[
        "live_adapter_dry_run_human_approval_linkage"].build(
            authority_evidence_linkage_review_packet=authority,
            human_approval_reference_bundle=fixture[
                "human_approval_reference_bundle"],
            reviewed_at=timestamps[18],
        ))
    final_readiness = verified(
        "live_adapter_dry_run_final_bind_authorization_readiness", stage[
            "live_adapter_dry_run_final_bind_authorization_readiness"].build(
                human_approval_linkage_review_packet=approval,
                final_bind_authorization_readiness_review_decision=fixture[
                    "final_bind_authorization_readiness_review_decision"],
                reviewed_at=timestamps[19],
            ))
    gate = verified("live_adapter_dry_run_bind_authorization_gate_review", stage[
        "live_adapter_dry_run_bind_authorization_gate_review"].build(
            final_bind_authorization_readiness_packet=final_readiness,
            bind_authorization_gate_review_decision=fixture[
                "bind_authorization_gate_review_decision"],
            reviewed_at=timestamps[20],
        ))
    if len(verified_names) != len(STAGE_SYMBOLS):
        raise BenchmarkError("native prerequisite chain was not fully verified")
    return packet_dict(gate), verified_names


def base_result(case: dict[str, Any], handoff_result: dict[str, Any]) -> dict[str, Any]:
    status = handoff_result["status"]
    expected = case["ground_truth"]["expected_bind_gate_outcome"]
    return {
        "case_id": case["case_id"],
        "handoff_status": status,
        "handoff_aggregate_decision": handoff_runner.aggregate_from_status(status),
        "bind_chain_reached": status == "READY_FOR_GUARDED_PROMOTION",
        "bind_stop_stage": None,
        "bind_stop_reason": None,
        "native_bind_gate_invoked": False,
        "native_bind_gate_outcome": None,
        "native_bind_gate_packet_id": None,
        "native_bind_gate_packet_hash": None,
        "full_chain_bind_eligibility_outcome": BIND_FAIL,
        "expected_bind_gate_outcome": expected,
        "bind_eligibility_match": expected == BIND_FAIL,
        **EFFECT_FLAGS,
    }


def run_case(case: dict[str, Any], repo: Path, native: dict[str, Any],
             stages: tuple[StageSpec, ...],
             profile: dict[str, Any]) -> dict[str, Any]:
    handoff, flags = handoff_runner.build_handoff(case, repo)
    context = handoff_runner.build_context(handoff, native, flags)
    validated = native["validate"](
        handoff, context, handoff_runner.EVALUATED_AT
    ).to_dict()
    row = base_result(case, validated)
    if validated["status"] != "READY_FOR_GUARDED_PROMOTION":
        row["bind_stop_stage"] = "NOT_REACHED_UPSTREAM_GOVERNANCE_STOP"
        row["bind_stop_reason"] = "HANDOFF_NOT_READY_FOR_GUARDED_PROMOTION"
        return row
    fixture = treatment_fixture(case, profile)
    if not fixture["approval_required"]:
        row["bind_stop_stage"] = "HUMAN_APPROVAL_LINKAGE_COMPATIBILITY"
        row["bind_stop_reason"] = "NATIVE_BIND_PROFILE_UNSUPPORTED_APPROVAL_NOT_REQUIRED"
        return row
    packet, verified = execute_native_chain(
        handoff, context, fixture, stages
    )
    outcome = packet["gate_review_state"]
    if outcome not in {BIND_PASS, BIND_FAIL}:
        raise BenchmarkError(f"unexpected native gate_review_state: {outcome}")
    row.update({
        "native_bind_gate_invoked": True,
        "native_bind_gate_outcome": outcome,
        "native_bind_gate_packet_id": packet[
            "live_adapter_dry_run_bind_authorization_gate_review_id"],
        "native_bind_gate_packet_hash": packet[
            "live_adapter_dry_run_bind_authorization_gate_review_hash"],
        "full_chain_bind_eligibility_outcome": outcome,
        "verified_native_stages": verified,
    })
    row["bind_eligibility_match"] = (
        row["full_chain_bind_eligibility_outcome"]
        == row["expected_bind_gate_outcome"]
    )
    return row


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    invoked = [r for r in rows if r["native_bind_gate_invoked"]]
    ready = [r for r in rows if r["handoff_status"] == "READY_FOR_GUARDED_PROMOTION"]
    compatible = [r for r in ready if r["bind_stop_reason"] !=
                  "NATIVE_BIND_PROFILE_UNSUPPORTED_APPROVAL_NOT_REQUIRED"]
    counts = Counter(r["native_bind_gate_outcome"] for r in invoked)
    return {
        "total_cases": len(rows),
        "handoff_ready_cases": len(ready),
        "upstream_stopped_cases": len(rows) - len(ready),
        "native_bind_chain_eligible_cases": len(compatible),
        "native_bind_gate_invoked_count": len(invoked),
        "native_bind_gate_not_reached_count": len(rows) - len(invoked),
        "native_bind_gate_pass_count": counts[BIND_PASS],
        "native_bind_gate_fail_count": counts[BIND_FAIL],
        "native_bind_gate_error_count": sum(
            r["bind_stop_stage"] == "NATIVE_CHAIN_ERROR" for r in rows
        ),
        "native_bind_gate_supported_subset_accuracy": (
            sum(r["bind_eligibility_match"] for r in invoked) / len(invoked)
            if invoked else None
        ),
        "full_chain_bind_eligibility_accuracy": (
            sum(r["bind_eligibility_match"] for r in rows) / len(rows)
        ),
        "approval_required_true_ready_count": sum(
            r["case_id"] and c["input"]["governance_fixture"]["approval_required"]
            for r, c in zip(rows, _SUMMARY_CASES) if r in ready
        ),
        "approval_required_false_ready_count": sum(
            not c["input"]["governance_fixture"]["approval_required"]
            for r, c in zip(rows, _SUMMARY_CASES) if r in ready
        ),
        "approval_not_required_native_compatibility_block_count": sum(
            r["bind_stop_reason"] ==
            "NATIVE_BIND_PROFILE_UNSUPPORTED_APPROVAL_NOT_REQUIRED"
            for r in rows
        ),
        "mismatch_case_ids": [r["case_id"] for r in rows
                              if not r["bind_eligibility_match"]],
        "approval_not_required_compatibility_case_ids": [
            r["case_id"] for r in rows if r["bind_stop_reason"] ==
            "NATIVE_BIND_PROFILE_UNSUPPORTED_APPROVAL_NOT_REQUIRED"
        ],
        **EFFECT_FLAGS,
    }


_SUMMARY_CASES: list[dict[str, Any]] = []


def run(args: argparse.Namespace) -> dict[str, Any]:
    import jsonschema

    root = Path(__file__).resolve().parent
    integrity = verify_inputs(root, args.veritas_repo.resolve())
    dataset = handoff_runner.load_dataset(args.dataset.resolve())
    profile = json.loads(args.bind_profile.read_text(encoding="utf-8"))
    native, stages = load_native(args.veritas_repo.resolve())
    global _SUMMARY_CASES
    _SUMMARY_CASES = dataset["cases"]
    rows = [run_case(case, args.veritas_repo.resolve(), native, stages, profile)
            for case in dataset["cases"]]
    result_schema = json.loads((
        root / "schemas/joint-benchmark-case-result-v0.2.schema.json"
    ).read_text(encoding="utf-8"))
    for row in rows:
        jsonschema.validate(instance=row, schema=result_schema)
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    cases_path = output / "cases.jsonl"
    cases_path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8")
    summary = summarize(rows)
    summary_path = output / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest = {
        "runner_version": RUNNER_VERSION,
        "benchmark_repository_commit": _git(root, "rev-parse", "HEAD"),
        "pinned_veritas_commit": PINNED_VERITAS_COMMIT,
        **integrity,
        "python_version": platform.python_version(),
        "os_platform": platform.platform(),
        "native_bind_gate_invocation_count": summary["native_bind_gate_invoked_count"],
        "result_file_sha256": {
            "cases.jsonl": sha256_file(cases_path),
            "summary.json": sha256_file(summary_path),
        },
        **EFFECT_FLAGS,
    }
    report_path = output / "report.md"
    report_path.write_text(
        "# Native VERITAS Bind Benchmark v0.2\n\n"
        f"- Total cases: **{summary['total_cases']}**\n"
        f"- Handoff READY: **{summary['handoff_ready_cases']}**\n"
        f"- Native Bind gate invoked: **{summary['native_bind_gate_invoked_count']}**\n"
        f"- Native Bind gate not reached: **{summary['native_bind_gate_not_reached_count']}**\n"
        f"- Full-chain accuracy: **{summary['full_chain_bind_eligibility_accuracy']:.6f}**\n"
        "- Execution authority created: **false**\n"
        "- Real Bind invoked: **false**\n"
        "- External effect occurred: **false**\n",
        encoding="utf-8",
    )
    manifest["result_file_sha256"]["report.md"] = sha256_file(report_path)
    manifest_path = output / "run_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parent
    result = argparse.ArgumentParser()
    result.add_argument("--veritas-repo", type=Path)
    result.add_argument("--dataset", type=Path, default=root / "fixtures/Governance_labelled_Evaluation_Set_v0.1.1.json")
    result.add_argument("--bind-profile", type=Path, default=root / "fixtures/Bind_Profile_v0.2.json")
    result.add_argument("--output-dir", type=Path, default=root / "results/native-v0.2")
    result.add_argument("--self-check", action="store_true")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.self_check:
            print(json.dumps({"self_check": "PASS", **verify_inputs(Path(__file__).resolve().parent)}, indent=2))
            return 0
        if args.veritas_repo is None:
            raise BenchmarkError("--veritas-repo is required")
        print(json.dumps(run(args), indent=2))
        return 0
    except BenchmarkError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
