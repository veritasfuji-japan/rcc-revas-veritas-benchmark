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
PINNED_PROFILE_SHA256 = "c0af66a7e1f045e422bd10f17c926aaaf944569231cf7a7f137288307e607951"
PINNED_CONTRACT_SHA256 = "081e1a3f8069eaa336f8c1a0f5c7d7151206e9dd670207726906236c8bc1c08f"
PINNED_RUNTIME_SHA256 = "46b03b19904658e02d1bf401d7f54c533e97e543a4c92fb7f18d9cab6d62844a"
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


@dataclass(frozen=True)
class StageSpec:
    """Exact native symbol mapping at the pinned VERITAS commit."""

    module: str
    builder: str
    verifier: str


STAGE_SPECS = (
    StageSpec("guarded_promotion_eligibility",
              "build_guarded_promotion_eligibility_packet",
              "verify_guarded_promotion_eligibility_packet"),
    StageSpec("execution_intent_formation_readiness",
              "build_execution_intent_formation_readiness_packet",
              "verify_execution_intent_formation_readiness_packet"),
    StageSpec("canonical_execution_intent_formation",
              "build_canonical_execution_intent_formation_packet",
              "verify_canonical_execution_intent_formation_packet"),
    StageSpec("execution_intent_pre_bind_validation",
              "build_execution_intent_pre_bind_validation_packet",
              "verify_execution_intent_pre_bind_validation_packet"),
    StageSpec("canonical_bind_preflight_adjudication",
              "build_canonical_bind_preflight_adjudication_packet",
              "verify_canonical_bind_preflight_adjudication_packet"),
    StageSpec("bind_adapter_contract_selection",
              "build_bind_adapter_contract_selection_packet",
              "verify_bind_adapter_contract_selection_packet"),
    StageSpec("adapter_dry_run_plan", "build_adapter_dry_run_plan_packet",
              "verify_adapter_dry_run_plan_packet"),
    StageSpec("adapter_dry_run_result",
              "build_adapter_dry_run_fixture_result_packet",
              "verify_adapter_dry_run_fixture_result_packet"),
    StageSpec("reference_adapter_rehearsal",
              "build_reference_adapter_in_memory_rehearsal_packet",
              "verify_reference_adapter_in_memory_rehearsal_packet"),
    StageSpec("live_adapter_dry_run_readiness",
              "build_live_adapter_dry_run_request_readiness_packet",
              "verify_live_adapter_dry_run_request_readiness_packet"),
    StageSpec("live_adapter_dry_run_request",
              "build_live_adapter_dry_run_request_packet",
              "verify_live_adapter_dry_run_request_packet"),
    StageSpec("live_adapter_dry_run_dispatch_readiness",
              "build_live_adapter_dry_run_dispatch_readiness_packet",
              "verify_live_adapter_dry_run_dispatch_readiness_packet"),
    StageSpec("live_adapter_dry_run_endpoint_allowlist",
              "build_live_adapter_dry_run_endpoint_allowlist_evaluation_packet",
              "verify_live_adapter_dry_run_endpoint_allowlist_evaluation_packet"),
    StageSpec("live_adapter_dry_run_credential_authorization",
              "build_live_adapter_dry_run_credential_authorization_evaluation_packet",
              "verify_live_adapter_dry_run_credential_authorization_evaluation_packet"),
    StageSpec("live_adapter_dry_run_operator_dispatch_review",
              "build_live_adapter_dry_run_operator_dispatch_review_packet",
              "verify_live_adapter_dry_run_operator_dispatch_review_packet"),
    StageSpec("live_adapter_dry_run_bind_pre_dispatch_review",
              "build_live_adapter_dry_run_bind_pre_dispatch_review_packet",
              "verify_live_adapter_dry_run_bind_pre_dispatch_review_packet"),
    StageSpec("live_adapter_dry_run_authority_evidence_linkage",
              "build_live_adapter_dry_run_authority_evidence_linkage_review_packet",
              "verify_live_adapter_dry_run_authority_evidence_linkage_review_packet"),
    StageSpec("live_adapter_dry_run_human_approval_linkage",
              "build_live_adapter_dry_run_human_approval_linkage_review_packet",
              "verify_live_adapter_dry_run_human_approval_linkage_review_packet"),
    StageSpec("live_adapter_dry_run_final_bind_authorization_readiness",
              "build_live_adapter_dry_run_final_bind_authorization_readiness_packet",
              "verify_live_adapter_dry_run_final_bind_authorization_readiness_packet"),
    StageSpec("live_adapter_dry_run_bind_authorization_gate_review",
              "build_live_adapter_dry_run_bind_authorization_gate_review_packet",
              "verify_live_adapter_dry_run_bind_authorization_gate_review_packet"),
)
STAGES = tuple(spec.module for spec in STAGE_SPECS)


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


def load_native(veritas_repo: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    if str(veritas_repo) not in sys.path:
        sys.path.insert(0, str(veritas_repo))
    handoff = handoff_runner.load_native_veritas(veritas_repo)
    functions = {}
    for spec in STAGE_SPECS:
        module = importlib.import_module(f"veritas_os.policy.{spec.module}")
        functions[spec.builder] = getattr(module, spec.builder)
        functions[spec.verifier] = getattr(module, spec.verifier)
    return handoff, functions


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
        "fixture_step_results": [{
            "step_id": "validate-no-effect-request",
            "status": "PASSED",
            "request_dispatched": False,
            "external_effect_occurred": False,
        }],
        "reference_rehearsal_fixture": {
            "fixture_id": f"reference-rehearsal-{case_id.lower()}",
            "mode": "IN_MEMORY_ONLY",
            "external_effect_allowed": False,
        },
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
        "final_bind_authorization_readiness_review_decision": (
            "READY_FOR_BIND_GATE_REVIEW_NOT_AUTHORIZED"
        ),
        "bind_authorization_gate_review_decision": (
            "PASS_REVIEW_NOT_AUTHORIZED"
        ),
        "timestamps": list(profile["fixed_timestamps_utc"]),
        **EFFECT_FLAGS,
    }


def _verified(packet: Any, verifier: Callable[[Any], Any], stage: str) -> Any:
    verification = verifier(packet)
    if verification is False:
        raise BenchmarkError(f"native verification failed: {stage}")
    if hasattr(verification, "valid") and not verification.valid:
        raise BenchmarkError(f"native verification failed: {stage}")
    return packet


def execute_native_chain(
    handoff_packet: dict[str, Any], validation_context: Any,
    fixture: dict[str, Any], native: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """Build and independently verify every native prerequisite in order."""
    at = [datetime.fromisoformat(value.replace("Z", "+00:00"))
          for value in fixture["timestamps"]]
    verified_names = []

    def build(builder: str, verifier: str, stage: str, **kwargs: Any) -> Any:
        packet = native[builder](**kwargs)
        verified_names.append(stage)
        return _verified(packet, native[verifier], stage)

    eligibility_packet = build(
        STAGE_SPECS[0].builder, STAGE_SPECS[0].verifier, STAGES[0],
        handoff=handoff_packet, validation_context=validation_context,
        evaluated_at=at[0],
    )
    formation_readiness_packet = build(
        STAGE_SPECS[1].builder, STAGE_SPECS[1].verifier, STAGES[1],
        eligibility_packet=eligibility_packet, checked_at=at[1],
    )
    formation_packet = build(
        STAGE_SPECS[2].builder, STAGE_SPECS[2].verifier, STAGES[2],
        readiness_packet=formation_readiness_packet, formed_at=at[2],
    )
    pre_bind_validation_packet = build(
        STAGE_SPECS[3].builder, STAGE_SPECS[3].verifier, STAGES[3],
        formation_packet=formation_packet, checked_at=at[3],
    )
    preflight_packet = build(
        STAGE_SPECS[4].builder, STAGE_SPECS[4].verifier, STAGES[4],
        pre_bind_validation_packet=pre_bind_validation_packet,
        adjudicated_at=at[4],
    )
    selection_packet = build(
        STAGE_SPECS[5].builder, STAGE_SPECS[5].verifier, STAGES[5],
        preflight_packet=preflight_packet,
        adapter_contract_descriptor=fixture["adapter_contract_descriptor"],
        selected_at=at[5],
    )
    plan_packet = build(
        STAGE_SPECS[6].builder, STAGE_SPECS[6].verifier, STAGES[6],
        selection_packet=selection_packet, planned_at=at[6],
    )
    fixture_result_packet = build(
        STAGE_SPECS[7].builder, STAGE_SPECS[7].verifier, STAGES[7],
        plan_packet=plan_packet,
        fixture_step_results=fixture["fixture_step_results"],
        evaluated_at=at[7],
    )
    rehearsal_packet = build(
        STAGE_SPECS[8].builder, STAGE_SPECS[8].verifier, STAGES[8],
        fixture_result_packet=fixture_result_packet,
        reference_rehearsal_fixture=fixture["reference_rehearsal_fixture"],
        rehearsed_at=at[8],
    )
    request_readiness_packet = build(
        STAGE_SPECS[9].builder, STAGE_SPECS[9].verifier, STAGES[9],
        rehearsal_packet=rehearsal_packet, checked_at=at[9],
    )
    request_packet = build(
        STAGE_SPECS[10].builder, STAGE_SPECS[10].verifier, STAGES[10],
        readiness_packet=request_readiness_packet,
        endpoint_candidate=fixture["endpoint_candidate"], created_at=at[10],
    )
    dispatch_readiness_packet = build(
        STAGE_SPECS[11].builder, STAGE_SPECS[11].verifier, STAGES[11],
        request_packet=request_packet, checked_at=at[11],
    )
    allowlist_packet = build(
        STAGE_SPECS[12].builder, STAGE_SPECS[12].verifier, STAGES[12],
        dispatch_readiness_packet=dispatch_readiness_packet,
        endpoint_allowlist_snapshot=fixture["endpoint_allowlist_snapshot"],
        evaluated_at=at[12],
    )
    credential_packet = build(
        STAGE_SPECS[13].builder, STAGE_SPECS[13].verifier, STAGES[13],
        endpoint_allowlist_evaluation_packet=allowlist_packet,
        credential_reference=fixture["credential_reference"],
        credential_policy_snapshot=fixture["credential_policy_snapshot"],
        evaluated_at=at[13],
    )
    operator_packet = build(
        STAGE_SPECS[14].builder, STAGE_SPECS[14].verifier, STAGES[14],
        credential_authorization_evaluation_packet=credential_packet,
        operator_review_decision=fixture["operator_review_decision"],
        reviewed_at=at[14],
    )
    pre_dispatch_packet = build(
        STAGE_SPECS[15].builder, STAGE_SPECS[15].verifier, STAGES[15],
        operator_dispatch_review_packet=operator_packet,
        bind_pre_dispatch_review_decision=(
            fixture["bind_pre_dispatch_review_decision"]
        ), reviewed_at=at[15],
    )
    authority_packet = build(
        STAGE_SPECS[16].builder, STAGE_SPECS[16].verifier, STAGES[16],
        bind_pre_dispatch_review_packet=pre_dispatch_packet,
        authority_evidence_reference_bundle=(
            fixture["authority_evidence_reference_bundle"]
        ), reviewed_at=at[16],
    )
    approval_packet = build(
        STAGE_SPECS[17].builder, STAGE_SPECS[17].verifier, STAGES[17],
        authority_evidence_linkage_review_packet=authority_packet,
        human_approval_reference_bundle=(
            fixture["human_approval_reference_bundle"]
        ), reviewed_at=at[17],
    )
    final_readiness_packet = build(
        STAGE_SPECS[18].builder, STAGE_SPECS[18].verifier, STAGES[18],
        human_approval_linkage_review_packet=approval_packet,
        final_bind_authorization_readiness_review_decision=fixture[
            "final_bind_authorization_readiness_review_decision"
        ], reviewed_at=at[18],
    )
    gate_packet = build(
        STAGE_SPECS[19].builder, STAGE_SPECS[19].verifier, STAGES[19],
        final_bind_authorization_readiness_packet=final_readiness_packet,
        bind_authorization_gate_review_decision=fixture[
            "bind_authorization_gate_review_decision"
        ], reviewed_at=at[19],
    )
    return packet_dict(gate_packet), verified_names


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
             functions: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
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
    # The pinned v1 linkage contract requires at least one approval reference.
    # It has no native approval-not-required representation.  Supplying a
    # synthetic reference here would falsely manufacture Human Approval.
    if not fixture["approval_required"]:
        row["bind_stop_stage"] = "HUMAN_APPROVAL_LINKAGE_COMPATIBILITY"
        row["bind_stop_reason"] = "NATIVE_BIND_PROFILE_UNSUPPORTED_APPROVAL_NOT_REQUIRED"
        return row
    packet, verified = execute_native_chain(
        handoff, context, fixture, functions
    )
    gate_state = packet["bind_authorization_gate_review_state"]
    outcome = {
        "PASSED": BIND_PASS,
        "FAILED": BIND_FAIL,
    }[gate_state]
    row.update({
        "native_bind_gate_invoked": True,
        "native_bind_gate_outcome": outcome,
        "native_bind_gate_review_state": gate_state,
        "native_bind_gate_packet_id": packet[
            "bind_authorization_gate_review_packet_id"
        ],
        "native_bind_gate_packet_hash": packet[
            "bind_authorization_gate_review_packet_hash"
        ],
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
    root = Path(__file__).resolve().parent
    integrity = verify_inputs(root, args.veritas_repo.resolve())
    dataset = handoff_runner.load_dataset(args.dataset.resolve())
    profile = json.loads(args.bind_profile.read_text(encoding="utf-8"))
    native, functions = load_native(args.veritas_repo.resolve())
    global _SUMMARY_CASES
    _SUMMARY_CASES = dataset["cases"]
    rows = [run_case(case, args.veritas_repo.resolve(), native, functions, profile)
            for case in dataset["cases"]]
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
