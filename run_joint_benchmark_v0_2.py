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
import inspect
import json
import platform
import subprocess
import sys
from collections import Counter
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
STAGES = (
    "guarded_promotion_eligibility",
    "execution_intent_formation_readiness",
    "canonical_execution_intent_formation",
    "execution_intent_pre_bind_validation",
    "canonical_bind_preflight_adjudication",
    "bind_adapter_contract_selection",
    "adapter_dry_run_plan",
    "adapter_dry_run_result",
    "reference_adapter_rehearsal",
    "live_adapter_dry_run_readiness",
    "live_adapter_dry_run_request",
    "live_adapter_dry_run_dispatch_readiness",
    "live_adapter_dry_run_endpoint_allowlist",
    "live_adapter_dry_run_credential_authorization",
    "live_adapter_dry_run_operator_dispatch_review",
    "live_adapter_dry_run_bind_pre_dispatch_review",
    "live_adapter_dry_run_authority_evidence_linkage",
    "live_adapter_dry_run_human_approval_linkage",
    "live_adapter_dry_run_final_bind_authorization_readiness",
    "live_adapter_dry_run_bind_authorization_gate_review",
)


class BenchmarkError(RuntimeError):
    """An integrity or native-contract error (not a scientific mismatch)."""


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def packet_dict(packet: Any) -> dict[str, Any]:
    if isinstance(packet, dict):
        return copy.deepcopy(packet)
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


def load_native(veritas_repo: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if str(veritas_repo) not in sys.path:
        sys.path.insert(0, str(veritas_repo))
    handoff = handoff_runner.load_native_veritas(veritas_repo)
    stages = []
    for module_name in STAGES:
        module = importlib.import_module(f"veritas_os.policy.{module_name}")
        builder_name = f"build_{module_name}_packet"
        verifier_name = f"verify_{module_name}_packet"
        builder = getattr(module, builder_name)
        verifier = getattr(module, verifier_name, None)
        if verifier is None:
            raise BenchmarkError(f"native intermediate verifier absent: {verifier_name}")
        stages.append({"name": module_name, "build": builder, "verify": verifier})
    return handoff, stages


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
        "authority_reference_bundle": {
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
        "final_readiness_decision": "READY_FOR_BIND_GATE_REVIEW_NOT_AUTHORIZED",
        "bind_gate_review_decision": "PASS_REVIEW_NOT_AUTHORIZED",
        "timestamps": list(profile["fixed_timestamps_utc"]),
        **EFFECT_FLAGS,
    }


def approval_not_required_supported(stages: list[dict[str, Any]]) -> bool:
    """Inspect the native linkage contract; never invent an approval reference."""
    stage = next(s for s in stages if s["name"] == "live_adapter_dry_run_human_approval_linkage")
    signature = inspect.signature(stage["build"])
    for name, parameter in signature.parameters.items():
        if "approval" in name and "reference" in name:
            return parameter.default is not inspect.Parameter.empty
    source = inspect.getsource(stage["build"])
    return "approval_required" in source and "not approval_required" in source


def _call(function: Callable[..., Any], values: dict[str, Any]) -> Any:
    signature = inspect.signature(function)
    kwargs = {}
    missing = []
    for name, parameter in signature.parameters.items():
        if parameter.kind in (parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD):
            continue
        if name in values:
            kwargs[name] = values[name]
        elif parameter.default is inspect.Parameter.empty:
            missing.append(name)
    if missing:
        raise BenchmarkError(
            f"native contract inputs unavailable for {function.__name__}: {missing}"
        )
    return function(**kwargs)


def execute_native_chain(
    handoff_packet: dict[str, Any], fixture: dict[str, Any],
    stages: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[str]]:
    """Build and independently verify every native prerequisite in order."""
    values = dict(fixture)
    values.update({
        "canonical_decision_handoff": handoff_packet,
        "handoff": handoff_packet,
        "evaluated_at": fixture["timestamps"][0],
        "reviewed_at": fixture["timestamps"][0],
    })
    verified_names = []
    final_packet: Any = None
    for index, stage in enumerate(stages):
        timestamp = fixture["timestamps"][index]
        values.update({"evaluated_at": timestamp, "created_at": timestamp,
                       "reviewed_at": timestamp, "now": timestamp})
        packet = _call(stage["build"], values)
        packet_value = packet_dict(packet)
        values[stage["name"] + "_packet"] = packet
        values["previous_packet"] = packet
        verification = _call(stage["verify"], {**values, "packet": packet})
        if verification is False:
            raise BenchmarkError(f"native verification failed: {stage['name']}")
        if hasattr(verification, "valid") and not verification.valid:
            raise BenchmarkError(f"native verification failed: {stage['name']}")
        verified_names.append(stage["name"])
        final_packet = packet_value
    if len(verified_names) != len(STAGES):
        raise BenchmarkError("native prerequisite chain was not fully verified")
    return final_packet, verified_names


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
             stages: list[dict[str, Any]], profile: dict[str, Any]) -> dict[str, Any]:
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
    if not fixture["approval_required"] and not approval_not_required_supported(stages):
        row["bind_stop_stage"] = "HUMAN_APPROVAL_LINKAGE_COMPATIBILITY"
        row["bind_stop_reason"] = "NATIVE_BIND_PROFILE_UNSUPPORTED_APPROVAL_NOT_REQUIRED"
        return row
    try:
        packet, verified = execute_native_chain(handoff, fixture, stages)
        outcome = packet.get("outcome") or packet.get("review_outcome")
        row.update({
            "native_bind_gate_invoked": True,
            "native_bind_gate_outcome": outcome,
            "native_bind_gate_packet_id": packet.get("packet_id"),
            "native_bind_gate_packet_hash": packet.get("packet_hash"),
            "full_chain_bind_eligibility_outcome": outcome or BIND_FAIL,
            "verified_native_stages": verified,
        })
    except Exception as exc:  # Native fail-closed behavior is scientific evidence.
        row["bind_stop_stage"] = "NATIVE_CHAIN_ERROR"
        row["bind_stop_reason"] = f"{type(exc).__name__}: {exc}"
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
    native, stages = load_native(args.veritas_repo.resolve())
    global _SUMMARY_CASES
    _SUMMARY_CASES = dataset["cases"]
    rows = [run_case(case, args.veritas_repo.resolve(), native, stages, profile)
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
