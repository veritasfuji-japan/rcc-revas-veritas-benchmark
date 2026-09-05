#!/usr/bin/env python3
"""RCC/REVAS × VERITAS native Bind-chain benchmark v0.3.

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
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

import run_joint_benchmark as handoff_runner

RUNNER_VERSION = "0.3.0"
PINNED_VERITAS_COMMIT = "3d9b8f85138fb0c5cde48915f10410861d015abc"
PINNED_DATASET_SHA256 = handoff_runner.PINNED_DATASET_SHA256
PINNED_PROFILE_SHA256 = "fe26df3980941b4782bb48238341998f912e3637c044b314c2d4c5ae4f442479"
PINNED_CONTRACT_SHA256 = "91a6efef57210717f8b3727407c1fd3fa62d168bc15a5e8e299e2f652f797f4d"
PINNED_RUNTIME_SHA256 = "f6fdf95d0ddb7f4dc2eb9963a779fae77fe95e559837bed4cd9dbf6fe17d163a"
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
    StageSpec("human_approval_requirement_resolution",
              "build_human_approval_requirement_resolution_packet",
              "verify_human_approval_requirement_resolution_packet"),
    StageSpec("live_adapter_dry_run_human_approval_linkage",
              "build_live_adapter_dry_run_human_approval_linkage_review_packet",
              "verify_live_adapter_dry_run_human_approval_linkage_review_packet"),
    StageSpec("live_adapter_dry_run_human_approval_requirement_satisfaction",
              "build_live_adapter_dry_run_human_approval_requirement_satisfaction_packet",
              "verify_live_adapter_dry_run_human_approval_requirement_satisfaction_packet"),
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
        "bind_profile": (root / "fixtures/Bind_Profile_v0.3.json", PINNED_PROFILE_SHA256),
        "contract": (root / "contracts/VERITAS_Canonical_Benchmark_Contract_v0.3.json", PINNED_CONTRACT_SHA256),
        "runtime_manifest": (root / "contracts/VERITAS_Benchmark_Runtime_Manifest_v0.3.json", PINNED_RUNTIME_SHA256),
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
    functions: dict[str, Any] = {}
    modules: dict[str, Any] = {}
    for spec in STAGE_SPECS:
        module = importlib.import_module(f"veritas_os.policy.{spec.module}")
        modules[spec.module] = module
        functions[spec.builder] = getattr(module, spec.builder)
        functions[spec.verifier] = getattr(module, spec.verifier)

    selection = modules["bind_adapter_contract_selection"]
    fixture_result = modules["adapter_dry_run_result"]
    endpoint = modules["live_adapter_dry_run_endpoint_allowlist"]
    credential = modules["live_adapter_dry_run_credential_authorization"]
    final_readiness = modules["live_adapter_dry_run_final_bind_authorization_readiness"]
    gate_review = modules["live_adapter_dry_run_bind_authorization_gate_review"]
    action_contracts = importlib.import_module("veritas_os.governance.action_contracts")

    functions.update({
        "_ActionClassContract": action_contracts.ActionClassContract,
        "_adapter_methods": selection.ADAPTER_METHODS,
        "_prohibited_during_selection": selection.PROHIBITED_DURING_SELECTION,
        "_adapter_effect_profile": selection.EFFECT_PROFILE,
        "_descriptor_scope_limitations": selection.DESCRIPTOR_SCOPE_LIMITATIONS,
        "_result_limitations": fixture_result.RESULT_LIMITATIONS,
        "_endpoint_snapshot_hash": endpoint._snapshot_hash,
        "_credential_policy_snapshot_hash": credential._policy_snapshot_hash,
        "_final_acknowledgements": final_readiness.ACKNOWLEDGEMENTS,
        "_final_outcomes": final_readiness.OUTCOMES,
        "_gate_acknowledgements": gate_review.ACKNOWLEDGEMENTS,
        "_gate_outcomes": gate_review.OUTCOMES,
    })
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
        "profile": copy.deepcopy(profile),
    }



def _native_adapter_descriptor(
    preflight_packet: Any, selected_at: datetime, native: dict[str, Any]
) -> dict[str, Any]:
    source = packet_dict(preflight_packet)
    intent = source["execution_intent"]
    return {
        "adapter_contract_version": "bind-adapter-contract/v1",
        "adapter_kind": "reference",
        "adapter_name": "benchmark-inert-reference-v0.3",
        "target_system": intent["target_system"],
        "target_resource_scope": intent["target_resource"],
        "supported_methods": list(native["_adapter_methods"]),
        "required_methods": list(native["_adapter_methods"]),
        "prohibited_during_selection": list(native["_prohibited_during_selection"]),
        "effect_profile": copy.deepcopy(native["_adapter_effect_profile"]),
        "declared_by": "benchmark:v0.3",
        "declared_at": selected_at.isoformat(),
        "descriptor_scope_limitations": list(native["_descriptor_scope_limitations"]),
    }


def _native_fixture_step_results(
    plan_packet: Any, native: dict[str, Any]
) -> list[dict[str, Any]]:
    plan = packet_dict(plan_packet)
    results = []
    for step in plan["planned_steps"]:
        method = step["planned_adapter_method"]
        results.append({
            "step_result_id": (
                f"dry-run-fixture-result:v1:{step['ordinal']}:"
                f"{method.replace('_', '-')}"
            ),
            "planned_step_id": step["step_id"],
            "ordinal": step["ordinal"],
            "planned_adapter_method": method,
            "result_mode": "fixture_no_effect",
            "result_source_kind": "in_memory_fixture",
            "live_observed": False,
            "adapter_instance_created": False,
            "adapter_method_called": False,
            "network_used": False,
            "filesystem_used": False,
            "external_effect_used": False,
            "trustlog_written": False,
            "bind_receipt_created": False,
            "fixture_input_ref": f"benchmark-fixture:{method}",
            "fixture_value_summary": {
                "status": "FIXTURE_RESULT_AVAILABLE",
                "semantic": "no_effect_fixture",
                "live_system_claim": False,
            },
            "matched_expected_output_ref": step["expected_output_ref"],
            "refusal_if_missing_later": step["refusal_if_missing_later"],
            "result_scope_limitations": list(native["_result_limitations"]),
        })
    return results


def _native_endpoint_inputs(
    dispatch_packet: Any, profile: dict[str, Any], evaluated_at: datetime,
    native: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    source = packet_dict(dispatch_packet)
    intent = source["execution_intent"]
    endpoint_profile = profile["endpoint"]
    candidate = {
        "endpoint_candidate_id": (
            f"endpoint:benchmark:{source['execution_intent_id'][-16:]}"
        ),
        "endpoint_kind": "HTTPS_API",
        "endpoint_scheme": endpoint_profile["scheme"],
        "endpoint_host": endpoint_profile["host"],
        "endpoint_port": endpoint_profile["port"],
        "endpoint_path_prefix": endpoint_profile["path"],
        "endpoint_environment": "benchmark",
        "endpoint_purpose": "dry-run",
        "adapter_contract_id": source["adapter_contract_id"],
        "target_system": intent["target_system"],
        "target_resource_scope": intent["target_resource"],
        "declared_by": "benchmark:v0.3",
        "declared_at": evaluated_at.isoformat(),
    }
    entry = {
        "entry_id": f"allow:benchmark:{source['execution_intent_id'][-16:]}",
        "endpoint_kind": candidate["endpoint_kind"],
        "endpoint_scheme": candidate["endpoint_scheme"],
        "endpoint_host": candidate["endpoint_host"],
        "endpoint_port": candidate["endpoint_port"],
        "endpoint_path_prefix": candidate["endpoint_path_prefix"],
        "endpoint_environment": candidate["endpoint_environment"],
        "allowed_adapter_contract_ids": [candidate["adapter_contract_id"]],
        "allowed_target_systems": [candidate["target_system"]],
        "allowed_target_resource_scopes": [candidate["target_resource_scope"]],
        "allowed_purposes": [candidate["endpoint_purpose"]],
        "entry_status": "ACTIVE",
    }
    snapshot = {
        "allowlist_snapshot_id": (
            f"allowlist:benchmark:{source['execution_intent_id'][-16:]}"
        ),
        "allowlist_snapshot_hash": "0" * 64,
        "allowlist_version": "0.3",
        "allowlist_source": "benchmark-local-reviewed-fixture",
        "allowlist_generated_at": evaluated_at.isoformat(),
        "allowlist_entries": [entry],
        "allowlist_scope_limitations": ["LOCAL_DECLARATIONS_ONLY"],
    }
    snapshot["allowlist_snapshot_hash"] = native["_endpoint_snapshot_hash"](snapshot)
    return candidate, snapshot


def _native_credential_inputs(
    allowlist_packet: Any, evaluated_at: datetime, native: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    source = packet_dict(allowlist_packet)
    candidate = source["endpoint_candidate"]
    reference = {
        "credential_reference_id": (
            f"credential-ref:benchmark:{source['execution_intent_id'][-16:]}"
        ),
        "credential_kind": "API_CREDENTIAL",
        "credential_provider_type": "LOCAL_REFERENCE",
        "credential_scope": (
            f"{candidate['target_system']}:{candidate['target_resource_scope']}"
        ),
        "credential_environment": candidate["endpoint_environment"],
        "credential_purpose": candidate["endpoint_purpose"],
        "adapter_contract_id": source["adapter_contract_id"],
        "endpoint_candidate_id": candidate["endpoint_candidate_id"],
        "target_system": candidate["target_system"],
        "target_resource_scope": candidate["target_resource_scope"],
        "declared_by": "benchmark:v0.3",
        "declared_at": evaluated_at.isoformat(),
    }
    entry = {
        "entry_id": (
            f"credential-policy:benchmark:{source['execution_intent_id'][-16:]}"
        ),
        "credential_kind": reference["credential_kind"],
        "credential_provider_type": reference["credential_provider_type"],
        "credential_scope": reference["credential_scope"],
        "credential_environment": reference["credential_environment"],
        "allowed_adapter_contract_ids": [reference["adapter_contract_id"]],
        "allowed_endpoint_candidate_ids": [reference["endpoint_candidate_id"]],
        "allowed_target_systems": [reference["target_system"]],
        "allowed_target_resource_scopes": [reference["target_resource_scope"]],
        "allowed_purposes": [reference["credential_purpose"]],
        "requires_operator_review": True,
        "requires_bind_pre_dispatch_review": True,
        "entry_status": "ACTIVE",
    }
    snapshot = {
        "credential_policy_snapshot_id": (
            f"credential-policy-snapshot:benchmark:"
            f"{source['execution_intent_id'][-16:]}"
        ),
        "credential_policy_snapshot_hash": "0" * 64,
        "credential_policy_version": "0.3",
        "credential_policy_source": "benchmark-local-reviewed-fixture",
        "credential_policy_generated_at": evaluated_at.isoformat(),
        "credential_policy_entries": [entry],
        "credential_policy_scope_limitations": ["LOCAL_METADATA_ONLY"],
    }
    snapshot["credential_policy_snapshot_hash"] = (
        native["_credential_policy_snapshot_hash"](snapshot)
    )
    return reference, snapshot


def _native_operator_decision(
    credential_packet: Any, recorded_at: datetime
) -> dict[str, Any]:
    source = packet_dict(credential_packet)
    reference = source["credential_reference"]
    candidate = source["endpoint_candidate"]
    return {
        "operator_review_id": (
            f"operator-review:benchmark:{source['execution_intent_id'][-16:]}"
        ),
        "reviewer_id": "benchmark-reviewer:operator",
        "reviewer_role": "dispatch-reviewer",
        "reviewer_organization": "benchmark-local",
        "reviewed_at": recorded_at.isoformat(),
        "review_decision": "APPROVE_FOR_BIND_PRE_DISPATCH_REVIEW",
        "review_reason": (
            "Synthetic metadata reviewed; advance only to separate Bind review."
        ),
        "reviewed_endpoint_candidate_id": candidate["endpoint_candidate_id"],
        "reviewed_credential_reference_id": reference["credential_reference_id"],
        "reviewed_adapter_contract_id": source["adapter_contract_id"],
        "reviewed_target_system": reference["target_system"],
        "reviewed_target_resource_scope": reference["target_resource_scope"],
        "acknowledged_scope_limitations": True,
        "acknowledged_non_effect_guarantees": True,
        "acknowledged_future_bind_pre_dispatch_review_required": True,
        "acknowledged_no_dispatch": True,
        "acknowledged_no_credential_access": True,
        "acknowledged_no_network": True,
        "acknowledged_no_bind": True,
        "acknowledged_no_bind_receipt": True,
        "acknowledged_no_trustlog_write": True,
    }


def _native_bind_pre_dispatch_decision(recorded_at: datetime) -> dict[str, Any]:
    return {
        "bind_pre_dispatch_review_decision_id": "bind-review:benchmark:v0.3",
        "reviewer_id": "benchmark-reviewer:bind",
        "reviewer_role": "bind-boundary-reviewer",
        "reviewer_attestation": (
            "Reviewed as deterministic synthetic metadata, not authority."
        ),
        "reviewed_at": recorded_at.isoformat(),
        "review_outcome": "ACCEPTED_FOR_FUTURE_BIND_DISPATCH_GATE_REVIEW",
        "review_reason": "Suitable only for a separate future Bind gate review.",
        "acknowledged_not_bind_authorization": True,
        "acknowledged_no_bind_invocation": True,
        "acknowledged_no_bind_receipt": True,
        "acknowledged_no_trustlog_write": True,
        "acknowledged_no_dispatch": True,
        "acknowledged_no_credential_access": True,
        "acknowledged_no_network_call": True,
        "acknowledged_semantic_match_not_authority": True,
    }


def _native_authority_bundle(
    pre_dispatch_packet: Any, recorded_at: datetime
) -> dict[str, Any]:
    source = packet_dict(pre_dispatch_packet)
    reference_id = (
        f"authority-ref:benchmark:{source['execution_intent_id'][-16:]}"
    )
    scope = "benchmark-bind-scope"
    reference = {
        "authority_evidence_reference_id": reference_id,
        "authority_evidence_kind": "synthetic-delegated-policy-attestation",
        "authority_source_type": "benchmark-synthetic-upstream-artifact",
        "authority_source_id": "authority-source:benchmark:v0.3",
        "authority_policy_id": "policy:benchmark:v0.3",
        "authority_policy_version": "0.3",
        "authority_scope": scope,
        "authority_subject": source["execution_intent"]["actor_identity"],
        "authority_issuer": "benchmark-authority-metadata-only",
        "authority_issued_at": (recorded_at - timedelta(days=1)).isoformat(),
        "authority_expires_at": (recorded_at + timedelta(days=1)).isoformat(),
        "authority_evidence_hash": "sha256:synthetic-metadata-only",
        "authority_evidence_format": "benchmark-declared-reference/v0.3",
        "declared_verification_state": "DECLARED_VERIFIED_BY_UPSTREAM_ARTIFACT",
        "linked_execution_intent_id": source["execution_intent_id"],
        "linked_adapter_contract_id": source["adapter_contract_id"],
        "linked_endpoint_candidate_id": source["endpoint_candidate"][
            "endpoint_candidate_id"
        ],
        "linked_credential_reference_id": source["credential_reference"][
            "credential_reference_id"
        ],
        "linked_target_system": source["credential_reference"]["target_system"],
        "linked_target_resource_scope": source["credential_reference"][
            "target_resource_scope"
        ],
        "linked_purpose": source["credential_reference"]["credential_purpose"],
    }
    return {
        "authority_evidence_reference_bundle_id": (
            f"authority-bundle:benchmark:{source['execution_intent_id'][-16:]}"
        ),
        "bundle_declared_by": "benchmark:v0.3",
        "bundle_declared_at": recorded_at.isoformat(),
        "bundle_scope": [scope],
        "authority_evidence_references": [reference],
        "authority_evidence_binding_claims": [],
        "bundle_limitations": [
            "synthetic-metadata-only",
            "no-external-verification-by-benchmark",
        ],
    }


def _native_human_approval_bundle(
    authority_packet: Any, recorded_at: datetime
) -> dict[str, Any]:
    source = packet_dict(authority_packet)
    authority_ids = [
        item["authority_evidence_reference_id"]
        for item in source["authority_evidence_reference_bundle"][
            "authority_evidence_references"
        ]
    ]
    scope = "benchmark-bind-scope"
    reference = {
        "human_approval_reference_id": (
            f"approval-ref:benchmark:{source['execution_intent_id'][-16:]}"
        ),
        "approval_source_type": "benchmark-synthetic-upstream-artifact",
        "approval_source_id": "approval-source:benchmark:v0.3",
        "approver_id": "benchmark-approver:synthetic",
        "approver_role": "benchmark-bind-reviewer",
        "approval_scope": scope,
        "approval_subject": "benchmark-synthetic-request",
        "approval_reason": "declared synthetic dry-run review",
        "approval_issued_at": (recorded_at - timedelta(days=1)).isoformat(),
        "approval_expires_at": (recorded_at + timedelta(days=1)).isoformat(),
        "approval_evidence_hash": "sha256:synthetic-metadata-only",
        "approval_evidence_format": "benchmark-declared-reference/v0.3",
        "declared_approval_state": "DECLARED_APPROVED_BY_UPSTREAM_ARTIFACT",
        "linked_execution_intent_id": source["execution_intent_id"],
        "linked_adapter_contract_id": source["adapter_contract_id"],
        "linked_endpoint_candidate_id": source["endpoint_candidate"][
            "endpoint_candidate_id"
        ],
        "linked_credential_reference_id": source["credential_reference"][
            "credential_reference_id"
        ],
        "linked_target_system": source["credential_reference"]["target_system"],
        "linked_target_resource_scope": source["credential_reference"][
            "target_resource_scope"
        ],
        "linked_purpose": source["credential_reference"]["credential_purpose"],
        "linked_authority_evidence_reference_ids": authority_ids,
    }
    return {
        "human_approval_reference_bundle_id": (
            f"approval-bundle:benchmark:{source['execution_intent_id'][-16:]}"
        ),
        "bundle_declared_by": "benchmark:v0.3",
        "bundle_declared_at": recorded_at.isoformat(),
        "bundle_scope": [scope],
        "human_approval_references": [reference],
        "human_approval_binding_claims": [],
        "bundle_limitations": [
            "synthetic-metadata-only",
            "no-external-verification-by-benchmark",
        ],
    }


def _native_action_contract(
    authority_packet: Any, approval_required: bool, native: dict[str, Any]
) -> Any:
    """Construct the synthetic treatment contract without reading ground truth."""
    source = packet_dict(authority_packet)
    intended_action = str(source["execution_intent"]["intended_action"])
    allowed_scope = list(source["authority_evidence_reference_bundle"]["bundle_scope"])
    return native["_ActionClassContract"](
        id=intended_action,
        version="0.3",
        domain="benchmark",
        action_class="benchmark_native_bind_action",
        description="Synthetic benchmark ActionClassContract for native Bind treatment",
        declared_intent=intended_action,
        allowed_scope=allowed_scope,
        prohibited_scope=["benchmark:admin"],
        authority_sources=["benchmark-authority-metadata-only"],
        required_evidence=[],
        evidence_freshness={},
        irreversibility={"level": "low"},
        human_approval_rules={
            "required": bool(approval_required),
            "minimum_approvals": 1 if approval_required else 0,
        },
        refusal_conditions=[],
        escalation_conditions=[],
        default_failure_mode="deny",
        metadata={
            "benchmark_fixture": True,
            "ground_truth_used": False,
            "external_effect_allowed": False,
        },
    )


def _native_final_readiness_decision(
    recorded_at: datetime, native: dict[str, Any]
) -> dict[str, Any]:
    value = {
        "final_bind_authorization_readiness_review_decision_id": (
            "final-review:benchmark:v0.3"
        ),
        "reviewer_id": "benchmark-reviewer:final-readiness",
        "reviewer_role": "bind-readiness-reviewer",
        "reviewer_attestation": "Reviewed local synthetic readiness only.",
        "reviewed_at": recorded_at.isoformat(),
        "review_outcome": native["_final_outcomes"][0],
        "review_reason": "Synthetic local linkage artifacts reviewed.",
    }
    value.update({field: True for field in native["_final_acknowledgements"]})
    return value


def _native_gate_decision(
    recorded_at: datetime, native: dict[str, Any]
) -> dict[str, Any]:
    value = {
        "bind_authorization_gate_review_decision_id": "gate-review:benchmark:v0.3",
        "reviewer_id": "benchmark-reviewer:gate",
        "reviewer_role": "bind-gate-reviewer",
        "reviewer_attestation": "Reviewed local synthetic gate evidence only.",
        "reviewed_at": recorded_at.isoformat(),
        "review_outcome": native["_gate_outcomes"][0],
        "review_reason": "Deterministic synthetic local gate review.",
    }
    value.update({field: True for field in native["_gate_acknowledgements"]})
    return value

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
) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
    """Build and independently verify every native prerequisite in order."""
    at = [
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        for value in fixture["timestamps"]
    ]
    verified_names: list[str] = []

    def build(builder: str, verifier: str, stage: str, **kwargs: Any) -> Any:
        packet = native[builder](**kwargs)
        packet = _verified(packet, native[verifier], stage)
        verified_names.append(stage)
        return packet

    eligibility_packet = build(
        STAGE_SPECS[0].builder, STAGE_SPECS[0].verifier, STAGES[0],
        handoff=handoff_packet,
        trusted_context=validation_context,
        evaluated_at=at[0],
        issued_at=at[0],
    )
    formation_readiness_packet = build(
        STAGE_SPECS[1].builder, STAGE_SPECS[1].verifier, STAGES[1],
        eligibility_packet=eligibility_packet,
        checked_at=at[1],
    )
    formation_packet = build(
        STAGE_SPECS[2].builder, STAGE_SPECS[2].verifier, STAGES[2],
        readiness_packet=formation_readiness_packet,
        formed_at=at[2],
    )
    pre_bind_validation_packet = build(
        STAGE_SPECS[3].builder, STAGE_SPECS[3].verifier, STAGES[3],
        formation_packet=formation_packet,
        checked_at=at[3],
    )
    preflight_packet = build(
        STAGE_SPECS[4].builder, STAGE_SPECS[4].verifier, STAGES[4],
        pre_bind_validation_packet=pre_bind_validation_packet,
        adjudicated_at=at[4],
    )
    descriptor = _native_adapter_descriptor(preflight_packet, at[5], native)
    selection_packet = build(
        STAGE_SPECS[5].builder, STAGE_SPECS[5].verifier, STAGES[5],
        bind_preflight_adjudication_packet=preflight_packet,
        adapter_contract_descriptor=descriptor,
        selected_at=at[5],
    )
    plan_packet = build(
        STAGE_SPECS[6].builder, STAGE_SPECS[6].verifier, STAGES[6],
        adapter_contract_selection_packet=selection_packet,
        planned_at=at[6],
    )
    fixture_step_results = _native_fixture_step_results(plan_packet, native)
    fixture_result_packet = build(
        STAGE_SPECS[7].builder, STAGE_SPECS[7].verifier, STAGES[7],
        adapter_dry_run_plan_packet=plan_packet,
        fixture_step_results=fixture_step_results,
        resulted_at=at[7],
    )
    rehearsal_packet = build(
        STAGE_SPECS[8].builder, STAGE_SPECS[8].verifier, STAGES[8],
        adapter_dry_run_fixture_result_packet=fixture_result_packet,
        reference_rehearsal_fixture={"scenario": "deterministic-reference-v0.3"},
        rehearsed_at=at[8],
    )
    request_readiness_packet = build(
        STAGE_SPECS[9].builder, STAGE_SPECS[9].verifier, STAGES[9],
        reference_rehearsal_packet=rehearsal_packet,
        readiness_evaluated_at=at[9],
    )
    request_packet = build(
        STAGE_SPECS[10].builder, STAGE_SPECS[10].verifier, STAGES[10],
        live_adapter_dry_run_readiness_packet=request_readiness_packet,
        requested_at=at[10],
    )
    dispatch_readiness_packet = build(
        STAGE_SPECS[11].builder, STAGE_SPECS[11].verifier, STAGES[11],
        source_live_adapter_dry_run_request_packet=request_packet,
        dispatch_readiness_evaluated_at=at[11],
    )
    endpoint_candidate, allowlist_snapshot = _native_endpoint_inputs(
        dispatch_readiness_packet, fixture["profile"], at[12], native
    )
    allowlist_packet = build(
        STAGE_SPECS[12].builder, STAGE_SPECS[12].verifier, STAGES[12],
        source_dispatch_readiness_packet=dispatch_readiness_packet,
        endpoint_candidate=endpoint_candidate,
        allowlist_snapshot=allowlist_snapshot,
        endpoint_allowlist_evaluated_at=at[12],
    )
    credential_reference, credential_policy_snapshot = _native_credential_inputs(
        allowlist_packet, at[13], native
    )
    credential_packet = build(
        STAGE_SPECS[13].builder, STAGE_SPECS[13].verifier, STAGES[13],
        source_endpoint_allowlist_evaluation_packet=allowlist_packet,
        credential_reference=credential_reference,
        credential_policy_snapshot=credential_policy_snapshot,
        credential_authorization_evaluated_at=at[13],
    )
    operator_packet = build(
        STAGE_SPECS[14].builder, STAGE_SPECS[14].verifier, STAGES[14],
        source_credential_authorization_evaluation_packet=credential_packet,
        operator_review_decision=_native_operator_decision(
            credential_packet, at[14]
        ),
        operator_dispatch_review_recorded_at=at[14],
    )
    pre_dispatch_packet = build(
        STAGE_SPECS[15].builder, STAGE_SPECS[15].verifier, STAGES[15],
        source_operator_dispatch_review_packet=operator_packet,
        bind_pre_dispatch_review_decision=_native_bind_pre_dispatch_decision(
            at[15]
        ),
        bind_pre_dispatch_review_recorded_at=at[15],
    )
    authority_packet = build(
        STAGE_SPECS[16].builder, STAGE_SPECS[16].verifier, STAGES[16],
        source_bind_pre_dispatch_review_packet=pre_dispatch_packet,
        authority_evidence_reference_bundle=_native_authority_bundle(
            pre_dispatch_packet, at[16]
        ),
        authority_evidence_linkage_review_recorded_at=at[16],
    )
    action_contract = _native_action_contract(
        authority_packet, fixture["approval_required"], native
    )
    requirement_packet = build(
        STAGE_SPECS[17].builder, STAGE_SPECS[17].verifier, STAGES[17],
        source_authority_evidence_linkage_review_packet=authority_packet,
        action_contract=action_contract,
        resolved_at=at[17],
    )
    approval_packet = None
    if fixture["approval_required"]:
        approval_packet = build(
            STAGE_SPECS[18].builder, STAGE_SPECS[18].verifier, STAGES[18],
            source_authority_evidence_linkage_review_packet=authority_packet,
            human_approval_reference_bundle=_native_human_approval_bundle(
                authority_packet, at[18]
            ),
            human_approval_linkage_review_recorded_at=at[18],
        )
    satisfaction_packet = build(
        STAGE_SPECS[19].builder, STAGE_SPECS[19].verifier, STAGES[19],
        source_authority_evidence_linkage_review_packet=authority_packet,
        human_approval_requirement_resolution_packet=requirement_packet,
        action_contract=action_contract,
        required_human_approval_linkage_review_packet=approval_packet,
        human_approval_linkage_review_recorded_at=at[19],
    )
    final_readiness_packet = build(
        STAGE_SPECS[20].builder, STAGE_SPECS[20].verifier, STAGES[20],
        source_human_approval_linkage_review_packet=satisfaction_packet,
        final_bind_authorization_readiness_review_decision=(
            _native_final_readiness_decision(at[20], native)
        ),
        final_bind_authorization_readiness_recorded_at=at[20],
    )
    gate_packet = build(
        STAGE_SPECS[21].builder, STAGE_SPECS[21].verifier, STAGES[21],
        source_final_bind_authorization_readiness_packet=final_readiness_packet,
        bind_authorization_gate_review_decision=_native_gate_decision(
            at[21], native
        ),
        bind_authorization_gate_review_recorded_at=at[21],
    )
    requirement = packet_dict(requirement_packet)
    metadata = {
        "required_human_approval": requirement["required_human_approval"],
        "requirement_state": requirement["requirement_state"],
        "human_approval_linkage_invoked": approval_packet is not None,
        "requirement_satisfaction_state": packet_dict(satisfaction_packet)[
            "requirement_satisfaction_state"
        ],
    }
    return packet_dict(gate_packet), verified_names, metadata

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
    packet, verified, approval_meta = execute_native_chain(
        handoff, context, fixture, functions
    )
    gate_state = packet["gate_review_state"]
    if gate_state not in (BIND_PASS, BIND_FAIL):
        raise BenchmarkError(f"unexpected native gate_review_state: {gate_state}")
    outcome = gate_state
    row.update({
        "native_bind_gate_invoked": True,
        "native_bind_gate_outcome": outcome,
        "native_bind_gate_review_state": gate_state,
        "native_bind_gate_packet_id": packet[
            "live_adapter_dry_run_bind_authorization_gate_review_id"
        ],
        "native_bind_gate_packet_hash": packet[
            "live_adapter_dry_run_bind_authorization_gate_review_hash"
        ],
        "full_chain_bind_eligibility_outcome": outcome,
        "verified_native_stages": verified,
        "required_human_approval": approval_meta["required_human_approval"],
        "approval_requirement_state": approval_meta["requirement_state"],
        "human_approval_linkage_invoked": approval_meta[
            "human_approval_linkage_invoked"
        ],
        "approval_requirement_satisfaction_state": approval_meta[
            "requirement_satisfaction_state"
        ],
    })
    row["bind_eligibility_match"] = (
        row["full_chain_bind_eligibility_outcome"]
        == row["expected_bind_gate_outcome"]
    )
    return row


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    invoked = [r for r in rows if r["native_bind_gate_invoked"]]
    ready = [r for r in rows if r["handoff_status"] == "READY_FOR_GUARDED_PROMOTION"]
    compatible = list(ready)
    counts = Counter(r["native_bind_gate_outcome"] for r in invoked)
    approval_not_required = [
        r for r in ready if r.get("approval_requirement_state")
        == "NOT_REQUIRED_BY_ACTION_CONTRACT"
    ]
    approval_required = [
        r for r in ready if r.get("approval_requirement_state") == "REQUIRED"
    ]
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
        "approval_not_required_native_compatibility_block_count": 0,
        "approval_not_required_native_gate_invoked_count": sum(
            r["native_bind_gate_invoked"] for r in approval_not_required
        ),
        "approval_required_native_gate_invoked_count": sum(
            r["native_bind_gate_invoked"] for r in approval_required
        ),
        "approval_not_required_native_gate_case_ids": [
            r["case_id"] for r in approval_not_required
            if r["native_bind_gate_invoked"]
        ],
        "approval_required_native_gate_case_ids": [
            r["case_id"] for r in approval_required
            if r["native_bind_gate_invoked"]
        ],
        "mismatch_case_ids": [r["case_id"] for r in rows
                              if not r["bind_eligibility_match"]],
        "approval_not_required_compatibility_case_ids": [],
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
        "# Native VERITAS Bind Benchmark v0.3\n\n"
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
    result.add_argument("--bind-profile", type=Path, default=root / "fixtures/Bind_Profile_v0.3.json")
    result.add_argument("--output-dir", type=Path, default=root / "results/native-v0.3")
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
