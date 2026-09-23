#!/usr/bin/env python3
"""RCC/REVAS × VERITAS paired-clean synthetic engineering testbed runner v1.2.

v1.2 preserves the historical v1.0.1 adverse result and the v1.1 synthetic
testbed result. It adds the pinned VERITAS Action Class Contract-bound Human
Approval requirement-satisfaction path so approval-not-required cases can be
evaluated without fabricating Human Approval evidence.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

import paired_clean_metrics_v1 as metrics
import run_joint_benchmark as handoff_runner
import run_joint_benchmark_v0_2 as bind_runner

RUNNER_VERSION = "paired-clean-v1.2.0"
REMEDIATION_ACK_CONFIRMATION = "COUNTERPARTY_TESTBED_DIRECTION_RECORDED_FOR_PAIRED_CLEAN_V1_2"
CONTRACT_SHA256 = "532958fc9371fb34e550fb2a108868c64e87a980833dd46e8a92c7a133d9ae1f"
DATASET_SHA256 = "1e6ea7f9366876b4cbf041cc0841ab72bd58d6f561ff78553deb6645e5bf2a88"
RCC_COMMIT = "805cd5ff17e431cf50a3dafa7f78a60a704613b9"
RCC_ARCHIVE_SHA256 = "4c736357ab93a8f4b5027b94c20340b973c760de1a0027df30bb53d3d10f47d8"
VERITAS_COMMIT = "b39961b003179aea70e320a57cb000f56a81951e"
DIVERGENCES = ("GOV-H06", "GOV-H07", "GOV-D08")
CASE_COUNT = 36
EFFECTS = {
    "credential_material_handoff": False,
    "transport_invoked": False,
    "network_dispatch": False,
    "external_effect": False,
    "bind_authorization_created": False,
    "execution_authority_created": False,
}


class RunnerError(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def sha_json(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def sha_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_bytes(b"".join(canonical(row) + b"\n" for row in rows))


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def require_pin(repo: Path, expected: str, name: str) -> None:
    if git(repo, "rev-parse", "HEAD") != expected:
        raise RunnerError(f"{name} commit mismatch")
    if git(repo, "status", "--porcelain"):
        raise RunnerError(f"{name} checkout dirty")


def contract(root: Path) -> dict[str, Any]:
    path = root / "contracts/PAIRED_CLEAN_EVALUATION_CONTRACT_v1.0.json"
    if sha_file(path) != CONTRACT_SHA256:
        raise RunnerError("contract SHA-256 mismatch")
    c = read_json(path)
    checks = [
        (c["dataset"]["sha256"] == DATASET_SHA256, "dataset pin"),
        (c["dataset"]["case_count"] == CASE_COUNT, "case count"),
        (tuple(c["dataset"]["known_preserved_semantic_divergences"]) == DIVERGENCES, "divergences"),
        (c["baseline"]["publication_commit"] == RCC_COMMIT, "RCC pin"),
        (c["baseline"]["source_archive_sha256"] == RCC_ARCHIVE_SHA256, "RCC archive"),
        (c["treatment"]["commit"] == VERITAS_COMMIT, "VERITAS pin"),
        (c["pairing"]["same_case_required"] is True, "same case"),
        (c["pairing"]["same_pre_state_required"] is True, "same pre-state"),
        (c["pairing"]["same_rcc_revas_candidate_handoff_required"] is True, "same candidate"),
        (c["pairing"]["selective_reruns_permitted"] is False, "no rerun"),
        (c["pairing"]["failed_case_denominator_removal_permitted"] is False, "denominator"),
        (c["treatment"]["external_dispatch_permitted"] is False, "dispatch"),
        (c["treatment"]["credential_material_handoff_permitted"] is False, "credentials"),
        (c["treatment"]["network_effect_permitted"] is False, "network effect"),
    ]
    for ok, label in checks:
        if not ok:
            raise RunnerError(f"frozen contract invariant mismatch: {label}")
    return c


def dataset(root: Path) -> dict[str, Any]:
    path = root / "fixtures/Governance_labelled_Evaluation_Set_v0.1.1.json"
    if sha_file(path) != DATASET_SHA256:
        raise RunnerError("dataset SHA-256 mismatch")
    data = read_json(path)
    cases = data.get("cases")
    if not isinstance(cases, list) or len(cases) != CASE_COUNT:
        raise RunnerError("dataset denominator mismatch")
    if len({c["case_id"] for c in cases}) != CASE_COUNT:
        raise RunnerError("duplicate case_id")
    return data


def treatment_case(source_case: dict[str, Any]) -> dict[str, Any]:
    """Return the exact non-label case surface allowed into treatment helpers."""
    clean = {k: copy.deepcopy(v) for k, v in source_case.items() if k != "ground_truth"}
    if "ground_truth" in clean:
        raise RunnerError("ground_truth leaked into treatment case")
    return clean


def verify_inputs(root: Path, upstream: Path, veritas: Path) -> dict[str, Any]:
    contract(root)
    dataset(root)
    require_pin(upstream, RCC_COMMIT, "RCC/REVAS")
    require_pin(veritas, VERITAS_COMMIT, "VERITAS")
    archive = upstream / "rcc-revas-eval/v0.1.0/source/rcc-revas-eval-v0.1.0-source.tar.gz"
    if sha_file(archive) != RCC_ARCHIVE_SHA256:
        raise RunnerError("RCC archive SHA-256 mismatch")
    profile = read_json(root / "fixtures/Bind_Profile_v0.2.json")
    if profile["endpoint"]["routable"] is not False:
        raise RunnerError("bind profile routable")
    if profile["credential_reference"]["secret_present"] is not False:
        raise RunnerError("credential material present")
    if any(profile["effects"].values()):
        raise RunnerError("bind profile effect flag true")
    _, funcs = bind_runner.load_native(veritas)
    for spec in bind_runner.STAGE_SPECS:
        if not callable(funcs.get(spec.builder)) or not callable(funcs.get(spec.verifier)):
            raise RunnerError(f"native stage unavailable: {spec.module}")
    return {
        "runner_version": RUNNER_VERSION,
        "contract_sha256": CONTRACT_SHA256,
        "dataset_sha256": DATASET_SHA256,
        "case_count": CASE_COUNT,
        "rcc_publication_commit": RCC_COMMIT,
        "rcc_archive_sha256": RCC_ARCHIVE_SHA256,
        "veritas_commit": VERITAS_COMMIT,
        "contract_bytes_unchanged": True,
        "native_stage_import_compatibility": "PASS",
        "remediation_version": "v1.2",
        "remediation_scope": [
            "runtime_request_lineage_rebinding",
            "approval_candidate_reference_rebinding",
            "contract_bound_human_approval_requirement_satisfaction",
            "approval_not_required_zero_reference_path",
        ],
        "counterparty_direction_recorded": True,
        "evaluation_role": "SYNTHETIC_ENGINEERING_TESTBED",
        "independent_external_validation": False,
        "counterparty_ack_required_before_scored_execution": True,
        "synthetic_testbed_execution_performed": False,
        "scored_execution_performed": False,
        "effect_flags": EFFECTS,
    }


def upstream_runtime(upstream: Path) -> Path:
    path = upstream / "rcc-revas-eval/v0.1.0/runtime"
    if not path.is_dir():
        raise RunnerError("RCC runtime missing")
    if str(path.resolve()) not in sys.path:
        sys.path.insert(0, str(path.resolve()))
    return path


def run_rcc(root: Path, upstream: Path, out: Path) -> tuple[Path, Path]:
    runtime = upstream_runtime(upstream)
    from rcc_revas_eval.bundle import create_run
    from rcc_revas_eval.partner_review import register_partner

    reg = out / "rcc-registration"
    run = out / "rcc-run"
    source = root / "fixtures/Governance_labelled_Evaluation_Set_v0.1.1.json"
    manifest = runtime / "evaluation_manifest.json"
    registration = register_partner(manifest, source, reg)
    if registration["case_count"] != CASE_COUNT:
        raise RunnerError("registration denominator changed")
    summary = create_run(
        manifest,
        reg / "runtime_inputs.jsonl",
        run,
        plan_path=reg / "preregistration.json",
    )
    if summary["enrolled"] != CASE_COUNT or summary["errors"] != 0:
        raise RunnerError("RCC execution incomplete")
    return reg, run


def index_rcc(reg: Path, run: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    results = {r["decision"]["case_id"]: r for r in read_jsonl(run / "rcc_results.jsonl")}
    handoffs = {r["rcc_revas"]["audit"]["case_id"]: r for r in read_jsonl(run / "handoff_results.jsonl")}
    source = {r["case_id"]: r["source_case_id"] for r in read_jsonl(reg / "scoring_labels.jsonl")}
    if set(results) != set(source) or not set(handoffs).issubset(results):
        raise RunnerError("RCC case accounting mismatch")
    return results, handoffs, source


def candidate_state(
    result: dict[str, Any], handoff: dict[str, Any] | None
) -> tuple[dict[str, Any] | None, dict[str, Any], str]:
    from rcc_revas_eval.integrity import digest

    d = result["decision"]
    state = d["evaluation_pre_state"]
    state_hash = d["evaluation_pre_state_hash"]
    if digest(state, "rcc-evaluation-pre-state-v1") != state_hash:
        raise RunnerError("RCC pre-state hash mismatch")
    candidate = d["adoption"]["selected_candidate"]
    if candidate is not None and handoff is None:
        raise RunnerError("released candidate missing RCC handoff")
    return candidate, state, state_hash


def candidate_matches_case(candidate: dict[str, Any], case: dict[str, Any]) -> bool:
    action = case["input"]["action_context"]
    typed = candidate.get("typed_action") or {}
    fields = (
        "actor_identity",
        "action_class",
        "canonical_action",
        "target_system",
        "target_resource",
        "requested_scope",
    )
    if {k: typed.get(k) for k in fields} != {k: action.get(k) for k in fields}:
        return False
    return candidate.get("binding", {}).get("object_id") == action.get("subject")


@contextmanager
def block_network() -> Iterator[None]:
    old_connect = socket.socket.connect
    old_connect_ex = socket.socket.connect_ex

    def blocked(*args: Any, **kwargs: Any) -> Any:
        raise RunnerError("network dispatch prohibited during treatment")

    socket.socket.connect = blocked  # type: ignore[assignment]
    socket.socket.connect_ex = blocked  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.socket.connect = old_connect  # type: ignore[assignment]
        socket.socket.connect_ex = old_connect_ex  # type: ignore[assignment]


def post_decide(veritas: Path, payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if str(veritas.resolve()) not in sys.path:
        sys.path.insert(0, str(veritas.resolve()))
    os.environ["VERITAS_API_KEY"] = "paired-clean-inprocess-only"
    from fastapi.testclient import TestClient
    from veritas_os.api.schemas import DecideRequest
    from veritas_os.api.server import app
    from veritas_os.governance.canonical_decision_artifact import verify_canonical_decision_artifact

    parsed = DecideRequest.model_validate(payload).model_dump(mode="json")
    before = payload["context"]["rcc_revas"]
    after = parsed["context"]["rcc_revas"]
    if canonical(before["candidate"]) != canonical(after["candidate"]):
        raise RunnerError("candidate changed at POST boundary")
    if canonical(before["evaluation_pre_state"]) != canonical(after["evaluation_pre_state"]):
        raise RunnerError("pre-state changed at POST boundary")

    started = time.perf_counter_ns()
    with block_network(), TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(
            "/v1/decide",
            headers={"X-API-Key": os.environ["VERITAS_API_KEY"]},
            json=payload,
        )
    elapsed = time.perf_counter_ns() - started
    if response.status_code != 200:
        raise RunnerError(f"POST /v1/decide failed: HTTP {response.status_code}")
    body = response.json()
    v = verify_canonical_decision_artifact(body.get("canonical_decision_artifact"))
    if not v.is_valid:
        raise RunnerError(f"Canonical Decision Artifact invalid: {v.reason_codes}")
    return body, {
        "request_sha256": sha_json(payload),
        "parsed_request_sha256": sha_json(parsed),
        "candidate_sha256": sha_json(after["candidate"]),
        "pre_state_sha256": sha_json(after["evaluation_pre_state"]),
        "response_sha256": sha_json(body),
        "canonical_decision_id": body["canonical_decision_artifact"]["decision_id"],
        "canonical_decision_hash": body["canonical_decision_artifact"]["decision_hash"],
        "elapsed_ns": elapsed,
        "socket_connect_count": 0,
        **EFFECTS,
    }


def require_response_candidate(
    response: dict[str, Any], candidate: dict[str, Any], proof: dict[str, Any]
) -> None:
    chosen = response.get("chosen")
    expected_id = "rcc-candidate:" + proof["candidate_semantic_hash"]
    if not isinstance(chosen, dict) or chosen.get("id") != expected_id:
        raise RunnerError("VERITAS did not retain exact RCC candidate id")
    try:
        observed = json.loads(chosen["description"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise RunnerError("VERITAS chosen candidate missing exact JSON") from exc
    if canonical(observed) != canonical(candidate):
        raise RunnerError("VERITAS chosen candidate changed")


def rebind_runtime_handoff_identity(
    handoff: dict[str, Any],
    response: dict[str, Any],
    rcc_candidate: dict[str, Any],
) -> None:
    """Atomically rebind template identities to the real runtime/CDA identity.

    This is the narrow v1.1 remediation for the defect preserved by scored Run
    35813291352. It does not weaken CanonicalDecisionHandoff validation.
    """
    artifact = response["canonical_decision_artifact"]
    runtime_request_id = response["request_id"]
    canonical_decision_hash = "sha256:" + artifact["decision_hash"]

    handoff["source_decision"].update(
        request_id=runtime_request_id,
        canonical_decision_id=artifact["decision_id"],
        canonical_decision_hash=canonical_decision_hash,
        canonical_decision_ts=artifact["decision_ts"],
    )
    handoff["decision_lineage"]["decision_id"] = artifact["decision_id"]

    for lineage_name in ("trustlog_lineage", "replay_lineage"):
        lineage = handoff.get(lineage_name)
        if not isinstance(lineage, dict):
            raise RunnerError(f"{lineage_name} missing during runtime identity rebinding")
        lineage["request_id"] = runtime_request_id

    replay = handoff["replay_lineage"]
    if replay.get("format_version") == "canonical-replay-handoff-lineage/v1":
        replay["original_decision_id"] = artifact["decision_id"]
        replay["original_decision_hash"] = canonical_decision_hash
        replay["original_decision_ts"] = artifact["decision_ts"]

    approval = handoff.get("human_approval_evidence")
    if isinstance(approval, dict):
        approval["candidate_ref"] = rcc_candidate["candidate_id"]


def require_remediation_ack(value: str | None) -> None:
    if value != REMEDIATION_ACK_CONFIRMATION:
        raise RunnerError("explicit counterparty synthetic-testbed direction confirmation required")


def bind_handoff(
    case: dict[str, Any],
    veritas: Path,
    response: dict[str, Any],
    rcc_candidate: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, bool]]:
    if not candidate_matches_case(rcc_candidate, case):
        raise RunnerError("RCC candidate/source semantics mismatch")
    handoff, flags = handoff_runner.build_handoff(case, veritas)
    rebind_runtime_handoff_identity(handoff, response, rcc_candidate)
    typed = rcc_candidate["typed_action"]
    binding = rcc_candidate["binding"]
    handoff["candidate"].update(
        candidate_id=rcc_candidate["candidate_id"],
        actor_identity=typed.get("actor_identity"),
        target_system=typed.get("target_system"),
        target_resource=typed.get("target_resource"),
        canonical_action={
            "contract_id": f"benchmark.{typed.get('action_class') or 'unknown'}",
            "version": "1",
            "parameters": {
                "operation": typed.get("canonical_action"),
                "requested_scope": copy.deepcopy(typed.get("requested_scope") or []),
                "subject": binding.get("object_id"),
            },
        },
    )
    handoff["candidate_hash"] = "sha256:" + handoff_runner.sha256_json(handoff["candidate"])
    if not flags.get("target_context_mismatch"):
        handoff["target_context"] = {
            "target_system": typed.get("target_system"),
            "target_resource": typed.get("target_resource"),
            "canonicalized": True,
        }
    handoff_runner.sync_provenance(handoff)
    return handoff, flags


def load_requirement_satisfaction_support(veritas: Path) -> dict[str, Any]:
    """Load only pinned VERITAS requirement-resolution / satisfaction symbols."""
    resolved = str(veritas.resolve())
    if resolved not in sys.path:
        sys.path.insert(0, resolved)
    from veritas_os.governance.action_contracts import ActionClassContract
    from veritas_os.policy.human_approval_requirement_resolution import (
        build_human_approval_requirement_resolution_packet,
        verify_human_approval_requirement_resolution_packet,
    )
    from veritas_os.policy.live_adapter_dry_run_human_approval_requirement_satisfaction import (
        build_live_adapter_dry_run_human_approval_requirement_satisfaction_packet,
        verify_live_adapter_dry_run_human_approval_requirement_satisfaction_packet,
    )
    return {
        "ActionClassContract": ActionClassContract,
        "build_resolution": build_human_approval_requirement_resolution_packet,
        "verify_resolution": verify_human_approval_requirement_resolution_packet,
        "build_satisfaction": (
            build_live_adapter_dry_run_human_approval_requirement_satisfaction_packet
        ),
        "verify_satisfaction": (
            verify_live_adapter_dry_run_human_approval_requirement_satisfaction_packet
        ),
    }


def build_testbed_action_contract(
    authority_packet: Any,
    case: dict[str, Any],
    approval_required: bool,
    support: dict[str, Any],
) -> Any:
    """Build deterministic synthetic policy from non-label case inputs."""
    source = bind_runner.packet_dict(authority_packet)
    scope = list(source["authority_evidence_reference_bundle"]["bundle_scope"])
    if not scope:
        raise RunnerError("authority bundle scope missing for action contract")
    action = case["input"]["action_context"]
    intended_action = source["execution_intent"]["intended_action"]
    expected_id = f"benchmark.{action.get('action_class') or 'unknown'}"
    if intended_action != expected_id:
        raise RunnerError("execution intent/action-contract identity mismatch")
    return support["ActionClassContract"](
        id=intended_action,
        version="1",
        domain="synthetic-testbed",
        action_class=action.get("action_class") or "unknown",
        description="RCC/REVAS × VERITAS v1.2 synthetic testbed action contract",
        declared_intent="exercise no-effect native Bind governance compatibility",
        allowed_scope=scope,
        prohibited_scope=["synthetic-testbed:out-of-scope"],
        authority_sources=["synthetic-benchmark-authority"],
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
            "regulated": False,
            "synthetic_engineering_testbed": True,
            "source_case_id": case["case_id"],
        },
    )


def execute_native_chain_v1_2(
    handoff_packet: dict[str, Any],
    validation_context: Any,
    case: dict[str, Any],
    fixture: dict[str, Any],
    native: dict[str, Any],
    funcs: dict[str, Any],
    veritas: Path,
) -> tuple[dict[str, Any], list[str]]:
    """Run the pinned no-effect chain with contract-bound approval semantics."""
    at = [
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        for value in fixture["timestamps"]
    ]
    verified_names: list[str] = []

    def build(builder: str, verifier: str, stage: str, **kwargs: Any) -> Any:
        packet = funcs[builder](**kwargs)
        packet = bind_runner._verified(packet, funcs[verifier], stage)
        verified_names.append(stage)
        return packet

    eligibility_packet = build(
        bind_runner.STAGE_SPECS[0].builder, bind_runner.STAGE_SPECS[0].verifier,
        bind_runner.STAGES[0], handoff=handoff_packet,
        trusted_context=validation_context, evaluated_at=at[0], issued_at=at[0],
    )
    formation_readiness_packet = build(
        bind_runner.STAGE_SPECS[1].builder, bind_runner.STAGE_SPECS[1].verifier,
        bind_runner.STAGES[1], eligibility_packet=eligibility_packet, checked_at=at[1],
    )
    formation_packet = build(
        bind_runner.STAGE_SPECS[2].builder, bind_runner.STAGE_SPECS[2].verifier,
        bind_runner.STAGES[2], readiness_packet=formation_readiness_packet,
        formed_at=at[2],
    )
    pre_bind_validation_packet = build(
        bind_runner.STAGE_SPECS[3].builder, bind_runner.STAGE_SPECS[3].verifier,
        bind_runner.STAGES[3], formation_packet=formation_packet, checked_at=at[3],
    )
    preflight_packet = build(
        bind_runner.STAGE_SPECS[4].builder, bind_runner.STAGE_SPECS[4].verifier,
        bind_runner.STAGES[4], pre_bind_validation_packet=pre_bind_validation_packet,
        adjudicated_at=at[4],
    )
    descriptor = bind_runner._native_adapter_descriptor(preflight_packet, at[5], funcs)
    selection_packet = build(
        bind_runner.STAGE_SPECS[5].builder, bind_runner.STAGE_SPECS[5].verifier,
        bind_runner.STAGES[5], bind_preflight_adjudication_packet=preflight_packet,
        adapter_contract_descriptor=descriptor, selected_at=at[5],
    )
    plan_packet = build(
        bind_runner.STAGE_SPECS[6].builder, bind_runner.STAGE_SPECS[6].verifier,
        bind_runner.STAGES[6], adapter_contract_selection_packet=selection_packet,
        planned_at=at[6],
    )
    fixture_step_results = bind_runner._native_fixture_step_results(plan_packet, funcs)
    fixture_result_packet = build(
        bind_runner.STAGE_SPECS[7].builder, bind_runner.STAGE_SPECS[7].verifier,
        bind_runner.STAGES[7], adapter_dry_run_plan_packet=plan_packet,
        fixture_step_results=fixture_step_results, resulted_at=at[7],
    )
    rehearsal_packet = build(
        bind_runner.STAGE_SPECS[8].builder, bind_runner.STAGE_SPECS[8].verifier,
        bind_runner.STAGES[8], adapter_dry_run_fixture_result_packet=fixture_result_packet,
        reference_rehearsal_fixture={"scenario": "deterministic-reference-v0.2"},
        rehearsed_at=at[8],
    )
    request_readiness_packet = build(
        bind_runner.STAGE_SPECS[9].builder, bind_runner.STAGE_SPECS[9].verifier,
        bind_runner.STAGES[9], reference_rehearsal_packet=rehearsal_packet,
        readiness_evaluated_at=at[9],
    )
    request_packet = build(
        bind_runner.STAGE_SPECS[10].builder, bind_runner.STAGE_SPECS[10].verifier,
        bind_runner.STAGES[10],
        live_adapter_dry_run_readiness_packet=request_readiness_packet,
        requested_at=at[10],
    )
    dispatch_readiness_packet = build(
        bind_runner.STAGE_SPECS[11].builder, bind_runner.STAGE_SPECS[11].verifier,
        bind_runner.STAGES[11],
        source_live_adapter_dry_run_request_packet=request_packet,
        dispatch_readiness_evaluated_at=at[11],
    )
    endpoint_candidate, allowlist_snapshot = bind_runner._native_endpoint_inputs(
        dispatch_readiness_packet, fixture["profile"], at[12], funcs
    )
    allowlist_packet = build(
        bind_runner.STAGE_SPECS[12].builder, bind_runner.STAGE_SPECS[12].verifier,
        bind_runner.STAGES[12],
        source_dispatch_readiness_packet=dispatch_readiness_packet,
        endpoint_candidate=endpoint_candidate, allowlist_snapshot=allowlist_snapshot,
        endpoint_allowlist_evaluated_at=at[12],
    )
    credential_reference, credential_policy_snapshot = bind_runner._native_credential_inputs(
        allowlist_packet, at[13], funcs
    )
    credential_packet = build(
        bind_runner.STAGE_SPECS[13].builder, bind_runner.STAGE_SPECS[13].verifier,
        bind_runner.STAGES[13],
        source_endpoint_allowlist_evaluation_packet=allowlist_packet,
        credential_reference=credential_reference,
        credential_policy_snapshot=credential_policy_snapshot,
        credential_authorization_evaluated_at=at[13],
    )
    operator_packet = build(
        bind_runner.STAGE_SPECS[14].builder, bind_runner.STAGE_SPECS[14].verifier,
        bind_runner.STAGES[14],
        source_credential_authorization_evaluation_packet=credential_packet,
        operator_review_decision=bind_runner._native_operator_decision(
            credential_packet, at[14]
        ),
        operator_dispatch_review_recorded_at=at[14],
    )
    pre_dispatch_packet = build(
        bind_runner.STAGE_SPECS[15].builder, bind_runner.STAGE_SPECS[15].verifier,
        bind_runner.STAGES[15], source_operator_dispatch_review_packet=operator_packet,
        bind_pre_dispatch_review_decision=bind_runner._native_bind_pre_dispatch_decision(
            at[15]
        ),
        bind_pre_dispatch_review_recorded_at=at[15],
    )
    authority_packet = build(
        bind_runner.STAGE_SPECS[16].builder, bind_runner.STAGE_SPECS[16].verifier,
        bind_runner.STAGES[16], source_bind_pre_dispatch_review_packet=pre_dispatch_packet,
        authority_evidence_reference_bundle=bind_runner._native_authority_bundle(
            pre_dispatch_packet, at[16]
        ),
        authority_evidence_linkage_review_recorded_at=at[16],
    )

    support = load_requirement_satisfaction_support(veritas)
    contract = build_testbed_action_contract(
        authority_packet, case, fixture["approval_required"], support
    )
    resolution = support["build_resolution"](authority_packet, contract, at[17])
    resolution = support["verify_resolution"](resolution, authority_packet, contract)
    verified_names.append("human_approval_requirement_resolution")

    required_linkage = None
    if fixture["approval_required"]:
        required_linkage = build(
            bind_runner.STAGE_SPECS[17].builder, bind_runner.STAGE_SPECS[17].verifier,
            bind_runner.STAGES[17],
            source_authority_evidence_linkage_review_packet=authority_packet,
            human_approval_reference_bundle=bind_runner._native_human_approval_bundle(
                authority_packet, at[17]
            ),
            human_approval_linkage_review_recorded_at=at[17],
        )

    satisfaction = support["build_satisfaction"](
        authority_packet, resolution, contract, required_linkage, at[17]
    )
    satisfaction = support["verify_satisfaction"](
        satisfaction, expected_source=authority_packet, expected_contract=contract
    )
    verified_names.append("human_approval_requirement_satisfaction")

    final_builder = funcs[bind_runner.STAGE_SPECS[18].builder]
    final_verifier = funcs[bind_runner.STAGE_SPECS[18].verifier]
    final_readiness_packet = final_builder(
        satisfaction,
        bind_runner._native_final_readiness_decision(at[18], funcs),
        at[18],
        expected_source=authority_packet,
        expected_contract=contract,
    )
    final_readiness_packet = final_verifier(
        final_readiness_packet,
        expected_source=authority_packet,
        expected_contract=contract,
    )
    verified_names.append(bind_runner.STAGES[18])

    gate_builder = funcs[bind_runner.STAGE_SPECS[19].builder]
    gate_verifier = funcs[bind_runner.STAGE_SPECS[19].verifier]
    gate_packet = gate_builder(
        final_readiness_packet,
        bind_runner._native_gate_decision(at[19], funcs),
        at[19],
        expected_source=authority_packet,
        expected_contract=contract,
    )
    gate_packet = gate_verifier(
        gate_packet,
        expected_source=authority_packet,
        expected_contract=contract,
    )
    verified_names.append(bind_runner.STAGES[19])
    return bind_runner.packet_dict(gate_packet), verified_names


def native_gate(
    case: dict[str, Any],
    veritas: Path,
    response: dict[str, Any],
    candidate: dict[str, Any],
    profile: dict[str, Any],
    native: dict[str, Any],
    funcs: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    handoff, flags = bind_handoff(case, veritas, response, candidate)
    context = handoff_runner.build_context(handoff, native, flags)
    validated = native["validate"](handoff, context, handoff_runner.EVALUATED_AT).to_dict()
    if validated["status"] != "READY_FOR_GUARDED_PROMOTION":
        return {
            "native_handoff_status": validated["status"],
            "native_bind_gate_invoked": False,
            "native_bind_gate_outcome": None,
            "stop_reason": "HANDOFF_NOT_READY_FOR_GUARDED_PROMOTION",
            **EFFECTS,
        }, handoff

    fixture = bind_runner.treatment_fixture(case, profile)
    packet, verified = execute_native_chain_v1_2(
        handoff, context, case, fixture, native, funcs, veritas
    )
    state = packet["gate_review_state"]
    if state not in (bind_runner.BIND_PASS, bind_runner.BIND_FAIL):
        raise RunnerError(f"unexpected gate state: {state}")
    human_result = packet["human_approval_linkage_result"]
    human_bundle = packet["human_approval_reference_bundle"]
    return {
        "native_handoff_status": validated["status"],
        "native_bind_gate_invoked": True,
        "native_bind_gate_outcome": state,
        "native_bind_gate_packet_id": packet[
            "live_adapter_dry_run_bind_authorization_gate_review_id"
        ],
        "native_bind_gate_packet_hash": packet[
            "live_adapter_dry_run_bind_authorization_gate_review_hash"
        ],
        "native_human_approval_required": human_result["required_human_approval"],
        "native_human_approval_requirement_state": human_result["requirement_state"],
        "native_human_approval_satisfaction_state": human_result["satisfaction_state"],
        "native_human_approval_linkage_used": human_result["approval_linkage_used"],
        "native_human_approval_reference_count": len(
            human_bundle["human_approval_references"]
        ),
        "native_human_approval_created": packet["human_approval_created"],
        "verified_native_stages": verified,
        "stop_reason": "STOPPED_AT_BIND_AUTHORIZATION_GATE_REVIEW",
        **EFFECTS,
    }, handoff

def arm_a(result: dict[str, Any]) -> str:
    return {"ADOPT": "ALLOW", "HOLD": "HOLD", "REJECT": "DENY"}[
        result["decision"]["adoption"]["decision"]
    ]


def arm_b(gate: dict[str, Any], baseline: str) -> str | None:
    if gate["native_bind_gate_invoked"]:
        return "ALLOW" if gate["native_bind_gate_outcome"] == bind_runner.BIND_PASS else "DENY"
    return handoff_runner.aggregate_from_status(gate["native_handoff_status"])


def environment_manifest() -> dict[str, Any]:
    freeze = subprocess.run(
        [sys.executable, "-m", "pip", "freeze"], check=True, capture_output=True, text=True
    ).stdout.splitlines()
    return {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "uname_a": subprocess.run(
            ["uname", "-a"], check=True, capture_output=True, text=True
        ).stdout.strip(),
        "pip_freeze": freeze,
        "runner_image_os": os.environ.get("ImageOS"),
        "runner_image_version": os.environ.get("ImageVersion"),
    }


def require_scored_environment(c: dict[str, Any]) -> None:
    if platform.python_version() != c["runtime_environment"]["python"]:
        raise RunnerError("wrong Python version")
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise RunnerError("scored run requires frozen GitHub-hosted runner class")
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RunnerError("wrong scored runner platform")


def run_testbed(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(__file__).resolve().parent
    head = git(root, "rev-parse", "HEAD")
    if args.runner_commit != head:
        raise RunnerError("runner commit pin mismatch")
    if args.acknowledged_contract_sha256 != CONTRACT_SHA256:
        raise RunnerError("exact acknowledged contract hash required")
    require_remediation_ack(args.remediation_ack_confirmation)
    if args.output_dir.exists():
        raise RunnerError("output directory already exists")
    args.output_dir.mkdir(parents=True)
    started = time.perf_counter_ns()
    cpu_started = time.process_time_ns()

    integrity = verify_inputs(root, args.upstream_repo, args.veritas_repo)
    c = contract(root)
    require_scored_environment(c)
    data = dataset(root)
    source_cases = {row["case_id"]: row for row in data["cases"]}
    treatment_cases = {cid: treatment_case(row) for cid, row in source_cases.items()}
    reg, rcc_run = run_rcc(root, args.upstream_repo, args.output_dir)
    results, handoffs, source_ids = index_rcc(reg, rcc_run)
    profile = read_json(root / "fixtures/Bind_Profile_v0.2.json")
    native, funcs = bind_runner.load_native(args.veritas_repo)

    upstream_runtime(args.upstream_repo)
    from rcc_revas_eval.native_veritas import build_decide_request

    rows: list[dict[str, Any]] = []
    for runtime_id in sorted(results):
        result = results[runtime_id]
        case_id = source_ids[runtime_id]
        case = treatment_cases[case_id]
        handoff = handoffs.get(runtime_id)
        candidate, state, state_hash = candidate_state(result, handoff)
        baseline = arm_a(result)
        candidate_handoff_sha = sha_json(handoff) if handoff else None
        common = {
            "case_id": case_id,
            "runtime_case_id": runtime_id,
            "input_sha256": sha_json(case["input"]),
            "rcc_result_sha256": sha_json(result),
            "candidate_handoff_sha256": candidate_handoff_sha,
            "candidate_present": candidate is not None,
            "same_candidate_handoff": handoff is not None,
            "arm_a_pre_state_sha256": state_hash,
            "arm_a": baseline,
            "arm_a_result_sha256": sha_json(result),
            "label_attached_after_treatment": False,
            **EFFECTS,
        }
        if candidate is None:
            rows.append(
                {
                    **common,
                    "arm_b": baseline,
                    "arm_b_status": "UPSTREAM_RCC_WITHHELD_BEFORE_VERITAS",
                    "arm_b_pre_state_sha256": state_hash,
                    "same_pre_state": True,
                    "same_candidate": None,
                    "http_boundary": None,
                    "native_gate": None,
                    "pair_binding_sha256": None,
                    "infrastructure_error": None,
                    "arm_b_result_sha256": sha_json(
                        {
                            "status": "UPSTREAM_RCC_WITHHELD_BEFORE_VERITAS",
                            "result": sha_json(result),
                            "candidate_handoff_sha256": candidate_handoff_sha,
                            "pre_state_sha256": state_hash,
                        }
                    ),
                }
            )
            continue

        if handoff is None:
            raise RunnerError(f"{case_id}: released candidate missing RCC handoff")
        request, proof = build_decide_request(handoff, rcc_run)
        exact = request["context"]["rcc_revas"]
        if canonical(exact["candidate"]) != canonical(candidate):
            raise RunnerError(f"{case_id}: candidate drift before treatment")
        if canonical(exact["evaluation_pre_state"]) != canonical(state):
            raise RunnerError(f"{case_id}: pre-state drift before treatment")
        if proof["evaluation_pre_state_hash"] != state_hash:
            raise RunnerError(f"{case_id}: pre-state hash drift")

        same_pre_state = proof["evaluation_pre_state_hash"] == state_hash
        try:
            response, boundary = post_decide(args.veritas_repo, request)
        except Exception as exc:
            error = {
                "status": "INFRASTRUCTURE_ERROR",
                "stage": "POST_V1_DECIDE",
                "error_type": type(exc).__name__,
                "detail": str(exc)[:500],
                "governance_outcome": None,
                "automatic_retry_performed": False,
            }
            rows.append(
                {
                    **common,
                    "candidate_sha256": sha_json(candidate),
                    "arm_b": None,
                    "arm_b_status": "INFRASTRUCTURE_ERROR_POST_V1_DECIDE",
                    "arm_b_pre_state_sha256": proof["evaluation_pre_state_hash"],
                    "same_pre_state": same_pre_state,
                    "same_candidate": None,
                    "http_boundary": None,
                    "native_gate": None,
                    "pair_binding_sha256": None,
                    "infrastructure_error": error,
                    "arm_b_result_sha256": sha_json(error),
                }
            )
            continue

        try:
            require_response_candidate(response, candidate, proof)
        except RunnerError as exc:
            violation = {
                "status": "PAIRING_VIOLATION",
                "stage": "POST_V1_DECIDE_RESPONSE",
                "detail": str(exc)[:500],
                "governance_outcome": None,
                "automatic_retry_performed": False,
            }
            rows.append(
                {
                    **common,
                    "candidate_sha256": sha_json(candidate),
                    "arm_b": None,
                    "arm_b_status": "PAIRING_VIOLATION_CANDIDATE_CHANGED",
                    "arm_b_pre_state_sha256": proof["evaluation_pre_state_hash"],
                    "same_pre_state": same_pre_state,
                    "same_candidate": False,
                    "http_boundary": boundary,
                    "native_gate": None,
                    "pair_binding_sha256": None,
                    "infrastructure_error": None,
                    "pairing_violation": violation,
                    "arm_b_result_sha256": sha_json(
                        {"http_boundary": boundary, "pairing_violation": violation}
                    ),
                }
            )
            continue

        gate_started = time.perf_counter_ns()
        try:
            gate, native_handoff = native_gate(
                case, args.veritas_repo, response, candidate, profile, native, funcs
            )
        except Exception as exc:
            gate_elapsed = time.perf_counter_ns() - gate_started
            error = {
                "status": "INFRASTRUCTURE_ERROR",
                "stage": "NATIVE_BIND_GATE_REVIEW",
                "error_type": type(exc).__name__,
                "detail": str(exc)[:500],
                "governance_outcome": None,
                "automatic_retry_performed": False,
            }
            pair_binding = {
                "rcc_candidate_handoff_sha256": candidate_handoff_sha,
                "rcc_candidate_sha256": sha_json(candidate),
                "rcc_pre_state_sha256": state_hash,
                "veritas_request_sha256": boundary["request_sha256"],
                "veritas_canonical_decision_hash": boundary["canonical_decision_hash"],
            }
            rows.append(
                {
                    **common,
                    "candidate_sha256": sha_json(candidate),
                    "arm_b": None,
                    "arm_b_status": "INFRASTRUCTURE_ERROR_NATIVE_BIND_GATE",
                    "arm_b_pre_state_sha256": proof["evaluation_pre_state_hash"],
                    "same_pre_state": same_pre_state,
                    "same_candidate": True,
                    "http_boundary": boundary,
                    "native_gate_elapsed_ns": gate_elapsed,
                    "native_gate": None,
                    "pair_binding_sha256": sha_json(pair_binding),
                    "infrastructure_error": error,
                    "arm_b_result_sha256": sha_json(
                        {
                            "http_boundary": boundary,
                            "pair_binding": pair_binding,
                            "infrastructure_error": error,
                        }
                    ),
                }
            )
            continue

        gate_elapsed = time.perf_counter_ns() - gate_started
        treatment = arm_b(gate, baseline)
        pair_binding = {
            "rcc_candidate_handoff_sha256": candidate_handoff_sha,
            "rcc_candidate_sha256": sha_json(candidate),
            "rcc_pre_state_sha256": state_hash,
            "veritas_request_sha256": boundary["request_sha256"],
            "veritas_canonical_decision_hash": boundary["canonical_decision_hash"],
            "native_handoff_sha256": sha_json(native_handoff),
            "native_bind_gate_packet_hash": gate.get("native_bind_gate_packet_hash"),
        }
        row = {
            **common,
            "candidate_sha256": sha_json(candidate),
            "arm_b": treatment,
            "arm_b_status": gate["stop_reason"],
            "arm_b_pre_state_sha256": proof["evaluation_pre_state_hash"],
            "same_pre_state": same_pre_state,
            "same_candidate": True,
            "http_boundary": boundary,
            "native_handoff_sha256": sha_json(native_handoff),
            "native_gate_elapsed_ns": gate_elapsed,
            "native_gate": gate,
            "pair_binding_sha256": sha_json(pair_binding),
            "infrastructure_error": None,
        }
        row["arm_b_result_sha256"] = sha_json(
            {
                "http_boundary": boundary,
                "pair_binding": pair_binding,
                "native_gate": gate,
            }
        )
        if not row["same_pre_state"]:
            raise RunnerError(f"{case_id}: pre-state identity failed")
        if any(row[name] for name in EFFECTS):
            raise RunnerError(f"{case_id}: effect flag true")
        rows.append(row)

    if len(rows) != CASE_COUNT:
        raise RunnerError("paired denominator changed")

    # Labels enter only after every treatment attempt has already been recorded.
    for row in rows:
        label = source_cases[row["case_id"]]["ground_truth"]
        row["expected"] = label["expected_decision"]
        row["expected_bind_gate_outcome"] = label["expected_bind_gate_outcome"]
        row["conditions"] = {
            k: label.get(k)
            for k in ("authority_valid", "approval_valid", "scope_valid", "evidence_complete")
        }
        row["label_attached_after_treatment"] = True

    env = environment_manifest()
    write_json(args.output_dir / "environment_manifest.json", env)
    write_jsonl(args.output_dir / "paired_cases.jsonl", rows)
    gov = metrics.governance(rows)
    preservation = metrics.preservation(rows)
    infrastructure_errors = sum(
        str(r["arm_b_status"]).startswith("INFRASTRUCTURE_ERROR") for r in rows
    )
    pairing_violations = sum(
        str(r["arm_b_status"]).startswith("PAIRING_VIOLATION") for r in rows
    )
    unsupported = sum(r["arm_b_status"] == "UNSUPPORTED_APPROVAL_NOT_REQUIRED" for r in rows)
    operational = {
        "total_latency_ns": time.perf_counter_ns() - started,
        "veritas_added_latency_ns": sum(
            (r.get("http_boundary") or {}).get("elapsed_ns", 0)
            + int(r.get("native_gate_elapsed_ns") or 0)
            for r in rows
        ),
        "additional_model_calls": "UNKNOWN",
        "token_consumption": "UNKNOWN",
        "api_provider_calls": 0,
        "api_provider_calls_basis": "ALL_SOCKET_CONNECTS_BLOCKED_DURING_TREATMENT",
        "api_provider_cost": "NOT_APPLICABLE",
        "compute_time_or_overhead_ns": time.process_time_ns() - cpu_started,
        "retry_count": 0,
        "error_count": infrastructure_errors + pairing_violations,
        "infrastructure_error_count": infrastructure_errors,
        "pairing_violation_count": pairing_violations,
        "unsupported_count": unsupported,
        "cost_estimates_used": False,
    }
    write_json(args.output_dir / "governance_metrics.json", gov)
    write_json(args.output_dir / "preservation_metrics.json", preservation)
    write_json(args.output_dir / "operational_metrics.json", operational)

    candidate_present_count = sum(r["candidate_present"] for r in rows)
    same_candidate_when_present = sum(
        r["candidate_present"] and r.get("same_candidate") is True for r in rows
    )
    summary = {
        "schema_version": "veritas.rcc-revas.paired-clean-evaluation.v1.2",
        "runner_version": RUNNER_VERSION,
        "paired_runner_commit": head,
        "contract_sha256": CONTRACT_SHA256,
        "dataset_sha256": DATASET_SHA256,
        "rcc_publication_commit": RCC_COMMIT,
        "rcc_archive_sha256": RCC_ARCHIVE_SHA256,
        "veritas_commit": VERITAS_COMMIT,
        "enrolled": len(rows),
        "arm_a_observed": len(rows),
        "arm_b_observed": sum(r["arm_b"] is not None for r in rows),
        "candidate_present_count": candidate_present_count,
        "same_candidate_when_present_count": same_candidate_when_present,
        "same_candidate_handoff_count": sum(r["same_candidate_handoff"] for r in rows),
        "same_pre_state_count": sum(r["same_pre_state"] for r in rows),
        "infrastructure_error_count": infrastructure_errors,
        "pairing_violation_count": pairing_violations,
        "unsupported_count": unsupported,
        "selective_reruns": 0,
        "denominator_reduction": 0,
        "preserved_divergence_case_ids": list(DIVERGENCES),
        "ground_truth_passed_to_treatment_helpers": False,
        "labels_attached_after_treatment_attempts": True,
        "environment_manifest_sha256": sha_file(args.output_dir / "environment_manifest.json"),
        "paired_cases_sha256": sha_file(args.output_dir / "paired_cases.jsonl"),
        "governance_metrics_sha256": sha_file(args.output_dir / "governance_metrics.json"),
        "preservation_metrics_sha256": sha_file(args.output_dir / "preservation_metrics.json"),
        "operational_metrics_sha256": sha_file(args.output_dir / "operational_metrics.json"),
        "evaluation_role": "SYNTHETIC_ENGINEERING_TESTBED",
        "contract_claim_boundary_snapshot": c["claim_boundary"],
        "runtime_facts": {
            "synthetic_testbed_execution_performed": True,
            "paired_run_executed": True,
            "complete_denominator_observed": len(rows) == CASE_COUNT,
            "arm_b_observed_count": sum(r["arm_b"] is not None for r in rows),
            "unsupported_count": unsupported,
            "treatment_delta_measured": (
                infrastructure_errors == 0
                and pairing_violations == 0
                and unsupported == 0
            ),
            "independent_external_validation": False,
        },
        **EFFECTS,
    }
    write_json(args.output_dir / "summary.json", summary)
    manifest = {
        **integrity,
        **{k: summary[k] for k in (
            "paired_runner_commit",
            "contract_sha256",
            "dataset_sha256",
            "environment_manifest_sha256",
            "paired_cases_sha256",
            "governance_metrics_sha256",
            "preservation_metrics_sha256",
            "operational_metrics_sha256",
        )},
        "summary_sha256": sha_file(args.output_dir / "summary.json"),
        "rcc_run_bundle_seal_sha256": sha_file(rcc_run / "bundle_seal.json"),
        "registration_sha256": sha_file(reg / "registration.json"),
        "evaluation_role": "SYNTHETIC_ENGINEERING_TESTBED",
        "synthetic_testbed_execution_performed": True,
        "scored_execution_performed": False,
        "independent_external_validation": False,
        "runtime_facts": summary["runtime_facts"],
        "single_complete_run_required": True,
        "no_automatic_retry": True,
        "ground_truth_passed_to_treatment_helpers": False,
        **EFFECTS,
    }
    write_json(args.output_dir / "run_manifest.json", manifest)
    evidence_index = {
        "schema_version": "veritas.rcc-revas.paired-clean-evidence-index.v1.2",
        "algorithm": "sha256/raw-bytes",
        "run_manifest_sha256": sha_file(args.output_dir / "run_manifest.json"),
        "summary_sha256": sha_file(args.output_dir / "summary.json"),
        "environment_manifest_sha256": sha_file(args.output_dir / "environment_manifest.json"),
        "paired_cases_sha256": sha_file(args.output_dir / "paired_cases.jsonl"),
        "governance_metrics_sha256": sha_file(args.output_dir / "governance_metrics.json"),
        "preservation_metrics_sha256": sha_file(args.output_dir / "preservation_metrics.json"),
        "operational_metrics_sha256": sha_file(args.output_dir / "operational_metrics.json"),
        "rcc_run_bundle_seal_sha256": sha_file(rcc_run / "bundle_seal.json"),
        "registration_sha256": sha_file(reg / "registration.json"),
    }
    write_json(args.output_dir / "evidence_index.json", evidence_index)
    return {
        **summary,
        "run_manifest_sha256": evidence_index["run_manifest_sha256"],
        "evidence_index_sha256": sha_file(args.output_dir / "evidence_index.json"),
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    p.add_argument("--upstream-repo", type=Path, required=True)
    p.add_argument("--veritas-repo", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, default=Path("results/paired-clean-v1_2"))
    p.add_argument("--runner-commit")
    p.add_argument("--acknowledged-contract-sha256")
    p.add_argument("--remediation-ack-confirmation")
    p.add_argument("--preflight", action="store_true")
    p.add_argument("--testbed-run", action="store_true")
    p.add_argument("--scored-run", action="store_true", help=argparse.SUPPRESS)
    return p


def main() -> int:
    args = build_parser().parse_args()
    try:
        root = Path(__file__).resolve().parent
        if args.preflight:
            print(json.dumps(verify_inputs(root, args.upstream_repo, args.veritas_repo), indent=2))
            return 0
        if args.scored_run:
            raise RunnerError(
                "v1.1 is a synthetic engineering testbed; --scored-run is disabled"
            )
        if not args.testbed_run:
            raise RunnerError("refusing execution without --testbed-run after runner pin")
        print(json.dumps(run_testbed(args), indent=2))
        return 0
    except (RunnerError, OSError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
