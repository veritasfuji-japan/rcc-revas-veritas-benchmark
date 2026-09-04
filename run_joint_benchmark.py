#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import platform
import subprocess
import sys
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

RUNNER_VERSION = "0.1.0"
PINNED_VERITAS_COMMIT = "4a794e31b26c28e43eb1bb8e6a2474f511c5bd7c"
PINNED_DATASET_SHA256 = "1e6ea7f9366876b4cbf041cc0841ab72bd58d6f561ff78553deb6645e5bf2a88"
PINNED_CANONICAL_BENCHMARK_CONTRACT_SHA256 = "a1352dc3cea28da07ca4799e1587b45616376521021e88c724c753fb60738628"
PINNED_RUNTIME_MANIFEST_SHA256 = "edefe64da6ab0980ff94fdc62086933b4ce79860e352472f92873d6e0ac310d8"
PINNED_FIELD_CONTRACT_SHA256 = "47de8bc99999d7f2d7791f51f6afa046e50f56b5777123374e1d43c00a4496fa"
EVALUATED_AT = datetime(2030, 1, 1, 0, 0, 2, tzinfo=timezone.utc)
BIND_PASS = "PASSED_FOR_FUTURE_BIND_AUTHORIZATION_ARTIFACT"
BIND_FAIL = "FAILED_FOR_FUTURE_BIND_AUTHORIZATION_ARTIFACT"


class RunnerError(RuntimeError):
    pass


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_head(repo: Path) -> str | None:
    try:
        return subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
    except Exception:
        return None


def git_dirty(repo: Path) -> bool | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "status", "--porcelain"],
            check=True, capture_output=True, text=True,
        ).stdout
        return bool(out.strip())
    except Exception:
        return None


def load_dataset(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise RunnerError(f"dataset not found: {path}")
    actual = sha256_file(path)
    if actual != PINNED_DATASET_SHA256:
        raise RunnerError(
            f"dataset SHA-256 mismatch: expected={PINNED_DATASET_SHA256} actual={actual}"
        )
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("artifact_version") != "0.1.1":
        raise RunnerError("runner v0.1 requires Governance-labelled Evaluation Set v0.1.1")
    cases = data.get("cases")
    if not isinstance(cases, list) or len(cases) < 30:
        raise RunnerError("dataset must contain >=30 cases")
    if len({c.get("case_id") for c in cases}) != len(cases):
        raise RunnerError("duplicate case_id")
    for case in cases:
        gt = case.get("ground_truth", {})
        if gt.get("execution_authorized") is not False:
            raise RunnerError(f"{case.get('case_id')}: execution_authorized must be false")
        if gt.get("external_effect_must_occur") is not False:
            raise RunnerError(f"{case.get('case_id')}: external_effect_must_occur must be false")
    return data


def load_native_veritas(repo: Path) -> dict[str, Any]:
    if str(repo.resolve()) not in sys.path:
        sys.path.insert(0, str(repo.resolve()))
    try:
        from veritas_os.policy.canonical_decision_handoff import (
            AUTHORITY_SATISFIES_REQUIREMENT_CLAIM,
            HUMAN_APPROVAL_EXACT_OPERATION_CLAIM,
            AuthorityEvidenceRequirementBindingAssertion,
            CandidateHashBindingAssertion,
            CanonicalDecisionHandoffValidationContext,
            TrustedValueAssertion,
            canonical_handoff_assertion_value_digest,
            validate_canonical_decision_handoff,
        )
    except Exception as exc:
        raise RunnerError(
            "Could not import VERITAS native CanonicalDecisionHandoff validator. "
            "Install dependencies from the pinned repository first: python -m pip install ."
        ) from exc
    return {
        "AUTHORITY_CLAIM": AUTHORITY_SATISFIES_REQUIREMENT_CLAIM,
        "APPROVAL_CLAIM": HUMAN_APPROVAL_EXACT_OPERATION_CLAIM,
        "AuthorityBinding": AuthorityEvidenceRequirementBindingAssertion,
        "CandidateBinding": CandidateHashBindingAssertion,
        "Context": CanonicalDecisionHandoffValidationContext,
        "Assertion": TrustedValueAssertion,
        "digest": canonical_handoff_assertion_value_digest,
        "validate": validate_canonical_decision_handoff,
    }


def record_map(handoff: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["field_path"]: r for r in handoff["provenance"]}


def resolve(handoff: dict[str, Any], path: str) -> Any:
    cur: Any = handoff
    for part in path.split("."):
        cur = cur[part]
    return cur


def sync_provenance(handoff: dict[str, Any]) -> None:
    paths = [
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
    records = record_map(handoff)
    for path in paths:
        if path not in records:
            raise RunnerError(f"pinned vector-01 template missing provenance path: {path}")
        value = resolve(handoff, path)
        records[path]["value"] = value
        records[path]["verification_status"] = "VERIFIED"
        if value is None and path in {"human_approval_evidence", "authority_evidence", "expected_state"}:
            records[path]["provenance_class"] = "VERIFIED_POLICY_ARTIFACT"


def build_handoff(
    case: dict[str, Any], repo: Path
) -> tuple[dict[str, Any], dict[str, bool]]:
    vector_path = repo / "docs/en/architecture/test-vectors/decision-to-bind-handoff-v1/vector-01.json"
    if not vector_path.exists():
        raise RunnerError(f"pinned READY handoff vector missing: {vector_path}")
    handoff = copy.deepcopy(json.loads(vector_path.read_text(encoding="utf-8"))["input"])
    cid = case["case_id"]
    action = case["input"]["action_context"]
    gf = case["input"]["governance_fixture"]
    request_id = f"req-{cid.lower()}"
    decision_id = f"decision-{cid.lower()}"
    candidate_id = f"candidate-{cid.lower()}"
    contract_id = f"benchmark.{action.get('action_class') or 'unknown'}"

    handoff["handoff_id"] = f"handoff-{cid.lower()}"
    handoff["created_at"] = "2030-01-01T00:00:01Z"
    handoff["expires_at"] = "2030-01-01T00:05:01Z"
    handoff["source_decision"].update({
        "request_id": request_id,
        "canonical_decision_id": decision_id,
        "canonical_decision_hash": f"sha256:{sha256_json({'decision_id':decision_id,'case_id':cid})}",
        "canonical_decision_ts": "2030-01-01T00:00:00Z",
        "gate_decision": "ALLOW",
    })
    handoff["decision_lineage"]["decision_id"] = decision_id
    handoff["trustlog_lineage"] = {
        "verified": True, "request_id": request_id,
        "artifact_ref": f"trustlog-{cid}",
        "chain_hash": f"sha256:{sha256_json({'trustlog':cid})}",
    }
    handoff["replay_lineage"] = {
        "verified": True, "request_id": request_id,
        "artifact_ref": f"replay-{cid}",
        "artifact_hash": f"sha256:{sha256_json({'replay':cid})}",
    }
    handoff["candidate"] = {
        "candidate_id": candidate_id,
        "actor_identity": action.get("actor_identity"),
        "target_system": action.get("target_system"),
        "target_resource": action.get("target_resource"),
        "canonical_action": {
            "contract_id": contract_id,
            "version": "1",
            "parameters": {
                "operation": action.get("canonical_action"),
                "requested_scope": action.get("requested_scope", []),
                "subject": action.get("subject"),
            },
        },
        "lineage_promotability": "promotable",
    }
    handoff["candidate_hash"] = f"sha256:{sha256_json(handoff['candidate'])}"
    handoff["target_context"] = {
        "target_system": action.get("target_system"),
        "target_resource": action.get("target_resource"),
        "canonicalized": True,
    }
    handoff["policy_lineage"] = {
        "verified": True,
        "snapshot_id": gf.get("policy_snapshot_id") or "benchmark-policy-profile-v0.1",
        "version": "0.1",
        "semantic_digest": "sha256:benchmark-policy-profile-v0.1",
        "policy_ids": ["benchmark-policy-profile-v0.1"],
        "effective_at": "2029-01-01T00:00:00Z",
        "expires_at": "2031-01-01T00:00:00Z",
        "superseded": False,
    }
    handoff["authority_requirement"] = {
        "resolved": True, "required": True,
        "authority_type": f"{action.get('action_class')}-operator",
    }
    handoff["authority_evidence"] = {
        "validation_result": "VALID",
        "actor_identity": action.get("actor_identity"),
        "action_contract_id": contract_id,
        "target_system": action.get("target_system"),
        "target_scope": action.get("target_resource"),
        "issuer": "synthetic-benchmark-authority",
        "issued_at": "2029-12-31T00:00:00Z",
        "expires_at": "2030-02-01T00:00:00Z",
        "evidence_ref": f"authority-{cid}",
        "evidence_hash": f"sha256:{sha256_json({'authority':cid})}",
    }
    approval_required = bool(gf.get("approval_required"))
    handoff["human_approval_requirement"] = {
        "resolved": True, "required": approval_required,
        "policy_ref": "benchmark-policy-profile-v0.1",
    }
    handoff["human_approval_evidence"] = None
    if approval_required:
        handoff["human_approval_evidence"] = {
            "validation_result": "VALID",
            "approver_identity": "approver:synthetic-reviewer",
            "approval_scope": action.get("requested_scope", []),
            "candidate_ref": candidate_id,
            "action_contract_id": contract_id,
            "target_resource": action.get("target_resource"),
            "approved_at": "2029-12-31T12:00:00Z",
            "expires_at": "2030-01-02T00:00:00Z",
            "receipt_ref": f"approval-{cid}",
            "receipt_hash": f"sha256:{sha256_json({'approval':cid})}",
        }
    # Current v1 validator requires expected_state for READY coverage.
    handoff["expected_state"] = {
        "fingerprint": f"sha256:{sha256_json({'state':cid})}",
        "observed_at": "2029-12-31T23:59:00Z",
        "source_ref": f"state-{cid}",
        "verified": True,
    }

    mutation = case.get("mutation", {}).get("type", "")
    flags = {"candidate_binding_mismatch": False, "provenance_mismatch": False}
    if mutation == "AUTHORITY_MISSING":
        handoff["authority_evidence"] = None
    elif mutation == "APPROVAL_MISSING":
        handoff["human_approval_evidence"] = None
    elif mutation == "POLICY_MISSING":
        handoff["policy_lineage"] = None
    elif mutation == "STATE_MISSING":
        handoff["expected_state"] = None
    elif mutation in {"ACTOR_MISSING", "FORBIDDEN_ACTOR_INFERENCE"}:
        handoff["candidate"]["actor_identity"] = None
    elif mutation == "TARGET_MISSING":
        handoff["candidate"]["target_resource"] = None
        handoff["target_context"]["target_resource"] = None
    elif mutation == "ACTION_MISSING":
        handoff["candidate"]["canonical_action"] = None
    elif mutation == "AUTHORITY_REQ_UNRESOLVED":
        handoff["authority_requirement"]["resolved"] = False
    elif mutation in {"APPROVAL_REQ_UNRESOLVED", "FORBIDDEN_APPROVAL_INFERENCE"}:
        handoff["human_approval_requirement"]["resolved"] = False
    elif mutation == "DECISION_HASH_MISSING":
        handoff["source_decision"]["canonical_decision_hash"] = ""
    elif mutation == "AUTHORITY_EXPIRED":
        handoff["authority_evidence"]["expires_at"] = "2029-12-31T23:00:00Z"
    elif mutation == "AUTHORITY_INVALID":
        handoff["authority_evidence"]["validation_result"] = "INVALID"
    elif mutation == "APPROVAL_EXPIRED":
        handoff["human_approval_evidence"]["expires_at"] = "2029-12-31T23:00:00Z"
    elif mutation == "APPROVAL_INVALID":
        handoff["human_approval_evidence"]["validation_result"] = "INVALID"
    elif mutation == "TARGET_MISMATCH":
        handoff["target_context"]["target_resource"] = "resource:deliberate-mismatch"
    elif mutation == "CANDIDATE_HASH_MISMATCH":
        flags["candidate_binding_mismatch"] = True
    elif mutation == "REQUEST_LINEAGE_MISMATCH":
        handoff["replay_lineage"]["request_id"] = f"different-{request_id}"
    elif mutation == "POLICY_STALE":
        handoff["policy_lineage"]["expires_at"] = "2029-12-31T23:00:00Z"
    elif mutation == "STATE_STALE":
        handoff["expected_state"]["observed_at"] = "2030-01-01T00:00:03Z"
    elif mutation == "LINEAGE_NONPROMOTABLE":
        handoff["candidate"]["lineage_promotability"] = "non_promotable"
    elif mutation == "AMBIGUOUS_ACTION":
        handoff["candidate"]["canonical_action"] = {"contract_id": contract_id, "version": "1"}
    elif mutation == "PROVENANCE_MISMATCH":
        flags["provenance_mismatch"] = True
    elif mutation in {"NONE", "NON_AUTHORITATIVE_METADATA_PRESENT", "HIGH_SOURCE_RISK_ADVISORY_ONLY"}:
        pass
    else:
        raise RunnerError(f"unsupported mutation type: {mutation}")

    sync_provenance(handoff)
    # Preserve the template declarations. Ground-truth labels are scoring inputs
    # only and must never influence the native validator's treatment input.
    return handoff, flags


def build_context(handoff: dict[str, Any], native: dict[str, Any], flags: dict[str, bool]) -> Any:
    assertions = []
    for record in handoff["provenance"]:
        digest = native["digest"](record["value"])
        if flags["provenance_mismatch"] and record["field_path"] == "candidate.actor_identity":
            digest = native["digest"]("different-actor")
        claims = ()
        if (
            record["field_path"] == "human_approval_evidence"
            and handoff["human_approval_requirement"]["required"]
        ):
            claims = (native["APPROVAL_CLAIM"],)
        assertions.append(native["Assertion"](
            field_path=record["field_path"],
            value_digest=digest,
            source_artifact_ref=record.get("source_artifact_ref"),
            source_hash=record.get("source_hash"),
            verification_mechanism="joint-benchmark-synthetic-independent-verifier/v0.1",
            verified_at=EVALUATED_AT,
            claims=claims,
        ))
    asserted_hash = handoff["candidate_hash"]
    if flags["candidate_binding_mismatch"]:
        asserted_hash = "sha256:deliberate-mismatch"
    candidate_binding = native["CandidateBinding"](
        candidate_value_digest=native["digest"](handoff["candidate"]),
        asserted_candidate_hash=asserted_hash,
        candidate_hash_profile="joint-benchmark-candidate-hash/v0.1",
        source_artifact_ref=f"synthetic://candidate/{handoff['candidate'].get('candidate_id')}",
        source_hash=handoff["candidate_hash"],
        verification_mechanism="joint-benchmark-synthetic-independent-verifier/v0.1",
        verified_at=EVALUATED_AT,
    )
    authority_binding = None
    if handoff["authority_requirement"]["required"] and handoff.get("authority_evidence") is not None:
        authority_binding = native["AuthorityBinding"](
            authority_requirement_value_digest=native["digest"](handoff["authority_requirement"]),
            authority_evidence_value_digest=native["digest"](handoff["authority_evidence"]),
            source_artifact_ref=handoff["authority_evidence"].get("evidence_ref"),
            source_hash=handoff["authority_evidence"].get("evidence_hash"),
            verification_mechanism="joint-benchmark-synthetic-independent-verifier/v0.1",
            verified_at=EVALUATED_AT,
            claim=native["AUTHORITY_CLAIM"],
        )
    return native["Context"](
        value_assertions=tuple(assertions),
        candidate_hash_binding=candidate_binding,
        authority_requirement_binding=authority_binding,
    )


def path_a_proxy(case: dict[str, Any]) -> dict[str, Any]:
    upstream = case["input"]["upstream_rcc_revas"]
    adoption = upstream.get("adoption_decision")
    verifier = upstream.get("runtime_verifier_passed")
    decision = "ALLOW" if adoption == "candidate_adopted" and verifier is True else "HOLD"
    return {
        "aggregate_decision": decision,
        "semantic_scope": "UPSTREAM_ADOPTION_PROXY_NOT_EXECUTION_AUTHORITY",
        "source_adoption_decision": adoption,
        "source_runtime_verifier_passed": verifier,
        "execution_authority_conferred": False,
    }


def aggregate_from_status(status: str) -> str:
    if status == "READY_FOR_GUARDED_PROMOTION":
        return "ALLOW"
    if status in {"INCOMPLETE", "REVIEW_REQUIRED"}:
        return "HOLD"
    if status in {"INVALID", "STRUCTURALLY_REFUSED"}:
        return "DENY"
    raise RunnerError(f"unknown handoff status: {status}")


def gate_from_status(status: str) -> str:
    return {
        "READY_FOR_GUARDED_PROMOTION": "proceed",
        "INCOMPLETE": "hold",
        "REVIEW_REQUIRED": "human_review_required",
        "INVALID": "block",
        "STRUCTURALLY_REFUSED": "block",
    }[status]


def business_from_status(status: str, reasons: list[str]) -> str:
    if status == "READY_FOR_GUARDED_PROMOTION":
        return "APPROVE"
    if status == "REVIEW_REQUIRED":
        return "REVIEW_REQUIRED"
    if status in {"INVALID", "STRUCTURALLY_REFUSED"}:
        return "DENY"
    if any(r in {
        "HANDOFF_AUTHORITY_REQUIREMENT_UNRESOLVED",
        "HANDOFF_APPROVAL_REQUIREMENT_UNRESOLVED",
        "HANDOFF_POLICY_LINEAGE_MISSING",
    } for r in reasons):
        return "POLICY_DEFINITION_REQUIRED"
    return "EVIDENCE_REQUIRED"


def summarize(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    n = len(rows)
    correct = sum(r[key] == r["expected_decision"] for r in rows)
    non_allow = sum(r["expected_decision"] != "ALLOW" for r in rows)
    exp_allow = sum(r["expected_decision"] == "ALLOW" for r in rows)
    false_allow = sum(r[key] == "ALLOW" and r["expected_decision"] != "ALLOW" for r in rows)
    false_stop = sum(r[key] != "ALLOW" and r["expected_decision"] == "ALLOW" for r in rows)
    false_deny = sum(r[key] == "DENY" and r["expected_decision"] == "ALLOW" for r in rows)
    return {
        "total": n,
        "correct": correct,
        "accuracy": correct / n if n else 0.0,
        "false_allow_count": false_allow,
        "false_allow_rate": false_allow / non_allow if non_allow else 0.0,
        "false_stop_count": false_stop,
        "false_stop_rate": false_stop / exp_allow if exp_allow else 0.0,
        "false_deny_count": false_deny,
        "false_deny_rate": false_deny / exp_allow if exp_allow else 0.0,
        "prediction_counts": dict(Counter(r[key] for r in rows)),
    }


def run_decide_preflight(repo: Path, output_dir: Path) -> dict[str, Any]:
    report = output_dir / "decide_preflight_report.json"
    cmd = [sys.executable, str(repo / "scripts/run_decide_pipeline_poc.py"), "--report", str(report)]
    start = time.perf_counter_ns()
    proc = subprocess.run(cmd, cwd=repo, capture_output=True, text=True)
    return {
        "executed": True,
        "exit_code": proc.returncode,
        "latency_ms": (time.perf_counter_ns() - start) / 1e6,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "report": str(report) if report.exists() else None,
        "report_sha256": sha256_file(report) if report.exists() else None,
        "passed": proc.returncode == 0,
        "scope": "canonical POST /v1/decide preflight only; not per-case treatment",
    }


def run_benchmark(args: argparse.Namespace) -> dict[str, Any]:
    repo = args.veritas_repo.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    dataset = load_dataset(args.dataset.resolve())
    head = git_head(repo)
    if head != PINNED_VERITAS_COMMIT:
        raise RunnerError(
            f"VERITAS repository must be at {PINNED_VERITAS_COMMIT}; observed {head}."
        )
    if git_dirty(repo) is not False:
        raise RunnerError("VERITAS repository must be a clean pinned checkout")
    native = load_native_veritas(repo)
    preflight = run_decide_preflight(repo, output_dir) if args.run_decide_preflight else {"executed": False, "passed": None}

    run_id = f"joint-bench-{uuid.uuid4().hex[:16]}"
    started = datetime.now(timezone.utc)
    rows = []
    for case in dataset["cases"]:
        start_ns = time.perf_counter_ns()
        pa = path_a_proxy(case)
        handoff, flags = build_handoff(case, repo)
        context = build_context(handoff, native, flags)
        result = native["validate"](handoff, context, EVALUATED_AT).to_dict()
        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1e6
        status = result["status"]
        reasons = list(result["reason_codes"])
        pb = aggregate_from_status(status)
        gt = case["ground_truth"]
        row = {
            "case_id": case["case_id"],
            "subset": case["subset"],
            "scenario_family": case["scenario_family"],
            "title": case["title"],
            "mutation_type": case["mutation"]["type"],
            "expected_decision": gt["expected_decision"],
            "expected_handoff_state": gt["expected_handoff_state"],
            "expected_reason_codes": gt["expected_reason_codes"],
            "path_a_decision": pa["aggregate_decision"],
            "path_a_semantic_scope": pa["semantic_scope"],
            "path_b_decision": pb,
            "actual_handoff_state": status,
            "actual_reason_codes": reasons,
            "actual_gate_decision": gate_from_status(status),
            "actual_business_decision": business_from_status(status, reasons),
            "aggregate_decision_match": pb == gt["expected_decision"],
            "handoff_status_match": status == gt["expected_handoff_state"],
            "reason_codes_match": reasons == gt["expected_reason_codes"],
            "case_treatment_latency_ms": elapsed_ms,
            "native_ready_for_guarded_promotion": result["ready_for_guarded_promotion"],
            "native_fail_closed": result["fail_closed"],
            "bind_measurement_kind": "DERIVED_READINESS_PROXY_NOT_NATIVE_BIND_GATE" if args.bind_proxy else "NOT_EXECUTED",
            "actual_bind_gate_outcome": (BIND_PASS if status == "READY_FOR_GUARDED_PROMOTION" else BIND_FAIL) if args.bind_proxy else None,
            "bind_ground_truth_scored": bool(args.bind_proxy),
            "execution_authority_created": False,
            "external_effect_occurred": False,
        }
        if args.bind_proxy:
            row["bind_gate_outcome_match"] = row["actual_bind_gate_outcome"] == gt["expected_bind_gate_outcome"]
        rows.append(row)

    pa_summary = summarize(rows, "path_a_decision")
    pb_summary = summarize(rows, "path_b_decision")
    exact = {
        "aggregate_accuracy": sum(r["aggregate_decision_match"] for r in rows) / len(rows),
        "handoff_status_accuracy": sum(r["handoff_status_match"] for r in rows) / len(rows),
        "reason_code_exact_accuracy": sum(r["reason_codes_match"] for r in rows) / len(rows),
    }
    if args.bind_proxy:
        exact["bind_proxy_accuracy"] = sum(r.get("bind_gate_outcome_match", False) for r in rows) / len(rows)

    cases_path = output_dir / "cases.jsonl"
    cases_path.write_text("\n".join(json.dumps(r, ensure_ascii=False, sort_keys=True) for r in rows) + "\n", encoding="utf-8")
    summary = {
        "run_id": run_id,
        "runner_version": RUNNER_VERSION,
        "started_at_utc": started.isoformat(),
        "finished_at_utc": datetime.now(timezone.utc).isoformat(),
        "veritas_commit": head,
        "repo_dirty": git_dirty(repo),
        "dataset_sha256": sha256_file(args.dataset.resolve()),
        "path_a": pa_summary,
        "path_b": pb_summary,
        "governance_delta": {
            "accuracy_delta": pb_summary["accuracy"] - pa_summary["accuracy"],
            "false_allow_rate_reduction": pa_summary["false_allow_rate"] - pb_summary["false_allow_rate"],
            "false_stop_rate_delta": pb_summary["false_stop_rate"] - pa_summary["false_stop_rate"],
        },
        "native_exact": exact,
        "bind_stage": {
            "mode": "DERIVED_READINESS_PROXY_NOT_NATIVE_BIND_GATE" if args.bind_proxy else "NOT_EXECUTED",
            "claim_allowed": False,
            "note": "The v0.1 runner does not execute the native VERITAS dry-run Bind Authorization gate. Proxy mode is plumbing-only.",
        },
        "decide_preflight": preflight,
        "negative_assertions": {
            "real_bind_invoked": False,
            "external_effect_occurred": False,
            "execution_authority_created": False,
            "credential_material_accessed_by_harness": False,
        },
    }
    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    manifest = {
        "artifact_type": "joint_benchmark_run_manifest",
        "runner_version": RUNNER_VERSION,
        "run_id": run_id,
        "veritas_commit": head,
        "repo_dirty": git_dirty(repo),
        "dataset_sha256": sha256_file(args.dataset.resolve()),
        "canonical_benchmark_contract_sha256": PINNED_CANONICAL_BENCHMARK_CONTRACT_SHA256,
        "benchmark_runtime_manifest_sha256": PINNED_RUNTIME_MANIFEST_SHA256,
        "field_contract_sha256": PINNED_FIELD_CONTRACT_SHA256,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cases_sha256": sha256_file(cases_path),
        "summary_sha256": sha256_file(summary_path),
        "real_bind_invoked": False,
        "external_effect_occurred": False,
    }
    manifest_path = output_dir / "run_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report = output_dir / "report.md"
    report.write_text(
        "# Joint Benchmark Run " + run_id + "\n\n"
        + f"- VERITAS commit: `{head}`\n"
        + f"- Dataset SHA-256: `{manifest['dataset_sha256']}`\n"
        + f"- Path A accuracy: **{pa_summary['accuracy']:.3f}**\n"
        + f"- Path B accuracy: **{pb_summary['accuracy']:.3f}**\n"
        + f"- Accuracy delta: **{summary['governance_delta']['accuracy_delta']:+.3f}**\n"
        + f"- Path A false-allow rate: **{pa_summary['false_allow_rate']:.3f}**\n"
        + f"- Path B false-allow rate: **{pb_summary['false_allow_rate']:.3f}**\n"
        + f"- Native handoff status accuracy: **{exact['handoff_status_accuracy']:.3f}**\n"
        + f"- Native reason-code exact accuracy: **{exact['reason_code_exact_accuracy']:.3f}**\n"
        + "- Native dry-run Bind gate executed: **NO**\n"
        + "- External effect: **NONE**\n\n"
        + "Path A is an upstream-adoption proxy and is not execution authority. "
        + "The optional Bind proxy is not native Bind-gate evidence.\n",
        encoding="utf-8",
    )
    return summary


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parent
    p = argparse.ArgumentParser(description="RCC/REVAS -> VERITAS Joint Benchmark Runner / Evaluation Harness v0.1")
    p.add_argument("--veritas-repo", type=Path)
    p.add_argument("--dataset", type=Path, default=root / "fixtures/Governance_labelled_Evaluation_Set_v0.1.1.json")
    p.add_argument("--output-dir", type=Path, default=Path("joint-benchmark-results"))
    p.add_argument("--run-decide-preflight", action="store_true")
    p.add_argument("--bind-proxy", action="store_true", help="Plumbing-only derived readiness proxy; NOT native Bind-gate evidence")
    p.add_argument("--self-check", action="store_true")
    return p


def main() -> int:
    args = build_parser().parse_args()
    if args.self_check:
        try:
            data = load_dataset(args.dataset.resolve())
        except RunnerError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        print(
            json.dumps(
                {
                    "self_check": "PASS",
                    "runner_version": RUNNER_VERSION,
                    "dataset_version": data["artifact_version"],
                    "case_count": len(data["cases"]),
                    "dataset_sha256": sha256_file(args.dataset.resolve()),
                },
                indent=2,
            )
        )
        return 0
    if args.veritas_repo is None:
        raise SystemExit("--veritas-repo is required unless --self-check is used")
    try:
        summary = run_benchmark(args)
    except RunnerError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
