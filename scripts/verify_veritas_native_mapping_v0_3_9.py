#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib
import inspect
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAPPING_PATH = ROOT / "contracts" / "rcc_revas_external_v0_3_9_veritas_native_mapping.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve_symbol(qualified: str):
    module_name, symbol_name = qualified.rsplit(".", 1)
    module = importlib.import_module(module_name)
    return module, getattr(module, symbol_name)


def require_params(obj, required: list[str]) -> list[str]:
    params = list(inspect.signature(obj).parameters)
    missing = [name for name in required if name not in params]
    if missing:
        raise AssertionError(f"{obj}: missing expected parameters {missing}; got {params}")
    return params


def main() -> None:
    mapping = json.loads(MAPPING_PATH.read_text())
    veritas_root = Path(os.environ["VERITAS_REPO"]).resolve()
    upstream_root = Path(os.environ["UPSTREAM_REPO"]).resolve()
    sys.path.insert(0, str(veritas_root))

    expected_veritas_commit = mapping["veritas_native"]["commit"]
    expected_ben_commit = mapping["ben_canonical_package"]["commit"]

    import subprocess

    actual_veritas_commit = subprocess.check_output(
        ["git", "-C", str(veritas_root), "rev-parse", "HEAD"], text=True
    ).strip()
    actual_ben_commit = subprocess.check_output(
        ["git", "-C", str(upstream_root), "rev-parse", "HEAD"], text=True
    ).strip()
    assert actual_veritas_commit == expected_veritas_commit
    assert actual_ben_commit == expected_ben_commit

    ben_mapping = upstream_root / mapping["ben_canonical_package"]["mapping_contract_path"]
    assert sha256(ben_mapping) == mapping["ben_canonical_package"]["mapping_contract_sha256"]

    symbol_report = {}
    source_hashes = {}
    for surface in mapping["connection_surfaces"]:
        assert surface["status"] == "ADAPTER_REQUIRED"
        for qualified in surface["native_primitives"]:
            module, obj = resolve_symbol(qualified)
            symbol_report[qualified] = {
                "module": module.__name__,
                "kind": (
                    "class" if inspect.isclass(obj)
                    else "function" if inspect.isfunction(obj)
                    else type(obj).__name__
                ),
                "signature": str(inspect.signature(obj)) if callable(obj) else None,
            }
        for rel in surface["source_files"]:
            p = veritas_root / rel
            assert p.is_file(), rel
            source_hashes[rel] = sha256(p)

    # Exact semantic seam checks. These freeze current native API expectations;
    # they do not execute any effect.
    from veritas_os.policy.decision_candidate import (
        DecisionCandidate,
        hash_decision_candidate,
        try_promote_verified_canonical_decision_candidate_to_execution_intent,
    )
    from veritas_os.governance.authority_evidence import (
        verify_authority_evidence_artifact_to_proof,
        validate_verified_authority_evidence,
    )
    from veritas_os.policy.human_approval_requirement_resolution import (
        build_human_approval_requirement_resolution_packet,
    )
    from veritas_os.policy.live_adapter_dry_run_human_approval_requirement_satisfaction import (
        build_live_adapter_dry_run_human_approval_requirement_satisfaction_packet,
    )
    from veritas_os.policy.bind_core import execute_bind_adjudication
    from veritas_os.policy.bind_core.contracts import BindAdapterContract
    from veritas_os.benchmarks.agentdojo_banking_adapter import (
        AGENTDOJO_COMMIT,
        AGENTDOJO_BENCHMARK_VERSION,
        AgentDojoBankingBindAdapter,
        build_agentdojo_benchmark_execution_intent,
        freeze_agentdojo_candidate,
    )

    require_params(
        try_promote_verified_canonical_decision_candidate_to_execution_intent,
        [
            "candidate",
            "canonical_decision_artifact",
            "policy_snapshot_id",
            "now",
            "ttl_seconds",
            "expected_state_fingerprint",
            "approval_context",
            "policy_lineage",
        ],
    )
    require_params(
        verify_authority_evidence_artifact_to_proof,
        [
            "artifact",
            "action_contract",
            "actor_identity",
            "requested_scope",
            "policy_snapshot_id",
            "signature_verifier",
            "signer_policy",
            "revocation_checker",
            "revocation_policy",
            "now",
        ],
    )
    require_params(
        validate_verified_authority_evidence,
        [
            "proof",
            "action_contract",
            "actor_identity",
            "requested_scope",
            "policy_snapshot_id",
            "now",
        ],
    )
    require_params(
        build_human_approval_requirement_resolution_packet,
        [
            "source_authority_evidence_linkage_review_packet",
            "action_contract",
            "resolved_at",
        ],
    )
    require_params(
        build_live_adapter_dry_run_human_approval_requirement_satisfaction_packet,
        [
            "source_authority_evidence_linkage_review_packet",
            "human_approval_requirement_resolution_packet",
            "action_contract",
            "required_human_approval_linkage_review_packet",
            "human_approval_linkage_review_recorded_at",
        ],
    )
    require_params(
        execute_bind_adjudication,
        ["execution_intent", "adapter", "bind_ts", "bind_receipt_id", "append_trustlog"],
    )

    assert inspect.isclass(DecisionCandidate)
    assert inspect.isclass(BindAdapterContract)
    assert inspect.isclass(AgentDojoBankingBindAdapter)
    assert callable(hash_decision_candidate)
    assert callable(freeze_agentdojo_candidate)
    assert callable(build_agentdojo_benchmark_execution_intent)
    assert AGENTDOJO_COMMIT == mapping["future_agentdojo_surface"]["agentdojo_commit"]
    assert AGENTDOJO_BENCHMARK_VERSION == mapping["future_agentdojo_surface"]["benchmark_version"]

    # Ben names three integration wrapper surfaces. Current VERITAS product uses
    # different native primitives, so an explicit adapter layer is expected.
    exact_wrapper_names = {
        "NativeDecisionIntentFactory": False,
        "NativeAuthorityResolver": False,
        "NativeBindExecutor": False,
    }

    report = {
        "schema_version": "veritas.rcc-revas.external-native-mapping-audit.v1",
        "status": "PASS_PRIMITIVES_VERIFIED_ADAPTER_LAYER_REQUIRED",
        "ben_canonical_commit": actual_ben_commit,
        "veritas_native_commit": actual_veritas_commit,
        "ben_mapping_contract_sha256": sha256(ben_mapping),
        "mapping_file_sha256": sha256(MAPPING_PATH),
        "source_hashes": dict(sorted(source_hashes.items())),
        "native_symbols": dict(sorted(symbol_report.items())),
        "ben_wrapper_names_are_product_native_classes": exact_wrapper_names,
        "connection_surface_status": {
            item["surface"]: item["status"] for item in mapping["connection_surfaces"]
        },
        "claim_boundary": mapping["claim_boundary"],
        "next_gate": (
            "implement explicit versioned adapter layer and freeze interface semantics "
            "before any fresh external benchmark execution"
        ),
    }
    out = Path(os.environ.get("REPORT_PATH", "veritas-native-mapping-audit.json"))
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
