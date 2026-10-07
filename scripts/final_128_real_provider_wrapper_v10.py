#!/usr/bin/env python3
"""V12 shared execution control flow.

All modes enter execute_control_flow(). Provider-free mode traverses the same
runtime validation, receipt handoff, and provider-boundary implementation used
by the real two-phase workflow, but substitutes the durable consume and stops
before provider credential availability. Real execution remains fail-closed
until exact V12 authorization and human-confirmation contracts exist.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
AUTH_PATH = ROOT / "contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v12.json"
CONFIRM_PATH = ROOT / "contracts/AGENTDOJO_FINAL_128_V12_HUMAN_CONFIRMATION_v1.json"
AUTH_ID = "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V12"
CONFIRM = "RUN_FINAL_128_V12_ONCE"
RUNNER = "scripts/agentdojo_clean_ab_canonical_final_runner_v2_7.py"
RUNNER_BLOB = "c5f96220b79383fed5ff96305863180193d366f5"
MANUAL_DISPATCH_WORKFLOW = ".github/workflows/final-128-v12-manual-dispatch-template.yml"
RUNNER_CONFIRM = "RUN_CANONICAL_AGENTDOJO_CLEAN_AB_V2_7"
RECEIPT_SCHEMA = "veritas.agentdojo-final-128-runtime-dispatch-receipt.v1"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def blob(path: Path | str) -> str:
    p = Path(path)
    if p.is_absolute():
        p = p.relative_to(ROOT)
    return subprocess.run(
        ["git", "hash-object", str(ROOT / p)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def runtime_component_blobs() -> dict[str, str]:
    return {
        "runner_git_blob_sha": blob(RUNNER),
        "wrapper_git_blob_sha": blob(Path(__file__)),
        "manual_dispatch_workflow_git_blob_sha": blob(MANUAL_DISPATCH_WORKFLOW),
    }


def validate_runtime_contract(a: dict[str, Any], c: dict[str, Any], confirmation: str) -> None:
    components = runtime_component_blobs()
    assert components["runner_git_blob_sha"] == RUNNER_BLOB
    assert a["authorization"] == {
        "id": AUTH_ID,
        "issued": True,
        "single_use": True,
        "consumed": False,
        "rerun_authorized": False,
    }
    assert a["dispatch"] == {
        "provider_dispatch_authorized": True,
        "manual_dispatch_authorized": True,
    }
    assert a["cost_boundary"]["maximum_usd"] == 5
    assert a["frozen_target"] == {
        "runner_git_blob_sha": RUNNER_BLOB,
        "wrapper_git_blob_sha": components["wrapper_git_blob_sha"],
        "manual_dispatch_workflow_git_blob_sha": components[
            "manual_dispatch_workflow_git_blob_sha"
        ],
    }
    assert c["authorization_id"] == AUTH_ID
    assert c["authorization_git_blob_sha"] == a["_self_blob"]
    assert c["confirmation"] == {
        "received": True,
        "maximum_usd": 5,
        "single_consumption_only": True,
        "rerun_authorized": False,
    }
    assert confirmation == CONFIRM


def synthetic_contracts() -> tuple[dict[str, Any], dict[str, Any]]:
    synthetic_blob = "V12_SYNTHETIC_AUTH_BLOB"
    components = runtime_component_blobs()
    a = {
        "_self_blob": synthetic_blob,
        "authorization": {
            "id": AUTH_ID,
            "issued": True,
            "single_use": True,
            "consumed": False,
            "rerun_authorized": False,
        },
        "dispatch": {
            "provider_dispatch_authorized": True,
            "manual_dispatch_authorized": True,
        },
        "cost_boundary": {"maximum_usd": 5},
        "frozen_target": {
            "runner_git_blob_sha": RUNNER_BLOB,
            "wrapper_git_blob_sha": components["wrapper_git_blob_sha"],
            "manual_dispatch_workflow_git_blob_sha": components[
                "manual_dispatch_workflow_git_blob_sha"
            ],
        },
    }
    c = {
        "authorization_id": AUTH_ID,
        "authorization_git_blob_sha": synthetic_blob,
        "confirmation": {
            "received": True,
            "maximum_usd": 5,
            "single_consumption_only": True,
            "rerun_authorized": False,
        },
    }
    return a, c


def load_real_contracts() -> tuple[dict[str, Any], dict[str, Any]]:
    if not AUTH_PATH.is_file() or not CONFIRM_PATH.is_file():
        raise SystemExit("V12_AUTHORIZATION_OR_CONFIRMATION_MISSING")
    a = json.loads(AUTH_PATH.read_text())
    c = json.loads(CONFIRM_PATH.read_text())
    a["_self_blob"] = blob(AUTH_PATH)
    return a, c


def seal_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    sealed = dict(receipt)
    sealed["receipt_sha256"] = hashlib.sha256(canonical(sealed)).hexdigest()
    return sealed


def verify_receipt_handoff(receipt: dict[str, Any], *, provider_free: bool) -> None:
    r = dict(receipt)
    digest = r.pop("receipt_sha256", None)
    if not isinstance(digest, str) or hashlib.sha256(canonical(r)).hexdigest() != digest:
        raise SystemExit("V12_RECEIPT_INTEGRITY_MISMATCH")
    if r.get("schema_version") != RECEIPT_SCHEMA:
        raise SystemExit("V12_RECEIPT_SCHEMA_MISMATCH")
    if r.get("authorization_id") != AUTH_ID:
        raise SystemExit("V12_RECEIPT_AUTHORIZATION_MISMATCH")
    if r.get("atomic_consumption_won") is not True:
        raise SystemExit("V12_RECEIPT_ATOMIC_WIN_REQUIRED")
    if r.get("single_use") is not True or r.get("rerun_authorized") is not False:
        raise SystemExit("V12_RECEIPT_SINGLE_USE_MISMATCH")
    if r.get("provider_spend_cap_usd") != 5.0:
        raise SystemExit("V12_RECEIPT_BUDGET_MISMATCH")
    if r.get("runner_git_blob_sha") != RUNNER_BLOB:
        raise SystemExit("V12_RECEIPT_RUNNER_BINDING_MISMATCH")
    components = runtime_component_blobs()
    if r.get("wrapper_git_blob_sha") != components["wrapper_git_blob_sha"]:
        raise SystemExit("V12_RECEIPT_WRAPPER_BINDING_MISMATCH")
    if r.get("manual_dispatch_workflow_git_blob_sha") != components[
        "manual_dispatch_workflow_git_blob_sha"
    ]:
        raise SystemExit("V12_RECEIPT_MANUAL_DISPATCH_WORKFLOW_BINDING_MISMATCH")
    expected_phase = (
        "V12_PROVIDER_FREE_CONSUME_SURROGATE"
        if provider_free
        else "V12_DURABLE_CONSUME_SUCCESS"
    )
    if r.get("phase_marker") != expected_phase:
        raise SystemExit("V12_RECEIPT_PHASE_MISMATCH")


async def consume_phase(a: dict[str, Any], *, provider_free: bool) -> dict[str, Any]:
    # OPENAI credential must never be present in the consume process.
    if os.environ.get("OPENAI_API_KEY"):
        raise SystemExit("OPENAI_API_KEY_PRESENT_DURING_V12_CONSUME")

    if provider_free:
        if os.environ.get("VERITAS_DATABASE_URL"):
            raise SystemExit("DATABASE_CREDENTIAL_PRESENT_DURING_PROVIDER_FREE_PROOF")
        return seal_receipt(
            {
                "schema_version": RECEIPT_SCHEMA,
                "authorization_id": AUTH_ID,
                "durable_authorization_id": AUTH_ID,
                "atomic_consumption_won": True,
                "single_use": True,
                "rerun_authorized": False,
                "provider_spend_cap_usd": 5.0,
                "authorization_git_blob_sha": a["_self_blob"],
                "runner_git_blob_sha": RUNNER_BLOB,
                "wrapper_git_blob_sha": a["frozen_target"]["wrapper_git_blob_sha"],
                "manual_dispatch_workflow_git_blob_sha": a["frozen_target"][
                    "manual_dispatch_workflow_git_blob_sha"
                ],
                "phase_marker": "V12_PROVIDER_FREE_CONSUME_SURROGATE",
                "consumption_id": "PROVIDER_FREE_SURROGATE_NOT_DURABLE",
                "consumption_hash": "PROVIDER_FREE_SURROGATE_NOT_DURABLE",
            }
        )

    from veritas_os.policy.live_adapter_bind_authorization_consumption_store import (
        PostgresAtomicAuthorizationConsumptionStore,
        build_authorization_consumption_record,
    )
    from veritas_os.storage.db import close_pool

    database_url = os.environ.get("VERITAS_DATABASE_URL", "")
    if not database_url.startswith(("postgres://", "postgresql://")):
        raise SystemExit("REAL_POSTGRES_REQUIRED")

    rec = build_authorization_consumption_record(
        live_adapter_bind_authorization_id=AUTH_ID,
        live_adapter_bind_authorization_hash=sha("agentdojo-final-128-execution-v12:" + AUTH_ID),
        idempotency_key="agentdojo-final-128-v12:" + sha(AUTH_ID),
        bind_context_hash=sha("canonical-final-128-provider-dispatch-v12"),
        execution_intent_id="agentdojo-canonical-final-128-provider-v12",
        execution_intent_hash=sha("agentdojo-canonical-final-128-provider-v12"),
        endpoint_identity_binding_digest=sha("openai:gpt-4.1-mini-2025-04-14"),
        credential_reference_digest=sha("github-actions:OPENAI_API_KEY"),
        credential_scope_binding_digest=sha("openai:model:gpt-4.1-mini-2025-04-14"),
        consumed_at=datetime.now(timezone.utc).isoformat(),
    )
    store = PostgresAtomicAuthorizationConsumptionStore()
    try:
        won = await store.consume_once(rec)
        if not won:
            raise SystemExit("V12_ALREADY_CONSUMED_FAIL_CLOSED")
        durable = await store.get(AUTH_ID)
        if (
            durable is None
            or durable.consumption_id != rec.consumption_id
            or durable.consumption_hash != rec.consumption_hash
        ):
            raise SystemExit("V12_DURABLE_READBACK_MISMATCH")
    finally:
        await close_pool()

    return seal_receipt(
        {
            "schema_version": RECEIPT_SCHEMA,
            "authorization_id": AUTH_ID,
            "durable_authorization_id": AUTH_ID,
            "atomic_consumption_won": True,
            "single_use": True,
            "rerun_authorized": False,
            "provider_spend_cap_usd": 5.0,
            "authorization_git_blob_sha": a["_self_blob"],
            "runner_git_blob_sha": RUNNER_BLOB,
            "wrapper_git_blob_sha": a["frozen_target"]["wrapper_git_blob_sha"],
            "manual_dispatch_workflow_git_blob_sha": a["frozen_target"][
                "manual_dispatch_workflow_git_blob_sha"
            ],
            "phase_marker": "V12_DURABLE_CONSUME_SUCCESS",
            "consumption_id": rec.consumption_id,
            "consumption_hash": rec.consumption_hash,
        }
    )


def provider_phase(receipt: dict[str, Any], args: argparse.Namespace, *, provider_free: bool) -> int:
    verify_receipt_handoff(receipt, provider_free=provider_free)

    if provider_free:
        # Exact stop point: before provider credential availability/read and call.
        if os.environ.get("OPENAI_API_KEY"):
            raise SystemExit("OPENAI_API_KEY_PRESENT_BEFORE_PROVIDER_BOUNDARY")
        return 0

    if not os.environ.get("OPENAI_API_KEY"):
        raise SystemExit("OPENAI_API_KEY_MISSING_AFTER_DURABLE_CONSUME")
    if not os.environ.get("VERITAS_DATABASE_URL", "").startswith(("postgres://", "postgresql://")):
        raise SystemExit("V12_PROVIDER_PHASE_DURABLE_READBACK_DATABASE_REQUIRED")

    cmd = [
        "python",
        RUNNER,
        "--execute",
        "--confirmation",
        RUNNER_CONFIRM,
        "--runtime-dispatch-receipt",
        str(args.receipt_path),
        "--agentdojo-root",
        args.agentdojo_root,
        "--rcc-root",
        args.rcc_root,
        "--veritas-root",
        args.veritas_root,
        "--output-dir",
        args.output_dir,
    ]
    return subprocess.call(cmd)


async def execute_control_flow(args: argparse.Namespace) -> int:
    if args.provider_free_preflight:
        a, c = synthetic_contracts()
        validate_runtime_contract(a, c, CONFIRM)
        receipt = await consume_phase(a, provider_free=True)
        rc = provider_phase(receipt, args, provider_free=True)
        if rc != 0:
            raise SystemExit(rc)
        print(
            json.dumps(
                {
                    "status": "PASS_V12_SHARED_EXECUTION_CONTROL_FLOW_TO_PROVIDER_CREDENTIAL_BOUNDARY",
                    "shared_entrypoint": "execute_control_flow",
                    "runtime_contract_validated": True,
                    "runtime_component_self_binding_validated": True,
                    "consume_handoff_kind": "provider_free_surrogate_not_durable_db_receipt",
                    "receipt_verified": True,
                    "stopped_before_provider_credential": True,
                    "database_write": 0,
                    "provider_credential_access": 0,
                    "provider_api_calls": 0,
                    "final_128_execution": 0,
                },
                sort_keys=True,
            )
        )
        return 0

    a, c = load_real_contracts()
    validate_runtime_contract(a, c, args.confirmation)

    if args.phase1_real:
        receipt = await consume_phase(a, provider_free=False)
        args.receipt_path.parent.mkdir(parents=True, exist_ok=True)
        args.receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        print("PASS_V12_PHASE1_DURABLE_CONSUME_AND_RECEIPT")
        return 0

    if args.phase2_real:
        if not args.receipt_path.is_file():
            raise SystemExit("V12_RECEIPT_FILE_MISSING")
        receipt = json.loads(args.receipt_path.read_text())
        return provider_phase(receipt, args, provider_free=False)

    raise SystemExit("V12_MODE_UNREACHABLE")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--provider-free-preflight", action="store_true")
    mode.add_argument("--phase1-real", action="store_true")
    mode.add_argument("--phase2-real", action="store_true")
    p.add_argument("--confirmation", default="")
    p.add_argument("--receipt-path", type=Path, default=Path(".v12_handoff/v12_dispatch_receipt.json"))
    p.add_argument("--agentdojo-root", default="_pins/agentdojo")
    p.add_argument("--rcc-root", default="_pins/rcc")
    p.add_argument("--veritas-root", default="_pins/veritas")
    p.add_argument("--output-dir", default="results/agentdojo-clean-ab-final-v12")
    return p


def main() -> int:
    return asyncio.run(execute_control_flow(build_parser().parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
