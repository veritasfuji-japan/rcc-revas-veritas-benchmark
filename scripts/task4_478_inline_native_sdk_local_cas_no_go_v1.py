#!/usr/bin/env python3
"""Task4 #478: inline local CAS before #472 deny-only Native worker claim.

Local offline synthetic only: NOT a production or cross-runner SEND boundary.
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

from scripts import task4_477_simulated_shared_store_single_use_no_go_v1 as ledger
from scripts import task4_476_native_wire_separate_signer_no_go_v1 as native

RULE = "TASK4_478_INLINE_NATIVE_SDK_LOCAL_CAS_NO_GO_V1"
ROOT = Path(__file__).resolve().parents[1]
Denied = ledger.Denied


def require(value, code):
    if value is not True:
        raise Denied(code)


def run():
    ledger.ensure_offline()
    ctx = mp.get_context("spawn")
    with tempfile.TemporaryDirectory(prefix="task4-478-inline-local-") as folder:
        db = Path(folder) / "inline-local.sqlite"
        ledger.init_store(db)
        parent, child = ctx.Pipe()
        signer_process = ctx.Process(target=native.signer.signer_child,
                                     args=(child,))
        signer_process.start()
        child.close()
        observed = []
        original = native.native.prior.check_sdk_wire
        # original = #473.check_sdk_wire, called BEFORE #472 local worker claim
        try:
            info = parent.recv()
            require(info["pid"] != os.getpid(),
                    "478_SIGNER_MUST_BE_SEPARATE_OS_PROCESS")
            public_hex = info["public_hex"]
            policy_hash = native.signer.digest(
                b"task4-478-local-synthetic-signed-no-send-policy")

            def inline_gate(arm, ordinal, raw):
                # Fail closed BEFORE handing the original bytes to #472 worker.
                scope = original(arm, ordinal, raw)
                claim = native.native.make_claim(
                    arm=arm, ordinal=ordinal,
                    wire_sha=scope["original_sdk_wire_sha256"],
                    policy_digest=policy_hash,
                    nonce=f"478-{arm}-{ordinal}")
                parent.send({"op": "sign_synthetic_no_send", "claim": claim})
                reply = parent.recv()
                require(reply.get("decision") == "SIGNED_SYNTHETIC_NO_SEND",
                        "478_SIGNER_DENIED")
                # Verify cryptographic binding BEFORE consuming local slot.
                native.signer.verify(
                    public_hex=public_hex, claim=claim,
                    signature_hex=reply["signature_hex"],
                    expected=claim, consumed=set())
                item = ledger.record(
                    arm, ordinal, scope["original_sdk_wire_sha256"],
                    native.signer.digest(native.signer.canonical(claim)))
                result = ledger.reserve(db, item)
                require(result.get("decision") == "CONSUMED_UNKNOWN_NO_SEND"
                        and result.get("provider_post_allowed") is False,
                        "478_LOCAL_CAS_DENIED_BEFORE_NATIVE_WORKER")
                observed.append({
                    "arm": arm, "ordinal": ordinal,
                    "original_sdk_wire_sha256": scope["original_sdk_wire_sha256"],
                    "synthetic_claim_sha256": item["authority_claim_sha256"],
                    "local_ledger_receipt_sha256": result["receipt_sha256"],
                    "state": ledger.STATE,
                })
                return scope

            with patch.object(native.native.prior, "check_sdk_wire",
                              inline_gate):
                report = native.native.prior.run_offline_native_budget_join()

            expected = [(a, i) for a in ("A", "B") for i in range(4)]
            require([(x["arm"], x["ordinal"]) for x in observed] == expected
                    and len(observed) == 8 and ledger.count(db) == 8,
                    "478_EIGHT_INLINE_SDK_CAS_CLAIMS_REQUIRED")
            require(report["offline_sdk_requests_budget_checked"] == 8
                    and report["same_run_worker_once_claims"] == 8
                    and report["same_run_preparse_aead_scripted_responses"] == 8
                    and report["restart_replays_denied"] == 8
                    and report["real_provider_posts"] == 0
                    and report["score_status"] == "UNSCORED",
                    "478_NATIVE_WORKER_AEAD_CHAIN_MISMATCH")
            for local, preflight in zip(
                    observed, report["hash_only_budget_preflight_receipts"]):
                require(local["original_sdk_wire_sha256"]
                        == preflight["original_sdk_wire_sha256"],
                        "478_INLINE_CAS_ORIGINAL_WIRE_HASH_DRIFT")

            # Native has finished: simulate restart/retry of all eight slots.
            for entry in observed:
                same = ledger.record(
                    entry["arm"], entry["ordinal"],
                    entry["original_sdk_wire_sha256"],
                    entry["synthetic_claim_sha256"])
                require(ledger.reserve(db, same)["decision"]
                        == "DENY_ALREADY_CONSUMED",
                        "478_REPLAY_AFTER_NATIVE_MUST_BE_DENIED")

            parent.send({"op": "send_live", "claim": {}})
            require(parent.recv()["decision"] ==
                    "DENY_NOT_SYNTHETIC_NO_SEND",
                    "478_SIGNER_MUST_NOT_IMPLEMENT_LIVE_SEND")
            return {
                "rule": RULE,
                "inline_pre_worker_local_cas_claims": len(observed),
                "same_run_native_sdk_wires": report["offline_sdk_requests_budget_checked"],
                "same_run_deny_only_worker_claims": report["same_run_worker_once_claims"],
                "same_run_preparse_aead_scripted_responses":
                    report["same_run_preparse_aead_scripted_responses"],
                "restart_native_worker_replays_denied": report["restart_replays_denied"],
                "local_cas_replays_denied": len(observed),
                "signer_separate_os_process": True,
                "local_db_entries": ledger.count(db),
                "hash_only_inline_cas_receipts": observed,
                "native_cas_inline_before_local_worker": True,
                "production_non_bypassable_sender_proven": False,
                "remote_shared_store_cross_runner_proven": False,
                "independent_iam_egress_proven": False,
                "durable_remote_revocation_proven": False,
                "real_owner_approval": False,
                "provider_posts": 0,
                "external_bank_effects": 0,
                "genuine_native_utility": None,
                "score_status": "UNSCORED",
                "no_go": True,
            }
        finally:
            if signer_process.is_alive():
                try:
                    parent.send({"op": "stop"})
                except (EOFError, BrokenPipeError):
                    pass
            signer_process.join(timeout=5)
            if signer_process.is_alive():
                signer_process.terminate()
                signer_process.join(timeout=5)
            parent.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    args = p.parse_args()
    ledger.ensure_offline()
    output = (ROOT / args.output).resolve()
    require(output.is_relative_to(ROOT) and not output.exists()
            and not output.is_symlink(),
            "478_CREATE_ONLY_REPO_OUTPUT_REQUIRED")
    result = run()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("TASK4_478_INLINE_LOCAL_CAS_NATIVE_SDK_NO_PROVIDER")


if __name__ == "__main__":
    main()
