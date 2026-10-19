#!/usr/bin/env python3
"""Offline-only: separate signer child process joins original Native SDK bytes.

No live Provider sender, no external bank effect, no independent IAM or approval.
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
from pathlib import Path
from unittest.mock import patch

from scripts import task4_474_independent_signed_authority_offline_no_go_v1 as native
from scripts import task4_475_separate_process_synthetic_signer_no_go_v1 as signer

ROOT = Path(__file__).resolve().parents[1]
RULE = "TASK4_476_NATIVE_WIRE_SEPARATE_SYNTHETIC_SIGNER_NO_GO_V1"
Denied = signer.Denied


def run():
    signer.ensure_offline()
    native.deny_live()
    ctx = mp.get_context("spawn")
    parent, child = ctx.Pipe()
    proc = ctx.Process(target=signer.signer_child, args=(child,))
    proc.start()
    child.close()
    observed = []
    consumed = set()
    policy_hash = signer.digest(b"task4-476-frozen-local-no-send-policy")
    original = native.prior.check_sdk_wire
    try:
        info = parent.recv()
        if info.get("pid") == os.getpid():
            raise Denied("476_SIGNER_NOT_SEPARATE_PROCESS")
        public_hex = info["public_hex"]

        def verify_original_wire(arm, ordinal, raw):
            # This hook executes on original SDK request bytes in #473 before
            # #472 worker claim; the full local Native/AEAD path then continues.
            preflight = original(arm, ordinal, raw)
            claim = native.make_claim(
                arm=arm, ordinal=ordinal,
                wire_sha=preflight["original_sdk_wire_sha256"],
                policy_digest=policy_hash,
                nonce=f"476-{arm}-{ordinal}",
            )
            parent.send({"op": "sign_synthetic_no_send", "claim": claim})
            response = parent.recv()
            if response.get("decision") != "SIGNED_SYNTHETIC_NO_SEND":
                raise Denied("476_SIGNER_REFUSED_OR_UNEXPECTED_REPLY")
            verified = signer.verify(
                public_hex=public_hex, claim=claim,
                signature_hex=response["signature_hex"],
                expected=claim, consumed=consumed)
            if verified["decision"] != "LOCAL_PROVENANCE_VERIFIED_NO_SEND":
                raise Denied("476_PROVENANCE_NOT_VERIFIED")
            observed.append({
                "arm": arm, "ordinal": ordinal,
                "original_sdk_wire_sha256": preflight["original_sdk_wire_sha256"],
                "claim_sha256": verified["claim_sha256"],
                "decision": "SIGNED_SYNTHETIC_NO_SEND",
            })
            return preflight

        with patch.object(native.prior, "check_sdk_wire", verify_original_wire):
            result = native.prior.run_offline_native_budget_join()

        expected_order = [(arm, ordinal) for arm in ("A", "B")
                          for ordinal in range(4)]
        if (len(observed) != 8
                or [(x["arm"], x["ordinal"]) for x in observed] != expected_order
                or len(consumed) != 8
                or result["offline_sdk_requests_budget_checked"] != 8
                or result["same_run_worker_once_claims"] != 8
                or result["same_run_preparse_aead_scripted_responses"] != 8
                or result["restart_replays_denied"] != 8
                or result["real_provider_posts"] != 0
                or result["score_status"] != "UNSCORED"):
            raise Denied("476_NATIVE_INTEGRATION_ASSERTIONS_FAILED")
        for actual, budget in zip(observed,
                                  result["hash_only_budget_preflight_receipts"]):
            if (actual["original_sdk_wire_sha256"]
                    != budget["original_sdk_wire_sha256"]):
                raise Denied("476_ORIGINAL_SDK_WIRE_HASH_JOIN_FAILED")

        first = observed[0]
        replay_claim = native.make_claim(
            arm="A", ordinal=0, wire_sha=first["original_sdk_wire_sha256"],
            policy_digest=policy_hash, nonce="476-A-0")
        parent.send({"op": "sign_synthetic_no_send", "claim": replay_claim})
        replay_signature = parent.recv()["signature_hex"]
        try:
            signer.verify(public_hex=public_hex, claim=replay_claim,
                          signature_hex=replay_signature,
                          expected=replay_claim, consumed=consumed)
        except Denied as exc:
            if "475_ALREADY_CONSUMED" not in str(exc):
                raise
            replay_denied = True
        else:
            raise Denied("476_REPLAY_NOT_DENIED")

        parent.send({"op": "send_live", "claim": replay_claim})
        live_refusal = parent.recv()
        if live_refusal.get("decision") != "DENY_NOT_SYNTHETIC_NO_SEND":
            raise Denied("476_LIVE_OPCODE_NOT_DENIED")

        return {
            "rule": RULE,
            "signer_separate_os_process": True,
            "same_runner_and_os_identity": True,
            "native_original_sdk_wire_signatures_verified": len(observed),
            "native_local_worker_claims": result["same_run_worker_once_claims"],
            "native_preparse_aead_scripted_responses":
                result["same_run_preparse_aead_scripted_responses"],
            "native_restart_replays_denied": result["restart_replays_denied"],
            "signed_claim_replay_denied": replay_denied,
            "live_send_opcode": live_refusal["decision"],
            "hash_only_native_authority_receipts": observed,
            "real_independent_iam_or_egress_proven": False,
            "remote_issuer_authority_proven": False,
            "durable_cross_runner_single_use_proven": False,
            "real_owner_consent": False,
            "provider_posts": 0,
            "external_bank_effects": 0,
            "genuine_native_utility": None,
            "score_status": "UNSCORED",
            "no_go": True,
        }
    finally:
        if proc.is_alive():
            try:
                parent.send({"op": "stop"})
            except (BrokenPipeError, EOFError):
                pass
        proc.join(timeout=5)
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=5)
        parent.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    signer.ensure_offline()
    native.deny_live()
    out = (ROOT / args.output).resolve()
    if not out.is_relative_to(ROOT) or out.exists() or out.is_symlink():
        raise Denied("476_REPORT_CREATE_ONLY_REPO_PATH")
    result = run()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("TASK4_476_ORIGINAL_NATIVE_SDK_WIRE_SEPARATE_SIGNER_NO_PROVIDER")


if __name__ == "__main__":
    main()
