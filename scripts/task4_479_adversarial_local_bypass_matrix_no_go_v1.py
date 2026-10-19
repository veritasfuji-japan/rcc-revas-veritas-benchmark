#!/usr/bin/env python3
"""Task4 #479: adversarial local bypass matrix, OFFLINE, explicit residual gaps.

An untrusted same-identity process CAN call the legacy local broker directly.
This is a detected boundary gap, not a proven bypass-resistant deployment.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from unittest.mock import patch

from scripts import task4_478_inline_native_sdk_local_cas_no_go_v1 as inline
from scripts import task4_477_simulated_shared_store_single_use_no_go_v1 as ledger
from scripts import task4_458_local_broker_once_ciphertext_v1 as broker

ROOT = Path(__file__).resolve().parents[1]
RULE = "TASK4_479_ADVERSARIAL_OFFLINE_BYPASS_MATRIX_GAPS_VISIBLE_NO_GO_V1"
Denied = ledger.Denied


def require(cond, reason):
    if cond is not True:
        raise Denied(reason)


def refused(fn):
    try:
        fn()
    except (Denied, broker.Refused):
        return True
    return False


def probe():
    ledger.ensure_offline()
    with tempfile.TemporaryDirectory(prefix="task4-479-adversarial-") as folder:
        db = Path(folder) / "cas.sqlite"
        ledger.init_store(db)
        base = ledger.synth()
        require(ledger.reserve(db, base)["decision"] == "CONSUMED_UNKNOWN_NO_SEND",
                "479_LOCAL_CAS_INITIAL_COMMIT_REQUIRED")
        replay = ledger.reserve(db, base)["decision"] == "DENY_ALREADY_CONSUMED"
        mutated = dict(base, wire_sha256="f"*64)
        mutated_replay = (ledger.reserve(db, mutated)["decision"]
                          == "DENY_ALREADY_CONSUMED")
        fake_authority = dict(ledger.synth("B", 0),
                              provider_post_allowed=True)
        forged = refused(lambda: ledger.reserve(db, fake_authority))
        no_db = refused(lambda: ledger.reserve(
            Path(folder) / "missing.sqlite", ledger.synth("B", 0)))
        with sqlite3.connect(db) as conn:
            conn.execute("BEGIN EXCLUSIVE")
            lock_refused = refused(lambda: ledger.reserve(
                db, ledger.synth("B", 0)))
            conn.rollback()

        # Demonstrate same-identity bypass of the #478 Python hook:
        # #458's existing local consume opcode DOES NOT request #478 CAS receipt.
        # A direct call can consume a synthetic broker slot even if CAS is absent.
        legacy = Path(folder) / "legacy.sqlite"
        broker.prepare_db(legacy)
        direct = broker.action(legacy, "a"*64, {
            "op": "consume", "trial": broker.SYNTHETIC_TRIAL,
            "arm": "A", "ordinal": 0, "request_sha": "b"*64,
        })
        direct_broker_consumed_without_inline_cas = (
            direct["decision"] == "LOCAL_CONSUMED_NO_SEND"
            and ledger.count(db) == 1)
        require(direct_broker_consumed_without_inline_cas,
                "479_LEGACY_LOCAL_BROKER_BYPASS_MUST_BE_EXPOSED")

        # The legacy broker cannot perform a real Provider POST, even on bypass.
        require(direct["live_post"] is False,
                "479_LEGACY_BROKER_MUST_REMAIN_NO_PROVIDER")
        denied_live_opcode = refused(lambda: broker.action(
            legacy, "a"*64, {
                "op": "send_live", "trial": broker.SYNTHETIC_TRIAL,
                "arm": "B", "ordinal": 0,
            }))
        require(denied_live_opcode,
                "479_LEGACY_BROKER_LIVE_OPCODE_MUST_REFUSE")
        assert ledger.count(db) == 1
        return {
            "local_replay_refused": replay,
            "local_changed_wire_replay_refused": mutated_replay,
            "fake_provider_authority_refused": forged,
            "missing_store_refused": no_db,
            "locked_store_refused": lock_refused,
            "legacy_broker_live_opcode_refused": denied_live_opcode,
            "legacy_broker_direct_consume_without_inline_cas_possible":
                direct_broker_consumed_without_inline_cas,
            "direct_legacy_broker_exposes_local_hook_bypass": True,
            "legacy_broker_still_has_no_real_provider_transport": True,
            "same_identity_sqlite_tamper_not_protected": True,
            "direct_broker_request_uses_synthetic_bytes_only": True,
        }


def run(with_native=False):
    ledger.ensure_offline()
    adversarial = probe()
    native = inline.run() if with_native else None
    if native is not None:
        require(native["inline_pre_worker_local_cas_claims"] == 8
                and native["same_run_deny_only_worker_claims"] == 8
                and native["provider_posts"] == 0
                and native["no_go"] is True,
                "479_FROZEN_NATIVE_INLINE_CAS_CONTROL_REQUIRED")
    return {
        "rule": RULE,
        "offline_adversarial_matrix": adversarial,
        "original_native_sdk_inline_cas_control_runs":
            8 if native is not None else 0,
        "native_hash_only_control_receipts":
            native["hash_only_inline_cas_receipts"] if native else [],
        "bypass_resistance_proven": False,
        "direct_legacy_broker_local_bypass_detected": True,
        "real_provider_bypass_proven": False,
        "independent_iam_or_egress_proven": False,
        "protected_store_or_remote_cas_proven": False,
        "same_os_identity_as_attacker": True,
        "real_owner_approval": False,
        "real_provider_posts": 0,
        "external_bank_effects": 0,
        "genuine_native_utility": None,
        "score_status": "UNSCORED",
        "no_go": True,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--with-native", action="store_true")
    args = parser.parse_args()
    ledger.ensure_offline()
    target = (ROOT / args.output).resolve()
    require(target.is_relative_to(ROOT) and not target.exists()
            and not target.is_symlink(), "479_CREATE_ONLY_OUTPUT_REQUIRED")
    report = run(with_native=args.with_native)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
    print("TASK4_479_LOCAL_BYPASS_GAP_FOUND_NO_PROVIDER")


if __name__ == "__main__":
    main()
