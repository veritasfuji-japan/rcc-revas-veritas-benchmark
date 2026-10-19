#!/usr/bin/env python3
"""Task4 #477: OFFLINE single-host multi-process SQLite CAS failure model.

This is NOT a multi-runner durable store or a production permission to send.
SQLite remains local to one test runner. All accepted writes mean NO_SEND.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing as mp
import os
from pathlib import Path
import sqlite3
import tempfile
from unittest.mock import patch

from scripts import task4_476_native_wire_separate_signer_no_go_v1 as previous

RULE = "TASK4_477_SINGLE_HOST_SIMULATED_SHARED_STORE_CAS_NO_GO_V1"
ROOT = Path(__file__).resolve().parents[1]
TRIAL = "task4-477-synthetic-trial-no-send"
POLICY = hashlib.sha256(b"task4-477-local-frozen-deny-policy").hexdigest()
STATE = "UNKNOWN_PERMANENTLY_NO_SEND"
FIELDS = frozenset({"trial", "arm", "ordinal", "wire_sha256",
                    "authority_claim_sha256", "policy_sha256",
                    "provider_post_allowed"})
BLOCK_ENV = previous.signer.BLOCK_ENV + (
    "TASK4_477_LIVE", "TASK4_477_APPROVAL", "VERITAS_DATABASE_URL",
)
Denied = previous.Denied


def require(cond, reason):
    if cond is not True:
        raise Denied(reason)


def ensure_offline():
    require(not any(os.environ.get(name) for name in BLOCK_ENV),
            "477_LIVE_OR_SECRET_CONTEXT_REFUSED")
    previous.native.deny_live()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def record(arm, ordinal, wire_sha256, claim_sha256):
    return {"trial": TRIAL, "arm": arm, "ordinal": ordinal,
            "wire_sha256": wire_sha256,
            "authority_claim_sha256": claim_sha256,
            "policy_sha256": POLICY,
            "provider_post_allowed": False}


def valid(item):
    require(type(item) is dict and set(item) == FIELDS,
            "477_EXACT_SCOPE_FIELDS_REQUIRED")
    require(item["trial"] == TRIAL and item["arm"] in ("A", "B")
            and type(item["ordinal"]) is int and 0 <= item["ordinal"] < 4,
            "477_TRIAL_ARM_ORDINAL_REQUIRED")
    require(item["policy_sha256"] == POLICY
            and item["provider_post_allowed"] is False,
            "477_POLICY_OR_NO_SEND_REQUIRED")
    for field in ("wire_sha256", "authority_claim_sha256"):
        value = item[field]
        require(type(value) is str and len(value) == 64
                and all(c in "0123456789abcdef" for c in value),
                "477_EXACT_DIGEST_REQUIRED")


def init_store(path):
    """Explicit test setup only, never invoked by reserve on outage."""
    ensure_offline()
    require(isinstance(path, Path) and path.parent.is_dir()
            and not path.is_symlink() and not path.exists(),
            "477_CREATE_ONLY_LOCAL_TEST_DB_REQUIRED")
    connection = sqlite3.connect(str(path), timeout=1)
    try:
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("""CREATE TABLE consumed(
            trial TEXT NOT NULL, arm TEXT NOT NULL, ordinal INTEGER NOT NULL,
            wire_sha256 TEXT NOT NULL, authority_claim_sha256 TEXT NOT NULL,
            policy_sha256 TEXT NOT NULL,
            receipt_sha256 TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state='UNKNOWN_PERMANENTLY_NO_SEND'),
            PRIMARY KEY(trial,arm,ordinal)
        )""")
        connection.commit()
    finally:
        connection.close()


def reserve(path, item):
    """Single-host transaction; atomic CAS model, never actual SEND.

    Read-only duplicate lookup is inside BEGIN IMMEDIATE. COMMIT precedes reply.
    Storage timeout/error is always fail closed, never fallback to SEND.
    """
    ensure_offline()
    valid(item)
    require(isinstance(path, Path) and path.is_file()
            and not path.is_symlink(),
            "477_STORE_UNAVAILABLE_FAIL_CLOSED")
    try:
        con = sqlite3.connect(f"file:{path}?mode=rw", uri=True, timeout=0.2)
    except (sqlite3.Error, OSError) as exc:
        raise Denied("477_STORE_UNAVAILABLE_FAIL_CLOSED") from exc
    try:
        con.execute("PRAGMA synchronous=FULL")
        con.execute("BEGIN IMMEDIATE")
        row = con.execute(
            "SELECT wire_sha256 FROM consumed WHERE trial=? AND arm=? AND ordinal=?",
            (item["trial"], item["arm"], item["ordinal"])).fetchone()
        if row is not None:
            con.rollback()
            return {"decision": "DENY_ALREADY_CONSUMED",
                    "provider_post_allowed": False}
        receipt_hash = digest(canonical(item))
        con.execute("""INSERT INTO consumed
            (trial,arm,ordinal,wire_sha256,authority_claim_sha256,
             policy_sha256,receipt_sha256,state)
            VALUES (?,?,?,?,?,?,?,?)""",
            (item["trial"], item["arm"], item["ordinal"],
             item["wire_sha256"], item["authority_claim_sha256"],
             item["policy_sha256"], receipt_hash, STATE))
        con.commit()
        return {"decision": "CONSUMED_UNKNOWN_NO_SEND",
                "receipt_sha256": receipt_hash,
                "provider_post_allowed": False}
    except (sqlite3.Error, OSError) as exc:
        con.rollback()
        raise Denied("477_STORAGE_ERROR_FAIL_CLOSED") from exc
    finally:
        con.close()


def count(path):
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as con:
        return con.execute("SELECT COUNT(*) FROM consumed").fetchone()[0]


def race_child(path_str, item, start, queue):
    try:
        start.wait(timeout=5)
        queue.put(reserve(Path(path_str), item))
    except BaseException as exc:
        queue.put({"decision": "DENY_CHILD_FAIL_CLOSED",
                   "reason": type(exc).__name__,
                   "provider_post_allowed": False})


def crash_after_commit(path_str, item):
    reserve(Path(path_str), item)
    # Lose the reply AFTER the durable commit; no retry can grant authority.
    os._exit(17)


def synth(arm="A", ordinal=0):
    wire = digest(f"477-wire-{arm}-{ordinal}".encode())
    claim = digest(f"477-claim-{arm}-{ordinal}".encode())
    return record(arm, ordinal, wire, claim)


def demonstrate():
    """Independent OS processes contend for ONE shared local DB file."""
    ensure_offline()
    ctx = mp.get_context("spawn")
    with tempfile.TemporaryDirectory(prefix="task4-477-local-cas-") as directory:
        db = Path(directory) / "local-only.sqlite"
        init_store(db)
        item = synth()
        event, queue = ctx.Event(), ctx.Queue()
        children = [ctx.Process(target=race_child,
                                args=(str(db), item, event, queue))
                    for _ in range(4)]
        for proc in children:
            proc.start()
        event.set()
        answers = [queue.get(timeout=12) for _ in children]
        for proc in children:
            proc.join(timeout=8)
            require(proc.exitcode == 0,
                    "477_CONCURRENT_CHILD_FAILED_CLOSED")
        decisions = sorted(x["decision"] for x in answers)
        require(decisions == ["CONSUMED_UNKNOWN_NO_SEND"]
                + ["DENY_ALREADY_CONSUMED"] * 3,
                "477_EXACTLY_ONE_LOCAL_CAS_NOT_OBSERVED")
        require(count(db) == 1, "477_SHARED_LOCAL_DB_SINGLE_RECORD_REQUIRED")
        restart = reserve(db, item)
        require(restart["decision"] == "DENY_ALREADY_CONSUMED",
                "477_RESTART_REPLAY_ALLOWED")
        changed = dict(item, wire_sha256="f"*64)
        require(reserve(db, changed)["decision"] == "DENY_ALREADY_CONSUMED",
                "477_SCOPE_MUTATION_REUSED_SLOT")
        # A committed UNKNOWN must survive a lost/aborted acknowledgement.
        committed_without_ack = synth("B", 0)
        crashing = ctx.Process(target=crash_after_commit,
                               args=(str(db), committed_without_ack))
        crashing.start()
        crashing.join(timeout=8)
        require(crashing.exitcode == 17,
                "477_POST_COMMIT_CRASH_NOT_OBSERVED")
        require(reserve(db, committed_without_ack)["decision"]
                == "DENY_ALREADY_CONSUMED",
                "477_LOST_REPLY_MUST_DENY_RETRY")
        require(count(db) == 2, "477_LOST_REPLY_COMMIT_MUST_PERSIST")
        outage = False
        try:
            reserve(Path(directory) / "missing.sqlite", synth("A", 1))
        except Denied as exc:
            outage = str(exc) == "477_STORE_UNAVAILABLE_FAIL_CLOSED"
        require(outage, "477_STORE_OUTAGE_MUST_FAIL_CLOSED")
        policy = dict(synth("A", 1), policy_sha256="0"*64)
        try:
            reserve(db, policy)
        except Denied as exc:
            policy_denied = str(exc) == "477_POLICY_OR_NO_SEND_REQUIRED"
        else:
            policy_denied = False
        require(policy_denied, "477_POLICY_DRIFT_NOT_DENIED")
        return {
            "simulated_local_race_processes": len(children),
            "local_race_one_committed": decisions.count("CONSUMED_UNKNOWN_NO_SEND"),
            "local_race_replays_denied": decisions.count("DENY_ALREADY_CONSUMED"),
            "restart_replay_denied": True,
            "changed_wire_same_slot_denied": True,
            "crash_after_commit_retry_denied": True,
            "store_unavailable_fail_closed": outage,
            "policy_drift_denied": policy_denied,
            "local_db_records": count(db),
        }


def native_join():
    """Post-hoc local evidence join, NOT a pre-dispatch durable store hook."""
    ensure_offline()
    report = previous.run()
    receipts = report["hash_only_native_authority_receipts"]
    require(len(receipts) == 8 and
            [(x["arm"], x["ordinal"]) for x in receipts] ==
            [(arm, i) for arm in ("A", "B") for i in range(4)],
            "477_FROZEN_NATIVE_RECEIPTS_REQUIRED")
    with tempfile.TemporaryDirectory(prefix="task4-477-native-local-") as directory:
        db = Path(directory) / "local-native.sqlite"
        init_store(db)
        persisted = []
        for receipt in receipts:
            item = record(receipt["arm"], receipt["ordinal"],
                          receipt["original_sdk_wire_sha256"],
                          receipt["claim_sha256"])
            reply = reserve(db, item)
            require(reply["decision"] == "CONSUMED_UNKNOWN_NO_SEND",
                    "477_EIGHT_SYNTHETIC_LOCAL_RECORDS_REQUIRED")
            persisted.append({"arm": item["arm"], "ordinal": item["ordinal"],
                              "sdk_wire_sha256": item["wire_sha256"],
                              "claim_sha256": item["authority_claim_sha256"],
                              "ledger_receipt_sha256": reply["receipt_sha256"]})
        for receipt in receipts:
            again = record(receipt["arm"], receipt["ordinal"],
                           receipt["original_sdk_wire_sha256"],
                           receipt["claim_sha256"])
            require(reserve(db, again)["decision"] == "DENY_ALREADY_CONSUMED",
                    "477_NATIVE_LOCAL_REPLAY_NOT_DENIED")
        require(count(db) == 8 and report["provider_posts"] == 0
                and report["score_status"] == "UNSCORED",
                "477_OFFLINE_NATIVE_LOCAL_JOIN_FAILED")
    return persisted


def run(with_native=False):
    ensure_offline()
    sim = demonstrate()
    receipts = native_join() if with_native else []
    return {
        "rule": RULE,
        "scope": "ONE_RUNNER_SHARED_SQLITE_SIMULATION_NOT_CROSS_RUNNER",
        "local_failure_matrix": sim,
        "same_run_native_posthoc_hash_joins": len(receipts),
        "native_hash_only_receipts": receipts,
        "simulated_processes_share_one_db_file": True,
        "durable_cross_runner_single_use_proven": False,
        "independent_protected_store_proven": False,
        "pre_dispatch_native_gate_integrated": False,
        "remote_iam_or_egress_proven": False,
        "live_sender_implemented": False,
        "owner_paid_approval": False,
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
    ensure_offline()
    path = (ROOT / args.output).resolve()
    require(path.is_relative_to(ROOT) and not path.exists()
            and not path.is_symlink(), "477_REPORT_CREATE_ONLY_REPO_PATH")
    outcome = run(with_native=args.with_native)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(outcome, indent=2, sort_keys=True) + "\n",
                    encoding="utf8")
    print("TASK4_477_SINGLE_HOST_MULTI_PROCESS_CAS_LOCAL_NO_PROVIDER")


if __name__ == "__main__":
    main()
