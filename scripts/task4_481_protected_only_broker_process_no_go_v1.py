#!/usr/bin/env python3
"""Task4 #481: isolated protected-only local Broker server without a legacy listener.

Only offline signed synthetic NO_SEND claims. The legacy #458 callable and CLI
still exist outside this *bounded process*. This does NOT establish production
non-bypassability, independent IAM, or a cross-runner shared ledger.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import multiprocessing as mp
import os
from pathlib import Path
import socket
import sqlite3
import stat
import tempfile
import time
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts import task4_480_broker_owned_signed_cas_no_go_v1 as prior

ROOT = Path(__file__).resolve().parents[1]
RULE = "TASK4_481_PROTECTED_ONLY_BROKER_PROCESS_NO_LEGACY_LISTENER_NO_GO_V1"
Denied = prior.Denied
LEGACY = prior.legacy
NATIVE = prior.native
FIELDS = prior.FIELDS
STATE = "UNKNOWN_PERMANENTLY_NO_SEND"


def require(cond, code):
    if cond is not True:
        raise Denied(code)


def offline():
    prior.offline()


def private_root(root):
    require(isinstance(root, Path) and root.is_dir() and not root.is_symlink()
            and stat.S_IMODE(root.stat().st_mode) == 0o700,
            "481_PRIVATE_TEST_DIRECTORY_REQUIRED")


def init_store(path):
    offline()
    private_root(path.parent)
    require(isinstance(path, Path) and not path.exists() and not path.is_symlink(),
            "481_FIRST_BOOT_STORE_CREATE_ONLY")
    conn = sqlite3.connect(str(path), timeout=0.25)
    try:
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("""CREATE TABLE protected_attempt (
            trial TEXT NOT NULL, arm TEXT NOT NULL, ordinal INTEGER NOT NULL,
            wire_sha256 TEXT NOT NULL, claim_sha256 TEXT NOT NULL,
            receipt_sha256 TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state='UNKNOWN_PERMANENTLY_NO_SEND'),
            PRIMARY KEY(trial,arm,ordinal))""")
        conn.commit()
    finally:
        conn.close()
    os.chmod(path, 0o600)


def verify_existing_store(path):
    offline()
    private_root(path.parent)
    require(path.is_file() and not path.is_symlink()
            and stat.S_IMODE(path.stat().st_mode) == 0o600,
            "481_RESTART_STORE_MUST_EXIST_UNMODIFIED")
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=0.25) as con:
            columns = [c[1] for c in con.execute(
                "PRAGMA table_info(protected_attempt)")]
            require(columns == [
                "trial", "arm", "ordinal", "wire_sha256", "claim_sha256",
                "receipt_sha256", "state",
            ], "481_PROTECTED_STORE_SCHEMA_DRIFT")
            require(con.execute("PRAGMA integrity_check").fetchone()[0] == "ok",
                    "481_STORE_INTEGRITY_FAILURE")
    except (sqlite3.Error, OSError) as exc:
        raise Denied("481_STORE_UNAVAILABLE_FAIL_CLOSED") from exc


def count(path):
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as con:
        return con.execute("SELECT COUNT(*) FROM protected_attempt").fetchone()[0]


class ProtectedOnlyGate:
    """Signature and single-use are verified INSIDE the protected Broker process."""

    def __init__(self, db, public_hex, revoked=frozenset()):
        offline()
        verify_existing_store(db)
        try:
            require(type(public_hex) is str and len(public_hex) == 64,
                    "481_PINNED_SIGNER_KEY_REQUIRED")
            self.public = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(public_hex))
        except (ValueError, TypeError) as exc:
            raise Denied("481_INVALID_SIGNER_KEY") from exc
        self.db = db
        self.revoked = frozenset(revoked)

    def consume(self, packet):
        offline()
        require(type(packet) is dict and set(packet) == FIELDS,
                "481_ONLY_EXACT_SIGNED_PACKET_ALLOWED")
        require(packet["op"] == "consume"
                and packet["trial"] == LEGACY.SYNTHETIC_TRIAL,
                "481_NO_LEGACY_OR_LIVE_OPCODE")
        arm = packet["arm"]
        ordinal = packet["ordinal"]
        wire_sha = packet["request_sha"]
        require(arm in ("A", "B") and type(ordinal) is int
                and 0 <= ordinal < 4 and type(wire_sha) is str
                and len(wire_sha) == 64
                and all(c in "0123456789abcdef" for c in wire_sha),
                "481_FROZEN_SYNTHETIC_SCOPE_REQUIRED")
        require((arm, ordinal) not in self.revoked,
                "481_BROKER_REVOKED_SCOPE")
        expected = prior.claim_for(arm, ordinal, wire_sha)
        claim = packet["claim"]
        signature = packet["signature_hex"]
        require(type(claim) is dict and set(claim) == set(expected)
                and claim == expected
                and claim["provider_post_allowed"] is False,
                "481_CLAIM_SCOPE_AND_NO_SEND_REQUIRED")
        require(type(signature) is str and len(signature) == 128,
                "481_SIGNATURE_REQUIRED")
        try:
            self.public.verify(bytes.fromhex(signature),
                               NATIVE.signer.canonical(claim))
        except (ValueError, InvalidSignature, TypeError) as exc:
            raise Denied("481_WRONG_ISSUER_OR_TAMPERED_SIGNATURE") from exc
        claim_sha = NATIVE.signer.digest(NATIVE.signer.canonical(claim))
        receipt = NATIVE.signer.digest(LEGACY.canonical({
            "trial": LEGACY.SYNTHETIC_TRIAL, "arm": arm, "ordinal": ordinal,
            "wire_sha256": wire_sha, "claim_sha256": claim_sha,
            "state": STATE, "provider_post_allowed": False,
        }))
        verify_existing_store(self.db)
        try:
            con = sqlite3.connect(
                f"file:{self.db}?mode=rw", uri=True, timeout=0.20)
            try:
                con.execute("PRAGMA synchronous=FULL")
                con.execute("BEGIN IMMEDIATE")
                row = con.execute(
                    "SELECT 1 FROM protected_attempt WHERE trial=? AND arm=?"
                    " AND ordinal=?", (LEGACY.SYNTHETIC_TRIAL, arm, ordinal)
                ).fetchone()
                if row is not None:
                    con.rollback()
                    raise Denied("481_BROKER_ATOMIC_CAS_ALREADY_CONSUMED")
                con.execute(
                    "INSERT INTO protected_attempt"
                    "(trial,arm,ordinal,wire_sha256,claim_sha256,receipt_sha256,state)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (LEGACY.SYNTHETIC_TRIAL, arm, ordinal, wire_sha,
                     claim_sha, receipt, STATE))
                con.commit()
            finally:
                con.close()
        except (sqlite3.Error, OSError) as exc:
            raise Denied("481_STORAGE_ERROR_FAIL_CLOSED") from exc
        return {
            "decision": "BROKER_PROTECTED_ONLY_SYNTHETIC_CONSUMED_NO_SEND",
            "arm": arm, "ordinal": ordinal,
            "original_sdk_wire_sha256": wire_sha,
            "signed_claim_sha256": claim_sha,
            "cas_receipt_sha256": receipt,
            "provider_post_allowed": False, "live_post": False,
        }


def broker_child(root_str, public_hex, bootstrap, restart=False):
    """One distinct OS process. No legacy socket listener or legacy.action call."""
    root = Path(root_str)
    try:
        offline()
        private_root(root)
        db = root / "protected-only.sqlite"
        sock = root / "protected-only.sock"
        if restart:
            verify_existing_store(db)
        else:
            init_store(db)
        require(not sock.exists() and not sock.is_symlink(),
                "481_PROTECTED_LISTENER_MUST_BE_NEW")
        # These are tripwires, not an OS sandbox. Never import/use the raw
        # #458 Broker listener or raw action in the protected process.
        def forbidden(*args, **kwargs):
            raise Denied("481_LEGACY_BROKER_PATH_NOT_ALLOWED_IN_PROCESS")
        with patch.object(LEGACY, "Broker", forbidden), \
                patch.object(LEGACY, "action", forbidden), \
                patch.object(LEGACY, "spawn_server", forbidden):
            gate = ProtectedOnlyGate(db, public_hex)
            with prior.ProtectedBroker(sock, gate) as server:
                os.chmod(sock, 0o600)
                sockets = list(root.glob("*.sock"))
                require(sockets == [sock] and sock.is_socket(),
                        "481_ONLY_PROTECTED_SOCKET_ALLOWED")
                bootstrap.send({"ready": True, "pid": os.getpid(),
                                "one_protected_socket": True,
                                "legacy_listener_started": False,
                                "legacy_raw_action_called": False})
                server.serve_forever(poll_interval=0.05)
    except BaseException as exc:
        try:
            bootstrap.send({"ready": False, "failure": type(exc).__name__})
        except (BrokenPipeError, EOFError):
            pass
    finally:
        bootstrap.close()


def start_broker(ctx, root, public_hex, restart=False):
    ours, child = ctx.Pipe(duplex=False)
    proc = ctx.Process(
        target=broker_child, args=(str(root), public_hex, child, restart))
    proc.start()
    child.close()
    try:
        require(ours.poll(10), "481_BROKER_BOOTSTRAP_TIMEOUT")
        response = ours.recv()
        require(response.get("ready") is True
                and response.get("pid") == proc.pid
                and response.get("one_protected_socket") is True
                and response.get("legacy_listener_started") is False
                and response.get("legacy_raw_action_called") is False,
                "481_ONLY_PROTECTED_PROCESS_BOOTSTRAP_REQUIRED")
        return proc, root / "protected-only.sock"
    except BaseException:
        proc.terminate()
        proc.join(timeout=5)
        raise
    finally:
        ours.close()


def stop_broker(proc, sock):
    if proc.is_alive():
        proc.terminate()
    proc.join(timeout=5)
    if proc.is_alive():
        proc.kill()
        proc.join(timeout=5)
    sock.unlink(missing_ok=True)


def deny_exchange(socket_path, packet):
    return LEGACY.exchange(socket_path, packet) == {
        "decision": prior.DENY, "live_post": False}


def run(with_native=False):
    offline()
    ctx = mp.get_context("spawn")
    signer_parent, signer_child = ctx.Pipe()
    signer = ctx.Process(target=NATIVE.signer.signer_child,
                         args=(signer_child,))
    signer.start()
    signer_child.close()
    try:
        require(signer_parent.poll(10),
                "481_SIGNER_BOOTSTRAP_TIMEOUT")
        signer_info = signer_parent.recv()
        require(signer_info["pid"] == signer.pid
                and signer.pid != os.getpid(),
                "481_SIGNER_DISTINCT_OS_PROCESS_REQUIRED")
        with tempfile.TemporaryDirectory(prefix="task4-481-protected-only-") as td:
            root = Path(td)
            private_root(root)
            broker, sock = start_broker(ctx, root, signer_info["public_hex"])
            try:
                require(broker.pid != signer.pid and broker.pid != os.getpid(),
                        "481_BROKER_MUST_BE_THIRD_OS_PROCESS")
                unsigned = {
                    "op": "consume", "trial": LEGACY.SYNTHETIC_TRIAL,
                    "arm": "A", "ordinal": 0, "request_sha": "a" * 64,
                }
                unsigned_refused = deny_exchange(sock, unsigned)
                send_refused = deny_exchange(sock, {
                    "op": "send_live", "trial": LEGACY.SYNTHETIC_TRIAL,
                    "arm": "A", "ordinal": 0,
                })
                bad = prior.packet_for(
                    "A", 0, "a" * 64,
                    prior.claim_for("A", 0, "a" * 64), "0" * 128)
                forged_refused = deny_exchange(sock, bad)
                require(unsigned_refused and send_refused and forged_refused
                        and count(root / "protected-only.sqlite") == 0,
                        "481_UNAUTHENTICATED_OR_LIVE_DIRECT_REQUEST_DENIED")
                receipts = []

                def guarded(arm, ordinal, wire_sha):
                    pkt = prior.signed_request(
                        signer_parent, arm, ordinal, wire_sha)
                    reply = LEGACY.exchange(sock, pkt)
                    require(
                        reply.get("decision")
                        == "BROKER_PROTECTED_ONLY_SYNTHETIC_CONSUMED_NO_SEND"
                        and reply.get("original_sdk_wire_sha256") == wire_sha
                        and reply.get("provider_post_allowed") is False
                        and reply.get("live_post") is False,
                        "481_PROTECTED_ONLY_BROKER_SCOPE_OR_DENIAL")
                    receipts.append({
                        "arm": arm, "ordinal": ordinal,
                        "original_sdk_wire_sha256": wire_sha,
                        "signed_claim_sha256": reply["signed_claim_sha256"],
                        "cas_receipt_sha256": reply["cas_receipt_sha256"],
                    })

                if with_native:
                    original = NATIVE.native.prior.check_sdk_wire

                    def inline_before_worker(arm, ordinal, raw):
                        scope = original(arm, ordinal, raw)
                        guarded(arm, ordinal,
                                scope["original_sdk_wire_sha256"])
                        return scope

                    with patch.object(NATIVE.native.prior, "check_sdk_wire",
                                      inline_before_worker):
                        report = (
                            NATIVE.native.prior.run_offline_native_budget_join())
                    require(
                        report["offline_sdk_requests_budget_checked"] == 8
                        and report["same_run_worker_once_claims"] == 8
                        and report["same_run_preparse_aead_scripted_responses"] == 8
                        and report["restart_replays_denied"] == 8
                        and report["real_provider_posts"] == 0
                        and report["score_status"] == "UNSCORED",
                        "481_NATIVE_SDK_ORIGINAL_WIRE_CHAIN_FAILED")
                    require(all(
                        a["original_sdk_wire_sha256"]
                        == b["original_sdk_wire_sha256"]
                        for a, b in zip(
                            receipts,
                            report["hash_only_budget_preflight_receipts"])),
                        "481_NATIVE_WIRE_CAS_SHA_EVIDENCE_DRIFT")
                else:
                    for arm in ("A", "B"):
                        for ordinal in range(4):
                            guarded(arm, ordinal, sha256(
                                f"481-synthetic-{arm}-{ordinal}".encode()
                            ).hexdigest())
                    report = None
                require(len(receipts) == 8
                        and count(root / "protected-only.sqlite") == 8,
                        "481_EIGHT_ATOMIC_SYNTHETIC_CAS_REQUIRED")
                first = receipts[0]
                signed = prior.signed_request(
                    signer_parent, first["arm"], first["ordinal"],
                    first["original_sdk_wire_sha256"])
                replay_refused = deny_exchange(sock, signed)
                mutated = dict(signed, request_sha="f" * 64)
                tamper_refused = deny_exchange(sock, mutated)
                require(replay_refused and tamper_refused,
                        "481_LOCAL_SIGNED_REPLAY_OR_SHA_TAMPER_ALLOWED")
                sockets = sorted(p.name for p in root.glob("*.sock"))
                require(sockets == ["protected-only.sock"],
                        "481_UNEXPECTED_UNPROTECTED_SOCKET")
            finally:
                stop_broker(broker, sock)

            # Restart exactly the same protected-only server, persisting one CAS DB.
            restarted, socket_path = start_broker(
                ctx, root, signer_info["public_hex"], restart=True)
            try:
                restart_replay_refused = deny_exchange(socket_path, signed)
                restart_unsigned_refused = deny_exchange(socket_path, unsigned)
                require(restart_replay_refused and restart_unsigned_refused
                        and count(root / "protected-only.sqlite") == 8
                        and sorted(p.name for p in root.glob("*.sock"))
                        == ["protected-only.sock"],
                        "481_PROTECTED_ONLY_RESTART_OR_REPLAY_FAILED")
            finally:
                stop_broker(restarted, socket_path)
            return {
                "rule": RULE,
                "broker_distinct_os_process": True,
                "signer_distinct_os_process": True,
                "protected_only_process_has_no_legacy_socket": True,
                "protected_process_forbids_raw_legacy_action": True,
                "broker_owned_atomic_cas_claims": len(receipts),
                "direct_unsigned_consume_refused": unsigned_refused,
                "direct_live_opcode_refused": send_refused,
                "forged_signature_refused": forged_refused,
                "same_run_signed_replay_refused": replay_refused,
                "modified_original_sdk_sha_refused": tamper_refused,
                "restart_signed_replay_refused": restart_replay_refused,
                "restart_unsigned_direct_consume_refused":
                    restart_unsigned_refused,
                "original_native_sdk_pre_worker_broker_gated":
                    8 if with_native else 0,
                "native_deny_only_worker_claims":
                    report["same_run_worker_once_claims"] if report else 0,
                "native_preparse_aead_scripted_responses":
                    report["same_run_preparse_aead_scripted_responses"]
                    if report else 0,
                "hash_only_protected_broker_receipts": receipts,
                "legacy_broker_global_callable_still_available": True,
                "legacy_broker_cli_still_deployable": True,
                "same_runner_and_os_identity": True,
                "independently_protected_broker_and_db_proven": False,
                "cross_runner_single_use_proven": False,
                "production_unbypassable_egress_proven": False,
                "real_owner_approval": False,
                "real_provider_posts": 0,
                "external_bank_effects": 0,
                "genuine_native_utility": None,
                "score_status": "UNSCORED",
                "no_go": True,
            }
    finally:
        if signer.is_alive():
            try:
                signer_parent.send({"op": "stop"})
            except (EOFError, BrokenPipeError):
                pass
        signer.join(timeout=5)
        if signer.is_alive():
            signer.terminate()
            signer.join(timeout=5)
        signer_parent.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    ap.add_argument("--with-native", action="store_true")
    args = ap.parse_args()
    offline()
    target = (ROOT / args.output).resolve()
    require(target.is_relative_to(ROOT) and not target.exists()
            and not target.is_symlink(),
            "481_HASH_ONLY_REPORT_CREATE_ONLY_REPOSITORY")
    result = run(with_native=args.with_native)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print("TASK4_481_PROTECTED_ONLY_PROCESS_NO_LEGACY_LISTENER_NO_PROVIDER")


if __name__ == "__main__":
    main()
