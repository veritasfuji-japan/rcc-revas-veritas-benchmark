#!/usr/bin/env python3
"""Task4 #480: broker-OWNED Ed25519 synthetic NO_SEND + SQLite CAS.

Offline-only protected *local* UNIX socket endpoint. Legacy #458 endpoint
and its direct action() function remain accessible if separately deployed.
No IAM/egress isolation and absolutely NO real Provider send path.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import multiprocessing as mp
import os
from pathlib import Path
import socketserver
import tempfile
import threading
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts import task4_458_local_broker_once_ciphertext_v1 as legacy
from scripts import task4_476_native_wire_separate_signer_no_go_v1 as native
from scripts import task4_477_simulated_shared_store_single_use_no_go_v1 as ledger

ROOT = Path(__file__).resolve().parents[1]
RULE = "TASK4_480_BROKER_OWNED_SIGNED_CAS_OFFLINE_NO_GO_V1"
POLICY = native.signer.digest(b"task4-480-broker-owned-synthetic-no-send-policy")
FIELDS = frozenset({
    "op", "trial", "arm", "ordinal", "request_sha", "claim", "signature_hex",
})
DENY = "DENY_BROKER_REQUIRED_SIGNED_CAS"
Denied = ledger.Denied


def require(cond, code):
    if cond is not True:
        raise Denied(code)


def offline():
    ledger.ensure_offline()
    legacy.deny_live_context()


def claim_for(arm, ordinal, wire_sha):
    return native.native.make_claim(
        arm=arm, ordinal=ordinal, wire_sha=wire_sha,
        policy_digest=POLICY, nonce=f"480-{arm}-{ordinal}")


def packet_for(arm, ordinal, wire_sha, claim, signature_hex):
    return {
        "op": "consume", "trial": legacy.SYNTHETIC_TRIAL,
        "arm": arm, "ordinal": ordinal, "request_sha": wire_sha,
        "claim": claim, "signature_hex": signature_hex,
    }


class SignedGate:
    """The server owns verification and local CAS; client-side hook is NOT trusted."""

    def __init__(self, cas_path: Path, broker_path: Path, public_hex: str,
                 revoked_slots=frozenset()):
        offline()
        require(type(public_hex) is str and len(public_hex) == 64,
                "480_PUBLIC_ISSUER_PIN_REQUIRED")
        try:
            self.public = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(public_hex))
        except (ValueError, TypeError) as exc:
            raise Denied("480_BAD_ISSUER_PUBLIC_KEY") from exc
        self.cas_path = cas_path
        self.broker_path = broker_path
        self.revoked_slots = frozenset(revoked_slots)

    def consume(self, packet):
        """The ONLY consume operation the protected socket handler exposes.

        Validate scoped claim and real signature before durable local CAS,
        then call #458's *NO_SEND ONLY* synthetic storage operation.
        Ambiguous post-CAS broker failure burns the slot and denies retry.
        """
        offline()
        require(type(packet) is dict and set(packet) == FIELDS,
                "480_EXACT_SIGNED_CONSUME_PACKET_REQUIRED")
        require(packet["op"] == "consume"
                and packet["trial"] == legacy.SYNTHETIC_TRIAL,
                "480_NO_DIRECT_LEGACY_OR_SEND_OPCODE")
        arm, ordinal, wire_sha = (packet["arm"], packet["ordinal"],
                                  packet["request_sha"])
        require(arm in ("A", "B") and type(ordinal) is int
                and 0 <= ordinal < 4
                and type(wire_sha) is str
                and len(wire_sha) == 64
                and all(c in "0123456789abcdef" for c in wire_sha),
                "480_FROZEN_ARM_ORDINAL_SDK_SHA_REQUIRED")
        require((arm, ordinal) not in self.revoked_slots,
                "480_SERVER_REVOKED_SCOPE")
        expected = claim_for(arm, ordinal, wire_sha)
        claim, signature_hex = packet["claim"], packet["signature_hex"]
        require(type(claim) is dict and claim == expected
                and set(claim) == set(expected)
                and claim["provider_post_allowed"] is False,
                "480_SIGNED_CLAIM_SCOPE_OR_NO_SEND_MISMATCH")
        require(type(signature_hex) is str and len(signature_hex) == 128,
                "480_SIGNATURE_REQUIRED")
        try:
            signature = bytes.fromhex(signature_hex)
            self.public.verify(signature, native.signer.canonical(claim))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise Denied("480_SIGNATURE_NOT_ISSUED_BY_PINNED_SIGNER") from exc
        claim_sha = native.signer.digest(native.signer.canonical(claim))
        row = ledger.record(arm, ordinal, wire_sha, claim_sha)
        cas = ledger.reserve(self.cas_path, row)
        require(cas["decision"] == "CONSUMED_UNKNOWN_NO_SEND"
                and cas["provider_post_allowed"] is False,
                "480_BROKER_LOCAL_CAS_REPLAY_OR_STORE_REFUSED")
        legacy_result = legacy.action(
            self.broker_path, "a" * 64, {
                "op": "consume",
                "trial": legacy.SYNTHETIC_TRIAL,
                "arm": arm, "ordinal": ordinal,
                "request_sha": wire_sha,
            })
        require(legacy_result["decision"] == "LOCAL_CONSUMED_NO_SEND"
                and legacy_result["live_post"] is False,
                "480_POST_CAS_BROKER_MUST_STAY_NO_SEND")
        return {
            "decision": "BROKER_SIGNED_LOCAL_CAS_CONSUMED_NO_SEND",
            "arm": arm, "ordinal": ordinal,
            "original_sdk_wire_sha256": wire_sha,
            "signed_claim_sha256": claim_sha,
            "cas_receipt_sha256": cas["receipt_sha256"],
            "legacy_no_send_receipt_sha256": legacy_result["receipt_sha"],
            "provider_post_allowed": False, "live_post": False,
        }


class ProtectedHandler(socketserver.StreamRequestHandler):
    def handle(self):
        # Only SignedGate.consume is routed, NEVER raw legacy.action.
        try:
            raw = self.rfile.readline(legacy.MAX_LINE + 1)
            require(len(raw) <= legacy.MAX_LINE,
                    "480_PACKET_OVERSIZE")
            packet = legacy.strict_load(raw.strip())
            reply = self.server.gate.consume(packet)
        except Exception:
            # FAIL CLOSED, including SQLite error or client corruption.
            reply = {"decision": DENY, "live_post": False}
        self.wfile.write(legacy.canonical(reply) + b"\n")


class ProtectedBroker(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, socket_path: Path, gate: SignedGate):
        self.gate = gate
        super().__init__(str(socket_path), ProtectedHandler)


def signed_request(conn, arm, ordinal, wire_sha):
    claim = claim_for(arm, ordinal, wire_sha)
    conn.send({"op": "sign_synthetic_no_send", "claim": claim})
    signed = conn.recv()
    require(signed.get("decision") == "SIGNED_SYNTHETIC_NO_SEND",
            "480_SEPARATE_SIGNER_DENIED")
    return packet_for(arm, ordinal, wire_sha, claim,
                      signed["signature_hex"])


def denied_socket(path: Path, packet):
    reply = legacy.exchange(path, packet)
    return reply == {"decision": DENY, "live_post": False}


def run(with_native=False):
    offline()
    ctx = mp.get_context("spawn")
    signer_parent, signer_child = ctx.Pipe()
    proc = ctx.Process(target=native.signer.signer_child,
                       args=(signer_child,))
    proc.start()
    signer_child.close()
    try:
        info = signer_parent.recv()
        require(info["pid"] != os.getpid(),
                "480_SIGNER_NOT_SEPARATE_OS_PROCESS")
        with tempfile.TemporaryDirectory(prefix="task4-480-secure-broker-") as tmp:
            root = Path(tmp)
            cas_path = root / "signed-cas.sqlite"
            broker_db = root / "broker-no-send.sqlite"
            socket_path = root / "protected.sock"
            ledger.init_store(cas_path)
            legacy.prepare_db(broker_db)
            gate = SignedGate(cas_path, broker_db, info["public_hex"])
            with ProtectedBroker(socket_path, gate) as server:
                thread = threading.Thread(target=server.serve_forever,
                                          daemon=True)
                thread.start()
                try:
                    sha0 = sha256(b"480-local-unsigned-attacker").hexdigest()
                    unsigned = {"op": "consume", "trial": legacy.SYNTHETIC_TRIAL,
                                "arm": "A", "ordinal": 0,
                                "request_sha": sha0}
                    unsigned_refused = denied_socket(socket_path, unsigned)
                    direct_opcode_refused = denied_socket(socket_path, {
                        "op": "send_live", "trial": legacy.SYNTHETIC_TRIAL,
                        "arm": "A", "ordinal": 0,
                    })
                    fake = packet_for(
                        "A", 0, sha0, claim_for("A", 0, sha0), "0" * 128)
                    forged_refused = denied_socket(socket_path, fake)
                    require(unsigned_refused and direct_opcode_refused
                            and forged_refused
                            and ledger.count(cas_path) == 0,
                            "480_UNAUTHENTICATED_REQUEST_MUST_NOT_CONSUME")

                    observed = []
                    def guarded(arm, ordinal, wire_sha):
                        pkt = signed_request(signer_parent, arm, ordinal, wire_sha)
                        reply = legacy.exchange(socket_path, pkt)
                        require(reply.get("decision")
                                == "BROKER_SIGNED_LOCAL_CAS_CONSUMED_NO_SEND"
                                and reply.get("original_sdk_wire_sha256")
                                == wire_sha
                                and reply.get("live_post") is False,
                                "480_SIGNED_BROKER_GATE_DID_NOT_CONSUME")
                        observed.append({
                            "arm": arm, "ordinal": ordinal,
                            "original_sdk_wire_sha256": wire_sha,
                            "cas_receipt_sha256": reply["cas_receipt_sha256"],
                            "signed_claim_sha256": reply["signed_claim_sha256"],
                        })
                        return pkt

                    if with_native:
                        original = native.native.prior.check_sdk_wire

                        def inline_before_worker(arm, ordinal, raw):
                            scope = original(arm, ordinal, raw)
                            guarded(arm, ordinal,
                                    scope["original_sdk_wire_sha256"])
                            return scope

                        with patch.object(native.native.prior,
                                          "check_sdk_wire", inline_before_worker):
                            report = (native.native.prior
                                      .run_offline_native_budget_join())
                        require(report["offline_sdk_requests_budget_checked"] == 8
                                and report["same_run_worker_once_claims"] == 8
                                and report["same_run_preparse_aead_scripted_responses"] == 8
                                and report["restart_replays_denied"] == 8
                                and report["real_provider_posts"] == 0
                                and report["score_status"] == "UNSCORED",
                                "480_NATIVE_OFFLINE_AEAD_WORKER_JOIN_DRIFT")
                        require(all(
                            a["original_sdk_wire_sha256"]
                            == b["original_sdk_wire_sha256"]
                            for a, b in zip(
                                observed,
                                report["hash_only_budget_preflight_receipts"])),
                                "480_ORIGINAL_SDK_WIRE_SHA_MISMATCH")
                    else:
                        for arm in ("A", "B"):
                            for ordinal in range(4):
                                guarded(arm, ordinal, sha256(
                                    f"480-synthetic-{arm}-{ordinal}".encode()
                                ).hexdigest())
                        report = None

                    require(len(observed) == 8
                            and ledger.count(cas_path) == 8,
                            "480_BROKER_OWNED_EIGHT_CAS_CONSUMPTIONS_REQUIRED")
                    first = observed[0]
                    signed_replay = signed_request(
                        signer_parent, first["arm"], first["ordinal"],
                        first["original_sdk_wire_sha256"])
                    replay_refused = denied_socket(socket_path, signed_replay)
                    tampered = dict(signed_replay, request_sha="f" * 64)
                    tamper_refused = denied_socket(socket_path, tampered)
                    require(replay_refused and tamper_refused,
                            "480_DIRECT_SIGNED_REPLAY_OR_TAMPER_ALLOWED")
                    return {
                        "rule": RULE,
                        "broker_side_signature_verified": True,
                        "broker_side_atomic_local_cas_consumptions": len(observed),
                        "direct_unsigned_legacy_consume_refused": unsigned_refused,
                        "direct_send_live_opcode_refused": direct_opcode_refused,
                        "forged_signature_refused": forged_refused,
                        "signed_replay_refused": replay_refused,
                        "changed_sdk_digest_refused": tamper_refused,
                        "native_original_sdk_inline_broker_gated":
                            8 if with_native else 0,
                        "native_deny_only_worker_claims":
                            report["same_run_worker_once_claims"] if report else 0,
                        "native_preparse_aead_scripted_responses":
                            report["same_run_preparse_aead_scripted_responses"]
                            if report else 0,
                        "hash_only_broker_owned_cas_receipts": observed,
                        "protected_endpoint_only_exposes_signed_handler": True,
                        "legacy_raw_broker_endpoint_still_unprotected": True,
                        "same_runner_and_os_identity": True,
                        "broker_sqlite_independently_protected": False,
                        "cross_runner_single_use_proven": False,
                        "independent_iam_network_egress_proven": False,
                        "production_non_bypassable_sender_proven": False,
                        "real_owner_approval": False,
                        "real_provider_posts": 0,
                        "external_bank_effects": 0,
                        "genuine_native_utility": None,
                        "score_status": "UNSCORED",
                        "no_go": True,
                    }
                finally:
                    server.shutdown()
                    thread.join(timeout=5)
    finally:
        if proc.is_alive():
            try:
                signer_parent.send({"op": "stop"})
            except (EOFError, BrokenPipeError):
                pass
        proc.join(timeout=5)
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=5)
        signer_parent.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--with-native", action="store_true")
    args = parser.parse_args()
    offline()
    output = (ROOT / args.output).resolve()
    require(output.is_relative_to(ROOT) and not output.exists()
            and not output.is_symlink(),
            "480_CREATE_ONLY_REPOSITORY_OUTPUT_REQUIRED")
    report = run(with_native=args.with_native)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
    print("TASK4_480_BROKER_OWNED_SIGNED_LOCAL_CAS_NO_PROVIDER")


if __name__ == "__main__":
    main()
