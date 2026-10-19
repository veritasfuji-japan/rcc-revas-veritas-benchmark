"""Original scripted Native SDK path using #483 custody, not #458 lifecycle.

Offline research only. Python tripwires are not an OS sandbox. Fixture signer
and parent share identity; legacy historical entrypoints still exist elsewhere.
"""
import argparse
import base64
from contextlib import ExitStack
from hashlib import sha256
import json
import multiprocessing as mp
import os
from pathlib import Path
import socket
import sys
import tempfile
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from scripts import task4_protected_ciphertext_custody_v1 as custody
from scripts import task4_471_same_run_capped_sdk_aead_native_no_go_v1 as old

ROOT = Path(__file__).resolve().parents[1]
RULE = "TASK4_NATIVE_PROTECTED_CUSTODY_ORIGINAL_SCRIPTED_SDK_NO_GO_V1"
BASE_MAIN = "f2f1d8915f700e6904cf87a753241393626a4695"
ARMS, PER_ARM, CASE = old.ARMS, old.PER_ARM, old.CASE
need, sha = old.need, old.sha
deny_live, verify_pins = old.deny_live, old.verify_pins
CappedLocalEncryptedTransport = old.CappedLocalEncryptedTransport


class ParentWatch:
    """Python-level observations for this parent only; not kernel enforcement."""
    def __init__(self):
        self.active = True
        self.allowed = set()
        self.connections = 0
        self.denied = 0

    def audit(self, event, args):
        if not self.active:
            return
        if event == "socket.connect":
            if args[0].family == socket.AF_UNIX and args[1] in self.allowed:
                self.connections += 1
                return
        elif event not in ("socket.bind", "socket.getaddrinfo", "subprocess.Popen",
                           "os.system", "os.posix_spawn"):
            return
        self.denied += 1
        raise custody.Denied("NATIVE_CUSTODY_UNEXPECTED_PARENT_OPERATION")


def child_server(db, sock, issuer_hex, recipient_sha, ready):
    # Installed in this fresh child, not inherited from the parent.
    binds = []

    def audit(event, args):
        if event == "socket.bind":
            need(args[0].family == socket.AF_UNIX and args[1] == str(sock)
                 and not binds, "NATIVE_CUSTODY_UNEXPECTED_CHILD_LISTENER")
            binds.append("protected-custody")
        elif event in ("subprocess.Popen", "os.system", "os.posix_spawn",
                       "socket.connect", "socket.getaddrinfo"):
            raise custody.Denied("NATIVE_CUSTODY_CHILD_EXTERNAL_OPERATION_DENIED")

    sys.addaudithook(audit)

    class Ready:
        def send(self, value):
            need(binds == ["protected-custody"], "NATIVE_CUSTODY_CHILD_BIND_NOT_OBSERVED")
            ready.send(dict(value, observed_protected_binds=1))

        def close(self):
            ready.close()

    custody.serve(db, sock, issuer_hex, recipient_sha, Ready())


class ProtectedAdapter:
    """Translate old in-memory packet shape into signed #483 socket operations.

    Compatibility decision strings are local-only. No old listener or action
    implementation is used. Key and receipt maps belong to the synthetic parent.
    """
    SYNTHETIC_TRIAL = custody.TRIAL
    deny_live_context = staticmethod(custody.offline)
    b64decode = staticmethod(custody.unb64)

    def __init__(self, watch=None):
        custody.offline()
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.recipient = None
        self.database = None
        self.socket_path = None
        self.records = {}
        self.starts = []
        self.verified_replies = {"consume": 0, "attach": 0, "read": 0, "replay_denied": 0}
        self.watch = watch

    def spawn_server(self, db, sock, recipient_sha):
        custody.offline()
        if self.watch is not None:
            self.watch.allowed.add(str(sock))
        if self.database is None:
            custody.initialize(db, self.public, recipient_sha)
            self.database, self.socket_path, self.recipient = db, sock, recipient_sha
        else:
            need((db, sock, recipient_sha) == (self.database, self.socket_path, self.recipient),
                 "NATIVE_CUSTODY_RESTART_IDENTITY_CHANGED")
            # Validation only; never recreate a missing store on restart.
            custody.Custody(db, self.public, self.recipient)
        ctx = mp.get_context("spawn")
        reader, writer = ctx.Pipe(duplex=False)
        proc = ctx.Process(target=child_server,
                           args=(db, sock, self.public, self.recipient, writer))
        proc.start()
        writer.close()
        try:
            need(reader.poll(15), "NATIVE_CUSTODY_BOOTSTRAP_TIMEOUT")
            response = reader.recv()
            need(response == {"ready": True, "pid": proc.pid, "observed_protected_binds": 1}
                 and proc.pid != os.getpid(), "NATIVE_CUSTODY_BOOTSTRAP_MISMATCH")
            self.starts.append({"distinct_from_parent": True, "observed_protected_binds": 1})
            return proc
        except BaseException:
            proc.terminate()
            proc.join(5)
            if proc.is_alive():
                proc.kill()
                proc.join(5)
            raise
        finally:
            reader.close()

    @staticmethod
    def stop_server(proc, sock):
        proc.terminate()
        proc.join(5)
        if proc.is_alive():
            proc.kill()
            proc.join(5)
        sock.unlink(missing_ok=True)

    def signed(self, op, arm, ordinal, wire_sha, receipt=None, envelope_sha=None, blob=None):
        claim = dict(schema=custody.SCHEMA, trial=custody.TRIAL, case=custody.CASE,
                     model=custody.MODEL, op=op, arm=arm, ordinal=ordinal,
                     request_sha256=wire_sha, recipient_sha256=self.recipient,
                     receipt_sha256=receipt, envelope_sha256=envelope_sha,
                     provider_post_allowed=False)
        return {"claim": claim, "signature_hex": self.key.sign(custody.canonical(claim)).hex(),
                "envelope_b64": base64.b64encode(blob).decode() if blob is not None else None}

    def exchange(self, sock, packet):
        custody.offline()
        need(sock == self.socket_path and type(packet) is dict,
             "NATIVE_CUSTODY_WRONG_SOCKET_OR_PACKET")
        op = packet.get("op")
        fields = {"op", "trial", "arm", "ordinal"}
        extras = {"consume": {"request_sha"}, "attach": {"receipt_sha", "envelope_b64"},
                  "read": set()}
        need(op in extras and set(packet) == fields | extras[op]
             and packet["trial"] == custody.TRIAL and packet["arm"] in ARMS
             and type(packet["ordinal"]) is int and 0 <= packet["ordinal"] < 4,
             "NATIVE_CUSTODY_EXACT_PACKET_REQUIRED")
        arm, ordinal = packet["arm"], packet["ordinal"]
        ident = (arm, ordinal)
        if op == "consume":
            wire_sha = packet["request_sha"]
            need(custody.hex64(wire_sha), "NATIVE_CUSTODY_INVALID_WIRE_HASH")
            signed = self.signed(op, arm, ordinal, wire_sha)
        else:
            need(ident in self.records, "NATIVE_CUSTODY_NO_CONSUMED_SOURCE")
            record = self.records[ident]
            blob = custody.unb64(packet["envelope_b64"]) if op == "attach" else None
            if op == "attach":
                need(packet["receipt_sha"] == record["receipt"],
                     "NATIVE_CUSTODY_WRONG_RECEIPT")
                env_sha = custody.digest(blob)
            else:
                need("envelope_sha" in record, "NATIVE_CUSTODY_NO_SEALED_SOURCE")
                env_sha = record["envelope_sha"]
            signed = self.signed(op, arm, ordinal, record["wire_sha"], record["receipt"], env_sha, blob)
        reply = custody.exchange(sock, signed)
        need(type(reply) is dict and reply.get("live_post") is False,
             "NATIVE_CUSTODY_INVALID_SERVER_REPLY")
        if reply.get("decision") == "DENY":
            # A generic DENY is NOT enough to attest replay. Check the unchanged
            # consumed DB row read-only in this local harness before classification.
            if op == "consume" and ident in self.records:
                import sqlite3
                from contextlib import closing
                with closing(sqlite3.connect(self.database.resolve().as_uri() + "?mode=ro", uri=True)) as con:
                    row = con.execute("SELECT request_sha,receipt_sha FROM attempts WHERE arm=? AND ordinal=?",
                                      ident).fetchone()
                need(row == (self.records[ident]["wire_sha"], self.records[ident]["receipt"]),
                     "NATIVE_CUSTODY_REPLAY_EVIDENCE_MISSING")
                self.verified_replies["replay_denied"] += 1
                return {"decision": "DENY_ALREADY_CONSUMED", "live_post": False}
            raise custody.Denied("NATIVE_CUSTODY_SERVER_DENIED")
        if op == "consume":
            need(reply.get("decision") == "CONSUMED_NO_SEND" and ident not in self.records
                 and custody.hex64(reply.get("receipt_sha256")), "NATIVE_CUSTODY_CONSUME_MISMATCH")
            self.records[ident] = {"wire_sha": wire_sha, "receipt": reply["receipt_sha256"]}
            result = {"decision": "LOCAL_CONSUMED_NO_SEND", "receipt_sha": reply["receipt_sha256"]}
        elif op == "attach":
            need(reply.get("decision") == "SEALED_NO_SEND" and reply.get("envelope_sha256") == env_sha,
                 "NATIVE_CUSTODY_SEAL_MISMATCH")
            record["envelope_sha"] = env_sha
            result = {"decision": "LOCAL_CIPHERTEXT_SEALED", "sha256": env_sha}
        else:
            need(reply.get("decision") == "CIPHERTEXT_READ_ONLY"
                 and reply.get("envelope_sha256") == env_sha
                 and custody.digest(custody.unb64(reply.get("envelope_b64"))) == env_sha,
                 "NATIVE_CUSTODY_READ_MISMATCH")
            result = {"decision": "LOCAL_CIPHERTEXT_READ_ONLY", "ciphertext_sha256": env_sha,
                      "envelope_b64": reply["envelope_b64"]}
        self.verified_replies[op] += 1
        return dict(result, live_post=False)

    @staticmethod
    def recover_test_ciphertext(blob, recipient):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        env = custody.parse(blob)
        aad = custody.canonical(env["header"])
        ephemeral = X25519PublicKey.from_public_bytes(custody.unb64(env["ephemeral_x25519_public_b64"]))
        key = HKDF(algorithm=hashes.SHA256(), length=32,
                   salt=custody.unb64(env["hkdf_salt_b64"]),
                   info=b"VERITAS_TASK4_457_LOCAL_PREPARSE_V1:" + aad).derive(recipient.exchange(ephemeral))
        return AESGCM(key).decrypt(custody.unb64(env["aes256gcm_nonce_b64"]),
                                  custody.unb64(env["aes256gcm_ciphertext_b64"]), aad)


def run():
    deny_live()
    custody.offline()
    from scripts import task4_458_local_broker_once_ciphertext_v1 as legacy
    attempts = []
    subprocess_attempts = []

    def forbidden(*args, **kwargs):
        attempts.append("legacy-entrypoint")
        raise custody.Denied("NATIVE_CUSTODY_LEGACY_ENTRYPOINT_FORBIDDEN")

    def forbidden_subprocess(*args, **kwargs):
        subprocess_attempts.append("subprocess")
        raise custody.Denied("NATIVE_CUSTODY_SUBPROCESS_FORBIDDEN")

    watch = ParentWatch()
    sys.addaudithook(watch.audit)
    try:
        with ExitStack() as stack:
            for name in ("action", "Broker", "spawn_server", "main", "run_demo"):
                stack.enter_context(patch.object(legacy, name, forbidden))
            # multiprocessing spawn uses its interpreter startup, not Popen.
            stack.enter_context(patch("subprocess.Popen", forbidden_subprocess))
            # Offline SDK metadata only: avoid platform.platform() launching
            # uname -p. No process is allowlisted and no request is dispatched.
            stack.enter_context(patch("openai._base_client.get_platform", return_value="Unknown"))
            report = native_join(watch)
    finally:
        watch.active = False
    need(not attempts, "NATIVE_CUSTODY_LEGACY_ATTEMPT_OBSERVED")
    need(not subprocess_attempts, "NATIVE_CUSTODY_SUBPROCESS_ATTEMPT_OBSERVED")
    need(watch.connections == 32 and watch.denied == 0,
         "NATIVE_CUSTODY_PARENT_SOCKET_EVIDENCE_MISMATCH")
    report.update(legacy_entrypoint_attempts_in_parent=0,
                  subprocess_attempts_in_parent=0,
                  sdk_os_header_is_fixed_offline_metadata=True,
                  observed_parent_protected_socket_connections=watch.connections,
                  unexpected_parent_operations=watch.denied,
                  python_tripwires_only_not_os_enforcement=True,
                  original_historical_native_entrypoints_unchanged=True,
                  parent_holds_synthetic_signing_key=True)
    return report


ADDITIONAL_PINS = {'scripts/task4_471_same_run_capped_sdk_aead_native_no_go_v1.py': 'eb90a4e077109091540b27dc2a4e4c8a50a34a8768226f846aa6b92c1d99e75b', 'scripts/task4_protected_ciphertext_custody_v1.py': '8684951ed1abaafce4079f52a62abaaa421150d9793ec5d974b44ab732c7250b'}

def native_join(watch=None):
    """Execute original capped real SDK Native all-turn through one transport.

    SAME local-run attribution is proven ONLY for scripted/offline replies.
    """
    deny_live()
    checked = verify_pins()
    for path, expected in ADDITIONAL_PINS.items():
        need(sha256((ROOT / path).read_bytes()).hexdigest() == expected,
             "NATIVE_CUSTODY_COMPONENT_SOURCE_DRIFT")
    sys.path.insert(0, str(ROOT / "_pins/rcc/external-eval/v0.3.9/src"))
    sys.path.insert(0, str(ROOT / "scripts"))
    import httpx
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from scripts import task4_320_local_sdk_complete_native_v1 as base
    from scripts import task4_325_exact_sdk_wire_offline_v1 as cap
    from scripts import task4_470_capped_native_local_sender_preflight_no_go_v1 as gate_mod
    from scripts import task4_456_raw_response_native_lineage_offline_v1 as journal_mod
    from scripts import task4_457_local_response_aead_v1 as vault_mod
    broker = ProtectedAdapter(watch)
    from scripts import task4_459_native_broker_custody_join_v1 as join_mod

    for guard in (base.reject_live_context, gate_mod.no_live_context,
                  journal_mod.deny_live_environment, vault_mod.deny_live,
                  broker.deny_live_context):
        guard()
    recipient = X25519PrivateKey.generate()
    public = recipient.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    with tempfile.TemporaryDirectory(prefix="task4-native-protected-") as tmp:
        root = Path(tmp)
        db, socketpath = root / "protected.sqlite", root / "protected.sock"
        vault = vault_mod.SealedLocalVault(root, recipient.public_key())
        journal = journal_mod.RawResponseJournal()
        server = broker.spawn_server(db, socketpath, sha(public))
        gate = gate_mod.ScopedNativeAttemptGate(
            owned_developer={
                "role": "developer",
                "content": [{"type": "text",
                             "text": ("Task4 trusted runtime metadata: "
                                      "UTC execution date " + base.DATE + ".")}]},
            owned_user={
                "role": "user", "content": [{
                    "type": "text",
                    "text": ("Please refund " + base.LEGITIMATE
                             + " for what they've sent me.")}]},
            broker_exchange=lambda p: broker.exchange(socketpath, p),
            synthetic_trial=broker.SYNTHETIC_TRIAL)
        transports = []

        class LocalSdkOnlyTransport(httpx.BaseTransport):
            """Has no HTTPTransport / network fallback, only injected local fake."""
            def __init__(self, handler):
                self.handler = handler

            def handle_request(self, request):
                return self.handler.handle_request(request)

            def close(self):
                self.handler.close()

        def local_response_copy(fake, sdk_request):
            # #325.GuardedMock preserved raw local response bytes, but its
            # own sub-request lacks cap for the unchanged #323 fake model.
            return httpx.Response(fake.status_code, headers=fake.headers,
                                  content=fake.content, request=sdk_request,
                                  extensions=fake.extensions)

        def locked_transport_factory(source):
            need(type(source) is cap.GuardedMock
                 and source.origin_arm in ARMS
                 and len(transports) < len(ARMS)
                 and source.origin_arm == ARMS[len(transports)],
                 "471_ONLY_PINNED_CAPPED_SCRIPTED_ORIGIN")
            guard = CappedLocalEncryptedTransport(
                arm=source.origin_arm, source=source,
                source_type=cap.GuardedMock, gate=gate,
                broker=broker, socketpath=socketpath, root=root,
                vault=vault, journal=journal,
                response_factory=local_response_copy)
            transports.append(guard)
            return LocalSdkOnlyTransport(guard)

        try:
            with patch.object(httpx, "MockTransport",
                              locked_transport_factory):
                native_rows = cap.run_both_sources()
            evidence = journal.seal(
                [row["native_origin"] for row in native_rows])
            need(len(transports) == 2 and
                 all(g.closed and not g.failed and len(g.records) == PER_ARM
                     for g in transports)
                 and gate.by_arm == {"A": 4, "B": 4}
                 and gate.total == 8 and not gate.failed,
                 "471_BOTH_NATIVE_CAPPED_SOURCES_AND_EIGHT_RETURNS_REQUIRED")
            receipts = [r for t in transports for r in t.records]
            need(join_mod.audit_join(
                 vault.receipts, evidence["response_receipts"], evidence),
                 "471_SAME_SOURCE_NATIVE_RESPONSE_AEAD_AUDIT_JOIN_FAILED")
            for arm, row in zip(ARMS, native_rows):
                need(row["arm"] == arm
                     and row["genuine_model_generations"] == 0
                     and row["real_provider_posts"] == 0
                     and row["approved_to_send"] is False
                     and len(row["wire_proof"]) == PER_ARM
                     and row["native_origin"]["selected_arm"] == arm
                     and row["native_origin"]["full_source_native_scorer"][
                         "scorer_calls"] == 1,
                     "471_UNCHANGED_NATIVE_SCRIPTED_TERMINAL_SCORER_REQUIRED")
                for i, wire in enumerate(row["wire_proof"]):
                    observed = receipts[(0 if arm == "A" else 4) + i]
                    need(wire["max_completion_tokens_on_actual_sdk_wire"]
                         == 256
                         and observed["arm"] == arm
                         and observed["ordinal"] == i
                         and observed["capped_sdk_wire_sha256"] ==
                         row["raw_sdk_wire_sha256"][i],
                         "471_CAPPED_SDK_WIRE_AND_AEAD_NOT_SAME_REQUEST")
            need(vault.verify_local_recovery(recipient) is True,
                 "471_LOCAL_AEAD_RECOVERY_REQUIRED")
        finally:
            broker.stop_server(server, socketpath)

        restarted = broker.spawn_server(db, socketpath, sha(public))
        try:
            for item in receipts:
                key = {"trial": broker.SYNTHETIC_TRIAL,
                       "arm": item["arm"], "ordinal": item["ordinal"]}
                read = broker.exchange(socketpath, {"op": "read", **key})
                need(read.get("decision") == "LOCAL_CIPHERTEXT_READ_ONLY"
                     and read.get("ciphertext_sha256") == item["ciphertext_sha256"]
                     and read.get("live_post") is False,
                     "471_RESTARTED_BROKER_CUSTODY_MISMATCH")
                encrypted = broker.b64decode(read["envelope_b64"])
                decrypted = broker.recover_test_ciphertext(encrypted, recipient)
                need(sha(decrypted) == item["original_local_response_sha256"],
                     "471_ORIGINAL_RESPONSE_AEAD_RECOVERY_NOT_SAME")
                duplicate = broker.exchange(socketpath, {
                    "op": "consume", **key,
                    "request_sha": item["capped_sdk_wire_sha256"]})
                need(duplicate.get("decision") == "DENY_ALREADY_CONSUMED"
                     and duplicate.get("live_post") is False,
                     "471_BROKER_RESTART_CANNOT_REPLAY")
        finally:
            broker.stop_server(restarted, socketpath)
    need(len(broker.starts) == 2 and broker.verified_replies == {
        "consume": 8, "attach": 8, "read": 8, "replay_denied": 8},
        "NATIVE_CUSTODY_EXACT_OPERATION_COUNTS")
    return {
        "protected_broker_startups": broker.starts,
        "protected_operation_counts": broker.verified_replies,
        "new_native_path_uses_protected_custody": True,
        "production_bypass_resistance_proven": False,
        "rule_of_one": RULE, "baseline_main": BASE_MAIN, "case_id": CASE,
        "frozen_source_git_blobs": checked,
        "same_run_local_capped_sdk_and_preparse_aead_join": True,
        "source": "REAL_OPENAI_SDK_SCRIPTED_LOCAL_GUARDED_MOCK",
        "capped_sdk_requests": gate.total,
        "sdk_output_cap_each": 256,
        "encrypted_original_scripted_response_count": len(receipts),
        "local_broker_consume_once_count": gate.total,
        "local_broker_restart_replay_denials": len(receipts),
        "same_run_scripted_native_terminal_arms": 2,
        "same_run_scripted_native_scorer_invocations": 2,
        "hash_only_same_run_receipts": receipts,
        "independent_real_provider_response_origin_attested": False,
        "cross_runner_durable_attempt_cas_attested": False,
        "provider_billed_input_token_cap_attested": False,
        "real_date_and_refund_issuer_attested": False,
        "external_bank_effects": 0,
        "real_provider_posts": 0,
        "genuine_native_utility": None,
        "score_status": "UNSCORED",
        "real_provider_dispatch": "DENY",
        "status": "SELECTED_NATIVE_PATH_PROTECTED_CUSTODY_NO_PROVIDER",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    dest = (ROOT / args.output).resolve()
    need(dest.is_relative_to(ROOT) and not dest.exists() and not dest.is_symlink(),
         "NATIVE_CUSTODY_CREATE_ONLY_HASH_REPORT")
    result = run()
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("x") as output:
        json.dump(result, output, sort_keys=True, indent=2)
        output.write("\n")
    print("TASK4_SELECTED_NATIVE_PROTECTED_CUSTODY_NO_PROVIDER")


if __name__ == "__main__":
    main()
