#!/usr/bin/env python3
"""Task4 #458 OFFLINE UNIX-socket broker: one-shot consume + ciphertext custody.

Separate client OS processes and a separate broker process share ONLY a local
UNIX socket. Broker owns one SQLite file; it atomically consumes an exact
trial/arm/ordinal before *synthetic* capture, never reissues a permit, stores
only #457-encrypted local fixture bytes, and survives broker process restart.

This does NOT span GitHub-hosted runners, authenticate a remote caller, attest
Provider identity, or permit real Provider POST. NO TCP or model client exists.
"""
from __future__ import annotations
import argparse
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

RULE = "TASK4_458_LOCAL_BROKER_ATOMIC_ONCE_CIPHERTEXT_RESTART_NO_PROVIDER_V1"
CASE = "banking:user_task_4:injection_task_0:direct"
MODEL = "gpt-4.1-mini-2025-04-14"
SCHEMA = "task4.local.sdk.preparse.encrypted.v1"
ARMS = ("A", "B")
ROOT = Path(__file__).resolve().parents[1]
SENSITIVE = ("OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "OPENAI_BASE_URL",
             "ANTHROPIC_API_KEY", "VERITAS_DATABASE_URL", "TASK4_458_LIVE_APPROVAL")
HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_LINE = 180_000
MAX_ENVELOPE = 90_000
SYNTHETIC_TRIAL = "458" + "0" * 61  # Only for local test; never a live grant.


class Refused(ValueError):
    pass


def need(p, reason):
    if p is not True:
        raise Refused(reason)


def sha(raw):
    return sha256(raw).hexdigest()


def canonical(x):
    return json.dumps(x, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf8")


def no_dupes(pairs):
    out = {}
    for key, val in pairs:
        need(key not in out, "458_DUPLICATE_JSON_FIELD")
        out[key] = val
    return out


def strict_load(b):
    need(type(b) is bytes and 0 < len(b) <= MAX_LINE, "458_BOUNDED_JSON")
    return json.loads(b.decode("utf8"), object_pairs_hook=no_dupes,
                      parse_constant=lambda _: (_ for _ in ()).throw(
                          Refused("458_NONFINITE_DENY")))


def b64decode(v):
    need(type(v) is str, "458_B64_REQUIRED")
    try:
        return base64.b64decode(v, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Refused("458_INVALID_BASE64") from exc


def deny_live_context():
    need(not any(os.environ.get(k) for k in SENSITIVE),
         "458_PROVIDER_SECRET_CONTEXT_DENIED")


def valid_key(row):
    need(type(row) is dict and row.get("trial") == SYNTHETIC_TRIAL
         and row.get("arm") in ARMS and type(row.get("ordinal")) is int
         and 0 <= row["ordinal"] < 5, "458_FROZEN_LOCAL_TRIAL_KEY_ONLY")


def prepare_db(path):
    need(isinstance(path, Path) and path.parent.is_dir()
         and not path.parent.is_symlink()
         and stat.S_IMODE(path.parent.stat().st_mode) == 0o700,
         "458_PRIVATE_BROKER_DB_PARENT_ONLY")
    conn = sqlite3.connect(path, timeout=10)
    try:
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("""
          CREATE TABLE IF NOT EXISTS attempted(
            trial TEXT NOT NULL, arm TEXT NOT NULL, ordinal INTEGER NOT NULL,
            request_sha TEXT NOT NULL, receipt_sha TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state='UNKNOWN_PERMANENTLY_CONSUMED'),
            ciphertext BLOB, ciphertext_sha TEXT,
            PRIMARY KEY(trial, arm, ordinal))
        """)
        conn.commit()
    finally:
        conn.close()
    os.chmod(path, 0o600)


def action(db, public_sha, packet):
    """Atomic and fsynced local DB transaction; NEVER a send permit."""
    need(type(packet) is dict and set(packet) in (
        {"op", "trial", "arm", "ordinal", "request_sha"},
        {"op", "trial", "arm", "ordinal", "receipt_sha", "envelope_b64"},
        {"op", "trial", "arm", "ordinal"},
    ), "458_EXACT_PACKET_FIELDS")
    valid_key(packet)
    op = packet["op"]
    need(op in ("consume", "attach", "read"), "458_KNOWN_LOCAL_OPCODE")
    conn = sqlite3.connect(db, timeout=10)
    try:
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("BEGIN IMMEDIATE" if op != "read" else "BEGIN")
        key = (packet["trial"], packet["arm"], packet["ordinal"])
        if op == "consume":
            req = packet["request_sha"]
            need(type(req) is str and HEX.fullmatch(req) is not None,
                 "458_EXACT_REQUEST_SHA")
            receipt = sha(canonical({
                "trial": key[0], "arm": key[1], "ordinal": key[2],
                "request_sha256": req,
                "state": "UNKNOWN_PERMANENTLY_CONSUMED",
                "source": "SYNTHETIC_LOCAL_NOT_PERMISSION"}))
            try:
                conn.execute(
                    "INSERT INTO attempted(trial,arm,ordinal,request_sha,"
                    "receipt_sha,state) VALUES(?,?,?,?,?,?)",
                    (*key, req, receipt, "UNKNOWN_PERMANENTLY_CONSUMED"))
            except sqlite3.IntegrityError:
                conn.rollback()
                return {"decision": "DENY_ALREADY_CONSUMED", "live_post": False}
            conn.commit()
            return {"decision": "LOCAL_CONSUMED_NO_SEND", "receipt_sha": receipt,
                    "live_post": False}
        cur = conn.execute(
            "SELECT request_sha,receipt_sha,ciphertext,ciphertext_sha "
            "FROM attempted WHERE trial=? AND arm=? AND ordinal=?", key).fetchone()
        need(cur is not None, "458_NO_PRIOR_CONSUMPTION")
        if op == "attach":
            need(type(packet["receipt_sha"]) is str
                 and packet["receipt_sha"] == cur[1]
                 and cur[2] is None, "458_RECEIPT_OR_SINGLE_ATTACH_ONLY")
            blob = b64decode(packet["envelope_b64"])
            need(0 < len(blob) <= MAX_ENVELOPE, "458_ENVELOPE_TOO_LARGE")
            env = strict_load(blob)
            need(type(env) is dict and set(env) == {
                "header", "ephemeral_x25519_public_b64", "hkdf_salt_b64",
                "aes256gcm_nonce_b64", "aes256gcm_ciphertext_b64"
            }, "458_AEAD_ENVELOPE_FIELDS")
            h = env["header"]
            need(type(h) is dict and h.get("schema") == SCHEMA
                 and h.get("case_id") == CASE and h.get("arm") == key[1]
                 and h.get("ordinal") == key[2]
                 and h.get("local_request_sha256") == cur[0]
                 and h.get("recipient_public_sha256") == public_sha
                 and h.get("capture_origin") ==
                     "LOCAL_SCRIPTED_HTTPX_MOCK_NOT_PROVIDER"
                 and h.get("authentication_independently_proven") is False,
                 "458_AEAD_SOURCE_OR_REQUEST_BINDING")
            for field, length in (("ephemeral_x25519_public_b64", 32),
                                  ("hkdf_salt_b64", 32),
                                  ("aes256gcm_nonce_b64", 12)):
                need(len(b64decode(env[field])) == length,
                     "458_CRYPTO_ENVELOPE_LENGTH")
            need(len(b64decode(env["aes256gcm_ciphertext_b64"])) >= 16,
                 "458_EMPTY_AUTHENTICATED_CIPHERTEXT")
            update = conn.execute(
                "UPDATE attempted SET ciphertext=?,ciphertext_sha=? "
                "WHERE trial=? AND arm=? AND ordinal=? AND ciphertext IS NULL",
                (blob, sha(blob), *key))
            need(update.rowcount == 1, "458_CIPHERTEXT_CAS_CONFLICT")
            conn.commit()
            return {"decision": "LOCAL_CIPHERTEXT_SEALED", "sha256": sha(blob),
                    "live_post": False}
        conn.commit()
        return {"decision": "LOCAL_CIPHERTEXT_READ_ONLY",
                "ciphertext_sha256": cur[3],
                "envelope_b64": (base64.b64encode(cur[2]).decode()
                                 if cur[2] is not None else None),
                "live_post": False}
    finally:
        conn.close()


class Broker(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False
    def __init__(self, sockpath, dbpath, public_sha):
        need(type(public_sha) is str and HEX.fullmatch(public_sha) is not None,
             "458_TEST_RECIPIENT_PIN_REQUIRED")
        self.dbpath = dbpath
        self.public_sha = public_sha
        super().__init__(str(sockpath), Handler)


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        # One bounded request per connection, fixed local JSON-only protocol.
        try:
            b = self.rfile.readline(MAX_LINE + 1)
            if len(b) > MAX_LINE:
                raise Refused("458_PACKET_TOO_LARGE")
            result = action(self.server.dbpath, self.server.public_sha,
                            strict_load(b.strip()))
        except (ValueError, KeyError, sqlite3.Error, UnicodeError):
            result = {"decision": "DENY_UNKNOWN_OR_MALFORMED", "live_post": False}
        self.wfile.write(canonical(result) + b"\n")


def exchange(sockpath: Path, packet):
    deny_live_context()
    need(isinstance(sockpath, Path) and sockpath.is_socket(),
         "458_LOCAL_UNIX_BROKER_REQUIRED")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(8)
        sock.connect(str(sockpath))
        sock.sendall(canonical(packet) + b"\n")
        reply = bytearray()
        while b"\n" not in reply:
            chunk = sock.recv(8192)
            need(bool(chunk) and len(reply) + len(chunk) <= MAX_LINE,
                 "458_BROKER_UNKNOWN_RESPONSE")
            reply.extend(chunk)
    result = strict_load(bytes(reply).strip())
    need(type(result) is dict and result.get("live_post") is False,
         "458_BROKER_NEVER_CONVEYS_LIVE_AUTHORITY")
    return result


def synthetic_request(arm, ordinal):
    return ("task4-458-local-wire-" + arm + "-" + str(ordinal)).encode()


def synthetic_response(arm, ordinal):
    return ("SYNTHETIC_PRIVATE_OFFLINE_458_" + arm + str(ordinal)).encode()


def worker(sockpath: Path, *, arm, ordinal, public_b64, crash=False):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from types import SimpleNamespace
    from scripts.task4_457_local_response_aead_v1 import SealedLocalVault
    deny_live_context()
    public = X25519PublicKey.from_public_bytes(b64decode(public_b64))
    req = synthetic_request(arm, ordinal)
    claim = exchange(sockpath, {"op":"consume", "trial":SYNTHETIC_TRIAL,
                               "arm":arm, "ordinal":ordinal,
                               "request_sha":sha(req)})
    if claim["decision"] != "LOCAL_CONSUMED_NO_SEND":
        need(claim["decision"] == "DENY_ALREADY_CONSUMED",
             "458_UNEXPECTED_CLAIM_DENIAL")
        return "DENIED_NO_RETRY"
    if crash:
        # Consume must survive a process death before any ciphertext exists.
        os._exit(74)
    with tempfile.TemporaryDirectory(prefix="task4-458-worker-private-") as td:
        local = SealedLocalVault(Path(td), public)
        rec = local.commit_before_parser(
            arm=arm, ordinal=ordinal,
            request=SimpleNamespace(content=req),
            response=SimpleNamespace(content=synthetic_response(arm, ordinal),
                                     status_code=200))
        blob = (Path(td) / rec["envelope_filename"]).read_bytes()
        saved = exchange(sockpath, {
            "op": "attach", "trial": SYNTHETIC_TRIAL,
            "arm": arm, "ordinal": ordinal,
            "receipt_sha": claim["receipt_sha"],
            "envelope_b64": base64.b64encode(blob).decode()})
        need(saved["decision"] == "LOCAL_CIPHERTEXT_SEALED"
             and saved["sha256"] == sha(blob),
             "458_ENCRYPTED_CUSTODY_UNKNOWN_NO_RETRY")
    return "CONSUMED_CIPHERTEXT_ONLY"


def recover_test_ciphertext(envelope: bytes, recipient_private):
    """Owner-only local verification; no decryption key shared with broker."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    env = strict_load(envelope)
    aad = canonical(env["header"])
    ep = X25519PublicKey.from_public_bytes(b64decode(
        env["ephemeral_x25519_public_b64"]))
    key = HKDF(algorithm=hashes.SHA256(), length=32,
               salt=b64decode(env["hkdf_salt_b64"]),
               info=b"VERITAS_TASK4_457_LOCAL_PREPARSE_V1:" + aad
               ).derive(recipient_private.exchange(ep))
    return AESGCM(key).decrypt(b64decode(env["aes256gcm_nonce_b64"]),
                               b64decode(env["aes256gcm_ciphertext_b64"]), aad)


def spawn_server(db, sockpath, public_sha):
    cmd = [sys.executable, str(Path(__file__).resolve()),
           "--mode", "broker", "--db", str(db), "--socket", str(sockpath),
           "--recipient-sha", public_sha]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if sockpath.is_socket():
                return proc
            if proc.poll() is not None:
                break
            time.sleep(.04)
        raise Refused("458_LOCAL_BROKER_START_FAILED")
    except BaseException:
        proc.terminate()
        proc.wait(timeout=5)
        raise


def stop_server(proc, sockpath):
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    sockpath.unlink(missing_ok=True)


def run_demo():
    """Independent workers, collision, crash, broker restart, encrypted readback."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    deny_live_context()
    recipient = X25519PrivateKey.generate()  # private owner key never exported
    pub = recipient.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(pub).decode()
    with tempfile.TemporaryDirectory(prefix="task4-458-broker-private-") as td:
        root = Path(td)
        db, sockpath = root / "broker.sqlite", root / "broker.sock"
        server = spawn_server(db, sockpath, sha(pub))
        outcomes = []
        try:
            # Six genuinely separate OS client processes compete per slot.
            for arm in ARMS:
                workers = [subprocess.Popen([
                    sys.executable, str(Path(__file__).resolve()), "--mode", "worker",
                    "--socket", str(sockpath), "--arm", arm, "--ordinal", "0",
                    "--recipient-public", pub_b64], stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, cwd=str(ROOT)) for _ in range(6)]
                for w in workers:
                    out, err = w.communicate(timeout=20)
                    need(w.returncode == 0 and not err,
                         "458_ISOLATED_CLIENT_FAILED")
                    outcomes.append(out.decode().strip())
            need(outcomes.count("CONSUMED_CIPHERTEXT_ONLY") == 2
                 and outcomes.count("DENIED_NO_RETRY") == 10,
                 "458_EXACT_ONE_WINNER_PER_SLOT")
            # A third attempt is consumed, then the process exits immediately.
            crash = subprocess.run([
                sys.executable, str(Path(__file__).resolve()), "--mode", "worker",
                "--socket", str(sockpath), "--arm", "A", "--ordinal", "1",
                "--recipient-public", pub_b64, "--crash-after-consume"],
                capture_output=True, cwd=str(ROOT), timeout=20)
            need(crash.returncode == 74,
                 "458_CRASH_AFTER_COMMIT_NOT_PROVEN")
        finally:
            stop_server(server, sockpath)
        # Independent NEW broker process, same previously fsynced broker DB.
        restarted = spawn_server(db, sockpath, sha(pub))
        try:
            verified = []
            for arm in ARMS:
                row = exchange(sockpath, {
                    "op": "read", "trial": SYNTHETIC_TRIAL, "arm": arm,
                    "ordinal": 0})
                need(row["decision"] == "LOCAL_CIPHERTEXT_READ_ONLY"
                     and type(row["envelope_b64"]) is str,
                     "458_POST_RESTART_CIPHERTEXT_MISSING")
                blob = b64decode(row["envelope_b64"])
                need(sha(blob) == row["ciphertext_sha256"]
                     and recover_test_ciphertext(blob, recipient) ==
                         synthetic_response(arm, 0),
                     "458_RECIPIENT_POST_RESTART_DECRYPTION_FAILED")
                refused = exchange(sockpath, {
                    "op": "consume", "trial": SYNTHETIC_TRIAL, "arm": arm,
                    "ordinal": 0, "request_sha": sha(synthetic_request(arm, 0))})
                need(refused["decision"] == "DENY_ALREADY_CONSUMED",
                     "458_RESTART_REPLAYED_CONSUMPTION")
                verified.append({"arm": arm,
                    "ciphertext_sha256": row["ciphertext_sha256"],
                    "recovered_only_by_ephemeral_owner": True})
            unknown = exchange(sockpath, {
                "op": "read", "trial": SYNTHETIC_TRIAL, "arm": "A", "ordinal": 1})
            need(unknown["envelope_b64"] is None,
                 "458_CRASH_BEFORE_CIPHERTEXT_EXPECTED")
            denied = exchange(sockpath, {
                "op": "consume", "trial": SYNTHETIC_TRIAL, "arm":"A",
                "ordinal":1, "request_sha":sha(synthetic_request("A", 1))})
            need(denied["decision"] == "DENY_ALREADY_CONSUMED",
                 "458_UNKNOWN_CRASH_RETRY_DENIED")
        finally:
            stop_server(restarted, sockpath)
        return {"rule_of_one": RULE, "case_id": CASE,
                "distinct_isolated_client_processes": 13,
                "competing_attempts_per_arm": 6,
                "consumed_slots_total": 3,
                "ciphertext_slots_verified_after_restart": 2,
                "crash_unknown_slot_denied_after_restart": True,
                "ciphertext_only_broker_storage": True,
                "ephemeral_recipient_key_exported": False,
                "external_api_identity_or_iam_proven": False,
                "cross_github_runner_distributed_authority_proven": False,
                "shared_filesystem_required": True,
                "external_off_host_ciphertext_custody_proven": False,
                "persistent_remote_service_provisioned": False,
                "actual_provider_calls": 0, "actual_bank_effects": 0,
                "genuine_utility_scores": 0, "live_dispatch": "DENY",
                "verified": verified}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=("broker", "worker", "offline-demo"),
                   required=True)
    p.add_argument("--db")
    p.add_argument("--socket")
    p.add_argument("--recipient-sha")
    p.add_argument("--recipient-public")
    p.add_argument("--arm", choices=ARMS)
    p.add_argument("--ordinal", type=int)
    p.add_argument("--crash-after-consume", action="store_true")
    p.add_argument("--output")
    a = p.parse_args()
    deny_live_context()
    if a.mode == "broker":
        need(all((a.db, a.socket, a.recipient_sha)),
             "458_EXACT_OFFLINE_BROKER_SETUP")
        db, sockpath = Path(a.db), Path(a.socket)
        need(sockpath.parent == db.parent and sockpath.parent.is_dir()
             and stat.S_IMODE(sockpath.parent.stat().st_mode) == 0o700
             and not sockpath.exists(), "458_PRIVATE_LOCAL_BROKER_ONLY")
        prepare_db(db)
        with Broker(sockpath, db, a.recipient_sha) as svc:
            os.chmod(sockpath, 0o600)
            svc.serve_forever(poll_interval=.25)
    elif a.mode == "worker":
        need(a.socket and a.arm and a.ordinal is not None
             and a.recipient_public, "458_BOUNDED_WORKER_ONLY")
        print(worker(Path(a.socket), arm=a.arm, ordinal=a.ordinal,
                     public_b64=a.recipient_public,
                     crash=a.crash_after_consume))
    else:
        need(a.output is not None, "458_OUTPUT_PATH_REQUIRED")
        out = (ROOT / a.output).resolve()
        need(out.is_relative_to(ROOT) and not out.exists(),
             "458_HASH_REPORT_CREATE_ONLY")
        r = run_demo()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(canonical(r) + b"\n")
        print("TASK4_458_OFFLINE_BROKER_TWO_CIPHERTEXT_ONE_UNKNOWN_RESTART_DENY")


if __name__ == "__main__":
    main()
