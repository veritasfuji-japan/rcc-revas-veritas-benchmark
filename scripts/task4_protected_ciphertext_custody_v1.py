"""Offline signed consume/attach/read custody; no Provider or legacy Broker path.

Synthetic local protocol only. Same-UID storage and credentials are NOT isolated.
Not yet connected to the original Native SDK harness. No decryption key is held.
"""
import base64
from contextlib import closing
from hashlib import sha256
import json
import os
from pathlib import Path
import socket
import socketserver
import sqlite3
import stat

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = "task4.protected.ciphertext.custody.offline.v1"
CASE = "banking:user_task_4:injection_task_0:direct"
MODEL = "gpt-4.1-mini-2025-04-14"
TRIAL = "483" + "0" * 61
LIMIT = 180000
FIELDS = {"schema", "trial", "case", "model", "op", "arm", "ordinal",
          "request_sha256", "recipient_sha256", "receipt_sha256",
          "envelope_sha256", "provider_post_allowed"}
BLOCK_ENV = ("OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
             "OPENAI_BASE_URL", "VERITAS_DATABASE_URL", "TASK4_CUSTODY_LIVE")


class Denied(ValueError):
    pass


def need(value):
    if value is not True:
        raise Denied("CUSTODY_OFFLINE_DENY")


def offline():
    need(not any(os.environ.get(k) for k in BLOCK_ENV))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def digest(raw):
    return sha256(raw).hexdigest()


def hex64(value):
    return type(value) is str and len(value) == 64 and all(
        c in "0123456789abcdef" for c in value)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result)
        result[key] = value
    return result


def parse(raw):
    need(type(raw) is bytes and 0 < len(raw) <= LIMIT)
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: need(False))


def unb64(value):
    need(type(value) is str)
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Denied("CUSTODY_OFFLINE_DENY") from exc


def private_parent(path):
    need(isinstance(path, Path) and path.parent.is_dir()
         and not path.parent.is_symlink()
         and stat.S_IMODE(path.parent.stat().st_mode) == 0o700)


def initialize(path, issuer_hex, recipient_sha):
    offline()
    private_parent(path)
    need(hex64(issuer_hex) and hex64(recipient_sha))
    # Exclusive creation: a missing/replaced store is never auto-created on restart.
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    with closing(sqlite3.connect(path)) as con:
        con.execute("PRAGMA synchronous=FULL")
        con.execute("CREATE TABLE identity (schema TEXT, issuer TEXT, recipient TEXT)")
        con.execute("INSERT INTO identity VALUES(?,?,?)", (SCHEMA, issuer_hex, recipient_sha))
        con.execute("""CREATE TABLE attempts (
            arm TEXT NOT NULL, ordinal INTEGER NOT NULL,
            request_sha TEXT NOT NULL, receipt_sha TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state='CONSUMED_UNKNOWN_NO_SEND'),
            envelope BLOB, envelope_sha TEXT, PRIMARY KEY(arm,ordinal))""")
        con.commit()


class Custody:
    def __init__(self, path, issuer_hex, recipient_sha):
        offline()
        need(hex64(issuer_hex) and hex64(recipient_sha))
        self.path, self.issuer, self.recipient = path, issuer_hex, recipient_sha
        self.public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(issuer_hex))
        with closing(self.connect()) as con:
            need(con.execute("PRAGMA integrity_check").fetchone() == ("ok",))

    def connect(self):
        offline()
        private_parent(self.path)
        need(self.path.is_file() and not self.path.is_symlink()
             and stat.S_IMODE(self.path.stat().st_mode) == 0o600)
        con = sqlite3.connect(self.path.resolve().as_uri() + "?mode=rw", uri=True, timeout=.25)
        try:
            con.execute("PRAGMA synchronous=FULL")
            need(con.execute("SELECT * FROM identity").fetchall() == [
                (SCHEMA, self.issuer, self.recipient)])
            return con
        except BaseException:
            con.close()
            raise

    def verify(self, packet):
        offline()
        need(type(packet) is dict and set(packet) == {"claim", "signature_hex", "envelope_b64"})
        need(len(canonical(packet)) <= LIMIT)
        c = packet["claim"]
        need(type(c) is dict and set(c) == FIELDS)
        need(c["schema"] == SCHEMA and c["trial"] == TRIAL and c["case"] == CASE
             and c["model"] == MODEL and c["provider_post_allowed"] is False)
        need(c["op"] in ("consume", "attach", "read") and c["arm"] in ("A", "B")
             and type(c["ordinal"]) is int and 0 <= c["ordinal"] < 4
             and hex64(c["request_sha256"]) and c["recipient_sha256"] == self.recipient)
        if c["op"] == "consume":
            need(c["receipt_sha256"] is None and c["envelope_sha256"] is None)
        else:
            need(hex64(c["receipt_sha256"]) and hex64(c["envelope_sha256"]))
        need(type(packet["signature_hex"]) is str and len(packet["signature_hex"]) == 128)
        self.public.verify(bytes.fromhex(packet["signature_hex"]), canonical(c))
        if c["op"] != "attach":
            need(packet["envelope_b64"] is None)
        return c

    def envelope(self, packet, claim):
        blob = unb64(packet["envelope_b64"])
        need(0 < len(blob) <= 90000 and digest(blob) == claim["envelope_sha256"])
        env = parse(blob)
        need(type(env) is dict and set(env) == {"header", "ephemeral_x25519_public_b64",
             "hkdf_salt_b64", "aes256gcm_nonce_b64", "aes256gcm_ciphertext_b64"})
        header = env["header"]
        need(type(header) is dict and set(header) == {
            "schema", "case_id", "arm", "ordinal", "model_expected_not_attested",
            "local_request_sha256", "local_response_sha256", "http_status_observed_untrusted",
            "recipient_public_sha256", "capture_origin", "authentication_independently_proven"})
        need(header["schema"] == "task4.local.sdk.preparse.encrypted.v1"
             and header["case_id"] == CASE and header["arm"] == claim["arm"]
             and type(header["ordinal"]) is int and header["ordinal"] == claim["ordinal"]
             and header["model_expected_not_attested"] == MODEL
             and header["local_request_sha256"] == claim["request_sha256"]
             and header["recipient_public_sha256"] == self.recipient
             and hex64(header["local_response_sha256"])
             and header["capture_origin"] == "LOCAL_SCRIPTED_HTTPX_MOCK_NOT_PROVIDER"
             and header["authentication_independently_proven"] is False)
        need(header["http_status_observed_untrusted"] is None or
             type(header["http_status_observed_untrusted"]) is int)
        for name, size in (("ephemeral_x25519_public_b64", 32),
                           ("hkdf_salt_b64", 32), ("aes256gcm_nonce_b64", 12)):
            need(len(unb64(env[name])) == size)
        need(16 <= len(unb64(env["aes256gcm_ciphertext_b64"])) <= 64016)
        return blob

    def dispatch(self, packet):
        try:
            return self.apply(packet)
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError,
                InvalidSignature, sqlite3.Error, OSError):
            return {"decision": "DENY", "live_post": False}

    def apply(self, packet):
        c = self.verify(packet)
        blob = self.envelope(packet, c) if c["op"] == "attach" else None
        key = (c["arm"], c["ordinal"])
        with closing(self.connect()) as con:
            try:
                con.execute("BEGIN IMMEDIATE")
                row = con.execute("SELECT request_sha,receipt_sha,state,envelope,envelope_sha "
                                  "FROM attempts WHERE arm=? AND ordinal=?", key).fetchone()
                if c["op"] == "consume":
                    need(row is None)
                    receipt = digest(canonical({"claim": c, "issuer": self.issuer,
                                               "state": "CONSUMED_UNKNOWN_NO_SEND"}))
                    con.execute("INSERT INTO attempts VALUES(?,?,?,?,?,NULL,NULL)",
                                (*key, c["request_sha256"], receipt, "CONSUMED_UNKNOWN_NO_SEND"))
                    reply = {"decision": "CONSUMED_NO_SEND", "receipt_sha256": receipt}
                else:
                    need(row is not None and row[0] == c["request_sha256"]
                         and row[1] == c["receipt_sha256"] and row[2] == "CONSUMED_UNKNOWN_NO_SEND")
                    if c["op"] == "attach":
                        need(row[3] is None and row[4] is None)
                        cur = con.execute("UPDATE attempts SET envelope=?,envelope_sha=? "
                                          "WHERE arm=? AND ordinal=? AND envelope IS NULL",
                                          (blob, c["envelope_sha256"], *key))
                        need(cur.rowcount == 1)
                        reply = {"decision": "SEALED_NO_SEND", "envelope_sha256": digest(blob)}
                    else:
                        need(type(row[3]) is bytes and row[4] == c["envelope_sha256"]
                             and digest(row[3]) == row[4])
                        reply = {"decision": "CIPHERTEXT_READ_ONLY",
                                 "envelope_sha256": row[4],
                                 "envelope_b64": base64.b64encode(row[3]).decode()}
                con.commit()
                return dict(reply, live_post=False)
            except BaseException:
                con.rollback()
                raise


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(3)
        try:
            packet = parse(self.rfile.readline(LIMIT + 1))
            result = self.server.custody.dispatch(packet)
        except (ValueError, TypeError, RecursionError, OSError):
            result = {"decision": "DENY", "live_post": False}
        self.wfile.write(canonical(result) + b"\n")


def serve(path, socket_path, issuer_hex, recipient_sha, ready):
    """Existing store only. Parent fixture initializes it; no legacy imports."""
    try:
        gate = Custody(path, issuer_hex, recipient_sha)
        need(socket_path.parent == path.parent and not socket_path.exists()
             and not socket_path.is_symlink())
        with socketserver.UnixStreamServer(str(socket_path), Handler) as server:
            server.custody = gate
            os.chmod(socket_path, 0o600)
            ready.send({"ready": True, "pid": os.getpid()})
            server.serve_forever(poll_interval=.05)
    finally:
        ready.close()


def exchange(socket_path, packet):
    offline()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(str(socket_path))
        sock.sendall(canonical(packet) + b"\n")
        with sock.makefile("rb") as stream:
            return parse(stream.readline(LIMIT + 1))
