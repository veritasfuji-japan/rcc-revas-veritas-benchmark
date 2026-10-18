#!/usr/bin/env python3
"""Task4 #457: encrypt a LOCAL SDK HTTP response before parser/native continuation.

Uses the original #323 MockTransport only, and #456's read-only source audit.
No live Provider transport, API keys, production recipient, external bank effect
or proof of durable custody across GitHub Actions runners. Private key is an
ephemeral local TEST recipient generated in memory, never exported.
"""
from __future__ import annotations

import argparse
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from unittest.mock import patch

RULE = "TASK4_457_LOCAL_RESPONSE_PREPARSE_ENCRYPTION_AAD_CREATE_ONLY_V1"
CASE = "banking:user_task_4:injection_task_0:direct"
ARMS = ("A", "B")
MODEL = "gpt-4.1-mini-2025-04-14"
ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 64_000
MAX_RECORDS = 8
SCHEMA = "task4.local.sdk.preparse.encrypted.v1"
SENSITIVE = (
    "OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "OPENAI_BASE_URL", "VERITAS_DATABASE_URL", "TASK4_457_LIVE_APPROVAL",
)


class Refused(ValueError):
    pass


def need(ok, reason):
    if ok is not True:
        raise Refused(reason)


def digest(raw: bytes):
    return sha256(raw).hexdigest()


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def deny_live():
    need(not any(os.environ.get(k) for k in SENSITIVE),
         "457_NO_REAL_PROVIDER_CREDENTIAL_CONTEXT")


def b64(b):
    return base64.b64encode(b).decode("ascii")


def strict_b64(t):
    need(type(t) is str, "457_EXACT_B64")
    try:
        return base64.b64decode(t, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Refused("457_INVALID_BASE64") from exc


def unique_json(pairs):
    out = {}
    for k, v in pairs:
        need(k not in out, "457_DUPLICATE_ENVELOPE_FIELD")
        out[k] = v
    return out


class SealedLocalVault:
    """Create-only ciphertext, fsynced on private local disk; no live auth.

    A ciphertext can be locally recovered in this TEST run only because its
    ephemeral recipient key is held by the test caller. The private key is
    never placed inside this vault, a repo file or a GitHub artifact.
    """

    def __init__(self, directory: Path, recipient_public):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        need(type(directory) is Path and not directory.is_symlink()
             and directory.is_dir(), "457_EXISTING_DIRECTORY_REQUIRED")
        mode = directory.stat().st_mode
        need(stat.S_ISDIR(mode) and stat.S_IMODE(mode) & 0o077 == 0,
             "457_PRIVATE_DIR_0700_REQUIRED")
        need(isinstance(recipient_public, X25519PublicKey),
             "457_PUBLIC_KEY_ONLY_REQUIRED")
        self.directory = directory
        self.public = recipient_public
        self.public_bytes = recipient_public.public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        self.seen = set()
        self.receipts = []
        self.failed = False
        self.closed = False

    def commit_before_parser(self, *, arm, ordinal, request, response):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        need(not self.closed and not self.failed,
             "457_VAULT_ALREADY_CLOSED_OR_UNKNOWN")
        # Claim the slot before ANY parsing, fsync or SDK continuation.
        ident = (arm, ordinal)
        self.seen.add(ident)
        try:
            need(arm in ARMS and type(ordinal) is int and 0 <= ordinal < 4
                 and ident not in {(r["arm"], r["ordinal"]) for r in self.receipts}
                 and len(self.seen) <= MAX_RECORDS,
                 "457_ONLY_EIGHT_FRESH_A_B_SLOTS")
            request_raw = request.content
            response_raw = response.content
            need(type(request_raw) is bytes and 0 < len(request_raw) <= MAX_BYTES
                 and type(response_raw) is bytes
                 and 0 <= len(response_raw) <= MAX_BYTES,
                 "457_BOUNDED_ORIGINAL_REQUEST_AND_RESPONSE")
            # Response status/header validity is deliberately NOT required
            # before encryption. Malformed responses are evidence too.
            header = {
                "schema": SCHEMA, "case_id": CASE, "arm": arm,
                "ordinal": ordinal, "model_expected_not_attested": MODEL,
                "local_request_sha256": digest(request_raw),
                "local_response_sha256": digest(response_raw),
                "http_status_observed_untrusted": (
                    response.status_code if type(response.status_code) is int else None),
                "recipient_public_sha256": digest(self.public_bytes),
                "capture_origin": "LOCAL_SCRIPTED_HTTPX_MOCK_NOT_PROVIDER",
                "authentication_independently_proven": False,
            }
            aad = canon(header)
            # Fresh ephemeral sender key for EVERY response. This and nonce
            # never repeat even across A/B or repeated whole test runs.
            ephemeral = X25519PrivateKey.generate()
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            epk = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            salt = os.urandom(32)
            nonce = os.urandom(12)
            key = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=salt,
                info=b"VERITAS_TASK4_457_LOCAL_PREPARSE_V1:" + aad
            ).derive(ephemeral.exchange(self.public))
            ciphertext = AESGCM(key).encrypt(nonce, response_raw, aad)
            envelope = {
                "header": header, "ephemeral_x25519_public_b64": b64(epk),
                "hkdf_salt_b64": b64(salt), "aes256gcm_nonce_b64": b64(nonce),
                "aes256gcm_ciphertext_b64": b64(ciphertext),
            }
            filename = f"task4-457-{arm}-{ordinal}.enc.json"
            serialized = canon(envelope) + b"\n"
            need(len(serialized) < 4 * MAX_BYTES + 4096,
                 "457_BOUNDED_CIPHERTEXT_ENVELOPE")
            # Create-only + fsync; never overwrite a previous receipt.
            # No plaintext temporary file exists.
            dfd = os.open(self.directory,
                          os.O_RDONLY | os.O_DIRECTORY |
                          getattr(os, "O_NOFOLLOW", 0))
            try:
                mode = os.fstat(dfd).st_mode
                need(stat.S_ISDIR(mode) and stat.S_IMODE(mode) & 0o077 == 0,
                     "457_PRIVATE_DIRECTORY_CHANGED")
                fd = os.open(filename,
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, "O_NOFOLLOW", 0),
                             0o600, dir_fd=dfd)
                with os.fdopen(fd, "wb") as f:
                    f.write(serialized)
                    f.flush()
                    os.fsync(f.fileno())
                os.fsync(dfd)
            finally:
                os.close(dfd)
            receipt = {
                "arm": arm, "ordinal": ordinal,
                "envelope_filename": filename,
                "envelope_bytes": len(serialized),
                "envelope_sha256": digest(serialized),
                "request_sha256": header["local_request_sha256"],
                "response_sha256": header["local_response_sha256"],
                "local_fsync_completed": True,
                "independent_durable_custody": False,
                "recipient_is_ephemeral_test_only": True,
                "external_provider_authenticated": False,
            }
            self.receipts.append(receipt)
            return receipt
        except BaseException:
            self.failed = True
            raise

    def verify_local_recovery(self, recipient_private):
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey, X25519PublicKey)
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        need(isinstance(recipient_private, X25519PrivateKey) and not self.failed
             and not self.closed and len(self.receipts) == 8,
             "457_COMPLETE_LOCAL_RECOVERY_ONLY")
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        need(recipient_private.public_key().public_bytes(
                 Encoding.Raw, PublicFormat.Raw) == self.public_bytes,
             "457_RECIPIENT_MUST_MATCH_TEST_KEY")
        for r in self.receipts:
            path = self.directory / r["envelope_filename"]
            need(path.is_file() and not path.is_symlink()
                 and stat.S_IMODE(path.stat().st_mode) == 0o600,
                 "457_ENCRYPTED_FILE_PRIVATE_AND_REGULAR")
            raw = path.read_bytes()
            need(digest(raw) == r["envelope_sha256"],
                 "457_CIPHERTEXT_ARCHIVE_MUTATED")
            e = json.loads(raw.decode("utf8"), object_pairs_hook=unique_json)
            need(type(e) is dict and set(e) == {
                "header", "ephemeral_x25519_public_b64",
                "hkdf_salt_b64", "aes256gcm_nonce_b64", "aes256gcm_ciphertext_b64"
            } and e["header"]["local_request_sha256"] == r["request_sha256"]
              and e["header"]["local_response_sha256"] == r["response_sha256"]
              and e["header"]["capture_origin"] ==
                  "LOCAL_SCRIPTED_HTTPX_MOCK_NOT_PROVIDER",
                 "457_RESPONSE_PROVENANCE_OR_SCHEMA_CHANGED")
            aad = canon(e["header"])
            ep = X25519PublicKey.from_public_bytes(
                strict_b64(e["ephemeral_x25519_public_b64"]))
            key = HKDF(algorithm=hashes.SHA256(), length=32,
                       salt=strict_b64(e["hkdf_salt_b64"]),
                       info=b"VERITAS_TASK4_457_LOCAL_PREPARSE_V1:" + aad
                       ).derive(recipient_private.exchange(ep))
            plaintext = AESGCM(key).decrypt(
                strict_b64(e["aes256gcm_nonce_b64"]),
                strict_b64(e["aes256gcm_ciphertext_b64"]), aad)
            need(digest(plaintext) == r["response_sha256"],
                 "457_RECOVERED_ORIGINAL_BYTES_CHANGED")
            # Do NOT emit or archive any recovered plaintext.
        self.closed = True
        return True


def run_local_native_encrypted_capture():
    """Actual #323 SDK→Native/scorer; encrypt prior to #456 parse/continuation."""
    deny_live()
    sys.path.insert(0, str(ROOT / "_pins/rcc/external-eval/v0.3.9/src"))
    sys.path.insert(0, str(ROOT / "scripts"))
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from scripts import task4_323_one_arm_local_sdk_v1 as driver
    from scripts import task4_456_raw_response_native_lineage_offline_v1 as prev
    from scripts import task4_320_local_sdk_complete_native_v1 as base
    base.reject_live_context()
    # Ephemeral local test key: secret never persisted or passed via environment.
    recipient = X25519PrivateKey.generate()
    with tempfile.TemporaryDirectory(prefix="task4-457-test-only-") as folder:
        vault = SealedLocalVault(Path(folder), recipient.public_key())
        original = driver.OneArmMock.__call__
        journal = prev.RawResponseJournal()

        def observe(server, request):
            need(type(server) is driver.OneArmMock and
                 server.origin_arm in ARMS and not vault.failed,
                 "457_ONLY_FROZEN_LOCAL_SCRIPTED_TRANSPORT")
            response = original(server, request)
            ordinal = server.attempts - 1
            # Original raw HTTP response MUST be encrypted+fsynced BEFORE
            # untrusted JSON is parsed or the SDK/native can see a response.
            vault.commit_before_parser(
                arm=server.origin_arm, ordinal=ordinal,
                request=request, response=response)
            journal.observe(arm=server.origin_arm, request=request,
                            response=response)
            return response  # exact same object, no fabricated model text

        try:
            with patch.object(driver.OneArmMock, "__call__", observe):
                rows = [driver.run_source(arm) for arm in ARMS]
            lineage = journal.seal(rows)
            need(vault.verify_local_recovery(recipient)
                 and lineage["real_provider_calls"] == 0
                 and lineage["complete_native_terminals_locally"] == 2
                 and lineage["detached_native_scorer_calls_locally"] == 2
                 and len(vault.receipts) == 8,
                 "457_ORIGINAL_NATIVE_SOURCE_AND_CIPHERTEXT_NOT_BOUND")
            return {
                "rule_of_one": RULE,
                "case_id": CASE,
                "source_class": "LOCAL_SCRIPTED_SDK_RAW_RESPONSE_ONLY",
                "encrypted_local_receipts": list(vault.receipts),
                "ciphertext_locally_fsynced_and_recovered": 8,
                "same_source_native_terminal_and_scorer": 2,
                "recipient_private_key_exported": False,
                "test_recipient_private_key_discarded_with_process": True,
                "real_recipient_key_management_proven": False,
                "external_custody_or_cross_runner_retention_proven": False,
                "ciphertext_persisted_after_test": False,
                "plaintext_logged_or_uploaded": False,
                "genuine_model_responses": 0,
                "new_genuine_utility_recoveries": 0,
                "real_provider_posts": 0,
                "external_bank_effects": 0,
                "live_provider_dispatch": "DENY",
                "native_lineage_report_sha256": digest(canon(lineage)),
            }
        finally:
            journal.clear()
    # TemporaryDirectory removes only ciphertext test files before return.


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=("offline-encrypt-local-responses",),
                   required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()
    deny_live()
    out = (ROOT / args.output).resolve()
    need(out.is_relative_to(ROOT) and not out.exists(),
         "457_EXCLUSIVE_HASH_ONLY_OUTPUT_IN_REPOSITORY")
    report = run_local_native_encrypted_capture()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(canon(report) + b"\n")
    print("TASK4_457_LOCAL_RESPONSE_AESGCM_ENCRYPT_BEFORE_NATIVE_NO_PROVIDER")


if __name__ == "__main__":
    main()
