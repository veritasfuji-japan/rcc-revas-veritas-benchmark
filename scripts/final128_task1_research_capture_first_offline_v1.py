#!/usr/bin/env python3
"""Task1 B-pilot: offline-only encrypted mock-response capture-before-parse.

This module has NO Provider client, network transport, credential loader,
GitHub API integration, tag creation, workflow dispatch, policy authority or
real-response origin authentication. Importing/calling it cannot send a model
request. It accepts caller-supplied in-memory bytes as UNTRUSTED MOCK DATA.

The encrypted envelope is committed to a private directory with no overwrite
before a deliberately injected validator examines the response. Parser failures
therefore leave a recoverable sealed mock response, not a plaintext artifact.

This is design evidence ONLY. It is not a production capture implementation.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCHEMA = "veritas.task1.research.capture-first.mock.v1"
REPO = "veritasfuji-japan/rcc-revas-veritas-benchmark"
CASE = "banking:user_task_1:injection_task_2:direct"
MODEL = "gpt-4.1-mini-2025-04-14"
MAX_MOCK_BYTES = 1_000_000
_RUN_ID = re.compile(r"^[1-9][0-9]{5,19}$")
_SHA40 = re.compile(r"^[a-f0-9]{40}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


class Refused(ValueError):
    """No origin trust or execution grant can be derived from this operation."""


def _need(ok: bool, reason: str) -> None:
    if ok is not True:
        raise Refused("TASK1_RESEARCH_CAPTURE_FIRST_" + reason)


def _canonical(obj: dict) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"),
        allow_nan=False, ensure_ascii=True,
    ).encode("ascii")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _aad(*, arm: str, run_id: str, main_sha: str,
         request_sha256: str) -> bytes:
    return _canonical({
        "schema": SCHEMA, "repository": REPO, "case": CASE, "model": MODEL,
        "arm": arm, "run_id": run_id, "main_sha": main_sha,
        "request_sha256": request_sha256,
        "scope": "IN_MEMORY_FAKE_RESPONSE_ONLY_NO_PROVIDER_AUTHORITY",
    })


def _write_exclusive_encrypted(directory: Path, filename: str,
                               payload: bytes) -> None:
    """Durable link of fully encrypted bytes, never overwrite final filename.

    Any interrupted temp file contains ENCRYPTED content only. A private
    directory is mandatory to keep temporary evidence out of shared paths.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    dir_fd = os.open(directory, flags)
    try:
        st = os.fstat(dir_fd)
        _need(stat.S_ISDIR(st.st_mode)
              and stat.S_IMODE(st.st_mode) & 0o077 == 0,
              "PRIVATE_OUTPUT_DIRECTORY_REQUIRED")
        tmp_name = "." + filename + "." + secrets.token_hex(12) + ".tmp"
        fd = os.open(
            tmp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600, dir_fd=dir_fd,
        )
        try:
            try:
                with os.fdopen(fd, "wb", closefd=True) as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
            except BaseException:
                # If fdopen did not take ownership, close safely if possible.
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
            # link is create-only; it NEVER replaces an existing capture.
            os.link(tmp_name, filename, src_dir_fd=dir_fd,
                    dst_dir_fd=dir_fd, follow_symlinks=False)
            os.fsync(dir_fd)
        finally:
            try:
                os.unlink(tmp_name, dir_fd=dir_fd)
                os.fsync(dir_fd)
            except FileNotFoundError:
                pass
    finally:
        os.close(dir_fd)


def seal_mock_before_parse(*, raw: bytes, aes256_key: bytes, output_dir: Path,
                           arm: str, run_id: str, main_sha: str,
                           request_sha256: str) -> dict:
    """Seal MOCK bytes without inspecting JSON/Provider-response correctness.

    Receipt/status are local caller assertions, not attestation, authorization
    or proof of an actual Provider reply. No plaintext is written to disk.
    """
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_MOCK_BYTES,
          "BOUNDED_MOCK_BYTES_REQUIRED")
    _need(type(aes256_key) is bytes and len(aes256_key) == 32,
          "LOCAL_32_BYTE_TEST_KEY_REQUIRED")
    _need(arm in ("A", "B") and type(arm) is str,
          "EXACT_ARM_REQUIRED")
    _need(type(run_id) is str and _RUN_ID.fullmatch(run_id) is not None,
          "MOCK_RUN_ID_REQUIRED")
    _need(type(main_sha) is str and _SHA40.fullmatch(main_sha) is not None,
          "PINNED_MAIN_SHA_REQUIRED")
    _need(type(request_sha256) is str
          and _SHA256.fullmatch(request_sha256) is not None,
          "OWNED_REQUEST_DIGEST_REQUIRED")
    _need(isinstance(output_dir, Path), "OUTPUT_DIRECTORY_PATH_REQUIRED")

    aad = _aad(arm=arm, run_id=run_id, main_sha=main_sha,
               request_sha256=request_sha256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes256_key).encrypt(nonce, raw, aad)
    envelope = {
        "schema": SCHEMA,
        "status": "UNTRUSTED_MOCK_RESPONSE_SEALED_PREVALIDATION",
        "origin_authenticated": False,
        "eligible_for_official_scoring": False,
        "eligible_for_paid_dispatch": False,
        "production_tag_consumed": False,
        "arm": arm,
        "run_id": run_id,
        "main_sha": main_sha,
        "request_sha256": request_sha256,
        "raw_sha256": _digest(raw),
        "aad_sha256": _digest(aad),
        "nonce_base64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_base64": base64.b64encode(ciphertext).decode("ascii"),
        "format": "AES256_GCM",
    }
    filename = "task1-research-" + arm + "-" + run_id + "-mock.enc.json"
    _write_exclusive_encrypted(output_dir, filename,
                               _canonical(envelope) + b"\n")
    return {
        "status": "SEALED_BEFORE_VALIDATION_NO_PROVIDER",
        "file": filename,
        "arm": arm,
        "request_sha256": request_sha256,
        "raw_sha256": _digest(raw),
        "provider_requests": 0,
        "production_tag_writes": 0,
        "real_origin_authenticated": False,
        "eligible_for_official_scoring": False,
    }


def rehearse_mock_then_validate(*, raw: bytes, aes256_key: bytes,
                               output_dir: Path, arm: str, run_id: str,
                               main_sha: str, request_sha256: str,
                               validator) -> dict:
    """Return no raw body, even when an injected validator raises.

    This tests ordering only: durable encrypted evidence FIRST, then parse.
    External effects and real Provider identity are structurally absent.
    """
    _need(callable(validator), "MOCK_VALIDATOR_REQUIRED")
    receipt = seal_mock_before_parse(
        raw=raw, aes256_key=aes256_key, output_dir=output_dir,
        arm=arm, run_id=run_id, main_sha=main_sha,
        request_sha256=request_sha256,
    )
    try:
        validator(raw)
    except Exception:
        return {
            **receipt,
            "status": "MOCK_VALIDATION_REFUSED_RAW_REMAINS_SEALED",
            "validated_mock": False,
        }
    return {
        **receipt,
        "status": "MOCK_VALIDATED_RAW_REMAINS_SEALED",
        "validated_mock": True,
    }
