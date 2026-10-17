#!/usr/bin/env python3
"""#425: stdlib-only exact shared Task1 key-format check, NO model sender.

Never writes a secret, key fingerprint, length, partial string, or decoded
ciphertext. This probe is purely syntactic: successful local checks DO NOT
authenticate an OpenAI key or authorize, fund, or initiate a paid API call.
"""
from __future__ import annotations

import base64
import binascii
import os
import re
import sys

REPO = "veritasfuji-japan/rcc-revas-veritas-benchmark"
REASONS = frozenset({
    "RUNTIME_CONTEXT", "API_KEY_FORMAT", "AES256_KEY_FORMAT",
    "READY_FORMAT_ONLY_NO_PROVIDER_AUTHORITY",
    "UNCLASSIFIED",
})
RUN_ID = re.compile(r"^[1-9][0-9]{5,19}$")
SHA = re.compile(r"^[a-f0-9]{40}$")


class SecretFormatRefused(Exception):
    """Only a fixed reason code, NEVER a caller-originated value."""

    def __init__(self, code: str):
        if code not in ("API_KEY_FORMAT", "AES256_KEY_FORMAT"):
            code = "UNCLASSIFIED"
        self.code = code
        super().__init__(code)


def validate_secret_formats(*, api_key, capture_base64):
    """Exact Task1 live sender key checks; returns key material IN MEMORY.

    All validation errors are fixed categories, not secret-derived strings.
    """
    if (type(api_key) is not str or len(api_key) <= 20 or
            api_key.strip() != api_key or
            any(c.isspace() for c in api_key)):
        raise SecretFormatRefused("API_KEY_FORMAT")
    if type(capture_base64) is not str:
        raise SecretFormatRefused("AES256_KEY_FORMAT")
    try:
        raw = base64.b64decode(capture_base64, validate=True)
    except (ValueError, TypeError, binascii.Error):
        raise SecretFormatRefused("AES256_KEY_FORMAT") from None
    if (len(raw) != 32 or
            base64.b64encode(raw).decode("ascii") != capture_base64):
        raise SecretFormatRefused("AES256_KEY_FORMAT")
    return api_key, raw


def context_is_exact_protected_dispatch(environ):
    """Only accept the protected first-run main environment context.

    This diagnostic intentionally does NOT demand paid consent/billing
    phrases; it cannot authorize sending and never returns a lease.
    """
    run = environ.get("GITHUB_RUN_ID")
    sha = environ.get("GITHUB_SHA")
    return (
        environ.get("GITHUB_ACTIONS") == "true"
        and environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and environ.get("GITHUB_REF") == "refs/heads/main"
        and environ.get("GITHUB_REPOSITORY") == REPO
        and environ.get("GITHUB_ACTOR") == "veritasfuji-japan"
        and environ.get("GITHUB_RUN_ATTEMPT") == "1"
        and type(run) is str and RUN_ID.fullmatch(run) is not None
        and type(sha) is str and SHA.fullmatch(sha) is not None
    )


def diagnostic_code(environ):
    """Returns ONLY a static category, with no exposed secret characters."""
    if not context_is_exact_protected_dispatch(environ):
        return "RUNTIME_CONTEXT"
    try:
        validate_secret_formats(
            api_key=environ.get("TASK1_OPENAI_API_KEY"),
            capture_base64=environ.get("TASK1_CAPTURE_AES256_KEY"))
    except SecretFormatRefused as exc:
        return exc.code
    except BaseException:
        return "UNCLASSIFIED"
    return "READY_FORMAT_ONLY_NO_PROVIDER_AUTHORITY"


def main():
    # No args, network, file writes or trust token. Secret values stay only
    # in the protected runner's process memory.
    code = diagnostic_code(os.environ)
    if code not in REASONS:
        code = "UNCLASSIFIED"
    print("TASK1_425_NO_PAID_DIAGNOSTIC_" + code)
    return 0 if code == "READY_FORMAT_ONLY_NO_PROVIDER_AUTHORITY" else 2


if __name__ == "__main__":
    sys.exit(main())
