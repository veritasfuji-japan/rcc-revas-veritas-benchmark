#!/usr/bin/env python3
"""#425: read-only Task1 Environment secret format diagnostic.

No import of Provider SDK, native agent, GitHub API client, network or sender.
No provider request, Git tag mutation, artifact, credential print or spending.
Only a fixed allowlisted reason category may reach stdout/stderr.
"""
from __future__ import annotations

import base64
import binascii
import os
import re
import sys

REPO = "veritasfuji-japan/rcc-revas-veritas-benchmark"
ENV = "task1-real-model-pilot"
VALID_SHA = re.compile(r"^[a-f0-9]{40}$")
VALID_RUN = re.compile(r"^[1-9][0-9]{5,19}$")
RESULTS = frozenset({
    "SHAPES_OK_NOT_A_PROVIDER_AUTHENTICATION",
    "GITHUB_RUNTIME_CONTEXT",
    "ENVIRONMENT_SCOPE",
    "API_KEY_FORMAT",
    "AES_KEY_BASE64_OR_LENGTH",
})
PREFIX = "TASK1_425_SECRET_FORMAT_DIAGNOSTIC="


def classify_secret_shapes(*, api_key, capture_base64):
    """Constant-category checks shared by the live sender and safe diagnostic."""
    if not (type(api_key) is str and len(api_key) > 20
            and api_key.strip() == api_key
            and not any(c.isspace() for c in api_key)):
        return "API_KEY_FORMAT"
    try:
        raw = base64.b64decode(capture_base64, validate=True)
    except (ValueError, TypeError, binascii.Error):
        return "AES_KEY_BASE64_OR_LENGTH"
    if not (len(raw) == 32 and
            base64.b64encode(raw).decode("ascii") == capture_base64):
        return "AES_KEY_BASE64_OR_LENGTH"
    return "SHAPES_OK_NOT_A_PROVIDER_AUTHENTICATION"


def classify_protected_diagnostic_context(e):
    # The diagnostic has no write/token rights and no spending consent.
    if not (e.get("GITHUB_ACTIONS") == "true"
            and e.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and e.get("GITHUB_REF") == "refs/heads/main"
            and e.get("GITHUB_REPOSITORY") == REPO
            and e.get("GITHUB_ACTOR") == "veritasfuji-japan"
            and e.get("GITHUB_RUN_ATTEMPT") == "1"
            and type(e.get("GITHUB_RUN_ID")) is str
            and VALID_RUN.fullmatch(e["GITHUB_RUN_ID"]) is not None
            and type(e.get("GITHUB_SHA")) is str
            and VALID_SHA.fullmatch(e["GITHUB_SHA"]) is not None):
        return "GITHUB_RUNTIME_CONTEXT"
    if e.get("TASK1_425_DIAGNOSTIC_ENVIRONMENT") != ENV:
        return "ENVIRONMENT_SCOPE"
    return classify_secret_shapes(
        api_key=e.get("TASK1_OPENAI_API_KEY"),
        capture_base64=e.get("TASK1_CAPTURE_AES256_KEY"))


def main():
    try:
        result = classify_protected_diagnostic_context(os.environ)
    except BaseException:
        result = "GITHUB_RUNTIME_CONTEXT"
    # Do not print original exception, token shape, key length, prefix,
    # suffix, fragment, mask, hash or environment variable contents.
    if result not in RESULTS:
        result = "GITHUB_RUNTIME_CONTEXT"
    print(PREFIX + result)
    raise SystemExit(0 if result ==
        "SHAPES_OK_NOT_A_PROVIDER_AUTHENTICATION" else 1)


if __name__ == "__main__":
    main()
