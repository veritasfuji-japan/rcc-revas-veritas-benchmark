#!/usr/bin/env python3
"""#425 no-Provider, no-tag, stdlib-only format diagnostic.

This is a READ-ONLY GitHub Environment secret-shape check. Its only output
is a fixed category; it intentionally cannot authenticate the Provider key
or authorize a subsequent paid request. No API SDK, HTTP client or GitHub
mutation code is imported.
"""
from __future__ import annotations

import base64
import binascii
import os
import re
import sys

REPO = "veritasfuji-japan/rcc-revas-veritas-benchmark"
ACTOR = "veritasfuji-japan"
REF = "refs/heads/main"
OUT_PREFIX = "TASK1_425_SAFE_NO_PAID_DIAGNOSTIC_"
SHA = re.compile(r"[a-f0-9]{40}\Z")
RUN = re.compile(r"[1-9][0-9]{5,19}\Z")
OK = "LOCAL_SECRET_FORMATS_VALID_NOT_PROVIDER_AUTHENTICATED"
DENIED = frozenset(("RUNTIME_CONTEXT", "API_KEY_FORMAT",
                    "AES256_KEY_FORMAT", "UNCLASSIFIED"))


def diagnose(environ):
    """Return a closed static reason, never a secret or derived metadata."""
    if not (environ.get("GITHUB_ACTIONS") == "true"
            and environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and environ.get("GITHUB_REPOSITORY") == REPO
            and environ.get("GITHUB_ACTOR") == ACTOR
            and environ.get("GITHUB_REF") == REF
            and environ.get("GITHUB_RUN_ATTEMPT") == "1"
            and type(environ.get("GITHUB_RUN_ID")) is str
            and RUN.fullmatch(environ["GITHUB_RUN_ID"]) is not None
            and type(environ.get("GITHUB_SHA")) is str
            and SHA.fullmatch(environ["GITHUB_SHA"]) is not None):
        return "RUNTIME_CONTEXT"

    api_key = environ.get("TASK1_OPENAI_API_KEY")
    if not (type(api_key) is str and len(api_key) > 20
            and api_key.strip() == api_key
            and not any(c.isspace() for c in api_key)):
        return "API_KEY_FORMAT"

    capture_key = environ.get("TASK1_CAPTURE_AES256_KEY")
    if type(capture_key) is not str:
        return "AES256_KEY_FORMAT"
    try:
        raw = base64.b64decode(capture_key, validate=True)
        if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != capture_key:
            return "AES256_KEY_FORMAT"
    except (ValueError, TypeError, binascii.Error):
        return "AES256_KEY_FORMAT"

    return OK


def main():
    try:
        status = diagnose(os.environ)
        if status != OK and status not in DENIED:
            status = "UNCLASSIFIED"
    except BaseException:
        # Unrecognized errors must never print exception text or traceback.
        status = "UNCLASSIFIED"
    print(OUT_PREFIX + status)
    return 0 if status == OK else 1


if __name__ == "__main__":
    sys.exit(main())
