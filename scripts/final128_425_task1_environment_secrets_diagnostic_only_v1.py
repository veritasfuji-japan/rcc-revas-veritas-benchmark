#!/usr/bin/env python3
"""#425: independently runnable NO-PROVIDER/NO-TAG Environment secret format probe.

This is a separate *diagnostic*, not issuer, model sender, budget enforcement
or authentication test. Only static categoric values print; no secrets/lengths.
Stdlib only. The paid workflow and existing sender are NEVER imported here.
"""
from __future__ import annotations

import base64
import binascii
import os
import re
import sys

REPO = "veritasfuji-japan/rcc-revas-veritas-benchmark"
EXPECTED_ACTOR = "veritasfuji-japan"
PREFIX = "TASK1_425_SECRETS_ONLY_"
RUN_RE = re.compile(r"^[1-9][0-9]{5,19}$")
SHA_RE = re.compile(r"^[a-f0-9]{40}$")


class Refused(RuntimeError):
    """Internal constant reason ONLY, never call with interpolated secrets."""


def require(allowed, reason):
    if allowed is not True:
        raise Refused(reason)


def inspect_redacted(env):
    """Pure local syntax checks, no native source generation or outbound I/O."""
    require(
        env.get("GITHUB_ACTIONS") == "true"
        and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and env.get("GITHUB_REPOSITORY") == REPO
        and env.get("GITHUB_REF") == "refs/heads/main"
        and env.get("GITHUB_ACTOR") == EXPECTED_ACTOR
        and env.get("GITHUB_RUN_ATTEMPT") == "1"
        and type(env.get("GITHUB_RUN_ID")) is str
        and RUN_RE.fullmatch(env["GITHUB_RUN_ID"]) is not None
        and type(env.get("GITHUB_SHA")) is str
        and SHA_RE.fullmatch(env["GITHUB_SHA"]) is not None,
        "RUNTIME_CONTEXT",
    )
    api_key = env.get("TASK1_OPENAI_API_KEY")
    require(
        type(api_key) is str and len(api_key) > 20
        and api_key.strip() == api_key
        and not any(char.isspace() for char in api_key),
        "API_KEY_FORMAT",
    )
    capture = env.get("TASK1_CAPTURE_AES256_KEY")
    if type(capture) is not str:
        raise Refused("AES256_KEY_FORMAT")
    try:
        decoded = base64.b64decode(capture, validate=True)
    except (ValueError, binascii.Error):
        raise Refused("AES256_KEY_FORMAT") from None
    require(
        len(decoded) == 32
        and base64.b64encode(decoded).decode("ascii") == capture,
        "AES256_KEY_FORMAT",
    )
    return "FORMAT_OK_NO_PROVIDER_CALL_NO_TAG_NO_AUTHORITY"


def main():
    try:
        result = inspect_redacted(os.environ)
    except Refused as exc:
        code = str(exc)
        # Never echo untrusted exceptions or variable content, even if
        # future contributors accidentally interpolate a secret in Refused.
        if code not in {"RUNTIME_CONTEXT", "API_KEY_FORMAT", "AES256_KEY_FORMAT"}:
            code = "UNCLASSIFIED"
        print(PREFIX + code, file=sys.stderr)
        raise SystemExit(1) from None
    except BaseException:
        print(PREFIX + "UNCLASSIFIED", file=sys.stderr)
        raise SystemExit(1) from None
    print(PREFIX + result)


if __name__ == "__main__":
    main()
