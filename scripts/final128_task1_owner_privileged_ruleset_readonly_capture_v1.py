#!/usr/bin/env python3
"""Owner-side REAL GitHub Ruleset read-only checkpoint, NOT live authority.

Run only on a trusted operator-controlled computer with locally scoped GitHub
credentials. This intentionally cannot run inside GitHub Actions/CI. It does
not persist secrets, change refs, issue approvals, or dispatch any Provider.
An observation hash is NOT a GitHub-signed attestation or freshness guarantee.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

REPO = "veritasfuji-japan/rcc-revas-veritas-benchmark"
RULESET_ID = 24921425
TAG = "refs/tags/final128-task1-first-two-real-responses-v1-consumed"
PATTERN = "refs/tags/final128-task1-real-ab-once-v1-*"
REF_PATH = "git/ref/tags/final128-task1-first-two-real-responses-v1-consumed"
MAIN_PATH = "branches/main"
LIST_PATH = "rulesets?per_page=100"
DETAIL_PATH = "rulesets/24921425"
ALLOWED_PATHS = frozenset((REF_PATH, MAIN_PATH, LIST_PATH, DETAIL_PATH))
REQUIRED_RULES = frozenset(("deletion", "update", "non_fast_forward"))
PREFIX = "TASK1_OWNER_PRIVILEGED_RULESET_READ_ONLY_V1_"
MAX_BYTES = 100_000
SCHEMA = "TASK1_OWNER_GITHUB_READONLY_OBSERVATION_V1"


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect with an Authorization header."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def safe_get(path: str, token: str) -> tuple[int, object]:
    """Hardcoded GitHub host, limited paths, GET only, no response-body logging."""
    if path not in ALLOWED_PATHS:
        return 0, None
    req = urllib.request.Request(
        "https://api.github.com/repos/" + REPO + "/" + path,
        method="GET",
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.build_opener(_NoRedirects).open(req, timeout=15) as resp:
            status, raw = resp.status, resp.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (OSError, ValueError, TimeoutError):
        return 0, None
    if status != 200 or len(raw) > MAX_BYTES:
        return status, None
    try:
        return status, json.loads(raw)
    except (ValueError, UnicodeError):
        return 0, None


def time_valid(value: object) -> bool:
    if type(value) is not str or len(value) > 80:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def inspect_privileged_read(fetch, expected_sha: str, *, observed_at: str):
    """Return a minimal bounded observation or fixed refusal, never live GO."""
    if type(expected_sha) is not str or re.fullmatch(r"[a-f0-9]{40}", expected_sha) is None:
        return "DENY_INVALID_EXPECTED_SHA", None
    if not time_valid(observed_at):
        return "DENY_OBSERVATION_CLOCK", None

    code, _ = fetch(REF_PATH)
    if code != 404:
        return "DENY_SINGLETON_NOT_CONFIRMED_ABSENT", None

    code, main = fetch(MAIN_PATH)
    if code != 200 or type(main) is not dict:
        return "DENY_MAIN_UNREADABLE", None
    main_sha = main.get("commit", {}).get("sha") if type(main.get("commit")) is dict else None
    if main_sha != expected_sha:
        return "DENY_MAIN_SHA_CHANGED", None

    code, listed = fetch(LIST_PATH)
    if code != 200 or type(listed) is not list or len(listed) > 100:
        return "DENY_RULESET_LIST_UNREADABLE", None
    selected = [
        entry for entry in listed if type(entry) is dict
        and entry.get("id") == RULESET_ID
        and entry.get("target") == "tag"
        and entry.get("enforcement") == "active"
    ]
    if len(selected) != 1:
        return "DENY_EXPECTED_RULESET_NOT_UNIQUE_ACTIVE", None

    code, detail = fetch(DETAIL_PATH)
    if code != 200 or type(detail) is not dict:
        return "DENY_PRIVILEGED_RULESET_DETAIL_UNREADABLE", None

    # Presence, not default value, matters: an Actions token omits this field.
    if "bypass_actors" not in detail:
        return "DENY_BYPASS_FIELD_REDACTED", None
    if type(detail["bypass_actors"]) is not list or detail["bypass_actors"] != []:
        return "DENY_BYPASS_NOT_EXPLICITLY_EMPTY", None

    conditions = detail.get("conditions")
    if type(conditions) is not dict:
        return "DENY_RULESET_CONDITIONS", None
    names = conditions.get("ref_name")
    if type(names) is not dict:
        return "DENY_RULESET_CONDITIONS", None
    includes, excludes = names.get("include"), names.get("exclude")
    if (type(includes) is not list or len(includes) != 2
            or any(type(item) is not str for item in includes)
            or frozenset(includes) != {TAG, PATTERN}
            or type(excludes) is not list or excludes):
        return "DENY_RULESET_CONDITIONS", None

    rules = detail.get("rules")
    if type(rules) is not list or len(rules) != 3:
        return "DENY_RULESET_RULES", None
    if any(type(item) is not dict or type(item.get("type")) is not str
           for item in rules):
        return "DENY_RULESET_RULES", None
    if frozenset(item["type"] for item in rules) != REQUIRED_RULES:
        return "DENY_RULESET_RULES", None

    if (detail.get("id") != RULESET_ID
            or detail.get("target") != "tag"
            or detail.get("enforcement") != "active"
            or detail.get("source") != REPO
            or detail.get("source_type") != "Repository"
            or detail.get("current_user_can_bypass") != "never"
            or not time_valid(detail.get("updated_at"))):
        return "DENY_RULESET_IDENTITY_OR_REVISION", None

    observation = {
        "schema": SCHEMA,
        "audience": "AUDIT_ONLY_NOT_TAG_OR_PROVIDER_AUTHORITY",
        "repository": REPO,
        "expected_main_sha": expected_sha,
        "tag_ref": TAG,
        "tag_observed_absent": True,
        "ruleset_id": RULESET_ID,
        "ruleset_updated_at": detail["updated_at"],
        "observed_at": observed_at,
        "ruleset_active": True,
        "rule_types": sorted(REQUIRED_RULES),
        "ref_includes": sorted((TAG, PATTERN)),
        "ref_excludes": [],
        "bypass_actors_state": "EXPLICIT_EMPTY",
        "caller_can_bypass": "never",
        "source_claim": "LOCAL_AUTHENTICATED_GITHUB_REST_GET_NOT_SIGNED",
    }
    return "OBSERVATION_VALID_READ_ONLY_NOT_ISSUANCE_AUTHORITY", observation


def digest_observation(observation: dict) -> str:
    canonical = json.dumps(
        observation, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def main() -> int:
    # Do not even read the auth token if invoked inside a CI runner.
    if os.environ.get("GITHUB_ACTIONS") or os.environ.get("CI"):
        print(PREFIX + "STOP_CI_CONTEXT_FORBIDDEN")
        return 1

    parser = argparse.ArgumentParser(description="Owner-local Ruleset GET, never a live issuer")
    parser.add_argument("--expected-main-sha", required=True)
    args = parser.parse_args()
    token = os.environ.get("VERITAS_RULESET_OWNER_TOKEN")
    if not token:
        print(PREFIX + "STOP_OWNER_LOCAL_CREDENTIAL_MISSING")
        return 1
    observed = datetime.now(timezone.utc).isoformat(
        timespec="seconds",
    ).replace("+00:00", "Z")
    try:
        result, observation = inspect_privileged_read(
            lambda path: safe_get(path, token),
            args.expected_main_sha,
            observed_at=observed,
        )
    except BaseException:
        print(PREFIX + "STOP_UNCLASSIFIED")
        return 1

    print(PREFIX + result)
    if observation is None:
        return 1
    print(PREFIX + "SHA256_" + digest_observation(observation))
    print(PREFIX + "OWNER_LOCAL_GET_ONLY_NOT_SIGNED_NOT_REPLAY_SAFE")
    print(PREFIX + "NO_CREDENTIAL_OUTPUT_NO_GITHUB_REF_WRITE_NO_PROVIDER_CALL")
    print(PREFIX + "PAID_DISPATCH_NO_GO")
    return 0


if __name__ == "__main__":
    sys.exit(main())
