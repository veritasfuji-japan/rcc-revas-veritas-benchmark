#!/usr/bin/env python3
"""Read-only Task1 #427 investigation of GitHub Actions Ruleset visibility.

Only GitHub REST GET endpoints are used. Never writes refs, prints response
bodies, sends Provider traffic, reads Environment secrets, or persists tokens.
The output is a bounded set of categorical diagnostics, NOT execution approval.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request

REPO = "veritasfuji-japan/rcc-revas-veritas-benchmark"
ACTOR = "veritasfuji-japan"
TAG = "refs/tags/final128-task1-first-two-real-responses-v1-consumed"
RULESET_ID = 24921425
PREFIX = "TASK1_RULESET_GET_ONLY_"
REF_PATH = "git/ref/tags/final128-task1-first-two-real-responses-v1-consumed"
LIST_PATH = "rulesets?per_page=100"
MAX_ACTIVE_TAG = 20
REQUIRED_RULES = frozenset(("deletion", "non_fast_forward", "update"))


def status_label(status):
    """Allowlist output; do not reveal raw API error messages."""
    return str(status) if status in (200, 401, 403, 404, 429, 500, 502, 503) else "OTHER"


def safe_get(path, token):
    """Fixed-host, GET-only, bounded JSON; no response text in exceptions."""
    if not (path in (REF_PATH, LIST_PATH)
            or re.fullmatch(r"rulesets/[0-9]{1,16}", path)):
        return 0, None
    request = urllib.request.Request(
        "https://api.github.com/repos/" + REPO + "/" + path,
        method="GET",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            code, data = response.status, response.read(100_001)
    except urllib.error.HTTPError as err:
        code, data = err.code, b""
    except (OSError, ValueError, TimeoutError):
        return 0, None
    if code != 200 or len(data) > 100_000:
        return code, None
    try:
        return code, json.loads(data)
    except (ValueError, UnicodeError):
        return 0, None


def exact_match(rule):
    if not isinstance(rule, dict):
        return False
    conditions = rule.get("conditions", {})
    if not isinstance(conditions, dict):
        return False
    ref_name = conditions.get("ref_name", {})
    if not isinstance(ref_name, dict):
        return False
    rules = rule.get("rules", [])
    if not isinstance(rules, list):
        return False
    installed = {x.get("type") for x in rules if isinstance(x, dict)}
    includes = ref_name.get("include", [])
    return (
        isinstance(includes, list)
        and TAG in includes
        and REQUIRED_RULES <= installed
        and "creation" not in installed
        and rule.get("bypass_actors") == []
    )


def inspect(fetch, emit=print):
    """Mirror #423's list/detail predicate without ever creating a ref."""
    code, _ = fetch(REF_PATH)
    emit(PREFIX + "SINGLETON_REF_HTTP_" + status_label(code))
    if code != 404:
        emit(PREFIX + "STOP_REF_NOT_CONFIRMED_ABSENT")
        return False

    code, collection = fetch(LIST_PATH)
    emit(PREFIX + "RULESET_LIST_HTTP_" + status_label(code))
    if code != 200 or not isinstance(collection, list) or len(collection) > 100:
        emit(PREFIX + "STOP_LIST_UNREADABLE")
        return False
    emit(PREFIX + "LIST_COUNT_" + str(len(collection)))
    selected = [x for x in collection if isinstance(x, dict)
                and x.get("target") == "tag"
                and x.get("enforcement") == "active"]
    emit(PREFIX + "ACTIVE_TAG_COUNT_" + str(len(selected)))
    expected_listed = any(x.get("id") == RULESET_ID for x in selected)
    emit(PREFIX + "EXPECTED_ACTIVE_TAG_LISTED_" + ("YES" if expected_listed else "NO"))
    if len(selected) > MAX_ACTIVE_TAG:
        emit(PREFIX + "STOP_TOO_MANY_ACTIVE_TAG_RULESETS")
        return False

    matches = 0
    expected_detail_seen = False
    for item in selected:
        identifier = item.get("id")
        if type(identifier) is not int or identifier <= 0 or identifier >= 10**16:
            emit(PREFIX + "STOP_INVALID_LISTED_RULESET_ID")
            return False
        code, detail = fetch("rulesets/" + str(identifier))
        if identifier == RULESET_ID:
            expected_detail_seen = True
            emit(PREFIX + "EXPECTED_DETAIL_HTTP_" + status_label(code))
            if code == 200 and isinstance(detail, dict):
                emit(PREFIX + "EXPECTED_DETAIL_TAG_INCLUDED_" +
                     ("YES" if TAG in detail.get("conditions", {}).get("ref_name", {}).get("include", []) else "NO"))
                emit(PREFIX + "EXPECTED_DETAIL_BYPASS_IS_EMPTY_LIST_" +
                     ("YES" if detail.get("bypass_actors") == [] else "NO"))
                emit(PREFIX + "EXPECTED_DETAIL_EXACT_MATCH_" +
                     ("YES" if exact_match(detail) else "NO"))
        if code != 200 or not isinstance(detail, dict):
            emit(PREFIX + "STOP_DETAIL_UNREADABLE")
            return False
        if exact_match(detail):
            matches += 1
    if not expected_detail_seen:
        emit(PREFIX + "EXPECTED_DETAIL_NOT_VISITED")
    emit(PREFIX + "ORIGINAL_PREDICATE_MATCH_COUNT_" + str(matches))
    passed = matches == 1 and expected_detail_seen
    emit(PREFIX + ("READ_ONLY_PREDICATE_PASS_NOT_DISPATCH_AUTHORITY" if passed
                   else "READ_ONLY_PREDICATE_FAIL_NO_DISPATCH"))
    return passed


def main():
    env = os.environ
    if not (env.get("GITHUB_ACTIONS") == "true"
            and env.get("GITHUB_REPOSITORY") == REPO
            and env.get("GITHUB_ACTOR") == ACTOR
            and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("GITHUB_REF") == "refs/heads/main"
            and env.get("GITHUB_RUN_ATTEMPT") == "1"
            and re.fullmatch(r"[a-f0-9]{40}", env.get("GITHUB_SHA", ""))):
        print(PREFIX + "STOP_CONTEXT")
        return 1
    token = env.get("GH_TOKEN", "")
    if not token:
        print(PREFIX + "STOP_TOKEN_MISSING")
        return 1
    try:
        ok = inspect(lambda path: safe_get(path, token))
    except BaseException:
        print(PREFIX + "STOP_UNCLASSIFIED")
        return 1
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
