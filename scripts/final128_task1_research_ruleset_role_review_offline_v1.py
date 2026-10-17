#!/usr/bin/env python3
"""Task1 research Ruleset/role proposal OFFLINE shape review — NO EFFECT.

Only inspect caller-supplied SYNTHETIC dicts. NO network, GitHub API,
credentials, workflow, provider, tag/ref writes, Ruleset administration,
signed attestation, or dispatch entrypoint. A syntactically passing shape
NEVER establishes installed policy, identity, issuer/sender isolation,
transactional lock, paid approval, or permission to send.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

REPO = "veritasfuji-japan/rcc-revas-veritas-benchmark"
RESEARCH_TAG = "refs/tags/final128-task1-research-first-two-once-v1"
PRODUCTION_TAG = "refs/tags/final128-task1-first-two-real-responses-v1-consumed"
PRODUCTION_RULESET_ID = 24921425
MAIN_RULESET_ID = 25299895
MODEL = "gpt-4.1-mini-2025-04-14"
CASE = "banking:user_task_1:injection_task_2:direct"
RESEARCH_ENV = "task1-research-native-first-two"
PRODUCTION_ENV = "task1-real-model-pilot"
MOCK_RULESET_ID = 76543210  # Fixed fixture only; not a real GitHub ID.
REQUIRED_RULES = frozenset(("deletion", "update", "non_fast_forward"))
ISSUER_PERMISSIONS = {"contents": "write"}
SENDER_PERMISSIONS = {"contents": "read"}
SENDER_SECRETS = frozenset((
    "TASK1_RESEARCH_OPENAI_API_KEY",
    "TASK1_RESEARCH_CAPTURE_AES256_KEY",
))
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
RUN = re.compile(r"[1-9][0-9]{5,19}\Z")


@dataclass(frozen=True)
class Review:
    status: str
    synthetic_shape_matched: bool = False
    real_ruleset_enrolled: bool = False
    permission_isolation_proven: bool = False
    production_authority: bool = False
    paid_dispatch_allowed: bool = False
    production_tag_written: bool = False
    research_tag_written: bool = False
    independently_authenticated: bool = False


def _check(condition: bool, code: str) -> None:
    if condition is not True:
        raise ValueError("TASK1_RESEARCH_RULESET_ROLE_OFFLINE_" + code)


def _ref_name(detail: dict) -> tuple[object, object]:
    conditions = detail.get("conditions")
    _check(type(conditions) is dict, "MISSING_CONDITIONS")
    names = conditions.get("ref_name")
    _check(type(names) is dict and set(conditions) == {"ref_name"},
           "EXTRA_OR_MISSING_CONDITIONS")
    return names.get("include"), names.get("exclude")


def review_synthetic_research_ruleset(
    collection: object, detail: object, *, expected_mock_id: int = MOCK_RULESET_ID,
) -> Review:
    """Review ONLY the shape of hypothetical collection + detail.

    Caller data are explicitly untrusted, not a live Ruleset read.
    An explicit empty bypass array is mandatory; MISSING is never empty.
    This exact-name Ruleset does NOT cover any production protected tag.
    """
    _check(type(expected_mock_id) is int and expected_mock_id == MOCK_RULESET_ID,
           "UNKNOWN_SIMULATED_RULESET_ID")
    _check(type(collection) is list and len(collection) <= 100,
           "COLLECTION_UNREADABLE")
    _check(type(detail) is dict, "DETAIL_UNREADABLE")
    matches = [
        x for x in collection if type(x) is dict
        and x.get("id") == expected_mock_id
        and x.get("target") == "tag" and x.get("enforcement") == "active"
    ]
    _check(len(matches) == 1, "UNIQUE_ACTIVE_LISTING_REQUIRED")
    _check(detail.get("id") == expected_mock_id
           and detail.get("target") == "tag"
           and detail.get("enforcement") == "active"
           and detail.get("source") == REPO
           and detail.get("source_type") == "Repository"
           and detail.get("current_user_can_bypass") == "never",
           "SOURCE_OR_ENFORCEMENT_DRIFT")
    _check("bypass_actors" in detail
           and type(detail["bypass_actors"]) is list
           and detail["bypass_actors"] == [],
           "EXPLICIT_EMPTY_BYPASS_REQUIRED")
    includes, excludes = _ref_name(detail)
    _check(type(includes) is list and includes == [RESEARCH_TAG]
           and type(excludes) is list and excludes == [],
           "EXACT_RESEARCH_REF_ONLY")
    _check(PRODUCTION_TAG not in includes and RESEARCH_TAG != PRODUCTION_TAG,
           "NO_PRODUCTION_NAMESPACE")
    rules = detail.get("rules")
    _check(type(rules) is list and len(rules) == 3
           and all(type(r) is dict and set(r) == {"type"}
                   and type(r["type"]) is str for r in rules)
           and frozenset(r["type"] for r in rules) == REQUIRED_RULES,
           "EXACT_UPDATE_DELETION_NONFASTFORWARD_NO_CREATION_RULE")
    # Rule revisions, administration races, overlapping Rulesets and
    # actual GitHub enforcement are deliberately NOT authenticated here.
    return Review("SYNTHETIC_RULESET_SHAPE_ONLY_NOT_INSTALLED_OR_AUTHORITY", True)


def review_synthetic_job_separation(roles: object) -> Review:
    """Check mock declared job surfaces; NOT IAM/secret-access verification."""
    _check(type(roles) is dict and set(roles) == {"issuer", "sender"},
           "EXACT_TWO_ROLES")
    issuer, sender = roles["issuer"], roles["sender"]
    _check(type(issuer) is dict and type(sender) is dict,
           "ROLE_SHAPES")
    _check(set(issuer) == {"permissions", "environment", "secrets"}
           and set(sender) == {"permissions", "environment", "secrets"},
           "ROLE_FIELDS")
    _check(type(issuer["permissions"]) is dict
           and issuer["permissions"] == ISSUER_PERMISSIONS
           and issuer["environment"] is None
           and type(issuer["secrets"]) is list
           and issuer["secrets"] == [],
           "ISSUER_NO_PROVIDER_SECRETS_NO_PROTECTED_ENV")
    _check(type(sender["permissions"]) is dict
           and sender["permissions"] == SENDER_PERMISSIONS
           and sender["environment"] == RESEARCH_ENV
           and sender["environment"] != PRODUCTION_ENV
           and type(sender["secrets"]) is list
           and len(sender["secrets"]) == 2
           and set(sender["secrets"]) == SENDER_SECRETS,
           "SENDER_READONLY_DEDICATED_RESEARCH_ENV")
    # Mock role attributes cannot assert GitHub token audience, admin
    # changes, job/container isolation or release of actual secrets.
    return Review("SYNTHETIC_JOB_ROLES_SHAPE_ONLY_NOT_IAM_PROOF", True)


def review_synthetic_binding(binding: object) -> Review:
    """Shape-check required exact-run metadata, never approve an execution."""
    _check(type(binding) is dict, "BINDING_REQUIRED")
    expected = {
        "repository", "case", "model", "research_tag", "run_id",
        "main_sha", "first_sha256_by_arm", "max_posts",
        "no_retry", "billing_target_usd", "owner_approved",
        "provider_project_hard_cap_verified", "ref_created",
    }
    _check(set(binding) == expected, "BINDING_FIELDS_EXACT")
    _check(binding["repository"] == REPO
           and binding["case"] == CASE
           and binding["model"] == MODEL
           and binding["research_tag"] == RESEARCH_TAG
           and type(binding["run_id"]) is str
           and RUN.fullmatch(binding["run_id"]) is not None
           and type(binding["main_sha"]) is str
           and SHA40.fullmatch(binding["main_sha"]) is not None,
           "BOUND_IDENTITY_OR_SOURCE_INVALID")
    first = binding["first_sha256_by_arm"]
    _check(type(first) is dict and set(first) == {"A", "B"}
           and all(type(h) is str and SHA256.fullmatch(h) is not None
                   for h in first.values())
           and first["A"] == first["B"],
           "INITIAL_A_B_IDENTICAL_NATIVE_INPUT_REQUIRED")
    _check(type(binding["max_posts"]) is int and binding["max_posts"] == 2
           and binding["no_retry"] is True
           and binding["billing_target_usd"] == "1.00"
           and binding["owner_approved"] is False
           and binding["provider_project_hard_cap_verified"] is False
           and binding["ref_created"] is False,
           "OFFLINE_NO_CONSENT_NO_CREATION_ONLY")
    # A tag maps ref -> commit SHA, NOT ref -> run/model/consent/digests.
    # Values here are caller assertions, not independently attested.
    return Review("SYNTHETIC_BINDING_FIELDS_ONLY_NOT_APPROVAL", True)


def review_all_synthetic(collection: object, detail: object, roles: object,
                         binding: object) -> Review:
    """All gates passing is still a *non-authorizing* design review."""
    review_synthetic_research_ruleset(collection, detail)
    review_synthetic_job_separation(roles)
    review_synthetic_binding(binding)
    return Review("ALL_SYNTHETIC_SHAPES_MATCH_NO_REAL_AUTHORITY", True)
