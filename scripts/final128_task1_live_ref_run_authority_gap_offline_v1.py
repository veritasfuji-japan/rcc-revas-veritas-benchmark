#!/usr/bin/env python3
"""OFFLINE ONLY: audit frozen Task1 research-tag snapshot; NEVER grant execution.

Reads only a caller-supplied Python mapping. There is no HTTP client, GitHub
writer, credential access, workflow dispatch, Provider client, or executable CLI.
A source-controlled observation is not a fresh authenticated GitHub readback,
run-bound issuer identity, signed handoff, singleton Provider lease or paid consent.
"""
from __future__ import annotations

from dataclasses import dataclass

REPO = "veritasfuji-japan/rcc-revas-veritas-benchmark"
FROZEN_SHA = "4e864ebad860be2ce71a6c233e98a581094b45aa"
RESEARCH_REF = "refs/tags/final128-task1-research-first-two-once-v1"
PRODUCTION_REF = "refs/tags/final128-task1-first-two-real-responses-v1-consumed"
RESEARCH_RULESET = 25305970
CI_BLOB_SHA = "35eeb3670190cc96b341ea834cd03df11f8ed46e"
SCHEMA = "final128_task1_research_tag_live_readback_evidence_v1"
STATUS = "OFFLINE_SNAPSHOT_CONSISTENT_REF_NOT_RUN_AUTHORITY"
NO_PROVIDER = "PAID_TASK1_NO_GO"
TOP_LEVEL = frozenset((
    "schema", "observation_date", "observation_method", "evidence_status",
    "repository", "frozen_main_commit_sha", "research_ref",
    "research_ruleset", "ci_at_frozen_sha", "scoped_actions_observation",
    "production_tag_separation", "paid_execution_hold",
    "provenance_limitations", "prohibited_in_this_evidence_freeze",
))
REQUIRED_NOT_PROVEN = frozenset((
    "original_create_ref_http_201_response_archived",
    "original_post_attempt_count_independently_verified",
    "issuer_run_or_job_binding_verified",
    "independent_signer_attestation_present",
    "durable_global_once_only_provider_lease_proven",
    "exact_model_request_digests_bound_to_ref",
    "independent_provider_billing_or_egress_attestation_present",
    "external_github_apps_event_effects_fully_ruled_out",
    "provider_a_b_responses_observed_in_this_experiment",
))
BLOCKERS = (
    "INDEPENDENTLY_AUTHENTICATED_RUN_JOB_AND_EVENT",
    "INDEPENDENTLY_ENROLLED_ISSUER_AND_SENDER_ROLE_SEPARATION",
    "SIGNED_REQUEST_DIGEST_AND_RECIPIENT_HANDOFF",
    "DURABLE_AT_MOST_ONCE_PROVIDER_CONSUMPTION",
    "UNKNOWN_OUTCOME_NO_RETRY_AND_PARTIAL_EFFECT_ACCOUNTING",
    "INDEPENDENT_PROVIDER_EGRESS_AND_COST_CONTROLS",
    "FRESH_EXPLICIT_PAID_CONSENT_AND_BILLING_RISK_ACCEPTANCE",
    "REAL_NATIVE_AB_RESPONSE_AND_TERMINAL_SCORER_EVIDENCE",
)


class Refused(ValueError):
    """Frozen evidence drift or attempted promotion; no external action."""


def require(condition: bool, code: str) -> None:
    if condition is not True:
        raise Refused("TASK1_LIVE_REF_RUN_GAP_OFFLINE_" + code)


@dataclass(frozen=True)
class SnapshotReview:
    status: str = STATUS
    observed_tag_snapshot_consistent: bool = True
    observed_ruleset_snapshot_consistent: bool = True
    live_github_reauthenticated: bool = False
    run_job_origin_authenticated: bool = False
    independent_issuer_enrolled: bool = False
    issuer_sender_isolation_proven: bool = False
    durable_provider_single_use_proven: bool = False
    native_request_digest_bound: bool = False
    paid_consent_observed: bool = False
    provider_billing_hard_stop_proven: bool = False
    authorized_to_issue_tag: bool = False
    authorized_to_send_provider: bool = False
    authorized_to_consume_production_tag: bool = False
    authorized_to_score_official_native_utility: bool = False
    decision: str = NO_PROVIDER
    missing_authority_requirements: tuple[str, ...] = BLOCKERS


def review_frozen_snapshot(snapshot: object, *, caller_run_claim: object = None) -> SnapshotReview:
    """Validate the checked-in 2026-10-18 record, not any live authorization.

    A supplied run/job/provider/consent claim is always refused because this
    frozen snapshot has no independently authenticated claim channel.
    """
    require(caller_run_claim is None, "UNTRUSTED_CALLER_RUN_CLAIM")
    require(type(snapshot) is dict and set(snapshot) == TOP_LEVEL,
            "SNAPSHOT_SCHEMA_OR_EXTRA_FIELDS")
    s = snapshot
    require(s["schema"] == SCHEMA and s["observation_date"] == "2026-10-18"
            and s["repository"] == REPO
            and s["frozen_main_commit_sha"] == FROZEN_SHA
            and s["evidence_status"] ==
            "OBSERVED_RESEARCH_TAG_REF_AND_RULESET_ONLY_NO_LIVE_DISPATCH_AUTHORITY",
            "FROZEN_IDENTITY")
    require(type(s["observation_method"]) is str
            and "read-only" in s["observation_method"]
            and "not archived raw HTTP transcript" in s["observation_method"],
            "SNAPSHOT_NOT_RAW_ATTESTATION")

    ref = s["research_ref"]
    require(type(ref) is dict
            and ref.get("exact_ref") == RESEARCH_REF
            and ref.get("target_sha") == FROZEN_SHA
            and ref.get("object_type") == "commit"
            and ref.get("exact_get_readback_observed") is True
            and ref.get("url") ==
            f"https://api.github.com/repos/{REPO}/git/ref/tags/"
            "final128-task1-research-first-two-once-v1",
            "REF_SNAPSHOT_MISMATCH")
    rule = s["research_ruleset"]
    require(type(rule) is dict
            and type(rule.get("id")) is int and rule["id"] == RESEARCH_RULESET
            and rule.get("target") == "tag"
            and rule.get("enforcement") == "active"
            and rule.get("included_refs") == [RESEARCH_REF]
            and rule.get("excluded_refs") == []
            and type(rule.get("bypass_actors")) is list
            and rule["bypass_actors"] == []
            and type(rule.get("rules")) is list
            and len(rule["rules"]) == 3
            and set(rule["rules"]) == {"deletion", "update", "non_fast_forward"},
            "RULESET_SNAPSHOT_MISMATCH")

    ci = s["ci_at_frozen_sha"]
    require(type(ci) is dict
            and ci.get("source_path") == ".github/workflows/ci.yml"
            and ci.get("blob_sha") == CI_BLOB_SHA
            and ci.get("push_branches") == ["main"]
            and ci.get("pull_request_enabled") is True
            and ci.get("pr_439_merged") is True,
            "CI_SNAPSHOT_MISMATCH")

    actions = s["scoped_actions_observation"]
    require(type(actions) is dict
            and type(actions.get("total_count_at_observation")) is int
            and actions["total_count_at_observation"] == 0
            and actions.get("query_url") ==
            f"https://api.github.com/repos/{REPO}/actions/runs?"
            "branch=final128-task1-research-first-two-once-v1&per_page=25"
            and type(actions.get("limitation")) is str
            and "not proof" in actions["limitation"],
            "SCOPED_ACTIONS_NOT_GLOBAL_ATTESTATION")

    production = s["production_tag_separation"]
    require(type(production) is dict
            and production.get("reserved_production_ref") == PRODUCTION_REF
            and type(production.get("matching_refs_at_observation")) is int
            and production["matching_refs_at_observation"] == 0
            and production.get("research_tag_is_not_production_consumption") is True,
            "RESEARCH_NOT_PRODUCTION")

    paid = s["paid_execution_hold"]
    require(type(paid) is dict
            and paid.get("issue_427_state") == "open"
            and paid.get("issue_url") ==
            f"https://github.com/{REPO}/issues/427"
            and paid.get("paid_task1_dispatch_authorized") is False
            and paid.get("fresh_billing_consent_for_provider_run") is False
            and paid.get("safe_diagnostic_result") == "success"
            and paid.get("previously_completed_safe_diagnostic_run_id") == 39015342320,
            "PAID_HOLD_MUST_REMAIN_NO_GO")

    limits = s["provenance_limitations"]
    require(type(limits) is dict
            and set(limits) == REQUIRED_NOT_PROVEN |
            {"operator_reported_manual_iphone_tag_creation"}
            and limits.get("operator_reported_manual_iphone_tag_creation") is True
            and all(limits.get(name) is False for name in REQUIRED_NOT_PROVEN),
            "UNREVIEWED_PROVENANCE_PROMOTION")
    prohibited = s["prohibited_in_this_evidence_freeze"]
    require(type(prohibited) is list
            and len(prohibited) >= 4
            and all(type(x) is str for x in prohibited)
            and any("No Provider request" in x for x in prohibited),
            "NO_EFFECT_RESTRICTIONS_MISSING")
    return SnapshotReview()
