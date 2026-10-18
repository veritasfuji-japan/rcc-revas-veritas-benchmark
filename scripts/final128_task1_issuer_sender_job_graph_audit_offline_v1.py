#!/usr/bin/env python3
"""Read-only audit: the current #423 same-job exposure vs an INERT split plan.

No GitHub API, workflow creation/dispatch, Provider client, token read,
credential lookup, network, subprocess, ref mutation, signing or permission
grant exists here. A positive plan review is NOT real IAM enforcement.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

import yaml

REPO = "veritasfuji-japan/rcc-revas-veritas-benchmark"
WORKFLOW_PATH = (
    ".github/workflows/final128-423-task1-protected-first-two-native-chat-live-v1.yml"
)
WORKFLOW_BLOB = "c2182fef2574d1be3019cf6455947b64751ef474"
FROZEN_MAIN = "e57226797908488eb0711f46384905f221ecf528"
SCHEMA = "final128.task1.issuer_sender_job_split_inert_blueprint.v1"
MODE = "OFFLINE_DESIGN_DATA_NO_GITHUB_WORKFLOW_NO_EXECUTION"
RESEARCH_TAG = "refs/tags/final128-task1-research-first-two-once-v1"
PRODUCTION_TAG = "refs/tags/final128-task1-first-two-real-responses-v1-consumed"
CASE = "banking:user_task_1:injection_task_2:direct"
MODEL = "gpt-4.1-mini-2025-04-14"
SENDER_SECRETS = ("TASK1_OPENAI_API_KEY", "TASK1_CAPTURE_AES256_KEY")
ISSUER_TASKS = (
    "verify_issuer_run_from_independent_trust_root",
    "validate_exact_production_ref_ruleset_at_time_of_operation",
    "one_atomic_production_ref_create_only_after_separate_consent",
)
SENDER_TASKS = (
    "independently_attest_sender_run_job_and_verified_handoff",
    "verify_exact_native_packet_model_case_and_request_digest",
    "atomically_consume_durable_provider_permission_per_arm",
    "deny_after_unknown_outcome_without_retry",
    "capture_http_bytes_encrypted_before_validation",
)
HANDOFF_FIELDS = (
    "repository", "main_sha", "protected_workflow_ref", "run_id",
    "run_attempt", "independently_attested_issuer_job",
    "independently_attested_sender_job", "case", "model",
    "exact_request_sha256_A", "exact_request_sha256_B",
    "expiration_and_nonce", "operator_consent_record",
)
UNPROVEN_KEYS = (
    "actual_workflow_split_installed",
    "credential_and_network_bypass_blocked",
    "global_once_proven",
    "independent_billing_hard_limit_proven",
    "fresh_paid_consent",
    "actual_paid_provider_dispatch_authorized",
)


class Refused(ValueError):
    """Unexpected evidence or plan change must be reviewed before claiming a result."""


def need(check: bool, code: str) -> None:
    if check is not True:
        raise Refused("TASK1_ROLE_GRAPH_OFFLINE_" + code)


def exact_type_match(got: object, expected: object) -> bool:
    """Deep exact-key/type match; False is not integer 0."""
    if type(got) is not type(expected):
        return False
    if type(expected) is dict:
        return set(got) == set(expected) and all(
            exact_type_match(got[k], v) for k, v in expected.items()
        )
    if type(expected) is list:
        return len(got) == len(expected) and all(
            exact_type_match(a, b) for a, b in zip(got, expected)
        )
    return got == expected


def expected_blueprint() -> dict:
    """A design proposal only. Explicit positive capabilities are PROPOSED, never live."""
    return {
        "schema": SCHEMA,
        "mode": MODE,
        "repository": REPO,
        "observed_paid_workflow": {
            "path": WORKFLOW_PATH,
            "git_blob_sha": WORKFLOW_BLOB,
            "observed_main_sha": FROZEN_MAIN,
            "currently_same_job": True,
            "operator_decision": "NO_GO_ISSUE_427",
        },
        "case": CASE,
        "model": MODEL,
        "research_ref_already_issued_do_not_reuse": RESEARCH_TAG,
        "future_production_ref_not_authorized_to_issue": PRODUCTION_TAG,
        "proposal": {
            "issuer": {
                "needs": [],
                "permissions": {"contents": "write"},
                "environment": None,
                "secret_names": [],
                "intended_responsibilities": list(ISSUER_TASKS),
                "may_access_provider_secret": False,
                "may_write_git_ref_in_future_design": True,
                "may_send_provider_in_future_design": False,
            },
            "sender": {
                "needs": ["issuer"],
                "permissions": {"contents": "read"},
                "environment_name_in_design_not_reviewed": "task1-real-model-pilot",
                "secret_names_as_symbols_only": list(SENDER_SECRETS),
                "intended_responsibilities": list(SENDER_TASKS),
                "may_access_provider_secret_in_future_design": True,
                "may_write_git_ref_in_future_design": False,
                "may_send_provider_in_future_design": True,
            },
            "handoff": {
                "mechanism":
                    "UNIMPLEMENTED_EXTERNAL_ATTESTED_RUN_AND_SIGNED_RECIPIENT_HANDOFF",
                "required_bound_fields": list(HANDOFF_FIELDS),
                "trusted_issuer_enrolled": False,
                "recipient_identity_independently_authenticated": False,
                "durable_per_arm_claim_and_consume_enforced": False,
                "provider_egress_isolated": False,
            },
            "enforcement": {key: False for key in UNPROVEN_KEYS},
        },
    }


@dataclass(frozen=True)
class Report:
    observation: str
    observed_same_job_tag_and_provider_capability: bool
    observed_write_token_scope_in_provider_job: bool
    observed_provider_secret_reference_in_same_job_as_tag: bool
    proposed_two_role_graph_shape_matched: bool
    actual_job_separation_enforced: bool = False
    independently_enrolled_sender_or_issuer: bool = False
    trusted_run_and_job_identity_authenticated: bool = False
    protected_secret_release_verified: bool = False
    provider_egress_non_bypassable: bool = False
    cross_runner_once_ledger_proven: bool = False
    github_ruleset_to_ref_atomic_authority_proven: bool = False
    allowed_to_dispatch_paid_task1: bool = False
    allowed_to_issue_or_consume_tag: bool = False
    decision: str = "PAID_TASK1_NO_GO"


def git_blob_hash(content: bytes) -> str:
    need(type(content) is bytes, "WORKFLOW_BYTES_REQUIRED")
    return hashlib.sha1(
        b"blob " + str(len(content)).encode("ascii") + b"\0" + content
    ).hexdigest()


def inspect_current_workflow(workflow_bytes: object) -> Report:
    """Pin the ACTUAL checked-in #423 workflow, not a hypothetical role object.

    A changed live workflow requires fresh human review, rather than the
    auditor trusting an unknown newly edited source or claiming it is safe.
    """
    need(type(workflow_bytes) is bytes, "WORKFLOW_SOURCE_BYTES")
    need(git_blob_hash(workflow_bytes) == WORKFLOW_BLOB,
         "PRODUCTION_WORKFLOW_SOURCE_DRIFT_REVIEW_REQUIRED")
    try:
        data = yaml.safe_load(workflow_bytes)
    except yaml.YAMLError as exc:
        raise Refused("TASK1_ROLE_GRAPH_OFFLINE_INVALID_WORKFLOW") from exc
    need(type(data) is dict and type(data.get("jobs")) is dict
         and set(data["jobs"]) == {"protected-first-pair-only"},
         "OBSERVED_ONE_JOB_REQUIRED")
    job = data["jobs"]["protected-first-pair-only"]
    need(type(job) is dict and type(job.get("steps")) is list
         and type(data.get("permissions")) is dict
         and data["permissions"] == {"contents": "write"}
         and job.get("environment") == "task1-real-model-pilot"
         and "permissions" not in job,
         "OBSERVED_SAME_JOB_WRITE_SCOPE")
    found_tag = []
    found_send = []
    found_secret = []
    for i, step in enumerate(job["steps"]):
        need(type(step) is dict, "STEP_SHAPE")
        run = step.get("run", "")
        need(type(run) is str, "RUN_STEP_TEXT")
        if 'git/refs' in run and 'method="POST"' in run:
            found_tag.append(i)
        if "--mode send" in run and "final128_423_task1_protected_first_native_chat_sender_v1.py" in run:
            found_send.append(i)
        env = step.get("env", {})
        need(type(env) is dict, "STEP_ENV_SHAPE")
        if "TASK1_OPENAI_API_KEY" in env and (
            "secrets.TASK1_OPENAI_API_KEY" in env["TASK1_OPENAI_API_KEY"]
        ):
            found_secret.append(i)
    need(len(found_tag) == len(found_send) == 1
         and found_tag[0] < found_send[0]
         and found_secret == [found_send[0] - 2, found_send[0]]
         and job["steps"][found_tag[0]].get("env", {}).get("GH_TOKEN")
             == "${{ github.token }}",
         "TAG_SEND_AND_SECRET_SAME_JOB_EVIDENCE")
    return Report(
        observation="OBSERVED_PINNED_423_UNSPLIT_JOB_STATIC_SOURCE_ONLY",
        observed_same_job_tag_and_provider_capability=True,
        observed_write_token_scope_in_provider_job=True,
        observed_provider_secret_reference_in_same_job_as_tag=True,
        proposed_two_role_graph_shape_matched=False,
    )


def review_inert_blueprint(blueprint_source: object) -> Report:
    """Shape-check a non-runnable design DATA document; never grant authority."""
    need(type(blueprint_source) is bytes, "BLUEPRINT_BYTES_REQUIRED")
    try:
        proposal = yaml.safe_load(blueprint_source)
    except yaml.YAMLError as exc:
        raise Refused("TASK1_ROLE_GRAPH_OFFLINE_INVALID_BLUEPRINT") from exc
    need(exact_type_match(proposal, expected_blueprint()),
         "NOT_EXACT_INERT_JOB_SPLIT_DESIGN")
    need(type(proposal) is dict and "jobs" not in proposal
         and "on" not in proposal and "steps" not in proposal,
         "NO_RUNNABLE_WORKFLOW_KEYS")
    return Report(
        observation="TWO_INERT_DESIGN_ROLES_NOT_DEPLOYED_OR_AUTHORIZED",
        observed_same_job_tag_and_provider_capability=False,
        observed_write_token_scope_in_provider_job=False,
        observed_provider_secret_reference_in_same_job_as_tag=False,
        proposed_two_role_graph_shape_matched=True,
    )


def audit_inert_split(workflow_bytes: object, blueprint_bytes: object) -> dict:
    """Combined proof obligation: current risk + inert design, all enforcement false."""
    current = inspect_current_workflow(workflow_bytes)
    proposal = review_inert_blueprint(blueprint_bytes)
    return {
        "observed_live_source": current,
        "inert_design": proposal,
        "permission_to_send_provider": False,
        "permission_to_write_tags": False,
        "new_utility_or_attack_scores": None,
        "evidence_status": "OFFLINE_JOB_GRAPH_GAP_RECORDED_NO_LIVE_ROLE_ISOLATION",
    }
