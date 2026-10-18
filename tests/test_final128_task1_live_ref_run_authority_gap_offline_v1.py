"""Offline evidence snapshot cannot turn a real research tag into live authority."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import socket

import pytest

from scripts import final128_task1_live_ref_run_authority_gap_offline_v1 as gap


EVIDENCE = (Path(__file__).resolve().parents[1] /
            "evidence/final128_task1_research_tag_live_readback_2026-10-18_v1.json")
DOC = (Path(__file__).resolve().parents[1] /
       "docs/optimization/FINAL128_TASK1_RESEARCH_REF_TO_RUN_AUTHORITY_GAP_V1.md")


@pytest.fixture(autouse=True)
def block_network_and_sensitive_environment(monkeypatch):
    def deny(*_args, **_kwargs):
        pytest.fail("TASK1_LIVE_REF_OFFLINE_MUST_NOT_CONNECT")
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket.socket, "connect_ex", deny)
    for key in (
        "OPENAI_API_KEY", "TASK1_OPENAI_API_KEY", "TASK1_CAPTURE_AES256_KEY",
        "TASK1_RESEARCH_OPENAI_API_KEY", "TASK1_RESEARCH_CAPTURE_AES256_KEY",
        "GITHUB_TOKEN", "GH_TOKEN", "VERITAS_RULESET_OWNER_TOKEN",
    ):
        monkeypatch.delenv(key, raising=False)


def snapshot():
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def assert_no_authority(review):
    assert review.status == "OFFLINE_SNAPSHOT_CONSISTENT_REF_NOT_RUN_AUTHORITY"
    assert review.observed_tag_snapshot_consistent is True
    assert review.observed_ruleset_snapshot_consistent is True
    for name in (
        "live_github_reauthenticated", "run_job_origin_authenticated",
        "independent_issuer_enrolled", "issuer_sender_isolation_proven",
        "durable_provider_single_use_proven", "native_request_digest_bound",
        "paid_consent_observed", "provider_billing_hard_stop_proven",
        "authorized_to_issue_tag", "authorized_to_send_provider",
        "authorized_to_consume_production_tag",
        "authorized_to_score_official_native_utility",
    ):
        assert getattr(review, name) is False, name
    assert review.decision == "PAID_TASK1_NO_GO"
    assert len(review.missing_authority_requirements) >= 7
    assert len(set(review.missing_authority_requirements)) == len(
        review.missing_authority_requirements)


def test_actual_frozen_observation_is_consistent_but_never_authority():
    report = gap.review_frozen_snapshot(snapshot())
    assert_no_authority(report)
    assert gap.RESEARCH_REF != gap.PRODUCTION_REF
    assert report.missing_authority_requirements == gap.BLOCKERS


@pytest.mark.parametrize("corrupt", [
    lambda d: d.update(repository="attacker/repository"),
    lambda d: d.update(frozen_main_commit_sha="f" * 40),
    lambda d: d.update(evidence_status="PAID_AUTHORITY"),
    lambda d: d.update(schema="unknown"),
    lambda d: d.pop("observation_method"),
    lambda d: d.update(live_provider_dispatch_authorized=True),
    lambda d: d["research_ref"].update(exact_ref=gap.PRODUCTION_REF),
    lambda d: d["research_ref"].update(exact_ref=gap.RESEARCH_REF + "-other"),
    lambda d: d["research_ref"].update(target_sha="f" * 40),
    lambda d: d["research_ref"].update(object_type="tag"),
    lambda d: d["research_ref"].update(exact_get_readback_observed="true"),
    lambda d: d["research_ref"].update(exact_get_readback_observed=False),
    lambda d: d["research_ref"].update(url="https://example.test/ref"),
    lambda d: d["research_ruleset"].pop("bypass_actors"),
    lambda d: d["research_ruleset"].update(bypass_actors=None),
    lambda d: d["research_ruleset"].update(bypass_actors=[{"actor_id": 1}]),
    lambda d: d["research_ruleset"].update(id=True),
    lambda d: d["research_ruleset"].update(enforcement="disabled"),
    lambda d: d["research_ruleset"].update(included_refs=[gap.PRODUCTION_REF]),
    lambda d: d["research_ruleset"].update(excluded_refs=[gap.RESEARCH_REF]),
    lambda d: d["research_ruleset"].update(rules=["update", "deletion"]),
    lambda d: d["research_ruleset"].update(rules=["update", "deletion", "creation"]),
    lambda d: d["ci_at_frozen_sha"].update(push_branches=["main", "tags"]),
    lambda d: d["ci_at_frozen_sha"].update(blob_sha="a" * 40),
    lambda d: d["scoped_actions_observation"].update(
        total_count_at_observation=False),
    lambda d: d["scoped_actions_observation"].update(
        total_count_at_observation=1),
    lambda d: d["scoped_actions_observation"].update(limitation="all safe"),
    lambda d: d["production_tag_separation"].update(
        reserved_production_ref=gap.RESEARCH_REF),
    lambda d: d["production_tag_separation"].update(
        research_tag_is_not_production_consumption=False),
    lambda d: d["paid_execution_hold"].update(issue_427_state="closed"),
    lambda d: d["paid_execution_hold"].update(
        paid_task1_dispatch_authorized=True),
    lambda d: d["paid_execution_hold"].update(
        paid_task1_dispatch_authorized=0),
    lambda d: d["paid_execution_hold"].update(
        fresh_billing_consent_for_provider_run=True),
    lambda d: d["provenance_limitations"].update(
        original_post_attempt_count_independently_verified=True),
    lambda d: d["provenance_limitations"].update(
        issuer_run_or_job_binding_verified=True),
    lambda d: d["provenance_limitations"].update(
        durable_global_once_only_provider_lease_proven=True),
    lambda d: d["provenance_limitations"].update(
        exact_model_request_digests_bound_to_ref=True),
    lambda d: d["provenance_limitations"].update(
        independent_signer_attestation_present=True),
    lambda d: d["provenance_limitations"].update(
        operator_reported_manual_iphone_tag_creation="true"),
    lambda d: d["provenance_limitations"].pop(
        "external_github_apps_event_effects_fully_ruled_out"),
    lambda d: d["prohibited_in_this_evidence_freeze"].clear(),
])
def test_frozen_evidence_drift_refused_without_any_grant(corrupt):
    data = snapshot()
    corrupt(data)
    with pytest.raises(gap.Refused, match="TASK1_LIVE_REF_RUN_GAP_OFFLINE_"):
        gap.review_frozen_snapshot(data)


@pytest.mark.parametrize("claim", [
    {},
    {"run_id": "39089653670", "run_attempt": 1},
    {"run_id": "39089653670", "run_attempt": 1,
     "issuer_job_id": "117563478232", "sender_job_id": "117563478233",
     "model": "gpt-4.1-mini-2025-04-14",
     "paid_approved": True, "provider_secret_access": True,
     "global_single_use": True,
     "first_native_a_sha256": "a" * 64,
     "first_native_b_sha256": "a" * 64},
    {"authenticated_github_oidc": True,
     "independent_attestation": True, "paid_billing_review": True},
    ["fake", "approval"],
])
def test_arbitrary_run_claims_never_upgrade_research_snapshot(claim):
    with pytest.raises(gap.Refused, match="UNTRUSTED_CALLER_RUN_CLAIM"):
        gap.review_frozen_snapshot(snapshot(), caller_run_claim=claim)


def test_missing_or_unknown_snapshot_is_fail_closed():
    for invalid in (None, [], "{}", {"schema": gap.SCHEMA}, True):
        with pytest.raises(gap.Refused):
            gap.review_frozen_snapshot(invalid)


def test_no_network_or_tag_writer_or_paid_sender_entrypoint_exposed():
    # The target module exports only snapshot validation and static data.
    for forbidden in (
        "github_post", "issue_ref", "create_ref", "send_provider",
        "run_paid_workflow", "dispatch_workflow", "release_secret",
        "consume_production_tag", "approve_cost",
    ):
        assert not hasattr(gap, forbidden)
    assert gap.review_frozen_snapshot(snapshot()).authorized_to_send_provider is False


def test_documentation_preserves_live_boundary():
    doc = DOC.read_text(encoding="utf-8")
    for phrase in (
        "NO-GO", "Run ID", "issuer", "sender", "durable",
        "4e864ebad860be2ce71a6c233e98a581094b45aa",
        "25305970", "Issue #427",
    ):
        assert phrase in doc
    assert "POST /git/refs" in doc
    assert "read-only" in doc
