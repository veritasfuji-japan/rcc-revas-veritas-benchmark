"""Offline audit of frozen pre-452 #423 source + inert role design."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import socket

import pytest

from scripts import final128_task1_issuer_sender_job_graph_audit_offline_v1 as m

ROOT = Path(__file__).resolve().parents[1]
LIVE = ROOT / m.HISTORICAL_SNAPSHOT_PATH
CURRENT = ROOT / m.WORKFLOW_PATH
BLUEPRINT = (ROOT / "docs/optimization/"
             "TASK1_423_ISSUER_SENDER_JOB_SPLIT_INERT_BLUEPRINT_V1.json")
DOC = (ROOT / "docs/optimization/"
       "FINAL128_TASK1_ISSUER_SENDER_JOB_SPLIT_AUDIT_OFFLINE_V1.md")


@pytest.fixture(autouse=True)
def forbid_live_network_and_secret_environment(monkeypatch):
    def deny(*_args, **_kwargs):
        pytest.fail("TASK1_ISSUER_SENDER_GRAPH_OFFLINE_NO_NETWORK")
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket.socket, "connect_ex", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    for key in (
        "GITHUB_TOKEN", "GH_TOKEN", "OPENAI_API_KEY",
        "TASK1_OPENAI_API_KEY", "TASK1_CAPTURE_AES256_KEY",
        "TASK1_RESEARCH_OPENAI_API_KEY",
        "TASK1_RESEARCH_CAPTURE_AES256_KEY", "TASK4_OPENAI_API_KEY",
        "VERITAS_RULESET_OWNER_TOKEN",
    ):
        monkeypatch.delenv(key, raising=False)


def load():
    return LIVE.read_bytes(), BLUEPRINT.read_bytes()


def blueprint_object():
    return json.loads(BLUEPRINT.read_bytes())


def assert_non_authorizing(report):
    assert report.actual_job_separation_enforced is False
    assert report.independently_enrolled_sender_or_issuer is False
    assert report.trusted_run_and_job_identity_authenticated is False
    assert report.protected_secret_release_verified is False
    assert report.provider_egress_non_bypassable is False
    assert report.cross_runner_once_ledger_proven is False
    assert report.github_ruleset_to_ref_atomic_authority_proven is False
    assert report.allowed_to_dispatch_paid_task1 is False
    assert report.allowed_to_issue_or_consume_tag is False
    assert report.decision == "PAID_TASK1_NO_GO"


def test_historical_real_workflow_is_pinned_and_unsplit():
    live, _ = load()
    assert m.git_blob_hash(live) == m.WORKFLOW_BLOB
    assert m.git_blob_hash(CURRENT.read_bytes()) != m.WORKFLOW_BLOB
    report = m.inspect_current_workflow(live)
    assert report.observation == "OBSERVED_PINNED_423_UNSPLIT_JOB_STATIC_SOURCE_ONLY"
    assert report.observed_same_job_tag_and_provider_capability is True
    assert report.observed_write_token_scope_in_provider_job is True
    assert report.observed_provider_secret_reference_in_same_job_as_tag is True
    assert report.proposed_two_role_graph_shape_matched is False
    assert_non_authorizing(report)


def test_blueprint_is_inert_and_exactly_two_separate_proposed_jobs():
    _, spec = load()
    report = m.review_inert_blueprint(spec)
    assert report.observation == "TWO_INERT_DESIGN_ROLES_NOT_DEPLOYED_OR_AUTHORIZED"
    assert report.proposed_two_role_graph_shape_matched is True
    assert report.observed_same_job_tag_and_provider_capability is False
    assert_non_authorizing(report)
    candidate = blueprint_object()
    assert "jobs" not in candidate and "on" not in candidate
    roles = candidate["proposal"]
    assert roles["issuer"]["needs"] == []
    assert roles["sender"]["needs"] == ["issuer"]
    assert roles["issuer"]["permissions"] == {"contents": "write"}
    assert roles["issuer"]["environment"] is None
    assert roles["issuer"]["secret_names"] == []
    assert roles["sender"]["permissions"] == {"contents": "read"}
    assert "TASK1_OPENAI_API_KEY" in roles["sender"]["secret_names_as_symbols_only"]
    assert roles["sender"]["may_write_git_ref_in_future_design"] is False
    assert roles["issuer"]["may_send_provider_in_future_design"] is False
    assert candidate["proposal"]["handoff"]["trusted_issuer_enrolled"] is False
    assert candidate["proposal"]["enforcement"]["fresh_paid_consent"] is False
    assert m.RESEARCH_TAG != m.PRODUCTION_TAG


def test_combined_gap_review_never_grants_tag_provider_or_utility():
    a, b = load()
    report = m.audit_inert_split(a, b)
    assert_non_authorizing(report["observed_live_source"])
    assert_non_authorizing(report["inert_design"])
    assert report["permission_to_send_provider"] is False
    assert report["permission_to_write_tags"] is False
    assert report["new_utility_or_attack_scores"] is None
    assert report["evidence_status"] == (
        "OFFLINE_JOB_GRAPH_GAP_RECORDED_NO_LIVE_ROLE_ISOLATION"
    )


@pytest.mark.parametrize("change", [
    lambda d: d["proposal"]["issuer"].update(permissions={"contents": "read"}),
    lambda d: d["proposal"]["issuer"].update(
        permissions={"contents": "write", "actions": "write"}),
    lambda d: d["proposal"]["issuer"].update(
        permissions={"contents": "write", "administration": "write"}),
    lambda d: d["proposal"]["issuer"].update(
        permissions={"contents": "write", "id-token": "write"}),
    lambda d: d["proposal"]["issuer"].update(environment="task1-real-model-pilot"),
    lambda d: d["proposal"]["issuer"].update(
        secret_names=["TASK1_OPENAI_API_KEY"]),
    lambda d: d["proposal"]["issuer"].update(may_access_provider_secret=True),
    lambda d: d["proposal"]["issuer"].update(may_send_provider_in_future_design=True),
    lambda d: d["proposal"]["sender"].update(permissions={"contents": "write"}),
    lambda d: d["proposal"]["sender"].update(
        permissions={"contents": "read", "actions": "write"}),
    lambda d: d["proposal"]["sender"].update(
        secret_names_as_symbols_only=["GH_TOKEN"]),
    lambda d: d["proposal"]["sender"].update(
        secret_names_as_symbols_only=["TASK1_OPENAI_API_KEY"]),
    lambda d: d["proposal"]["sender"].update(
        environment_name_in_design_not_reviewed="task1-other-env"),
    lambda d: d["proposal"]["sender"].update(
        may_write_git_ref_in_future_design=True),
    lambda d: d["proposal"]["sender"].update(needs=[]),
    lambda d: d["proposal"]["sender"].update(needs=["sender"]),
    lambda d: d["proposal"]["handoff"].update(
        trusted_issuer_enrolled=True),
    lambda d: d["proposal"]["handoff"].update(
        recipient_identity_independently_authenticated=True),
    lambda d: d["proposal"]["handoff"].update(
        durable_per_arm_claim_and_consume_enforced=True),
    lambda d: d["proposal"]["handoff"].update(
        provider_egress_isolated=True),
    lambda d: d["proposal"]["handoff"].update(
        required_bound_fields=["run_id", "model"]),
    lambda d: d["proposal"]["enforcement"].update(
        actual_paid_provider_dispatch_authorized=True),
    lambda d: d["proposal"]["enforcement"].update(fresh_paid_consent=True),
    lambda d: d["proposal"]["enforcement"].update(fresh_paid_consent=0),
    lambda d: d["proposal"]["enforcement"].update(global_once_proven=True),
    lambda d: d.update(mode="LIVE_APPROVED_WORKFLOW"),
    lambda d: d.update(repository="attacker/fork"),
    lambda d: d.update(
        future_production_ref_not_authorized_to_issue=m.RESEARCH_TAG),
    lambda d: d["observed_paid_workflow"].update(
        git_blob_sha="0" * 40),
    lambda d: d["observed_paid_workflow"].update(
        currently_same_job=False),
    lambda d: d["observed_paid_workflow"].update(
        operator_decision="GO"),
    lambda d: d.update(on="workflow_dispatch", jobs={}),
    lambda d: d["proposal"]["issuer"].update(
        steps=[{"run": "send_to_provider"}]),
])
def test_mutated_inert_plan_never_claims_enforced_role_split(change):
    data = blueprint_object()
    change(data)
    with pytest.raises(m.Refused, match="NOT_EXACT_INERT_JOB_SPLIT_DESIGN"):
        m.review_inert_blueprint(json.dumps(data).encode("utf8"))


@pytest.mark.parametrize("modification", [
    lambda s: s.replace(b"contents: write", b"contents: read", 1),
    lambda s: s.replace(b"task1-real-model-pilot", b"task1-other-environment", 1),
    lambda s: s.replace(b"--mode send", b"--mode preflight", 1),
    lambda s: s.replace(b'"POST"', b'"PATCH"', 1),
    lambda s: s + b"\n# attacker-controlled edit\n",
])
def test_live_workflow_drift_cannot_silently_be_called_proven(modification):
    live, _ = load()
    changed = modification(live)
    assert changed != live
    with pytest.raises(m.Refused, match="PRODUCTION_WORKFLOW_SOURCE_DRIFT"):
        m.inspect_current_workflow(changed)


def test_reject_invalid_or_untrusted_input_without_network():
    a, b = load()
    for bad in (None, b"", "{}", [], {}, False):
        with pytest.raises(m.Refused):
            m.review_inert_blueprint(bad)
        with pytest.raises(m.Refused):
            m.inspect_current_workflow(bad)
    assert m.exact_type_match(False, 0) is False
    assert m.exact_type_match(True, 1) is False
    assert m.exact_type_match({"v": False}, {"v": 0}) is False
    assert m.exact_type_match({"v": [1]}, {"v": [True]}) is False


def test_doc_has_nonclaims_and_blueprint_is_not_runnable():
    txt = DOC.read_text(encoding="utf8")
    for phrase in (
        "NO-GO", "Issue #427", "PR #444", "contents: write",
        "contents: read", "Run ID", "not an executable workflow",
        "durable", "sender", "issuer",
    ):
        assert phrase in txt
    spec = BLUEPRINT.read_text(encoding="utf8")
    assert BLUEPRINT.parent.name == "optimization"
    assert '"mode": "OFFLINE_DESIGN_DATA_NO_GITHUB_WORKFLOW_NO_EXECUTION"' in spec
    assert '"jobs":' not in spec
    assert '"on":' not in spec
    assert '"steps":' not in spec
    assert '"run":' not in spec
    assert "github.token" not in spec
    source = Path(m.__file__).read_text(encoding="utf8")
    for forbidden in (
        "import socket", "import urllib", "import http.client",
        "import requests", "import subprocess", "from openai",
        "os.environ", "workflow_dispatch(", "api.openai.com",
    ):
        assert forbidden not in source
