"""Task4 #466: source evidence is not true authorization."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import shutil

import pytest
from scripts import task4_466_real_issuer_evidence_gap_audit_no_go_v1 as m


def test_frozen_audit_never_promotes_issuer_or_provider():
    report = m.audit()
    assert report["rule_of_one"] == m.RULE
    assert report["baseline_main"] == m.BASE_MAIN
    assert report["real_provider_dispatch"] == "DENY"
    assert report["real_provider_permission"] is False
    assert report["real_provider_posts"] == 0
    assert report["score_status"] == "UNSCORED"
    assert report["new_native_ab_utility"] is None
    for k in ("authenticated_external_issuer", "trusted_real_clock",
              "approved_refund_recipient", "authorized_refund_amount",
              "independent_production_boundary"):
        assert report[k] is False
    assert len(report["source_pins_verified"]) == 5
    assert len(report["research_evidence_gaps"]) == 8
    assert len(report["production_only_evidence_gaps"]) == 4
    assert all(g["status"] == "NOT_ATTESTED"
               for g in (report["research_evidence_gaps"] +
                         report["production_only_evidence_gaps"]))


@pytest.mark.parametrize("required_gate", [
    "AUTHENTIC_ORIGINAL_REQUEST_AND_SCOPE", "REFUND_AMOUNT_OWNER_PROVENANCE",
    "RECIPIENT_ACCOUNT_AUTHORITY", "TRUSTED_ISSUER_AND_KEY_ENROLLMENT",
    "BEFORE_FIRST_REQUEST_DATE_AND_CLOCK", "SIGNED_SCOPE_AND_ACTUAL_WIRE_ATTESTATION",
    "COST_CREDENTIAL_AND_EXPLICIT_OWNER_APPROVAL",
    "COMPLETE_NATIVE_AB_AUTHENTIC_EVIDENCE",
])
def test_all_research_gaps_still_unattested(required_gate):
    gaps = m.audit()["research_evidence_gaps"]
    matching = [row for row in gaps if row["requirement"] == required_gate]
    assert len(matching) == 1
    assert matching[0]["status"] == "NOT_ATTESTED"


@pytest.mark.parametrize("name", [
    "INDEPENDENTLY_OPERATED_ISSUER", "CROSS_RUNNER_PERMANENT_ONCE",
    "SENDER_IAM_CREDENTIAL_EGRESS", "INDEPENDENT_AUDIT_RECONCILIATION",
])
def test_do_not_require_production_claim_for_research_narrow_scope(name):
    report = m.audit()
    assert any(g["requirement"] == name for g in
               report["production_only_evidence_gaps"])
    assert not any(g["requirement"] == name for g in
                   report["research_evidence_gaps"])
    assert report["real_provider_permission"] is False


@pytest.mark.parametrize("key", m.SENSITIVE)
def test_present_provider_or_paid_context_is_refused(monkeypatch, key):
    monkeypatch.setenv(key, "SENTINEL_NEVER_REAL")
    with pytest.raises(m.AuditDenied, match="466_LIVE_CREDENTIAL"):
        m.audit()


@pytest.mark.parametrize("target", list(m.SOURCE_PINS))
def test_tampered_pinned_source_fails_closed(tmp_path, target):
    for name in m.SOURCE_PINS:
        dst = tmp_path / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(m.ROOT / name, dst)
    path = tmp_path / target
    path.write_bytes(path.read_bytes() + b"\n# tamper")
    with pytest.raises(m.AuditDenied, match="466_SOURCE_PIN_DRIFT"):
        m.audit(tmp_path)


def test_missing_pinned_file_denied(tmp_path):
    with pytest.raises(m.AuditDenied, match="466_REQUIRED_PINNED_SOURCE_PATH"):
        m.audit(tmp_path)


def test_cannot_create_go_claim_by_mutating_report():
    original = m.audit()
    forged = copy.deepcopy(original)
    forged["authenticated_external_issuer"] = True
    forged["real_provider_dispatch"] = "ALLOW"
    forged["research_evidence_gaps"][0]["status"] = "PROVEN"
    new = m.audit()
    assert new["real_provider_dispatch"] == "DENY"
    assert new["authenticated_external_issuer"] is False
    assert all(g["status"] == "NOT_ATTESTED"
               for g in new["research_evidence_gaps"])


def test_no_user_supplied_evidence_admission_or_transport_path():
    source = Path(m.__file__).read_text()
    for prohibited in (
        "import openai", "import httpx", "import requests",
        "requests.post(", "httpx.Client(", "workflow_dispatch:",
        "secrets.", '"real_provider_dispatch": "ALLOW"',
        '"real_provider_permission": True',
    ):
        assert prohibited not in source
    workflow = (m.ROOT /
                ".github/workflows/task4-466-real-issuer-gap-audit-offline.yml").read_text()
    for prohibited in (
        "workflow_dispatch:", "pull_request_target:",
        "repository_dispatch:", "secrets.", "environment:",
        "contents: write", "id-token: write",
    ):
        assert prohibited not in workflow
    assert "pull_request:" in workflow
    assert "persist-credentials: false" in workflow
    assert "permissions:" in workflow
    assert "contents: read" in workflow


def test_report_redacts_original_transaction_and_has_no_secrets():
    import json
    report = json.dumps(m.audit(), sort_keys=True)
    assert "GB29NWBK" not in report
    assert "Please refund " not in report
    assert "api_key" not in report.lower()


def test_source_snapshot_is_correct():
    assert len(m.check_pinned_sources()) == len(m.SOURCE_PINS)
    assert m.check_frozen_source_limitations() is True


def test_live_key_env_denied_before_access(monkeypatch):
    monkeypatch.setenv("TASK4_466_PAID_APPROVAL", "yes")
    with pytest.raises(m.AuditDenied):
        m.audit()
