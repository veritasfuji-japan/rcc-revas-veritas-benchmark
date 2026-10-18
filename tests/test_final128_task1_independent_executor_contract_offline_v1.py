"""Fail-closed design-contract tests. No Provider or GitHub side effects."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import socket

import pytest

from scripts import final128_task1_independent_executor_contract_offline_v1 as m


@pytest.fixture(autouse=True)
def no_network_no_credentials(monkeypatch):
    def blocked(*_args, **_kwargs):
        pytest.fail("TASK1_EXECUTOR_CONTRACT_NEVER_NETWORK")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    for key in ("GITHUB_TOKEN", "GH_TOKEN", "OPENAI_API_KEY", "TASK1_OPENAI_API_KEY",
                "TASK1_CAPTURE_AES256_KEY", "TASK4_OPENAI_API_KEY"):
        monkeypatch.delenv(key, raising=False)


def test_checked_in_contract_is_exact_and_no_go():
    result = m.review_file()
    assert result.status == "OFFLINE_REQUIREMENTS_INTEGRITY_ONLY_PAID_NO_GO"
    assert result.design_integrity_only is True
    assert result.paid_dispatch_authorized is False
    assert result.real_iam_installed is False
    assert result.remote_global_single_use_proven is False
    assert result.real_provider_non_bypassability_proven is False
    assert result.can_execute_provider is False
    assert len(result.blockers) == 8


@pytest.mark.parametrize("section,key,value", [
    ("trust_domains", "github_runner", {"principal": "OWNER"}),
    ("trust_domains", "executor", {"provider_credentials": "INHERITED_FROM_RUNNER"}),
    ("trust_domains", "ledger", {"cross_runner_scope": "LOCAL_SQLITE_ONLY"}),
    ("trust_domains", "issuer", {"provider_credentials": "ALLOWED"}),
    ("lease", "global_unique_key", ["run_id", "arm"]),
    ("lease", "unknown_result", "ALLOW_RETRY"),
    ("lease", "ledger_outage", "ALLOW_WITHOUT_LEDGER"),
    ("lease", "direct_sender_bypass", "APPLICATION_POLICY_ONLY"),
    ("lease", "arm_order", "B_CAN_PRECEDE_A"),
    ("current_evidence", "paid_consent_granted", True),
    ("current_evidence", "live_provider_requests", 1),
    ("current_evidence", "global_consumption_claim", "PROVEN"),
])
def test_each_wrong_boundary_or_false_go_is_rejected(section, key, value):
    forged = deepcopy(m.expected_contract())
    if section == "trust_domains":
        forged[section][key].update(value)
    else:
        forged[section][key] = value
    with pytest.raises(m.Refused, match="FALSE_ELEVATION"):
        m.review_contract(forged)


@pytest.mark.parametrize("field", [
    "real_enrolled_issuer_and_sender", "provider_secret_exclusivity_verified",
    "remote_atomic_ledger_multi_runner_verified", "no_bypass_egress_verified",
    "423_sender_integrated_into_executor", "real_bind_last_boundary_verified",
    "paid_consent_granted", "provider_budget_hard_cap_verified",
])
def test_setting_any_evidence_claim_to_true_does_not_upgrade_design(field):
    changed = deepcopy(m.expected_contract())
    changed["current_evidence"][field] = True
    with pytest.raises(m.Refused):
        m.review_contract(changed)


def test_extras_missing_fields_bool_integer_and_mutable_copy_refuse():
    contract = m.expected_contract()
    contract["source_prs"].append(999)
    with pytest.raises(m.Refused):
        m.review_contract(contract)
    contract = m.expected_contract()
    del contract["lease"]["unknown_result"]
    with pytest.raises(m.Refused):
        m.review_contract(contract)
    contract = m.expected_contract()
    contract["current_evidence"]["live_provider_requests"] = False
    with pytest.raises(m.Refused):
        m.review_contract(contract)
    contract = m.expected_contract()
    contract["unreviewed_permission"] = "ALLOW"
    with pytest.raises(m.Refused):
        m.review_contract(contract)


def test_duplicate_keys_and_nonfinite_json_fail_closed():
    for raw in (b'{"a":1,"a":2}', b'{"status":NaN}', b'{', b'[] trailing',
                b'\xff', b' ' * 32769):
        with pytest.raises(m.Refused):
            m.parse_strict(raw)


def test_false_attestations_cannot_become_authority():
    for value in ({}, {"all_proofs_green": True, "proof_id": "abc"},
                  {"iam_attested": True, "remote_store_usable": True}):
        r = m.review_live_claims(value)
        assert r.paid_dispatch_authorized is False and r.can_execute_provider is False
        assert r.real_provider_non_bypassability_proven is False
        assert r.remote_global_single_use_proven is False
    for invalid in (None, True, ["proven"], {12: "valid"},
                    {"provider_api_key": "placeholder"},
                    {"authorization": "granted"}, {"secret_proof": 1}):
        with pytest.raises(m.Refused):
            m.review_live_claims(invalid)


def test_local_contract_only_no_live_sender_routines():
    source = Path(m.__file__).read_text(encoding="utf-8")
    for forbidden in ("import http.client", "import requests", "from openai",
                      "import urllib", "import subprocess", "os.environ",
                      "api.openai.com", "workflow_dispatch", "POST /git/refs"):
        assert forbidden not in source
    assert not hasattr(m, "send_provider")
    assert not hasattr(m, "create_tag")
    assert m.review_file().status.endswith("PAID_NO_GO")
