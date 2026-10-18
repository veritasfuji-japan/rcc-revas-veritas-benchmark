"""#462: distinguish original capped SDK wire and the stripped local mock wire."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import pytest

from scripts import task4_462_ingress_broker_native_offline_v1 as m


def make_evidence():
    rows = [{"origin_arm": arm} for arm in ("A", "B")]
    report = {"response_receipts": [],
              "complete_native_terminals_locally": 2,
              "detached_native_scorer_calls_locally": 2,
              "real_provider_calls": 0,
              "new_genuine_native_utility_scores": 0}
    broker, ingress, vault = [], [], []
    for arm in ("A", "B"):
        for ordinal in range(4):
            token = arm + str(ordinal)
            sdk_sha = m.sha(("cap-" + token).encode())
            mock_sha = m.sha(("uncapped-" + token).encode())
            response_sha = m.sha(("response-" + token).encode())
            broker.append({"arm": arm, "ordinal": ordinal,
                           "sdk_request_sha256": sdk_sha,
                           "local_mock_request_sha256": mock_sha,
                           "response_sha256": response_sha})
            ingress.append({"arm": arm, "ordinal": ordinal,
                            "request_sha256": sdk_sha,
                            "response_sha256": response_sha,
                            "provenance": "UNVERIFIED_RESPONSE_SUPPLIED_BY_CALLER"})
            vault.append({"arm": arm, "ordinal": ordinal,
                          "request_sha256": sdk_sha,
                          "response_sha256": response_sha,
                          "external_provider_authenticated": False})
            report["response_receipts"].append({"arm": arm, "ordinal": ordinal,
                 "original_request_raw_sha256": mock_sha,
                 "original_response_raw_sha256": response_sha,
                 "source": "LOCAL_SCRIPTED_SDK_MOCK_NOT_REAL_PROVIDER"})
    return rows, report, broker, ingress, vault


def test_distinct_wire_and_mock_hashes_are_linked_but_not_spliced():
    assert m.verify_linkage(*make_evidence()) is True


@pytest.mark.parametrize("mutation", [
    "sdk_request_swap", "mock_request_swap", "response_swap", "ingress_swap",
    "duplicate_arm", "duplicate_ordinal", "missing_record", "vault_origin_promotion",
    "ingress_origin_promotion", "journal_origin_promotion", "fake_true_score",
    "true_provider_count", "missing_native_terminal", "missing_scorer",
    "wrong_native_arm", "pretend_sdk_and_mock_are_same",
])
def test_provenance_refuses_splicing_or_result_promotion(mutation):
    rows, report, broker, ingress, vault = copy.deepcopy(make_evidence())
    if mutation == "sdk_request_swap": broker[0]["sdk_request_sha256"] = "f" * 64
    elif mutation == "mock_request_swap": broker[0]["local_mock_request_sha256"] = "f" * 64
    elif mutation == "response_swap": broker[0]["response_sha256"] = "f" * 64
    elif mutation == "ingress_swap": ingress[0]["request_sha256"] = "f" * 64
    elif mutation == "duplicate_arm": vault[0]["arm"] = "B"
    elif mutation == "duplicate_ordinal": broker[0]["ordinal"] = 1
    elif mutation == "missing_record": ingress.pop()
    elif mutation == "vault_origin_promotion": vault[0]["external_provider_authenticated"] = True
    elif mutation == "ingress_origin_promotion": ingress[0]["provenance"] = "PROVIDER_ATTESTED"
    elif mutation == "journal_origin_promotion": report["response_receipts"][0]["source"] = "PROVIDER"
    elif mutation == "fake_true_score": report["new_genuine_native_utility_scores"] = 1
    elif mutation == "true_provider_count": report["real_provider_calls"] = 1
    elif mutation == "missing_native_terminal": report["complete_native_terminals_locally"] = 1
    elif mutation == "missing_scorer": report["detached_native_scorer_calls_locally"] = 1
    elif mutation == "wrong_native_arm": rows[0]["origin_arm"] = "B"
    elif mutation == "pretend_sdk_and_mock_are_same": broker[0]["local_mock_request_sha256"] = broker[0]["sdk_request_sha256"]
    with pytest.raises(m.Refused):
        m.verify_linkage(rows, report, broker, ingress, vault)


def test_reject_credentials(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sentinel")
    with pytest.raises(m.Refused):
        m.deny_live_context()


def test_reject_provider_approval_switch(monkeypatch):
    monkeypatch.setenv("TASK4_462_PAID_APPROVAL", "anything")
    with pytest.raises(m.Refused):
        m.deny_live_context()


def test_no_privileged_transport_or_paid_workflow_in_script():
    text = Path(m.__file__).read_text(encoding="utf8")
    for prohibited in ("workflow_dispatch", "requests.post(",
                       "httpx.HTTPTransport(", "httpx.Client(transport=None",
                       '"real_provider_dispatch": "ALLOW"',
                       '"score_status": "SCORED"'):
        assert prohibited not in text
    for required in ("SDKResponseIngress(", "vault.commit_before_parser(",
                     '"op": "consume"', '"op": "attach"',
                     "journal.observe(", "driver.run_source(arm)",
                     '"real_provider_dispatch": "DENY"'):
        assert required in text


@pytest.mark.skipif(os.environ.get("TASK4_462_NATIVE_PROOF") != "1",
                    reason="Requires pinned SDK/AgentDojo/RCC/VERITAS CI fixtures")
def test_actual_independent_local_native_ingress_broker_aead_scorer():
    report = m.run_local_direct_join()
    assert report["sdk_original_capped_requests"] == 8
    assert report["original_response_objects_preserved_after_ingress"] == 8
    assert report["local_aead_broker_attach_before_sdk_parser"] == 8
    assert report["broker_ciphertexts_recovered_after_restart"] == 8
    assert report["local_native_terminals"] == 2
    assert report["local_native_scorer_calls"] == 2
    assert report["score_status"] == "UNSCORED"
    assert report["true_utility"] is None and report["true_injection"] is None
    assert report["real_provider_posts"] == 0
    assert report["real_provider_dispatch"] == "DENY"
    assert report["external_provider_origin_authenticated"] is False
    assert report["remote_atomic_ledger_proven"] is False
    assert all(x["sdk_request_sha256"] != x["local_mock_request_sha256"]
               and x["response_object_identity_preserved"] is True
               for x in report["capped_sdk_vs_mock_uncapped_receipt_pairs"])