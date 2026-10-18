"""#459: source/receipt refusal plus one actual LOCAL Native->broker join test."""
from __future__ import annotations
import copy
import os
from pathlib import Path
import pytest

from scripts import task4_459_native_broker_custody_join_v1 as joined


def fixtures():
    crypt = []
    native = []
    for arm in ("A", "B"):
        for ordinal in range(4):
            sig = arm + str(ordinal)
            r = "a" * 63 + str(ordinal)
            s = "b" * 63 + str(ordinal)
            crypt.append({"arm": arm, "ordinal": ordinal, "request_sha256": r,
                          "response_sha256": s,
                          "external_provider_authenticated": False,
                          "independent_durable_custody": False})
            native.append({"arm": arm, "ordinal": ordinal,
                           "original_request_raw_sha256": r,
                           "original_response_raw_sha256": s,
                           "provider_authenticated": False,
                           "source": "LOCAL_SCRIPTED_SDK_MOCK_NOT_REAL_PROVIDER"})
    report = {"distinct_raw_sdk_response_count": 8,
              "complete_native_terminals_locally": 2,
              "detached_native_scorer_calls_locally": 2,
              "real_provider_calls": 0,
              "new_genuine_native_utility_scores": 0,
              "live_provider_dispatch": "DENY"}
    return crypt, native, report


def test_frozen_join_and_case_flags():
    assert joined.audit_join(*fixtures()) is True
    assert joined.CASE == "banking:user_task_4:injection_task_0:direct"


@pytest.mark.parametrize("mutation", [
    "request_swap", "response_swap", "duplicate_arm", "provider_label",
    "provider_auth", "custody_claim", "scorer_forgery", "dispatch_forgery",
    "missing_response", "incomplete_native",
])
def test_fail_closed_no_provenance_or_result_promotion(mutation):
    crypto, native, report = fixtures()
    if mutation == "request_swap":
        native[0]["original_request_raw_sha256"] = "f" * 64
    elif mutation == "response_swap":
        native[0]["original_response_raw_sha256"] = "f" * 64
    elif mutation == "duplicate_arm":
        crypto[0]["arm"] = "B"
    elif mutation == "provider_label":
        native[0]["source"] = "GENUINE_PROVIDER"
    elif mutation == "provider_auth":
        native[0]["provider_authenticated"] = True
    elif mutation == "custody_claim":
        crypto[0]["independent_durable_custody"] = True
    elif mutation == "scorer_forgery":
        report["new_genuine_native_utility_scores"] = 2
    elif mutation == "dispatch_forgery":
        report["live_provider_dispatch"] = "ALLOW"
    elif mutation == "missing_response":
        native.pop()
    elif mutation == "incomplete_native":
        report["complete_native_terminals_locally"] = 1
    with pytest.raises(joined.Refused):
        joined.audit_join(crypto, native, report)


def test_source_has_no_provider_sender_or_live_switch():
    s = Path(joined.__file__).read_text()
    for prohibited in ("workflow_dispatch", "requests.post(", "httpx.HTTPTransport(",
                       "socket.create_connection(", "OPENAI_API_KEY=", "live_post = True"):
        assert prohibited not in s
    assert "driver.run_source(arm)" in s
    assert "vault.commit_before_parser" in s
    assert '"op": "consume"' in s
    assert '"op": "attach"' in s


@pytest.mark.skipif(os.environ.get("TASK4_459_NATIVE_PROOF") != "1",
                    reason="Exact pinned AgentDojo/RCC/VERITAS CI environment required")
def test_actual_local_native_broker_restart_scoring():
    r = joined.run_local_join()
    assert r["native_model_requests_captured"] == 8
    assert r["encrypted_broker_slots_recovered_after_restart"] == 8
    assert r["source_native_terminals"] == 2
    assert r["source_detached_native_scorer_calls"] == 2
    assert len(r["hash_only_receipts"]) == 8
    assert r["real_provider_posts"] == r["new_genuine_utility"] == 0
    assert r["live_dispatch"] == "DENY"
    assert r["provider_authenticated"] is False
    assert r["off_runner_custody_proven"] is False
    assert r["independent_cross_runner_cas_proven"] is False
    assert all(set(x) == {"arm", "ordinal", "request_sha256", "response_sha256",
                              "ciphertext_sha256", "broker_receipt_sha256"}
               for x in r["hash_only_receipts"])