"""Task4 #451: one native case, genuine-vs-scripted Utility provenance gap."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from scripts import task4_451_one_case_utility_provenance_audit_v1 as m

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/optimization/TASK4_451_ONE_CASE_UTILITY_PROVENANCE_AUDIT_V1.md"


def proposal(kind="SDK_MOCK_SCRIPTED"):
    return {
        "case_id": m.CASE,
        "source_class": kind,
        "original_request_sha256": "a" * 64,
        "candidate_sha256": "b" * 64,
        "initial_prestate_sha256": "c" * 64,
        "arms": [
            {"arm": arm, "candidate_sha256": "b" * 64,
             "initial_prestate_sha256": "c" * 64,
             "terminal_model_response_sha256": (
                "d" * 64 if kind == "SDK_MOCK_SCRIPTED" else None),
             "detached_scorer_output_sha256": (
                "e" * 64 if kind == "SDK_MOCK_SCRIPTED" else None)}
            for arm in ("A", "B")
        ]
    }


def test_frozen_source_contracts_identify_actual_measurement_gap():
    result = m.existing_gap()
    assert result["target_case_id"] == m.CASE
    assert result["historical_v13"] == {
        "A": 93, "B": 64, "injection_B": 0,
        "net_utility_gap": 29, "new_recoveries": 0,
    }
    assert result["case_evidence"]["scripted_local_sdk_native_terminal_and_scorer"] is True
    assert result["case_evidence"]["scripted_local_sdk_genuine_model_generations"] == 0
    assert result["case_evidence"]["real_archived_third_proposals"] == 2
    assert result["case_evidence"]["real_archived_native_bind_denials"] == 2
    assert result["case_evidence"]["real_archived_terminal_model_responses"] == 0
    assert result["case_evidence"]["real_archived_native_terminal_scorer_calls"] == 0
    assert result["case_evidence"]["real_archived_preissued_trusted_date"] is False
    assert result["case_evidence"]["fresh_exact_owner_consent"] is False
    assert result["new_native_utility_recoveries"] == 0
    assert result["new_real_provider_calls"] == 0
    assert result["new_actual_native_scorer_calls"] == 0
    assert result["external_provider_dispatch"] == "DENY"
    assert len(result["missing_for_new_measurement"]) >= 6
    assert len(m.SOURCES) == 5


@pytest.mark.parametrize("kind,complete", [
    ("SDK_MOCK_SCRIPTED", True),
    ("ARCHIVED_REAL_THIRD_INCOMPLETE", False),
])
def test_paired_shape_never_becomes_native_utility_recovery(kind, complete):
    p = proposal(kind)
    v = m.inspect_untrusted_pair(p)
    assert v["pair_shape_verified"] is True
    assert v["terminal_digest_fields_present"] is complete
    assert v["provenance_independently_authenticated"] is False
    assert v["native_scorer_output_independently_verified"] is False
    assert type(v["new_measured_utility_recovery_credit"]) is int
    assert v["new_measured_utility_recovery_credit"] == 0
    assert v["trusted_execution_authority_created"] is False
    assert v["actual_provider_dispatch"] == "DENY"


@pytest.mark.parametrize("mutation", [
    lambda x: x.__setitem__("case_id", "banking:user_task_14:injection_task_0:direct"),
    lambda x: x.__setitem__("source_class", "AUTHENTIC_PROSPECTIVE"),
    lambda x: x.__setitem__("source_class", "SDK_MOCK_SCRIPTED_REAL_PROVIDER"),
    lambda x: x.__setitem__("new_utility_recovery", True),
    lambda x: x.__setitem__("paid_dispatch_authorized", True),
    lambda x: x.__setitem__("official_score_verified", True),
    lambda x: x.__setitem__("original_request_sha256", "Z" * 64),
    lambda x: x.__setitem__("candidate_sha256", 7),
    lambda x: x.__setitem__("arms", []),
    lambda x: x["arms"].reverse(),
    lambda x: x["arms"][0].__setitem__("candidate_sha256", "f" * 64),
    lambda x: x["arms"][1].__setitem__("initial_prestate_sha256", "a" * 64),
    lambda x: x["arms"][0].__setitem__("terminal_model_response_sha256", None),
    lambda x: x["arms"][0].__setitem__("detached_scorer_output_sha256", True),
    lambda x: x["arms"][0].__setitem__("execution_authorized", True),
])
def test_untrusted_proposal_mutation_never_authenticates(mutation):
    p = proposal()
    mutation(p)
    with pytest.raises(m.Refused):
        m.inspect_untrusted_pair(p)


@pytest.mark.parametrize("mutation", [
    lambda x: x["arms"][0].__setitem__("terminal_model_response_sha256", "1" * 64),
    lambda x: x["arms"][1].__setitem__("detached_scorer_output_sha256", "2" * 64),
    lambda x: x["arms"][0].__setitem__("native_dispatch_count", 1),
])
def test_archived_real_third_cannot_gain_terminal_or_score(mutation):
    p = proposal("ARCHIVED_REAL_THIRD_INCOMPLETE")
    mutation(p)
    with pytest.raises(m.Refused):
        m.inspect_untrusted_pair(p)


def test_duplicate_key_and_nonfinite_json_refused():
    for raw in ('{"score":1,"score":0}', '{"score":NaN}',
                '{"score":Infinity}', '{"scorer":-Infinity}', '{'):
        with pytest.raises(m.Refused):
            m.unique_json(raw)


def test_source_blob_tampering_fails_closed(tmp_path):
    for name in m.SOURCES:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / name).read_bytes())
    assert len(m.source_snapshot(tmp_path)) == len(m.SOURCES)
    for name in m.SOURCES:
        path = tmp_path / name
        original = path.read_bytes()
        path.write_bytes(original + b"\n")
        with pytest.raises(m.Refused):
            m.source_snapshot(tmp_path)
        path.write_bytes(original)


def test_source_is_not_provider_dispatch_or_new_official_scorer():
    content = Path(m.__file__).read_text(encoding="utf-8")
    for forbidden in ("import http.client", "from openai", "import requests",
                      "api.openai.com", "workflow_dispatch", "POST /git/refs",
                      "TASK4_OPENAI_API_KEY", "OPENAI_API_KEY", "import urllib"):
        assert forbidden not in content
    assert not hasattr(m, "send_provider")
    assert not hasattr(m, "run_official_scorer")
    doc = DOC.read_text(encoding="utf-8")
    for needed in ("#318", "#320", "#344", "#364", "#450", "Ben",
                   "NO-GO", "Task4", "Utility", "not a new"):
        assert needed in doc
