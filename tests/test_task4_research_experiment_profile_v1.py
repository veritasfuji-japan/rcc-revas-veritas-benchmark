"""Portable checks: configuration is bounded and never paid permission."""
from dataclasses import FrozenInstanceError, replace

import pytest

from task4_research_experiment_profile_v1 import Task4ResearchProfile


def profile(**kwargs):
    return Task4ResearchProfile("local-test-20261029", "2027-02-05", **kwargs)


def test_profile_is_explicit_immutable_and_non_authoritative():
    p = profile()
    assert p.to_dict()["provider_permission"] is False
    assert p.to_dict()["byte_limits_are_provider_token_or_billing_caps"] is False
    assert len(p.identity) == 64
    with pytest.raises(FrozenInstanceError):
        p.task_date = "2027-02-06"
    copy = p.to_dict()
    copy["provider_permission"] = True
    assert p.to_dict()["provider_permission"] is False


@pytest.mark.parametrize("field,value", [
    ("execution_id", "../bad"), ("execution_id", "short"),
    ("execution_id", None), ("task_date", "2027-2-5"),
    ("task_date", "not-a-date"), ("task_date", 20310708),
    ("model_id", "https://example.test"), ("model_id", ""),
    ("model_id", True), ("max_requests_per_arm", True),
    ("max_requests_per_arm", 0), ("max_requests_per_arm", 13),
    ("output_token_cap", False), ("output_token_cap", 4097),
    ("max_request_bytes", 0), ("max_request_bytes", 256001),
    ("max_total_request_bytes_per_arm", 1),
    ("max_total_request_bytes_per_arm", 3072001),
])
def test_invalid_configuration_is_rejected(field, value):
    with pytest.raises((ValueError, TypeError)):
        replace(profile(), **{field: value})


@pytest.mark.parametrize("field,value", [
    ("task_date", "2027-02-06"), ("model_id", "offline-other-model"),
    ("max_requests_per_arm", 5), ("output_token_cap", 512),
    ("max_request_bytes", 63000), ("max_total_request_bytes_per_arm", 250000),
])
def test_every_experiment_condition_changes_identity(field, value):
    p = profile()
    assert replace(p, **{field: value}).identity != p.identity
