"""Adversarial mock-only Task1 research Git-ref CAS tests: zero real writes."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import hashlib
import socket
import threading

import pytest

from scripts import final128_task1_research_tag_cas_mock_v1 as m

SHA = "a610c17a958c28405636b49258a4fd0def0c4abd"
FIRST = hashlib.sha256(b"native-first-identical-A-and-B-fixture").hexdigest()
RUN = "39030624944"


@pytest.fixture(autouse=True)
def no_outbound_network_or_tokens(monkeypatch):
    def fail(*_args, **_kwargs):
        pytest.fail("NO_REAL_NETWORK_IN_RESEARCH_REF_MOCK")
    monkeypatch.setattr(socket.socket, "connect", fail)
    monkeypatch.setattr(socket.socket, "connect_ex", fail)
    for name in (
        "OPENAI_API_KEY", "TASK1_OPENAI_API_KEY", "GH_TOKEN",
        "GITHUB_TOKEN", "VERITAS_RULESET_OWNER_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)


def plan(**kwargs):
    args = dict(
        run_id=RUN, main_sha=SHA, first_a_sha256=FIRST,
        first_b_sha256=FIRST,
    )
    args.update(kwargs)
    return m.MockPlan(**args)


def assert_no_authority(result):
    assert result.origin_authenticated is False
    assert result.live_provider_dispatch_authorized is False
    assert result.real_tag_issued is False
    assert result.official_native_scoring_eligible is False


def test_mock_clean_create_and_readback_remain_untrusted():
    s = m.InMemoryFakeGitRefs()
    result = m.decide_mock_claim(s, plan())
    assert result.status == "SIMULATED_CAS_OBSERVED_NOT_LIVE_AUTHORITY"
    assert result.created_ref_post_attempted is True
    assert (s.post_attempts, s.read_attempts) == (1, 2)
    assert s.read(m.RESEARCH_REF) == (
        200, {"ref": m.RESEARCH_REF, "object": {"sha": SHA}},
    )
    assert_no_authority(result)
    assert m.PRODUCTION_REF != m.RESEARCH_REF


def test_already_present_ref_never_posts_and_never_dispatches():
    s = m.InMemoryFakeGitRefs()
    assert m.decide_mock_claim(s, plan()).status.startswith("SIMULATED")
    before = s.post_attempts
    result = m.decide_mock_claim(s, plan())
    assert result.status == "DENY_MOCK_REF_ALREADY_PRESENT"
    assert s.post_attempts == before
    assert_no_authority(result)


def test_two_parallel_runners_share_one_mock_global_tag_winner():
    s = m.InMemoryFakeGitRefs()
    barrier = threading.Barrier(2)
    def attempt():
        return m.decide_mock_claim(
            s, plan(), after_pre_read=lambda: barrier.wait(timeout=10)
        )
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(attempt) for _ in range(2)]
        results = [f.result(timeout=20) for f in futures]
    assert sorted(r.status for r in results) == sorted((
        "SIMULATED_CAS_OBSERVED_NOT_LIVE_AUTHORITY",
        "STOP_MOCK_REF_CREATE_CONFLICT_NO_RETRY",
    ))
    assert s.post_attempts == 2
    for r in results:
        assert_no_authority(r)


def test_two_independent_fake_servers_do_not_prove_shared_lock():
    one, two = m.InMemoryFakeGitRefs(), m.InMemoryFakeGitRefs()
    assert m.decide_mock_claim(one, plan()).status.startswith("SIMULATED")
    assert m.decide_mock_claim(two, plan()).status.startswith("SIMULATED")
    # Separate runner disks/servers allow two "winners"; only one real remote
    # namespace with appropriate enforcement could provide global uniqueness.
    assert one.post_attempts == two.post_attempts == 1


@pytest.mark.parametrize("read_fault", ("http_403", "http_500"))
def test_unreadable_preflight_cannot_issue_or_post(read_fault):
    s = m.InMemoryFakeGitRefs()
    result = m.decide_mock_claim(s, plan(), pre_read_fault=read_fault)
    assert result.status == "STOP_MOCK_PREFLIGHT_UNKNOWN"
    assert result.created_ref_post_attempted is False
    assert s.post_attempts == 0
    assert_no_authority(result)


@pytest.mark.parametrize("fault,present", [
    ("timeout_before_commit", False),
    ("timeout_after_commit", True),
])
def test_timeout_before_or_after_fake_commit_never_retries(fault, present):
    s = m.InMemoryFakeGitRefs()
    result = m.decide_mock_claim(s, plan(), post_fault=fault)
    assert result.status == "STOP_MOCK_POST_OUTCOME_UNKNOWN_NO_RETRY"
    assert s.post_attempts == 1
    assert (s.read(m.RESEARCH_REF)[0] == 200) is present
    assert_no_authority(result)


@pytest.mark.parametrize("fault,present", [
    ("http_500_before_commit", False),
    ("http_500_after_commit", True),
    ("http_409_before_commit", False),
    ("http_403", False),
    ("http_429", False),
    ("conflict_422_without_ref", False),
])
def test_error_status_never_retries_or_borrows_authority(fault, present):
    s = m.InMemoryFakeGitRefs()
    result = m.decide_mock_claim(s, plan(), post_fault=fault)
    assert result.status in (
        "STOP_MOCK_CREATE_HTTP_UNCERTAIN_NO_RETRY",
        "STOP_MOCK_REF_CREATE_CONFLICT_NO_RETRY",
    )
    assert s.post_attempts == 1
    assert (s.read(m.RESEARCH_REF)[0] == 200) is present
    assert_no_authority(result)


@pytest.mark.parametrize("fault", (
    "malformed_201_after_commit", "wrong_sha_201_after_commit",
))
def test_http_201_with_wrong_reply_body_fails_closed(fault):
    s = m.InMemoryFakeGitRefs()
    result = m.decide_mock_claim(s, plan(), post_fault=fault)
    assert result.status == "STOP_MOCK_POST_BODY_UNTRUSTED_NO_RETRY"
    assert s.post_attempts == 1
    assert_no_authority(result)


@pytest.mark.parametrize("fault", (
    "http_403", "http_500", "stale_404", "wrong_sha", "malformed_200",
))
def test_readback_failure_even_after_201_is_no_go(fault):
    s = m.InMemoryFakeGitRefs()
    result = m.decide_mock_claim(s, plan(), readback_fault=fault)
    assert result.status == "STOP_MOCK_READBACK_MISMATCH_NO_RETRY"
    assert result.created_ref_post_attempted
    assert s.post_attempts == 1
    assert_no_authority(result)


def test_faked_201_without_ref_fails_readback():
    s = m.InMemoryFakeGitRefs()
    result = m.decide_mock_claim(
        s, plan(), post_fault="false_success_201_without_commit"
    )
    assert result.status == "STOP_MOCK_READBACK_MISMATCH_NO_RETRY"
    assert s.read(m.RESEARCH_REF)[0] == 404
    assert_no_authority(result)


def test_stale_pre_read_false_404_does_not_defeat_atomic_post():
    s = m.InMemoryFakeGitRefs()
    m.decide_mock_claim(s, plan())
    result = m.decide_mock_claim(s, plan(), pre_read_fault="stale_404")
    assert result.status == "STOP_MOCK_REF_CREATE_CONFLICT_NO_RETRY"
    assert_no_authority(result)
    assert s.post_attempts == 2


def test_mock_admin_deletion_allows_second_success_demonstrating_open_risk():
    s = m.InMemoryFakeGitRefs()
    first = m.decide_mock_claim(s, plan())
    assert first.status.startswith("SIMULATED")
    s.admin_deletes_mock_ref()
    again = m.decide_mock_claim(s, plan())
    assert again.status.startswith("SIMULATED")
    assert s.post_attempts == 2
    assert_no_authority(first)
    assert_no_authority(again)


def test_wrong_main_sha_bound_to_existing_ref_refuses():
    s = m.InMemoryFakeGitRefs()
    first = m.decide_mock_claim(s, plan())
    assert first.status.startswith("SIMULATED")
    second = m.decide_mock_claim(s, plan(main_sha="b" * 40))
    assert second.status == "DENY_MOCK_REF_ALREADY_PRESENT"
    assert s.post_attempts == 1
    assert_no_authority(second)


@pytest.mark.parametrize("wrong", (
    {"run_id": "0"},
    {"run_id": "../wrong"},
    {"main_sha": "not-a-sha"},
    {"first_a_sha256": "0" * 64},
    {"first_b_sha256": "0" * 64},
    {"proposed_ref": m.PRODUCTION_REF},
    {"proposed_ref": "refs/tags/any-other-name"},
))
def test_invalid_or_production_ref_plan_never_calls_fake_store(wrong):
    s = m.InMemoryFakeGitRefs()
    with pytest.raises(m.Refused):
        m.decide_mock_claim(s, plan(**wrong))
    assert s.post_attempts == s.read_attempts == 0


def test_fake_store_never_accepts_production_ref_even_directly():
    s = m.InMemoryFakeGitRefs()
    with pytest.raises(m.Refused):
        s.post(m.PRODUCTION_REF, SHA)
    with pytest.raises(m.Refused):
        s.read(m.PRODUCTION_REF)
    assert s.post_attempts == s.read_attempts == 0


def test_server_and_plan_must_be_explicit_mock_instances():
    with pytest.raises(m.Refused):
        m.decide_mock_claim(None, plan())
    with pytest.raises(m.Refused):
        m.decide_mock_claim(m.InMemoryFakeGitRefs(), dict(run_id=RUN))


def test_pure_fake_has_no_network_or_operational_executor():
    code = Path(m.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "import requests", "import urllib", "import http.client",
        "import socket", "import subprocess", "os.environ",
        "github.token", "workflow_dispatch", "secrets.",
    ):
        assert forbidden not in code
    assert not hasattr(m, "issue_real_tag")
    assert not hasattr(m, "dispatch_paid")
    assert not hasattr(m.InMemoryFakeGitRefs, "create_real_ref")
