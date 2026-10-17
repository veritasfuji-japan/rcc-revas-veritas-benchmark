"""No-effect synthetic research Ruleset + issuer/sender role separation tests."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import socket

import pytest

from scripts import final128_task1_research_ruleset_role_review_offline_v1 as m

SHA = "b6866dc6f245e81b850a466d6ae69506cce890ef"
PACKET = hashlib.sha256(b"same-native-first-A-and-B-offline").hexdigest()
RUN = "39031441000"


@pytest.fixture(autouse=True)
def zero_network_and_no_tokens(monkeypatch):
    def refuse(*_args, **_kwargs):
        pytest.fail("TASK1_RULESET_ROLE_REVIEW_NEVER_CONNECT")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    for key in (
        "GH_TOKEN", "GITHUB_TOKEN", "OPENAI_API_KEY", "TASK1_OPENAI_API_KEY",
        "TASK1_RESEARCH_OPENAI_API_KEY", "TASK1_CAPTURE_AES256_KEY",
        "VERITAS_RULESET_OWNER_TOKEN",
    ):
        monkeypatch.delenv(key, raising=False)


def ruleset():
    return {
        "id": m.MOCK_RULESET_ID, "target": "tag",
        "enforcement": "active", "source": m.REPO,
        "source_type": "Repository",
        "current_user_can_bypass": "never",
        "bypass_actors": [],
        "conditions": {
            "ref_name": {"include": [m.RESEARCH_TAG], "exclude": []},
        },
        "rules": [
            {"type": "deletion"}, {"type": "update"},
            {"type": "non_fast_forward"},
        ],
    }


def collection():
    return [{
        "id": m.MOCK_RULESET_ID, "target": "tag", "enforcement": "active",
    }]


def roles():
    return {
        "issuer": {
            "permissions": {"contents": "write"},
            "environment": None, "secrets": [],
        },
        "sender": {
            "permissions": {"contents": "read"},
            "environment": m.RESEARCH_ENV,
            "secrets": sorted(m.SENDER_SECRETS),
        },
    }


def binding():
    return {
        "repository": m.REPO,
        "case": m.CASE,
        "model": m.MODEL,
        "research_tag": m.RESEARCH_TAG,
        "run_id": RUN,
        "main_sha": SHA,
        "first_sha256_by_arm": {"A": PACKET, "B": PACKET},
        "max_posts": 2, "no_retry": True,
        "billing_target_usd": "1.00",
        "owner_approved": False,
        "provider_project_hard_cap_verified": False,
        "ref_created": False,
    }


def no_real_authority(review):
    assert review.synthetic_shape_matched is True
    assert review.real_ruleset_enrolled is False
    assert review.permission_isolation_proven is False
    assert review.production_authority is False
    assert review.paid_dispatch_allowed is False
    assert review.research_tag_written is False
    assert review.production_tag_written is False
    assert review.independently_authenticated is False


def test_all_synthetic_shapes_match_but_never_grant_dispatch():
    snapshots = (collection(), ruleset(), roles(), binding())
    outputs = [
        m.review_synthetic_research_ruleset(*snapshots[:2]),
        m.review_synthetic_job_separation(snapshots[2]),
        m.review_synthetic_binding(snapshots[3]),
        m.review_all_synthetic(*snapshots),
    ]
    assert outputs[-1].status == "ALL_SYNTHETIC_SHAPES_MATCH_NO_REAL_AUTHORITY"
    for output in outputs:
        no_real_authority(output)
    assert m.PRODUCTION_TAG != m.RESEARCH_TAG
    assert m.PRODUCTION_RULESET_ID != m.MOCK_RULESET_ID
    assert m.MAIN_RULESET_ID != m.MOCK_RULESET_ID


@pytest.mark.parametrize("change", [
    lambda d: d.pop("bypass_actors"),
    lambda d: d.update(bypass_actors=None),
    lambda d: d.update(bypass_actors="[]"),
    lambda d: d.update(bypass_actors=[{"actor_type": "User", "actor_id": 1}]),
    lambda d: d.update(bypass_actors=[None]),
])
def test_ruleset_redacted_or_nonempty_bypass_never_passes(change):
    data = ruleset()
    change(data)
    with pytest.raises(ValueError, match="EXPLICIT_EMPTY_BYPASS_REQUIRED"):
        m.review_synthetic_research_ruleset(collection(), data)


@pytest.mark.parametrize("change", [
    lambda d: d["conditions"]["ref_name"].update(include=[m.PRODUCTION_TAG]),
    lambda d: d["conditions"]["ref_name"].update(include=["~ALL"]),
    lambda d: d["conditions"]["ref_name"].update(include=[m.RESEARCH_TAG, m.PRODUCTION_TAG]),
    lambda d: d["conditions"]["ref_name"].update(include=[]),
    lambda d: d["conditions"]["ref_name"].update(exclude=[m.RESEARCH_TAG]),
    lambda d: d["conditions"]["ref_name"].update(include=[m.RESEARCH_TAG] * 2),
    lambda d: d.update(conditions={"ref_name": {"include": [m.RESEARCH_TAG]}}),
])
def test_exact_research_tag_only_without_exclusions(change):
    data = ruleset()
    change(data)
    with pytest.raises(ValueError):
        m.review_synthetic_research_ruleset(collection(), data)


@pytest.mark.parametrize("mutate", [
    lambda d: d["rules"].pop(),
    lambda d: d["rules"].append({"type": "creation"}),
    lambda d: d["rules"][0].update(type="creation"),
    lambda d: d["rules"][0].update(parameters={"authorized": True}),
    lambda d: d.update(rules=[]),
    lambda d: d.update(rules="deletion"),
    lambda d: d.update(rules=[{"type": "update"}] * 3),
])
def test_exact_protection_rules_and_creation_remains_allowed(mutate):
    data = ruleset()
    mutate(data)
    with pytest.raises(ValueError, match="EXACT_UPDATE_DELETION_NONFASTFORWARD"):
        m.review_synthetic_research_ruleset(collection(), data)


@pytest.mark.parametrize("field,bad", [
    ("id", m.PRODUCTION_RULESET_ID),
    ("target", "branch"),
    ("enforcement", "disabled"),
    ("enforcement", "evaluate"),
    ("source", "attacker/repository"),
    ("source_type", "Organization"),
    ("current_user_can_bypass", "always"),
    ("current_user_can_bypass", None),
])
def test_ruleset_identity_must_match_exact_synthetic_fixture(field, bad):
    data = ruleset()
    data[field] = bad
    with pytest.raises(ValueError, match="SOURCE_OR_ENFORCEMENT_DRIFT"):
        m.review_synthetic_research_ruleset(collection(), data)


def test_missing_or_duplicate_active_collection_is_denied():
    for entry in ([], collection() * 2, [
        {"id": m.MOCK_RULESET_ID, "target": "tag", "enforcement": "disabled"},
    ], [{"id": m.MAIN_RULESET_ID, "target": "tag", "enforcement": "active"}]):
        with pytest.raises(ValueError, match="UNIQUE_ACTIVE_LISTING_REQUIRED"):
            m.review_synthetic_research_ruleset(entry, ruleset())
    with pytest.raises(ValueError, match="COLLECTION_UNREADABLE"):
        m.review_synthetic_research_ruleset(None, ruleset())


def test_untrusted_fixture_must_not_pretend_enrolled_real_ruleset_id():
    with pytest.raises(ValueError, match="UNKNOWN_SIMULATED_RULESET_ID"):
        m.review_synthetic_research_ruleset(collection(), ruleset(),
                                            expected_mock_id=m.PRODUCTION_RULESET_ID)


@pytest.mark.parametrize("role,field,bad", [
    ("issuer", "permissions", {"contents": "read"}),
    ("issuer", "permissions", {"contents": "write", "administration": "write"}),
    ("issuer", "permissions", {"contents": "write", "actions": "write"}),
    ("issuer", "environment", m.RESEARCH_ENV),
    ("issuer", "environment", m.PRODUCTION_ENV),
    ("issuer", "secrets", ["TASK1_RESEARCH_OPENAI_API_KEY"]),
    ("issuer", "secrets", ["GH_TOKEN"]),
    ("sender", "permissions", {"contents": "write"}),
    ("sender", "permissions", {"contents": "read", "actions": "write"}),
    ("sender", "permissions", {"contents": "read", "administration": "write"}),
    ("sender", "environment", m.PRODUCTION_ENV),
    ("sender", "environment", None),
    ("sender", "secrets", ["TASK1_RESEARCH_OPENAI_API_KEY"]),
    ("sender", "secrets", ["TASK1_RESEARCH_OPENAI_API_KEY"] * 2),
    ("sender", "secrets", [None, "TASK1_RESEARCH_OPENAI_API_KEY"]),
    ("sender", "secrets", ["TASK1_OPENAI_API_KEY", "TASK1_CAPTURE_AES256_KEY"]),
])
def test_role_separation_rejects_credentials_write_and_production_env(role, field, bad):
    data = roles()
    data[role][field] = bad
    with pytest.raises(ValueError):
        m.review_synthetic_job_separation(data)


@pytest.mark.parametrize("bad", [
    {}, None, [], {"issuer": roles()["issuer"]},
    {"issuer": roles()["issuer"], "sender": roles()["sender"], "admin": {}},
])
def test_role_registry_exactly_issuer_and_sender(bad):
    with pytest.raises(ValueError):
        m.review_synthetic_job_separation(bad)


@pytest.mark.parametrize("field,value", [
    ("repository", "attacker/fork"),
    ("case", "banking:wrong"),
    ("model", "other-model"),
    ("research_tag", m.PRODUCTION_TAG),
    ("research_tag", "refs/tags/anything"),
    ("run_id", "0"),
    ("run_id", "invalid"),
    ("main_sha", "not-a-main-sha"),
    ("max_posts", 3),
    ("max_posts", True),
    ("no_retry", False),
    ("billing_target_usd", "2.00"),
    ("owner_approved", True),
    ("provider_project_hard_cap_verified", True),
    ("ref_created", True),
])
def test_untrusted_binding_plan_cannot_promote_fields_or_authority(field, value):
    data = binding()
    data[field] = value
    with pytest.raises(ValueError):
        m.review_synthetic_binding(data)


@pytest.mark.parametrize("value", [
    {"A": PACKET},
    {"A": "a" * 64, "B": PACKET},
    {"A": PACKET, "B": PACKET, "C": PACKET},
    {"A": "NOT_SHA", "B": "NOT_SHA"},
    [PACKET, PACKET],
    None,
])
def test_owned_first_native_hash_pair_parity_required(value):
    data = binding()
    data["first_sha256_by_arm"] = value
    with pytest.raises(ValueError, match="INITIAL_A_B_IDENTICAL_NATIVE_INPUT"):
        m.review_synthetic_binding(data)


def test_unknown_fields_and_missing_signals_stop():
    data = binding()
    data["cryptographic_attestation_verified"] = True
    with pytest.raises(ValueError, match="BINDING_FIELDS_EXACT"):
        m.review_synthetic_binding(data)
    data = binding()
    del data["owner_approved"]
    with pytest.raises(ValueError, match="BINDING_FIELDS_EXACT"):
        m.review_synthetic_binding(data)


def test_no_external_clients_or_dispatcher_exist():
    source = Path(m.__file__).read_text(encoding="utf-8")
    for text in ("api.openai.com", "import socket", "import urllib",
                 "import http.client", "import requests", "import subprocess",
                 "os.environ", "github.token", "secrets.get"):
        assert text not in source
    for name in ("send", "dispatch_paid", "issue_tag", "modify_ruleset",
                 "fetch_github", "save_secret"):
        assert not hasattr(m, name)
    assert m.RESEARCH_TAG.startswith("refs/tags/")
