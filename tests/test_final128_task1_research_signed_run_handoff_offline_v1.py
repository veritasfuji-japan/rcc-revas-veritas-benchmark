"""Ed25519 Task1 handoff: synthetic only, no real issuer/sender, no network."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
from pathlib import Path
import socket
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from scripts import final128_task1_research_signed_run_handoff_offline_v1 as m

MAIN = "16ad535282fc4010c9b77e0ef519ddec5ab7d9e1"
PACKET = hashlib.sha256(b"SYNTHETIC_NATIVE_IDENTICAL_FIRST_PACKET").hexdigest()


@pytest.fixture(autouse=True)
def deny_network_and_hide_secrets(monkeypatch):
    def denied(*_a, **_k):
        pytest.fail("NO_EXTERNAL_NETWORK_FOR_SYNTHETIC_HANDOFF")
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    for token in (
        "OPENAI_API_KEY", "TASK1_RESEARCH_OPENAI_API_KEY", "GITHUB_TOKEN",
        "GH_TOKEN", "VERITAS_RULESET_OWNER_TOKEN", "TASK1_RESEARCH_CAPTURE_AES256_KEY",
    ):
        monkeypatch.delenv(token, raising=False)


def context(**changes):
    fields = dict(
        main_sha=MAIN, run_id="39032743676", issuer_job_id="117396355799",
        sender_job_id="117396356327", request_sha256=PACKET,
        run_attempt=1,
    )
    fields.update(changes)
    return m.MockJobContext(**fields)


def signed_fixture(ctx=None):
    ctx = ctx or context()
    key = Ed25519PrivateKey.generate()  # ephemeral local test only
    envelope = m.mock_sign(m.mock_payload(ctx), key, ctx)
    return ctx, key, envelope


def verify(envelope, ctx, key, ledger=None):
    return m.verify_and_mark_mock(
        envelope, expected=ctx, pinned_test_public_key=key.public_key(),
        replay_ledger=ledger or m.EphemeralReplayLedger(),
    )


def assert_no_real_authority(outcome):
    assert outcome.status == "SIGNED_OFFLINE_MOCK_MATCH_NO_LIVE_AUTHORITY"
    assert outcome.mock_integrity_ok is True
    assert outcome.provider_dispatch_authorized is False
    assert outcome.claim_origin_authenticated is False
    assert outcome.github_identity_authenticated is False
    assert outcome.real_ref_created is False
    assert outcome.real_ruleset_installed is False
    assert outcome.cost_approved is False
    assert outcome.official_scoring_eligible is False


def test_matching_synthetic_handoff_is_not_paid_authority():
    ctx, key, env = signed_fixture()
    out = verify(env, ctx, key)
    assert_no_real_authority(out)
    assert env["payload"]["paid_consent"] is False
    assert env["payload"]["ruleset_enrolled"] is False
    assert env["payload"]["max_first_model_posts"] == 2
    assert env["payload"]["first_request_sha256_by_arm"]["A"] == PACKET
    assert env["payload"]["first_request_sha256_by_arm"]["B"] == PACKET


@pytest.mark.parametrize("field,value", [
    ("main_sha", "a" * 40),
    ("run_id", "39032743677"),
    ("run_attempt", 2),
    ("run_attempt", True),
    ("issuer_job_id", "117396355798"),
    ("sender_job_id", "117396356326"),
    ("request_sha256", "b" * 64),
])
def test_valid_signature_bound_to_exact_expected_context(field, value):
    ctx, key, env = signed_fixture()
    with pytest.raises(m.Refused):
        verify(env, context(**{field: value}), key)


@pytest.mark.parametrize("field,value", [
    ("repository", "attacker/fork"),
    ("case", "another_case"),
    ("model", "gpt-4.1"),
    ("research_ref", "refs/tags/final128-task1-first-two-real-responses-v1-consumed"),
    ("research_ref_target_sha", "b" * 40),
    ("main_sha", "b" * 40),
    ("run_id", "39032743677"),
    ("run_attempt", 2),
    ("issuer_job_id", "117396355798"),
    ("sender_job_id", "117396356326"),
    ("max_first_model_posts", 3),
    ("max_first_model_posts", True),
    ("no_retry", False),
    ("synthetic_only", False),
    ("paid_consent", True),
    ("ruleset_enrolled", True),
    ("provider_secret_access", True),
    ("production_tag_consumed", True),
    ("signer_label", "ENROLLED_PROD_SIGNER"),
])
def test_signed_contract_tamper_is_refused(field, value):
    ctx, key, env = signed_fixture()
    changed = deepcopy(env)
    changed["payload"][field] = value
    with pytest.raises(m.Refused):
        verify(changed, ctx, key)


def test_signed_first_arm_hash_drift_and_extra_arm_refused():
    ctx, key, env = signed_fixture()
    for hashes in (
        {"A": PACKET, "B": "b" * 64},
        {"A": PACKET},
        {"A": PACKET, "B": PACKET, "C": PACKET},
        {"A": PACKET, "B": PACKET, "A2": PACKET},
    ):
        changed = deepcopy(env)
        changed["payload"]["first_request_sha256_by_arm"] = hashes
        with pytest.raises(m.Refused):
            verify(changed, ctx, key)


def test_signed_payload_missing_extra_or_unknown_fields_refused():
    ctx, key, env = signed_fixture()
    for alteration in ("missing", "extra"):
        changed = deepcopy(env)
        if alteration == "missing":
            del changed["payload"]["run_id"]
        else:
            changed["payload"]["operator_approved"] = True
        with pytest.raises(m.Refused):
            verify(changed, ctx, key)


def test_wrong_key_is_not_authenticated():
    ctx, key, env = signed_fixture()
    impostor = Ed25519PrivateKey.generate()
    with pytest.raises(m.Refused, match="SIGNATURE_MISMATCH"):
        verify(env, ctx, impostor)


@pytest.mark.parametrize("signature", [
    "not-base64!", "", "YQ==", 123, None,
])
def test_malformed_or_incorrect_signature_is_rejected(signature):
    ctx, key, env = signed_fixture()
    changed = deepcopy(env)
    changed["signature_base64"] = signature
    with pytest.raises(m.Refused):
        verify(changed, ctx, key)


def test_wrong_signature_byte_refused_even_with_valid_shape():
    ctx, key, env = signed_fixture()
    changed = deepcopy(env)
    import base64
    sig = bytearray(base64.b64decode(env["signature_base64"]))
    sig[0] ^= 0x01
    changed["signature_base64"] = base64.b64encode(sig).decode("ascii")
    with pytest.raises(m.Refused, match="SIGNATURE_MISMATCH"):
        verify(changed, ctx, key)


def test_duplicate_same_ledger_is_denied_but_new_ledger_can_replay():
    ctx, key, env = signed_fixture()
    ledger = m.EphemeralReplayLedger()
    assert_no_real_authority(verify(env, ctx, key, ledger))
    with pytest.raises(m.Refused, match="DUPLICATE_HANDOFF_STOP"):
        verify(env, ctx, key, ledger)
    # Proves one local process is insufficient across ephemeral runners.
    assert_no_real_authority(verify(env, ctx, key, m.EphemeralReplayLedger()))


def test_competing_sender_threads_one_synthetic_winner():
    ctx, key, env = signed_fixture()
    ledger = m.EphemeralReplayLedger()
    barrier = threading.Barrier(2)
    def trial():
        barrier.wait(timeout=10)
        try:
            return verify(env, ctx, key, ledger)
        except m.Refused:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        got = [f.result(timeout=10) for f in [pool.submit(trial) for _ in range(2)]]
    assert sum(item is not None for item in got) == 1
    assert_no_real_authority(next(x for x in got if x is not None))


def test_bad_mock_job_context_or_attempt_rejected_before_sign():
    key = Ed25519PrivateKey.generate()
    for ctx in (
        context(run_id="../other"), context(main_sha="not-sha"),
        context(run_attempt=0), context(run_attempt=2),
        context(issuer_job_id="117396356327"),
        context(request_sha256="INVALID"),
    ):
        with pytest.raises(m.Refused):
            m.mock_sign(m.mock_payload(ctx), key, ctx)


def test_non_authorized_actor_cannot_sign_with_only_public_key():
    ctx, key, env = signed_fixture()
    with pytest.raises(m.Refused, match="EPHEMERAL_TEST_SIGNING_KEY"):
        m.mock_sign(env["payload"], key.public_key(), ctx)


def test_envelope_fields_fixed():
    ctx, key, env = signed_fixture()
    for modifier in ("extra", "missing", "wrong_algorithm"):
        changed = deepcopy(env)
        if modifier == "extra": changed["authorized"] = True
        elif modifier == "missing": changed.pop("algorithm")
        else: changed["algorithm"] = "ED25519_LIVE_APPROVED"
        with pytest.raises(m.Refused, match="SIGNED_ENVELOPE_SHAPE"):
            verify(changed, ctx, key)


def test_no_live_clients_or_execution_surface():
    source = Path(m.__file__).read_text("utf-8")
    for forbidden in (
        "import socket", "import urllib", "import http.client", "import requests",
        "import subprocess", "os.environ", "api.openai.com", "workflow_dispatch",
        "GITHUB_TOKEN", "gh api", "secrets.get", "modify_ruleset",
    ):
        assert forbidden not in source
    assert not hasattr(m, "dispatch")
    assert not hasattr(m, "issue_real_tag")
    assert not hasattr(m, "send_to_provider")
