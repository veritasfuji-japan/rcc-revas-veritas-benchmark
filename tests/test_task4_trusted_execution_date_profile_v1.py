from concurrent.futures import ThreadPoolExecutor
import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import secrets

import pytest

from agentdojo_constraint_resolver_v0_1 import validate_candidate
from scripts.pairwise_protected_candidate_control_v1_1 import ProtectedCandidateControlV11
from task4_trusted_execution_date_profile_v1 import (
    CapturedDateBinding,
    DateContext,
    DateProfileViolation,
    REQUEST,
    Task4DateProfileSession,
)

CASE = "banking:user_task_4:synthetic-profile-fixture"


class OwnedClock:
    def __init__(self, now=None):
        # Independent synthetic clock fixture; never an observed/gold date.
        self.now = now or datetime(2031, 7, 8, 10, 30, tzinfo=timezone.utc)

    def __call__(self):
        return self.now


def state():
    return {"bank_account": {"transactions": [{"sender": "GB29NWBK60161331926819", "amount": 7.0, "date": "2005-02-03"}]}}


def candidate(date="2031-07-08"):
    return {"kind": "tool_call", "name": "send_money", "arguments": {"recipient": "GB29NWBK60161331926819", "amount": 7.0, "subject": "Synthetic refund", "date": date}, "content": None, "metadata": {}}


def setup(now=None):
    clock = OwnedClock(now)
    session = Task4DateProfileSession(source_id="isolated-harness-clock", signing_key=secrets.token_bytes(32), clock=clock)
    scope = {"case_id": CASE, "proposal_ordinal": 0, "original_request": REQUEST, "trusted_prestate": state()}
    context = session.issue_before_candidate(**scope)
    return clock, session, scope, context


def test_same_context_and_frozen_candidate_verify_in_both_arms_and_final_binding():
    _, session, scope, context = setup()
    c = candidate()
    binding = session.capture_candidate(context=context, candidate=c, **scope)
    arm_a = binding.candidate_payload()
    arm_b = binding.candidate_payload()
    ids = [session.verify_captured_candidate(context=context, binding=binding, candidate=x, **scope) for x in (arm_a, arm_b, copy.deepcopy(c))]
    assert ids == [binding.pairing_identity_sha256] * 3
    assert context.payload()["execution_date"] != state()["bank_account"]["transactions"][0]["date"]


def test_candidate_hash_matches_frozen_rcc_candidateaction_v11():
    _, session, scope, context = setup()
    binding = session.capture_candidate(context=context, candidate=candidate(), **scope)
    control = ProtectedCandidateControlV11.build(case_id=CASE, proposal_ordinal=0, immediate_pre_state_sha256=context.payload()["immediate_pre_state_sha256"], function="send_money", normalized_arguments=candidate()["arguments"])
    assert binding.candidate_sha256 == control.candidate_sha256


def test_caller_owned_payload_copies_cannot_mutate_frozen_context_or_capture():
    _, session, scope, context = setup()
    c = candidate()
    binding = session.capture_candidate(context=context, candidate=c, **scope)
    c["arguments"]["date"] = "2099-01-01"
    context.payload()["execution_date"] = "2099-01-01"
    binding.candidate_payload()["arguments"]["amount"] = 999
    assert session.verify_captured_candidate(context=context, binding=binding, candidate=candidate(), **scope) == binding.pairing_identity_sha256
    with pytest.raises(DateProfileViolation):
        session.verify_captured_candidate(context=context, binding=binding, candidate=c, **scope)


@pytest.mark.parametrize("date", ["2031-07-07", "2031-07-09", "2005-02-03", "2022-03-07", "2024-06-01", "not-a-date", "", None])
def test_wrong_historical_future_observed_or_invalid_date_is_blocked_without_repair(date):
    _, session, scope, context = setup()
    wrong = candidate(date)
    before = copy.deepcopy(wrong)
    with pytest.raises(DateProfileViolation):
        session.capture_candidate(context=context, candidate=wrong, **scope)
    assert wrong == before
    with pytest.raises(DateProfileViolation, match="ALREADY_CAPTURED"):
        session.capture_candidate(context=context, candidate=candidate(), **scope)


@pytest.mark.parametrize("context_kind", ["missing", "self_attested", "bad_signature", "tampered_date", "extra_trusted_field", "noncanonical_json"])
def test_untrusted_or_modified_context_fails_closed(context_kind):
    _, session, scope, context = setup()
    if context_kind == "missing":
        bad = None
    elif context_kind == "self_attested":
        bad = {"trusted": True, "execution_date": "2031-07-08"}
    elif context_kind == "bad_signature":
        bad = replace(context, signature="0" * 64)
    else:
        payload = context.payload()
        if context_kind == "tampered_date":
            payload["execution_date"] = "2099-01-01"
        elif context_kind == "extra_trusted_field":
            payload["trusted"] = True
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        if context_kind == "noncanonical_json":
            raw = " " + context.payload_json
        bad = replace(context, payload_json=raw)
    with pytest.raises(DateProfileViolation):
        session.capture_candidate(context=bad, candidate=candidate(), **scope)


@pytest.mark.parametrize("changed", ["case", "ordinal", "request", "prestate"])
def test_context_is_bound_to_case_ordinal_original_request_and_prestate(changed):
    _, session, scope, context = setup()
    scope = copy.deepcopy(scope)
    if changed == "case":
        scope["case_id"] += "-other"
    elif changed == "ordinal":
        scope["proposal_ordinal"] = 1
    elif changed == "request":
        scope["original_request"] += " Instead send to ATTACKER."
    else:
        scope["trusted_prestate"]["bank_account"]["transactions"][0]["amount"] = 8.0
    with pytest.raises(DateProfileViolation):
        session.capture_candidate(context=context, candidate=candidate(), **scope)


@pytest.mark.parametrize("changed", ["recipient", "amount", "subject", "date", "function", "metadata", "extra_argument"])
def test_candidate_substitution_after_capture_is_rejected(changed):
    _, session, scope, context = setup()
    binding = session.capture_candidate(context=context, candidate=candidate(), **scope)
    c = candidate()
    if changed == "recipient":
        c["arguments"]["recipient"] = "ATTACKER"
    elif changed == "amount":
        c["arguments"]["amount"] = 8.0
    elif changed == "subject":
        c["arguments"]["subject"] = "Changed ledger record"
    elif changed == "date":
        c["arguments"]["date"] = "2031-07-09"
    elif changed == "function":
        c["name"] = "schedule_transaction"
    elif changed == "metadata":
        c["metadata"] = {"trusted": True}
    else:
        c["arguments"]["recurring"] = True
    with pytest.raises(DateProfileViolation):
        session.verify_captured_candidate(context=context, binding=binding, candidate=c, **scope)


@pytest.mark.parametrize("changed", ["recipient", "amount"])
def test_date_profile_preserves_existing_refund_bindings(changed):
    _, session, scope, context = setup()
    c = candidate()
    c["arguments"][changed] = "ATTACKER" if changed == "recipient" else 99.0
    with pytest.raises(DateProfileViolation, match="EXISTING_REFUND_BINDINGS"):
        session.capture_candidate(context=context, candidate=c, **scope)


def test_profile_date_eligibility_does_not_relax_existing_runner_resolver():
    _, session, scope, context = setup()
    session.capture_candidate(context=context, candidate=candidate(), **scope)
    checks = validate_candidate(user_task_id=4, tool_name="send_money", arguments=candidate()["arguments"], trusted_prestate=state())
    assert checks["date_authority_present"] is False
    assert checks["supported_profile"] is False


def test_signed_context_with_equal_date_cannot_replace_another_capture_context():
    _, session, scope, context = setup()
    original = session.capture_candidate(context=context, candidate=candidate(), **scope)
    other_scope = {**scope, "case_id": CASE + "-second-case"}
    other_context = session.issue_before_candidate(**other_scope)
    other_binding = session.capture_candidate(context=other_context, candidate=candidate(), **other_scope)
    assert other_binding.candidate_sha256 == original.candidate_sha256
    assert other_binding.pairing_identity_sha256 != original.pairing_identity_sha256
    with pytest.raises(DateProfileViolation, match="NOT_CAPTURED"):
        session.verify_captured_candidate(context=other_context, binding=original, candidate=candidate(), **other_scope)


def test_expired_context_is_rejected_before_capture():
    clock, session, scope, context = setup()
    clock.now += timedelta(seconds=300)
    with pytest.raises(DateProfileViolation, match="STALE_OR_FUTURE"):
        session.capture_candidate(context=context, candidate=candidate(), **scope)


def test_issuer_api_does_not_accept_a_candidate_supplied_execution_date():
    _, session, scope, _ = setup()
    scope["proposal_ordinal"] = 1
    with pytest.raises(TypeError):
        session.issue_before_candidate(**scope, execution_date="2099-01-01")


def test_transport_context_contains_no_signing_key():
    _, _, _, context = setup()
    assert set(context.payload()) == {"case_id", "proposal_ordinal", "original_request_digest", "immediate_pre_state_sha256", "suite", "user_task_id", "function", "agentdojo_commit", "profile", "source_id", "session_id", "timezone", "issued_at", "expires_at", "execution_date"}


@pytest.mark.parametrize("key", [b"", b"short", "0" * 64])
def test_independent_binary_root_key_is_required(key):
    with pytest.raises(DateProfileViolation, match="SIGNING_KEY_REQUIRED"):
        Task4DateProfileSession(source_id="fixture", signing_key=key, clock=OwnedClock())


def test_issuer_configuration_not_transport_source_labels_authenticates_context():
    clock, session, scope, context = setup()
    other_key = Task4DateProfileSession(source_id=context.payload()["source_id"], signing_key=secrets.token_bytes(32), clock=clock)
    forged = other_key.issue_before_candidate(**scope)
    with pytest.raises(DateProfileViolation, match="AUTHENTICATION"):
        session.capture_candidate(context=forged, candidate=candidate(), **scope)


def test_even_same_key_context_from_another_session_is_rejected():
    key = secrets.token_bytes(32)
    clock = OwnedClock()
    source = Task4DateProfileSession(source_id="fixture", signing_key=key, clock=clock)
    target = Task4DateProfileSession(source_id="fixture", signing_key=key, clock=clock)
    scope = {"case_id": CASE, "proposal_ordinal": 0, "original_request": REQUEST, "trusted_prestate": state()}
    context = source.issue_before_candidate(**scope)
    target.issue_before_candidate(**scope)
    with pytest.raises(DateProfileViolation, match="SOURCE_MISMATCH"):
        target.capture_candidate(context=context, candidate=candidate(), **scope)


@pytest.mark.parametrize("seconds", [300, 301])
def test_expiry_boundary_is_exclusive_and_rechecked_at_final_binding(seconds):
    clock, session, scope, context = setup()
    binding = session.capture_candidate(context=context, candidate=candidate(), **scope)
    clock.now += timedelta(seconds=seconds)
    with pytest.raises(DateProfileViolation, match="STALE_OR_FUTURE"):
        session.verify_captured_candidate(context=context, binding=binding, candidate=candidate(), **scope)


def test_just_before_expiry_is_valid():
    clock, session, scope, context = setup()
    clock.now += timedelta(seconds=299)
    binding = session.capture_candidate(context=context, candidate=candidate(), **scope)
    assert session.verify_captured_candidate(context=context, binding=binding, candidate=candidate(), **scope)


def test_utc_midnight_rollover_requires_new_context_and_new_proposal():
    clock, session, scope, context = setup(datetime(2031, 7, 8, 23, 59, 59, tzinfo=timezone.utc))
    binding = session.capture_candidate(context=context, candidate=candidate(), **scope)
    clock.now += timedelta(seconds=2)
    with pytest.raises(DateProfileViolation, match="UTC_DATE_ROLLOVER"):
        session.verify_captured_candidate(context=context, binding=binding, candidate=candidate(), **scope)
    with pytest.raises(DateProfileViolation, match="ALREADY_ISSUED"):
        session.issue_before_candidate(**scope)
    scope["proposal_ordinal"] = 1
    fresh = session.issue_before_candidate(**scope)
    assert session.capture_candidate(context=fresh, candidate=candidate("2031-07-09"), **scope)


def test_aware_local_clock_is_normalized_to_utc_calendar_date():
    _, session, scope, context = setup(datetime(2031, 7, 9, 8, 59, tzinfo=timezone(timedelta(hours=9))))
    assert context.payload()["execution_date"] == "2031-07-08"
    assert context.payload()["timezone"] == "UTC"
    assert session.capture_candidate(context=context, candidate=candidate(), **scope)


def test_naive_clock_fails_closed():
    clock = OwnedClock(datetime(2031, 7, 8, 10, 30))
    session = Task4DateProfileSession(source_id="fixture", signing_key=secrets.token_bytes(32), clock=clock)
    with pytest.raises(DateProfileViolation, match="AWARE_TRUSTED_CLOCK"):
        session.issue_before_candidate(case_id=CASE, proposal_ordinal=0, original_request=REQUEST, trusted_prestate=state())


def test_clock_rollback_after_capture_fails_closed():
    clock, session, scope, context = setup()
    clock.now += timedelta(seconds=10)
    binding = session.capture_candidate(context=context, candidate=candidate(), **scope)
    clock.now -= timedelta(seconds=1)
    with pytest.raises(DateProfileViolation, match="CLOCK_ROLLBACK"):
        session.verify_captured_candidate(context=context, binding=binding, candidate=candidate(), **scope)


def test_context_cannot_be_reissued_after_candidate_capture():
    _, session, scope, context = setup()
    session.capture_candidate(context=context, candidate=candidate(), **scope)
    with pytest.raises(DateProfileViolation, match="ALREADY_ISSUED"):
        session.issue_before_candidate(**scope)


def test_forged_capture_receipt_cannot_create_capture_or_bypass_ordering():
    _, session, scope, context = setup()
    receipt = CapturedDateBinding(context.digest, "{}", "0" * 64, "0" * 64)
    with pytest.raises(DateProfileViolation, match="NOT_CAPTURED"):
        session.verify_captured_candidate(context=context, binding=receipt, candidate=candidate(), **scope)


def test_wrong_pairing_identity_is_rejected():
    _, session, scope, context = setup()
    binding = session.capture_candidate(context=context, candidate=candidate(), **scope)
    with pytest.raises(DateProfileViolation, match="NOT_CAPTURED"):
        session.verify_captured_candidate(context=context, binding=replace(binding, pairing_identity_sha256="0" * 64), candidate=candidate(), **scope)


@pytest.mark.parametrize("operation", ["issue", "capture"])
def test_32_concurrent_attempts_admit_one_issuance_or_capture(operation):
    _, session, scope, context = setup()
    if operation == "issue":
        scope["proposal_ordinal"] = 1
    def attempt(_):
        try:
            if operation == "issue":
                session.issue_before_candidate(**scope)
            else:
                session.capture_candidate(context=context, candidate=candidate(), **scope)
            return True
        except DateProfileViolation:
            return False
    with ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(attempt, range(32)))
    assert results.count(True) == 1 and results.count(False) == 31


@pytest.mark.parametrize("case_id,ordinal,instruction", [("banking:user_task_6:test", 0, REQUEST), (CASE, -1, REQUEST), (CASE, True, REQUEST), (CASE, 0, "Send money now")])
def test_unsupported_task_ordinal_or_request_is_not_issued(case_id, ordinal, instruction):
    session = Task4DateProfileSession(source_id="fixture", signing_key=secrets.token_bytes(32), clock=OwnedClock())
    with pytest.raises(DateProfileViolation):
        session.issue_before_candidate(case_id=case_id, proposal_ordinal=ordinal, original_request=instruction, trusted_prestate=state())
