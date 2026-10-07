"""Review a Task6 scheduling policy draft; never issue date authority.

References and issuer names below are unverified review material. This module
has no approval API, mandate verifier, context issuer, candidate input or sink.
The supplied time is a review fixture, not authenticated clock evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
import re
from typing import Any, Mapping

from original_request_authority_lineage_v1 import OriginalRequestEnvelope
from task6_original_request_schedule_authority_profile_v1 import AGENTDOJO_COMMIT, REQUEST, canonical, sha

DESIGN = "TASK6_TRUSTED_SCHEDULE_DATE_POLICY_DESIGN_V1"
POLICY_ID = "task6-explicit-first-due-date.v1"
MAX_CONTEXT_AGE_SECONDS = 300
UNRESOLVED_REQUIREMENTS = (
    "independent_principal_and_schedule_mandate_authentication",
    "reviewed_policy_version_and_issuer_registry",
    "authenticated_clock_and_monotonic_session_registry",
    "prospective_context_issuance_before_first_candidate",
    "same_candidate_and_prestate_binding_with_final_sink_recheck",
    "per_arm_single_use_and_revocation_checks",
    "native_Bind_and_Rcc_integration_with_no_candidate_repair",
)


class SchedulePolicyDesignViolation(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise SchedulePolicyDesignViolation(reason)


def _calendar_date(value: Any) -> date:
    require(type(value) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value) is not None,
            "EXACT_CALENDAR_DATE_REQUIRED")
    try:
        result = date.fromisoformat(value)
    except ValueError as exc:
        raise SchedulePolicyDesignViolation("VALID_GREGORIAN_DATE_REQUIRED") from exc
    require(result.isoformat() == value, "CANONICAL_DATE_REQUIRED")
    return result


def _utc_instant(value: Any) -> datetime:
    require(type(value) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value)
            is not None, "EXACT_UTC_INSTANT_REQUIRED")
    try:
        result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise SchedulePolicyDesignViolation("VALID_UTC_INSTANT_REQUIRED") from exc
    return result


def request_scope(*, case_id: str, proposal_ordinal: int, original_request: str,
                  trusted_prestate: Mapping[str, Any]) -> dict:
    require(type(case_id) is str and case_id.startswith("banking:user_task_6:")
            and bool(case_id.removeprefix("banking:user_task_6:")), "TASK6_CASE_REQUIRED")
    require(type(proposal_ordinal) is int and proposal_ordinal >= 0, "ORDINAL_REQUIRED")
    require(type(original_request) is str and original_request == REQUEST, "EXACT_ORIGINAL_REQUEST_REQUIRED")
    require(isinstance(trusted_prestate, Mapping), "OWNED_PRESTATE_REQUIRED")
    return {"agentdojo_commit": AGENTDOJO_COMMIT, "suite": "banking", "user_task_id": 6,
            "function": "schedule_transaction", "case_id": case_id, "proposal_ordinal": proposal_ordinal,
            "request_digest": OriginalRequestEnvelope("banking", 6, original_request).digest,
            "immediate_pre_state_sha256": sha(dict(trusted_prestate))}


@dataclass(frozen=True)
class SchedulePolicyDraftReview:
    draft_sha256: str
    proposed_first_due_date: str
    unresolved_requirements: tuple[str, ...] = UNRESOLVED_REQUIREMENTS

    def observation(self) -> dict:
        # No approval fields are read from the draft, and no effective date is
        # returned. A valid reference is still only an unverified reference.
        return {"draft_sha256": self.draft_sha256, "draft_structure_valid": True,
                "proposed_first_due_date": self.proposed_first_due_date,
                "effective_first_due_date": None, "mandate_authenticated": False,
                "policy_activated": False, "date_authority_present": False,
                "full_action_admissible": False, "execution_permit": False,
                "unresolved_requirements": list(self.unresolved_requirements)}


def review_schedule_policy_draft(*, policy_draft: Mapping[str, Any], case_id: str,
                                 proposal_ordinal: int, original_request: str,
                                 trusted_prestate: Mapping[str, Any], reviewed_at_utc: datetime
                                 ) -> SchedulePolicyDraftReview:
    """Lint independent review material, with date/full-action admission closed.

    Neither the mandate reference nor any caller-supplied timestamp is
    authenticated here. This is not an issuer or a runtime verification gate.
    Repeated linting does not consume or authorize anything.
    """
    require(isinstance(policy_draft, Mapping), "POLICY_DRAFT_REQUIRED")
    import json
    draft = json.loads(canonical(dict(policy_draft)))
    constants = {"design": DESIGN, "status": "DRAFT_NOT_AUTHORITY", "policy_id": POLICY_ID,
                 "selection_rule": "EXPLICIT_MANDATE_DATE", "timezone": "UTC", "calendar": "GREGORIAN",
                 "wire_date_format": "YYYY-MM-DD", "max_context_age_seconds": MAX_CONTEXT_AGE_SECONDS,
                 "rollover": "REJECT_AND_REQUIRE_NEW_CONTEXT",
                 "recurrence_scope": "PINNED_NATIVE_RECORD_FLAG_ONLY",
                 "effect_scope": "APPEND_ONE_SCHEDULED_RECORD"}
    require(set(draft) == set(constants) | {"scope", "mandate", "not_before_utc", "expires_at_utc"},
            "EXACT_DRAFT_SCHEMA_REQUIRED")
    require(all(draft[k] == v and type(draft[k]) is type(v) for k, v in constants.items()),
            "UNSUPPORTED_POLICY_DESIGN")
    expected_scope = request_scope(case_id=case_id, proposal_ordinal=proposal_ordinal,
                                   original_request=original_request, trusted_prestate=trusted_prestate)
    actual_scope = draft["scope"]
    require(type(actual_scope) is dict and set(actual_scope) == set(expected_scope)
            and all(actual_scope[k] == v and type(actual_scope[k]) is type(v) for k, v in expected_scope.items()),
            "REQUEST_SCOPE_SUBSTITUTED")
    mandate = draft["mandate"]
    require(type(mandate) is dict and set(mandate) == {"reference", "issuer_id", "principal_id", "first_due_date"},
            "EXACT_MANDATE_DRAFT_REQUIRED")
    require(all(type(mandate[k]) is str and bool(mandate[k].strip())
                for k in ("reference", "issuer_id", "principal_id")), "MANDATE_REVIEW_REFERENCES_REQUIRED")
    due = _calendar_date(mandate["first_due_date"])
    start, end = _utc_instant(draft["not_before_utc"]), _utc_instant(draft["expires_at_utc"])
    require(type(reviewed_at_utc) is datetime and reviewed_at_utc.tzinfo is timezone.utc,
            "UTC_REVIEW_FIXTURE_REQUIRED")
    require(timedelta(0) < end - start <= timedelta(seconds=MAX_CONTEXT_AGE_SECONDS),
            "BOUNDED_VALIDITY_WINDOW_REQUIRED")
    require(start <= reviewed_at_utc < end, "REVIEW_OUTSIDE_VALIDITY_WINDOW")
    require(start.date() == end.date() == reviewed_at_utc.date(), "UTC_DAY_ROLLOVER_REJECTED")
    require(due >= reviewed_at_utc.date(), "BACKDATED_FIRST_DUE_DATE_REJECTED")
    return SchedulePolicyDraftReview(sha(draft), mandate["first_due_date"])
