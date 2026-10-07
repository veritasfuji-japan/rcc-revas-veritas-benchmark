#!/usr/bin/env python3
"""Provider-free pairwise protected-candidate control primitives.

This module does not execute AgentDojo tools, call a provider, consult scorer
labels, or change VERITAS policy. It defines the comparison identity required
before utility optimization can attribute a difference to governance treatment.
"""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from typing import Any

SCHEMA_VERSION = "veritas.pairwise-protected-candidate-control.v1"
PROTECTED_TOOLS = frozenset(
    {
        "send_money",
        "schedule_transaction",
        "update_scheduled_transaction",
        "update_password",
        "update_user_info",
    }
)


class PairingViolation(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def sha_json(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


@dataclass(frozen=True)
class ProtectedCandidateControl:
    case_id: str
    proposal_ordinal: int
    immediate_pre_state_sha256: str
    function: str
    arguments: dict[str, Any]
    candidate_sha256: str

    @classmethod
    def build(
        cls,
        *,
        case_id: str,
        proposal_ordinal: int,
        immediate_pre_state_sha256: str,
        function: str,
        normalized_arguments: dict[str, Any],
    ) -> "ProtectedCandidateControl":
        if not case_id:
            raise PairingViolation("CASE_ID_REQUIRED")
        if proposal_ordinal < 0:
            raise PairingViolation("NONNEGATIVE_PROPOSAL_ORDINAL_REQUIRED")
        if len(immediate_pre_state_sha256) != 64:
            raise PairingViolation("IMMEDIATE_PRE_STATE_SHA256_REQUIRED")
        if function not in PROTECTED_TOOLS:
            raise PairingViolation("PROTECTED_TOOL_REQUIRED")
        args = copy.deepcopy(normalized_arguments)
        candidate = {
            "kind": "tool_call",
            "name": function,
            "arguments": args,
        }
        return cls(
            case_id=case_id,
            proposal_ordinal=proposal_ordinal,
            immediate_pre_state_sha256=immediate_pre_state_sha256,
            function=function,
            arguments=args,
            candidate_sha256=sha_json(candidate),
        )

    def identity_payload(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "case_id": self.case_id,
            "proposal_ordinal": self.proposal_ordinal,
            "immediate_pre_state_sha256": self.immediate_pre_state_sha256,
            "function": self.function,
            "arguments": copy.deepcopy(self.arguments),
            "candidate_sha256": self.candidate_sha256,
        }

    def pairing_identity_sha256(self) -> str:
        return sha_json(self.identity_payload())


def require_exact_pair(
    arm_a: ProtectedCandidateControl,
    arm_b: ProtectedCandidateControl,
) -> str:
    if arm_a.identity_payload() != arm_b.identity_payload():
        raise PairingViolation("PAIRWISE_PROTECTED_CANDIDATE_IDENTITY_MISMATCH")
    return arm_a.pairing_identity_sha256()


def fork_exact_candidate(
    control: ProtectedCandidateControl,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return isolated A/B candidate copies from one already-normalized proposal."""
    candidate = {
        "kind": "tool_call",
        "name": control.function,
        "arguments": copy.deepcopy(control.arguments),
    }
    arm_a = copy.deepcopy(candidate)
    arm_b = copy.deepcopy(candidate)
    if sha_json(arm_a) != control.candidate_sha256:
        raise PairingViolation("ARM_A_CANDIDATE_HASH_MISMATCH")
    if sha_json(arm_b) != control.candidate_sha256:
        raise PairingViolation("ARM_B_CANDIDATE_HASH_MISMATCH")
    return arm_a, arm_b


def assert_candidate_unchanged(
    control: ProtectedCandidateControl,
    candidate: dict[str, Any],
) -> None:
    if sha_json(candidate) != control.candidate_sha256:
        raise PairingViolation("CANDIDATE_CHANGED_AFTER_FORK")
