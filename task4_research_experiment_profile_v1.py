"""Configuration for bounded LOCAL Task4 development, never paid permission."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import date
import hashlib
import json
import re

SOURCE_CASE = "banking:user_task_4:injection_task_0:direct"
RESEARCH_CASE = "banking:user_task_4:injection_task_0:research-variable-v1"
ORIGIN = "LOCAL_TEST_CALLBACK_NOT_AUTHENTICATED_PROVIDER"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf8")).hexdigest()


@dataclass(frozen=True)
class Task4ResearchProfile:
    execution_id: str
    task_date: str
    model_id: str = "gpt-4.1-mini-2025-04-14"
    max_requests_per_arm: int = 6
    output_token_cap: int = 256
    max_request_bytes: int = 64000
    max_total_request_bytes_per_arm: int = 256000

    def __post_init__(self):
        if type(self.execution_id) is not str or not re.fullmatch(
                r"[a-zA-Z0-9][a-zA-Z0-9_-]{7,63}", self.execution_id):
            raise ValueError("RESEARCH_EXECUTION_ID_REQUIRED")
        if type(self.task_date) is not str or date.fromisoformat(
                self.task_date).isoformat() != self.task_date:
            raise ValueError("CANONICAL_RESEARCH_DATE_REQUIRED")
        if type(self.model_id) is not str or not re.fullmatch(
                r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", self.model_id):
            raise ValueError("BOUNDED_MODEL_LABEL_REQUIRED")
        bounds = ((self.max_requests_per_arm, 1, 12),
                  (self.output_token_cap, 1, 4096),
                  (self.max_request_bytes, 1, 256000),
                  (self.max_total_request_bytes_per_arm, 1, 3072000))
        if any(type(v) is not int or not low <= v <= high
               for v, low, high in bounds):
            raise ValueError("BOUNDED_INTEGER_LIMIT_REQUIRED")
        if self.max_total_request_bytes_per_arm < self.max_request_bytes:
            raise ValueError("TOTAL_LIMIT_BELOW_REQUEST_LIMIT")

    def to_dict(self):
        return {**asdict(self), "source_case": SOURCE_CASE,
                "research_case": RESEARCH_CASE,
                "scope": "LOCAL_NATIVE_SIMULATOR_ONLY",
                "comparison": "PROSPECTIVE_FEASIBILITY_NOT_DATE_CAUSAL_EFFECT",
                "max_protected_operations_per_arm": 1,
                "provider_permission": False,
                "byte_limits_are_provider_token_or_billing_caps": False}

    @property
    def identity(self):
        return digest(self.to_dict())
