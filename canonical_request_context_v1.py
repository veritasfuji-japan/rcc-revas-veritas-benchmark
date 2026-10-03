"""Bounded bridge from independently captured original request to Ben's canonical request_context surface.

No candidate field, RCC disposition, benchmark gold, or scorer data can populate
query/context. This module does not claim the full canonical wrapper chain.
"""
from __future__ import annotations
from copy import deepcopy
from typing import Any, Mapping
from original_request_authority_lineage_v1 import OriginalRequestEnvelope

class CanonicalRequestContextV1:
    def __init__(self, *, envelope: OriginalRequestEnvelope, runtime_context: Mapping[str, Any]):
        if not isinstance(envelope, OriginalRequestEnvelope):
            raise TypeError("ORIGINAL_REQUEST_ENVELOPE_REQUIRED")
        if not isinstance(runtime_context, Mapping):
            raise TypeError("RUNTIME_CONTEXT_REQUIRED")
        self._envelope = envelope
        self._runtime_context = deepcopy(dict(runtime_context))
        self._digest = envelope.digest

    @property
    def request_digest(self) -> str:
        return self._digest

    def __call__(self, action: Any, pre_state: Mapping[str, Any]) -> dict[str, Any]:
        # Signature intentionally matches NativeDecisionIntentFactory.request_context.
        # action is ignored as an authority source.
        if self._envelope.digest != self._digest:
            raise RuntimeError("ORIGINAL_REQUEST_DIGEST_CHANGED")
        if not isinstance(pre_state, Mapping):
            raise TypeError("PRESTATE_REQUIRED")
        return {
            "query": self._envelope.instruction,
            "context": {
                **deepcopy(self._runtime_context),
                "original_request_digest": self._digest,
                "suite": self._envelope.suite,
                "user_task_id": self._envelope.user_task_id,
            },
        }
