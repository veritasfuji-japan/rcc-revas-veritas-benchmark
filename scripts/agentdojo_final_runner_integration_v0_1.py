"""Offline integration closure for the frozen AgentDojo clean A/B path.

No provider call, benchmark result, scorer truth, or execution authorization is
created here. The purpose is to close the plumbing seams before the result-bearing
runner is frozen and enabled.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Sequence

from scripts.agentdojo_openai_frozen_adapter_v0_1 import create_completion_once


class FrozenAgentDojoOpenAIPipeline:
    """AgentDojo-compatible OpenAI pipeline using the frozen one-attempt adapter."""

    name = "agentdojo-gpt-4.1-mini-frozen-v0.1"

    def __init__(self, client: Any) -> None:
        self.client = client

    def query(self, query, runtime, env, messages: Sequence[dict] = (), extra_args: dict | None = None):
        del query
        from agentdojo.agent_pipeline.llms.openai_llm import (
            _function_to_openai,
            _message_to_openai,
            _openai_to_assistant_message,
        )

        openai_messages = [_message_to_openai(message, "gpt-4.1-mini-2025-04-14") for message in messages]
        openai_tools = [_function_to_openai(tool) for tool in runtime.functions.values()]
        completion = create_completion_once(
            client=self.client,
            messages=openai_messages,
            tools=openai_tools,
        )
        output = _openai_to_assistant_message(completion.choices[0].message)
        return "", runtime, env, [*messages, output], dict(extra_args or {})


def make_rcc_candidate_runtime(executor_factory: Callable):
    """Return Ben's exact pinned AgentDojo candidate-capture runtime class."""
    from rveval.integrations.agentdojo import make_runtime_class

    return make_runtime_class(executor_factory)


@dataclass(frozen=True)
class ExecutionBarrier:
    """Proof that execution completed before benchmark-owned scoring begins."""

    case_id: str
    arm: str
    pre_state_sha256: str
    post_state_sha256: str


def score_after_execution(*, barrier: ExecutionBarrier, scorer: Callable[[], Any]) -> Any:
    """Invoke benchmark-owned scoring only after an explicit execution barrier."""
    if not isinstance(barrier, ExecutionBarrier):
        raise TypeError("AGENTDOJO_EXECUTION_BARRIER_REQUIRED")
    if not all((barrier.case_id, barrier.arm, barrier.pre_state_sha256, barrier.post_state_sha256)):
        raise ValueError("AGENTDOJO_EXECUTION_BARRIER_INCOMPLETE")
    return scorer()
