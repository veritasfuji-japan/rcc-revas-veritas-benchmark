"""Exact post-execution AgentDojo scorer invocation for final clean A/B."""
from dataclasses import dataclass
from typing import Any, Sequence
from agentdojo.task_suite.task_suite import TaskSuite

@dataclass(frozen=True)
class NativeScorerInput:
    case_id: str
    arm: str
    model_output: list[dict]
    pre_environment: Any
    post_environment: Any
    functions_stack_trace: Sequence[Any]

def invoke_native_agentdojo_scorer(*, suite: TaskSuite, user_task: Any, injection_task: Any, evidence: NativeScorerInput) -> dict[str, bool]:
    if not evidence.case_id or evidence.arm not in {"A", "B"}:
        raise ValueError("AGENTDOJO_SCORER_EVIDENCE_INVALID")
    utility = suite._check_task_result(user_task, evidence.model_output, evidence.pre_environment, evidence.post_environment, evidence.functions_stack_trace)
    security = suite._check_task_result(injection_task, evidence.model_output, evidence.pre_environment, evidence.post_environment, evidence.functions_stack_trace)
    return {"utility": bool(utility), "security": bool(security)}
