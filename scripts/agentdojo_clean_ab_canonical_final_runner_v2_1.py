#!/usr/bin/env python3
"""Result-bearing AgentDojo Clean A/B runner v0.1.

The runner body is executable, but the repository execution gate remains CLOSED.
No result-bearing run is authorized until a later reviewed commit changes the
gate contract to OPEN. Scoring is a separate post-execution phase.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import subprocess
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
MODEL_ID = "gpt-4.1-mini-2025-04-14"
AGENTDOJO_COMMIT = "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b"
RCC_COMMIT = "1d3782d3aae5ff9c88036709c1a5642320cc53c2"
VERITAS_COMMIT = "a1d66aef02262cf8a913295270c3aafd159c6adb"
BUDGET_USD = 5.0
MAX_COMPLETION_TOKENS = 1024
OPENAI_TIMEOUT_SECONDS = 60.0
OPENAI_MAX_RETRIES = 0
INPUT_RESERVATION_OVERHEAD_TOKENS = 4096
PROTECTED_TOOLS = {
    "send_money",
    "schedule_transaction",
    "update_scheduled_transaction",
    "update_password",
    "update_user_info",
}
GATE_CONFIRMATION = "RUN_CANONICAL_AGENTDOJO_CLEAN_AB_V2_1"
RUNTIME_RECEIPT_SCHEMA = "veritas.agentdojo-final-128-runtime-dispatch-receipt.v1"


class RunnerError(RuntimeError):
    pass


class BudgetExceeded(RunnerError):
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


def sha_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True, separators=(",", ":"), default=str) + "\n")


def jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if is_dataclass(value):
        return {k: jsonable(v) for k, v in asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    if hasattr(value, "value") and isinstance(getattr(value, "value"), (str, int, float, bool)):
        return value.value
    return value


def git_head(path: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def require_git_pin(path: Path, expected: str, label: str) -> None:
    if git_head(path) != expected:
        raise RunnerError(f"{label}_PIN_MISMATCH")
    dirty = subprocess.run(
        ["git", "-C", str(path), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if dirty:
        raise RunnerError(f"{label}_CHECKOUT_DIRTY")


def contracts() -> dict[str, Any]:
    return {
        "implementation": {"execution_gate": "RUNTIME_RECEIPT_ONLY"},
        "model": read_json(ROOT / "contracts/AGENTDOJO_EXACT_MODEL_CONFIGURATION_v0.1.json"),
        "enrollment": read_json(ROOT / "contracts/AGENTDOJO_INJECTION_ENROLLMENT_FREEZE_v0.1.json"),
        "scorer": read_json(ROOT / "contracts/AGENTDOJO_NATIVE_SCORER_FREEZE_v0.1.json"),
    }


def assert_frozen_configuration(
    c: dict[str, Any],
    *,
    expected_execution_gate: str,
) -> list[str]:
    impl = c["implementation"]
    model = c["model"]
    enrollment = c["enrollment"]
    scorer = c["scorer"]
    if expected_execution_gate != "RUNTIME_RECEIPT_ONLY":
        raise RunnerError("INVALID_EXPECTED_EXECUTION_GATE")
    if impl["execution_gate"] != "RUNTIME_RECEIPT_ONLY":
        raise RunnerError("EXECUTION_GATE_STATE_MISMATCH")
    if model["model"]["model_id"] != MODEL_ID or model["sampling"]["temperature"] != 0.0:
        raise RunnerError("MODEL_CONFIGURATION_DRIFT")
    if model["sampling"]["automatic_retry"] is not False or model["sampling"]["fallback_model"] is not None:
        raise RunnerError("MODEL_RETRY_OR_FALLBACK_DRIFT")
    if float(model["budget"]["provider_spend_cap_usd"]) != BUDGET_USD:
        raise RunnerError("MODEL_BUDGET_DRIFT")
    e = enrollment["enrollment"]
    expected = [
        f"banking:user_task_{u}:injection_task_{i}:direct"
        for u in range(16)
        for i in [0, 1, 2, 3, 4, 5, 6, 8]
    ]
    if e["exact_case_ids"] != expected or e["case_count"] != 128:
        raise RunnerError("ENROLLMENT_DRIFT")
    if scorer["invocation"]["timing"] != "POST_EXECUTION_ONLY":
        raise RunnerError("SCORER_TIMING_DRIFT")
    return expected


def verify_authority_fixture() -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    d = ROOT / "fixtures/agentdojo_authority_v0_1"
    manifest = read_json(d / "SHA256SUMS.json")
    for name, digest in manifest.items():
        if sha_file(d / name) != digest:
            raise RunnerError("AUTHORITY_FIXTURE_HASH_MISMATCH:" + name)
    artifact = read_json(d / "authority_fixture.json")
    signature = base64.b64decode(artifact.pop("benchmark_fixture_signature"))
    public = Ed25519PublicKey.from_public_bytes(
        base64.b64decode((d / "public_key.raw.b64").read_text().strip())
    )
    payload = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode()
    public.verify(signature, payload)
    if artifact["actor_identity"] != "agentdojo:banking:benchmark-user":
        raise RunnerError("AUTHORITY_ACTOR_MISMATCH")
    if artifact["authority_scope"] != ["agentdojo-banking-protected-mutation"]:
        raise RunnerError("AUTHORITY_SCOPE_MISMATCH")
    if artifact["policy_snapshot_id"] != "agentdojo-banking-clean-ab-v0.1":
        raise RunnerError("AUTHORITY_POLICY_MISMATCH")
    rev = read_json(d / "revocations.json")
    if rev["status_by_id"].get(artifact["evidence_id"]) is not False:
        raise RunnerError("AUTHORITY_REVOKED_OR_UNKNOWN")
    return True


class BudgetLedger:
    def __init__(self, cap_usd: float = BUDGET_USD) -> None:
        self.cap_usd = float(cap_usd)
        self.spent_usd = 0.0
        self.calls = 0
        self.prompt_tokens = 0
        self.cached_tokens = 0
        self.completion_tokens = 0

    def reserve(self, kwargs: dict[str, Any]) -> None:
        request_view = {
            "messages": kwargs.get("messages", []),
            "tools": kwargs.get("tools", []),
        }
        payload_bytes = len(
            json.dumps(request_view, ensure_ascii=True, default=str).encode()
        )
        if payload_bytes > 250_000:
            raise BudgetExceeded("REQUEST_PAYLOAD_TOO_LARGE_FOR_FROZEN_BUDGET_PROFILE")
        upper_input_tokens = payload_bytes + INPUT_RESERVATION_OVERHEAD_TOKENS
        reserved = (
            upper_input_tokens * 0.40 + MAX_COMPLETION_TOKENS * 1.60
        ) / 1_000_000
        if self.spent_usd + reserved > self.cap_usd:
            raise BudgetExceeded("LOCAL_PROVIDER_BUDGET_GUARD")

    def commit_usage(self, completion: Any) -> None:
        usage = getattr(completion, "usage", None)
        if usage is None:
            raise RunnerError("OPENAI_USAGE_MISSING")
        prompt = int(getattr(usage, "prompt_tokens", 0) or 0)
        completion_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
        details = getattr(usage, "prompt_tokens_details", None)
        cached = (
            int(getattr(details, "cached_tokens", 0) or 0)
            if details is not None
            else 0
        )
        uncached = max(0, prompt - cached)
        cost = (
            uncached * 0.40 + cached * 0.10 + completion_tokens * 1.60
        ) / 1_000_000
        self.spent_usd += cost
        self.calls += 1
        self.prompt_tokens += prompt
        self.cached_tokens += cached
        self.completion_tokens += completion_tokens
        if self.spent_usd > self.cap_usd:
            raise BudgetExceeded("REPORTED_PROVIDER_USAGE_EXCEEDED_CAP")

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_calls": self.calls,
            "prompt_tokens": self.prompt_tokens,
            "cached_tokens": self.cached_tokens,
            "completion_tokens": self.completion_tokens,
            "estimated_cost_usd": round(self.spent_usd, 8),
            "provider_spend_cap_usd": self.cap_usd,
            "automatic_retry": False,
        }


class BudgetedCompletions:
    def __init__(self, base: Any, ledger: BudgetLedger) -> None:
        self.base = base
        self.ledger = ledger

    def create(self, **kwargs: Any) -> Any:
        if kwargs.get("model") != MODEL_ID:
            raise RunnerError("MODEL_SNAPSHOT_MISMATCH")
        if kwargs.get("temperature") != 0.0:
            raise RunnerError("TEMPERATURE_MISMATCH")
        kwargs["max_completion_tokens"] = MAX_COMPLETION_TOKENS
        self.ledger.reserve(kwargs)
        completion = self.base.create(**kwargs)
        self.ledger.commit_usage(completion)
        return completion


class BudgetedClient:
    def __init__(self, base: Any, ledger: BudgetLedger) -> None:
        self.chat = SimpleNamespace(
            completions=BudgetedCompletions(base.chat.completions, ledger)
        )


def build_openai_client(ledger: BudgetLedger) -> BudgetedClient:
    import openai

    if not os.environ.get("OPENAI_API_KEY"):
        raise RunnerError("OPENAI_API_KEY_MISSING")
    base = openai.OpenAI(
        api_key=os.environ["OPENAI_API_KEY"],
        max_retries=OPENAI_MAX_RETRIES,
        timeout=OPENAI_TIMEOUT_SECONDS,
    )
    return BudgetedClient(base, ledger)


def build_pipeline(client: Any) -> Any:
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
    from scripts.agentdojo_final_runner_integration_v0_1 import FrozenAgentDojoOpenAIPipeline

    llm = FrozenAgentDojoOpenAIPipeline(client)
    loop = ToolsExecutionLoop([ToolsExecutor(), llm])
    pipeline = AgentPipeline(
        [SystemMessage(load_system_message(None)), InitQuery(), llm, loop]
    )
    pipeline.name = "gpt-4.1-mini-2025-04-14-agentdojo-frozen-v0.1"
    return pipeline


def load_rcc_gate(rcc_root: Path) -> Any:
    from rveval.integrations.rcc_external import ExternalRCCGate

    policy = rcc_root / "external-eval/v0.3.9/src/rveval/resources/policy.json"
    if not policy.is_file():
        raise RunnerError("RCC_POLICY_MISSING")
    return ExternalRCCGate(
        {
            "policy": str(policy.resolve()),
            "policy_sha256": sha_file(policy),
        },
        rcc_root,
    )


class RCCOnlyExecutor:
    def __init__(
        self,
        hook: Any,
        snapshot: Callable[[], Any],
        context: Callable[[Any], dict],
        journal: Callable[[str, dict], None],
    ) -> None:
        self.hook = hook
        self.snapshot = snapshot
        self.context = context
        self.journal = journal

    def call(self, candidate: Any, apply: Callable[[Any], Any]) -> Any:
        from rveval.canonical import sha_json as rsha
        from rveval.integrations.boundary import CallResult, GovernanceStop
        from rveval.models import CandidateAction

        before = rsha(self.snapshot())
        ctx = copy.deepcopy(self.context(candidate))
        record = self.hook.review(candidate=candidate, context=ctx)
        if rsha(self.snapshot()) != before:
            raise RunnerError("STATE_CHANGED_DURING_RCC_REVIEW")
        if not record.get("dispatch_allowed_by_hook"):
            self.journal(
                "RCC_REFUSAL",
                {
                    "candidate_sha256": rsha(candidate.to_dict()),
                    "review": record,
                },
            )
            raise GovernanceStop({"stage": "RCC", "review": record})
        adopted = CandidateAction(**record["candidate_to_dispatch"])
        self.hook.verify_dispatch(record, adopted)
        isolated = CandidateAction(**adopted.to_dict())
        value = apply(isolated)
        if rsha(isolated.to_dict()) != rsha(adopted.to_dict()):
            raise RunnerError("NATIVE_APPLY_MUTATED_CANDIDATE")
        receipt = {
            "rcc": record,
            "pre_state_sha256": before,
            "post_state_sha256": rsha(self.snapshot()),
        }
        self.journal("RCC_NATIVE_APPLY_RETURNED", receipt)
        return CallResult(value=value, receipt=receipt)


class RCCVeritasExecutor(RCCOnlyExecutor):
    def __init__(
        self,
        *args: Any,
        user_task_id: int,
        authority_admitted: bool,
        original_request: str,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.user_task_id = user_task_id
        self.authority_admitted = authority_admitted
        self.original_request = original_request

    def call(self, candidate: Any, apply: Callable[[Any], Any]) -> Any:
        if candidate.name not in PROTECTED_TOOLS:
            return super().call(candidate, apply)

        from rveval.canonical import sha_json as rsha
        from rveval.integrations.boundary import CallResult, GovernanceStop
        from rveval.models import CandidateAction
        from agentdojo_constraint_resolver_v0_1 import validate_candidate
        from original_request_authority_lineage_v1 import (
            OriginalRequestEnvelope,
            validate_task15_from_original_request,
        )
        from veritas_os.benchmarks.agentdojo_banking_adapter import (
            AgentDojoBankingBindAdapter,
            build_agentdojo_benchmark_execution_intent,
            freeze_agentdojo_candidate,
        )
        from veritas_os.policy.bind_core import execute_bind_adjudication
        from veritas_os.security.hash import sha256_of_canonical_json

        pre = copy.deepcopy(self.snapshot())
        pre_rsha = rsha(pre)
        ctx = copy.deepcopy(self.context(candidate))
        review = self.hook.review(candidate=candidate, context=ctx)
        if rsha(self.snapshot()) != pre_rsha:
            raise RunnerError("STATE_CHANGED_DURING_RCC_REVIEW")
        if not review.get("dispatch_allowed_by_hook"):
            self.journal(
                "RCC_REFUSAL",
                {
                    "candidate_sha256": rsha(candidate.to_dict()),
                    "review": review,
                },
            )
            raise GovernanceStop({"stage": "RCC", "review": review})
        adopted = CandidateAction(**review["candidate_to_dispatch"])
        self.hook.verify_dispatch(review, adopted)

        frozen = freeze_agentdojo_candidate(
            user_task_id=self.user_task_id,
            tool_name=adopted.name,
            arguments=adopted.arguments,
        )
        box: dict[str, Any] = {}

        def mutate(name: str, args: dict[str, Any]) -> bool:
            exact = CandidateAction(
                "tool_call",
                name=name,
                arguments=copy.deepcopy(args),
            )
            native_value = apply(exact)
            box["native_value"] = native_value
            return (
                isinstance(native_value, tuple)
                and len(native_value) == 2
                and native_value[1] is None
            )

        def constraints(fc: Any, snapshot: Any) -> dict[str, bool]:
            if fc.user_task_id == 15:
                return validate_task15_from_original_request(
                    envelope=OriginalRequestEnvelope(
                        suite="banking",
                        user_task_id=fc.user_task_id,
                        instruction=self.original_request,
                    ),
                    tool_name=fc.tool_name,
                    arguments=fc.arguments,
                    trusted_prestate=snapshot,
                )
            return validate_candidate(
                user_task_id=fc.user_task_id,
                tool_name=fc.tool_name,
                arguments=fc.arguments,
                trusted_prestate=snapshot,
            )

        adapter = AgentDojoBankingBindAdapter(
            candidate=frozen,
            snapshot_reader=lambda: copy.deepcopy(self.snapshot()),
            mutation_executor=mutate,
            postcondition_checker=lambda *_: rsha(self.snapshot()) != pre_rsha,
            authority_admitted=self.authority_admitted,
            constraint_validator=constraints,
        )
        rcc_digest = rsha(review["rcc"])
        intent = build_agentdojo_benchmark_execution_intent(
            frozen,
            decision_id="rcc:" + rcc_digest,
            request_id="agentdojo:"
            + sha_json(
                {
                    "task": self.user_task_id,
                    "candidate": adopted.to_dict(),
                    "pre": pre_rsha,
                }
            ),
            policy_snapshot_id="agentdojo-banking-clean-ab-v0.1",
            actor_identity="agentdojo:banking:benchmark-user",
            expected_state_fingerprint=sha256_of_canonical_json(pre),
            decision_hash=rcc_digest,
            decision_ts=datetime.now(timezone.utc).isoformat(),
        )
        receipt = execute_bind_adjudication(
            execution_intent=intent,
            adapter=adapter,
            bind_ts=datetime.now(timezone.utc).isoformat(),
            append_trustlog=False,
        )
        receipt_dict = jsonable(receipt)
        outcome = jsonable(receipt.final_outcome)
        self.journal(
            "VERITAS_BIND_RECEIPT",
            {
                "candidate_sha256": rsha(adopted.to_dict()),
                "receipt": receipt_dict,
            },
        )
        if outcome == "COMMITTED":
            return CallResult(
                value=box["native_value"],
                receipt={
                    "rcc": review,
                    "native_bind_receipt": receipt_dict,
                    "pre_state_sha256": pre_rsha,
                    "post_state_sha256": rsha(self.snapshot()),
                },
            )
        if outcome in {"BLOCKED", "ESCALATED", "PRECONDITION_FAILED"}:
            raise GovernanceStop(
                {
                    "stage": "VERITAS_BIND",
                    "outcome": outcome,
                    "receipt": receipt_dict,
                }
            )
        raise RunnerError("VERITAS_BIND_NON_GOVERNANCE_FAILURE:" + str(outcome))


def make_runtime_class(
    *,
    arm: str,
    rcc_gate: Any,
    user_task_id: int,
    case_id: str,
    prompt: str,
    journal_rows: list[dict[str, Any]],
    authority_admitted: bool,
) -> type:
    from rveval.integrations.agentdojo import (
        environment_snapshot,
        make_runtime_class as native_make_runtime,
    )
    from rveval.native_hook import NativeGovernanceHook
    from rveval.canonical import sha_json as rsha

    hook = NativeGovernanceHook(rcc_gate)

    def journal(event: str, payload: dict) -> None:
        journal_rows.append(
            {
                "sequence": len(journal_rows),
                "event": event,
                "payload": jsonable(payload),
            }
        )

    def factory(runtime: Any, env: Any) -> Any:
        snapshot = lambda: environment_snapshot(env)
        context = lambda c: {
            "task": {
                "request": prompt,
                "suite": "banking",
            },
            "case_id": case_id,
            "user_task_id": user_task_id,
            "candidate_sha256": rsha(c.to_dict()),
        }
        if arm == "A":
            return RCCOnlyExecutor(hook, snapshot, context, journal)
        return RCCVeritasExecutor(
            hook,
            snapshot,
            context,
            journal,
            user_task_id=user_task_id,
            authority_admitted=authority_admitted,
            original_request=prompt,
        )

    return native_make_runtime(factory)


def execute_trajectory(
    *,
    suite: Any,
    user_task: Any,
    injection_task: Any,
    initial_env: Any,
    arm: str,
    pipeline: Any,
    rcc_gate: Any,
    case_id: str,
    authority_admitted: bool,
) -> dict[str, Any]:
    from agentdojo.task_suite.task_suite import (
        functions_stack_trace_from_messages,
        model_output_from_messages,
    )

    env = initial_env.model_copy(deep=True)
    pre = env.model_copy(deep=True)
    pre_json = pre.model_dump(mode="json")
    journal_rows: list[dict[str, Any]] = []
    uid = int(user_task.ID.rsplit("_", 1)[1])
    Runtime = make_runtime_class(
        arm=arm,
        rcc_gate=rcc_gate,
        user_task_id=uid,
        case_id=case_id,
        prompt=user_task.PROMPT,
        journal_rows=journal_rows,
        authority_admitted=authority_admitted,
    )
    runtime = Runtime(suite.tools)
    messages = []
    model_output = None
    try:
        for _ in range(3):
            _, _, env, messages, _ = pipeline.query(
                user_task.PROMPT,
                runtime,
                env,
            )
            model_output = model_output_from_messages(messages)
            if model_output is not None:
                break
        trace = functions_stack_trace_from_messages(messages)
        post_json = env.model_dump(mode="json")
        return {
            "case_id": case_id,
            "arm": arm,
            "status": "COMPLETED",
            "pre_environment": pre_json,
            "post_environment": post_json,
            "pre_state_sha256": sha_json(pre_json),
            "post_state_sha256": sha_json(post_json),
            "model_output": jsonable(model_output or []),
            "functions_stack_trace": [jsonable(x) for x in trace],
            "governance_journal": journal_rows,
        }
    except Exception as exc:
        post_json = env.model_dump(mode="json")
        return {
            "case_id": case_id,
            "arm": arm,
            "status": "ERROR",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "pre_environment": pre_json,
            "post_environment": post_json,
            "pre_state_sha256": sha_json(pre_json),
            "post_state_sha256": sha_json(post_json),
            "model_output": [],
            "functions_stack_trace": [],
            "governance_journal": journal_rows,
        }


def score_records(
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from agentdojo.functions_runtime import FunctionCall
    from agentdojo.task_suite.load_suites import get_suite
    from scripts.agentdojo_final_runner_integration_v0_1 import (
        ExecutionBarrier,
        score_after_execution,
    )
    from scripts.agentdojo_native_scorer_invocation_v0_1 import (
        NativeScorerInput,
        invoke_native_agentdojo_scorer,
    )

    suite = get_suite("v1.2.2", "banking")
    scores: list[dict[str, Any]] = []
    for rec in records:
        if rec["status"] != "COMPLETED":
            scores.append(
                {
                    "case_id": rec["case_id"],
                    "arm": rec["arm"],
                    "score_status": "NOT_SCORED_EXECUTION_ERROR",
                }
            )
            continue
        parts = rec["case_id"].split(":")
        user = suite.get_user_task_by_id(parts[1])
        inj = suite.get_injection_task_by_id(parts[2])
        evidence = NativeScorerInput(
            case_id=rec["case_id"],
            arm=rec["arm"],
            model_output=rec["model_output"],
            pre_environment=suite.environment_type.model_validate(
                rec["pre_environment"]
            ),
            post_environment=suite.environment_type.model_validate(
                rec["post_environment"]
            ),
            functions_stack_trace=[
                FunctionCall.model_validate(x)
                for x in rec["functions_stack_trace"]
            ],
        )
        barrier = ExecutionBarrier(
            case_id=rec["case_id"],
            arm=rec["arm"],
            pre_state_sha256=rec["pre_state_sha256"],
            post_state_sha256=rec["post_state_sha256"],
        )
        result = score_after_execution(
            barrier=barrier,
            scorer=lambda e=evidence, u=user, i=inj: invoke_native_agentdojo_scorer(
                suite=suite,
                user_task=u,
                injection_task=i,
                evidence=e,
            ),
        )
        scores.append(
            {
                "case_id": rec["case_id"],
                "arm": rec["arm"],
                "score_status": "SCORED",
                **result,
            }
        )

    summary: dict[str, Any] = {}
    for arm in ("A", "B"):
        rows = [x for x in scores if x["arm"] == arm]
        scored = [x for x in rows if x["score_status"] == "SCORED"]
        summary[arm] = {
            "enrolled": len(rows),
            "scored": len(scored),
            "utility_rate": (
                sum(int(x["utility"]) for x in scored) / len(scored)
                if scored
                else None
            ),
            "security_rate": (
                sum(int(x["security"]) for x in scored) / len(scored)
                if scored
                else None
            ),
        }
    summary["valid_for_comparison"] = all(
        x["score_status"] == "SCORED"
        for x in scores
    )
    return scores, summary


def verify_durable_consumption(receipt: dict[str, Any], *, allow_synthetic: bool) -> None:
    import asyncio
    from veritas_os.policy.live_adapter_bind_authorization_consumption_store import PostgresAtomicAuthorizationConsumptionStore
    durable_id = receipt.get("durable_authorization_id")
    expected = receipt["authorization_id"]
    if allow_synthetic:
        if not isinstance(durable_id, str) or not durable_id.startswith(expected + "_SYNTHETIC_"):
            raise RunnerError("DURABLE_AUTHORIZATION_ID_MISMATCH")
    elif durable_id != expected:
        raise RunnerError("DURABLE_AUTHORIZATION_ID_MISMATCH")
    async def read():
        return await PostgresAtomicAuthorizationConsumptionStore().get(durable_id)
    try:
        record = asyncio.run(read())
    except Exception as exc:
        raise RunnerError("DURABLE_CONSUMPTION_READ_FAILED") from exc
    if record is None:
        raise RunnerError("DURABLE_CONSUMPTION_MISSING")
    if record.consumption_id != receipt.get("consumption_id"):
        raise RunnerError("DURABLE_CONSUMPTION_ID_MISMATCH")
    if record.consumption_hash != receipt.get("consumption_hash"):
        raise RunnerError("DURABLE_CONSUMPTION_HASH_MISMATCH")
    if record.live_adapter_bind_authorization_id != durable_id:
        raise RunnerError("DURABLE_CONSUMPTION_AUTHORIZATION_MISMATCH")
    if record.consumption_state != "CONSUMED" or record.single_use_enforced is not True:
        raise RunnerError("DURABLE_CONSUMPTION_STATE_MISMATCH")

def verify_runtime_dispatch_receipt(path: Path, *, verify_durable: bool = False, allow_synthetic: bool = False) -> dict[str, Any]:
    if not path.is_file():
        raise RunnerError("RUNTIME_DISPATCH_RECEIPT_MISSING")
    r=read_json(path)
    if r.get("schema_version") != RUNTIME_RECEIPT_SCHEMA:
        raise RunnerError("RUNTIME_DISPATCH_RECEIPT_SCHEMA_MISMATCH")
    if r.get("authorization_id") != "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V5":
        raise RunnerError("RUNTIME_DISPATCH_AUTHORIZATION_MISMATCH")
    if r.get("atomic_consumption_won") is not True:
        raise RunnerError("RUNTIME_DISPATCH_ATOMIC_WIN_REQUIRED")
    if r.get("single_use") is not True or r.get("rerun_authorized") is not False:
        raise RunnerError("RUNTIME_DISPATCH_SINGLE_USE_MISMATCH")
    if r.get("provider_spend_cap_usd") != BUDGET_USD:
        raise RunnerError("RUNTIME_DISPATCH_BUDGET_MISMATCH")
    if verify_durable:
        verify_durable_consumption(r, allow_synthetic=allow_synthetic)
    return r

def execute_all(
    *,
    output_dir: Path,
    agentdojo_root: Path,
    rcc_root: Path,
    veritas_root: Path,
    runtime_dispatch_receipt: Path,
) -> dict[str, Any]:
    verify_runtime_dispatch_receipt(runtime_dispatch_receipt, verify_durable=True, allow_synthetic=False)
    require_git_pin(agentdojo_root, AGENTDOJO_COMMIT, "AGENTDOJO")
    require_git_pin(rcc_root, RCC_COMMIT, "RCC")
    require_git_pin(veritas_root, VERITAS_COMMIT, "VERITAS")
    cases = assert_frozen_configuration(
        contracts(),
        expected_execution_gate="RUNTIME_RECEIPT_ONLY",
    )
    authority_ok = verify_authority_fixture()

    from agentdojo.attacks.baseline_attacks import DirectAttack
    from agentdojo.task_suite.load_suites import get_suite

    suite = get_suite("v1.2.2", "banking")
    rcc_gate = load_rcc_gate(rcc_root)
    ledger = BudgetLedger()
    pipeline = build_pipeline(build_openai_client(ledger))
    attack = DirectAttack(suite, pipeline)
    records: list[dict[str, Any]] = []

    for case_id in cases:
        _, user_id, injection_id, profile = case_id.split(":")
        if profile != "direct":
            raise RunnerError("ATTACK_PROFILE_DRIFT")
        user = suite.get_user_task_by_id(user_id)
        injection = suite.get_injection_task_by_id(injection_id)
        injections = attack.attack(user, injection)
        base_env = suite.load_and_inject_default_environment(injections)
        initial = user.init_environment(base_env)

        a = execute_trajectory(
            suite=suite,
            user_task=user,
            injection_task=injection,
            initial_env=initial,
            arm="A",
            pipeline=pipeline,
            rcc_gate=rcc_gate,
            case_id=case_id,
            authority_admitted=authority_ok,
        )
        b = execute_trajectory(
            suite=suite,
            user_task=user,
            injection_task=injection,
            initial_env=initial,
            arm="B",
            pipeline=pipeline,
            rcc_gate=rcc_gate,
            case_id=case_id,
            authority_admitted=authority_ok,
        )
        if a["pre_state_sha256"] != b["pre_state_sha256"]:
            raise RunnerError("PAIRING_PRESTATE_MISMATCH:" + case_id)
        records.extend([a, b])

    if len(records) != 256:
        raise RunnerError("ARM_DENOMINATOR_MISMATCH")

    write_jsonl(output_dir / "execution_records.jsonl", records)
    scores, score_summary = score_records(records)
    write_jsonl(output_dir / "native_scores.jsonl", scores)

    summary = {
        "schema_version": "veritas.agentdojo-clean-ab-final.v0.1",
        "execution_role": "CLEAN_INTEGRATION_REPLICATION_NOT_HELD_OUT_VALIDATION",
        "case_count": 128,
        "arm_record_count": 256,
        "execution_errors": sum(
            r["status"] != "COMPLETED"
            for r in records
        ),
        "same_initial_prestate_count": sum(
            records[i]["pre_state_sha256"]
            == records[i + 1]["pre_state_sha256"]
            for i in range(0, len(records), 2)
        ),
        "provider": ledger.to_dict(),
        "scores": score_summary,
        "claim_boundary": {
            "held_out_validation": False,
            "independent_third_party_validation": False,
            "production_readiness": False,
            "same_agentdojo_banking_corpus_previously_exposed": True,
        },
    }
    write_json(output_dir / "summary.json", summary)
    return summary


def audit_only(
    agentdojo_root: Path,
    rcc_root: Path,
    veritas_root: Path,
) -> dict[str, Any]:
    require_git_pin(agentdojo_root, AGENTDOJO_COMMIT, "AGENTDOJO")
    require_git_pin(rcc_root, RCC_COMMIT, "RCC")
    require_git_pin(veritas_root, VERITAS_COMMIT, "VERITAS")
    cases = assert_frozen_configuration(
        contracts(),
        expected_execution_gate="RUNTIME_RECEIPT_ONLY",
    )
    verify_authority_fixture()
    report = {
        "status": "PASS_FINAL_RUNNER_V2_RUNTIME_RECEIPT_REQUIRED",
        "case_count": len(cases),
        "pins": {
            "agentdojo": AGENTDOJO_COMMIT,
            "rcc": RCC_COMMIT,
            "veritas": VERITAS_COMMIT,
        },
        "model": MODEL_ID,
        "budget_usd": BUDGET_USD,
        "max_completion_tokens": MAX_COMPLETION_TOKENS,
        "openai_client_max_retries": OPENAI_MAX_RETRIES,
        "execution_gate": "CLOSED",
        "api_called": False,
        "clean_ab_executed": False,
    }
    write_json(
        ROOT / "agentdojo-final-runner-implementation-audit.json",
        report,
    )
    return report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--audit-only", action="store_true")
    mode.add_argument("--execute", action="store_true")
    mode.add_argument("--preflight-runtime-receipt", action="store_true")
    p.add_argument("--agentdojo-root", type=Path, required=True)
    p.add_argument("--rcc-root", type=Path, required=True)
    p.add_argument("--veritas-root", type=Path, required=True)
    p.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/agentdojo-clean-ab-final-v0_1"),
    )
    p.add_argument("--confirmation")
    p.add_argument("--runtime-dispatch-receipt", type=Path)
    return p


def main() -> int:
    args = build_parser().parse_args()
    if args.audit_only:
        print(
            json.dumps(
                audit_only(
                    args.agentdojo_root,
                    args.rcc_root,
                    args.veritas_root,
                ),
                indent=2,
            )
        )
        return 0

    if args.runtime_dispatch_receipt is None:
        raise RunnerError("RUNTIME_DISPATCH_RECEIPT_MISSING")
    receipt = verify_runtime_dispatch_receipt(args.runtime_dispatch_receipt, verify_durable=True, allow_synthetic=args.preflight_runtime_receipt)
    require_git_pin(args.agentdojo_root, AGENTDOJO_COMMIT, "AGENTDOJO")
    require_git_pin(args.rcc_root, RCC_COMMIT, "RCC")
    require_git_pin(args.veritas_root, VERITAS_COMMIT, "VERITAS")
    cases = assert_frozen_configuration(contracts(), expected_execution_gate="RUNTIME_RECEIPT_ONLY")
    verify_authority_fixture()
    if args.preflight_runtime_receipt:
        print(json.dumps({"status":"PASS_RUNNER_V2_1_DURABLE_DB_RECEIPT_PREFLIGHT","authorization_id":receipt["authorization_id"],"case_count":len(cases),"provider_api_calls":0,"final_128_execution":0}, sort_keys=True))
        return 0
    if args.confirmation != GATE_CONFIRMATION:
        raise RunnerError("EXPLICIT_HUMAN_EXECUTION_CONFIRMATION_REQUIRED")
    if args.output_dir.exists():
        raise RunnerError("OUTPUT_DIR_ALREADY_EXISTS")

    args.output_dir.mkdir(parents=True)
    summary = execute_all(
        output_dir=args.output_dir,
        agentdojo_root=args.agentdojo_root,
        rcc_root=args.rcc_root,
        veritas_root=args.veritas_root,
        runtime_dispatch_receipt=args.runtime_dispatch_receipt,
    )
    print(json.dumps(summary, indent=2))
    return 0 if summary["scores"]["valid_for_comparison"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
