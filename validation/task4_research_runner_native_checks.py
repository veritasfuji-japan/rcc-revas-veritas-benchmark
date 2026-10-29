"""Explicit pinned Native tests; no optional skips or external network.

Kept outside generic test discovery: invoke this file explicitly in dedicated
CI where Native dependencies/pins are installed. Test callbacks are scripted.
"""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import subprocess

import pytest

from task4_research_experiment_profile_v1 import Task4ResearchProfile, digest
from task4_research_case_runner_v1 import (
    LocalArmRecord, LocalModelTurn, Task4ResearchCaseRunner,
)
from task4_research_terminal_scoring_v1 import score_local_arm, summarize_local_pair


@pytest.fixture(autouse=True)
def no_network_or_secrets(monkeypatch):
    def denied(*args, **kwargs):
        pytest.fail("NO_PROVIDER_OR_EXTERNAL_BANK_IN_LOCAL_TEST")
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    for name in ("OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                 "OPENAI_BASE_URL", "VERITAS_DATABASE_URL", "GH_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def harness():
    from agentdojo.task_suite.load_suites import get_suite
    from task4_trusted_execution_date_profile_v1 import Task4DateProfileSession
    from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import (
        load_rcc_gate, verify_authority_fixture,
    )
    roots = {name: Path(os.environ["TASK4_RESEARCH_" + name.upper() + "_ROOT"])
             for name in ("agentdojo", "rcc", "veritas")}
    pins = {"agentdojo": "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b",
            "rcc": "1d3782d3aae5ff9c88036709c1a5642320cc53c2",
            "veritas": "a1d66aef02262cf8a913295270c3aafd159c6adb"}
    for name, root in roots.items():
        assert subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"],
                                       text=True).strip() == pins[name]
    p = Task4ResearchProfile("local-native-test-20261029", "2027-02-05")
    sessions = []
    def session(arm):
        s = Task4DateProfileSession(
            source_id="local-research-test-" + arm,
            signing_key=os.urandom(32),
            clock=lambda: datetime(2027, 2, 5, 12, tzinfo=timezone.utc))
        sessions.append(s)
        return s
    def build(profile=p, admitted=True):
        return Task4ResearchCaseRunner(
            profile=profile, suite=get_suite("v1.2.2", "banking"),
            rcc_gate=load_rcc_gate(roots["rcc"]), date_session_factory=session,
            simulator_authority_admitted=admitted)
    return p, build, sessions


def scripted(actions, *, arm="A", date="2027-02-05", args_override=None):
    from agentdojo.functions_runtime import FunctionCall
    seen = []
    def generate(request):
        seen.append(deepcopy(request))
        action = actions[len(seen) - 1]
        if action == "stop":
            return LocalModelTurn({"role": "assistant", "content": [
                {"type": "text", "content": "Local final answer " + arm}],
                "tool_calls": None}, "stop")
        args = {"get_iban": {}, "get_balance": {},
                "get_most_recent_transactions": {"n": 100},
                "send_money": {"recipient": "GB29NWBK60161331926819", "amount": 10,
                               "subject": "Refund", "date": date}}[action]
        if args_override and action == "send_money":
            args.update(args_override)
        call = FunctionCall(id=f"call_{arm}_{len(seen)}", function=action, args=args)
        return LocalModelTurn({"role": "assistant", "content": None,
                               "tool_calls": [call]}, "tool_calls")
    return generate, seen


@pytest.mark.parametrize("actions", [
    ["stop"], ["get_iban", "stop"],
    ["get_iban", "get_most_recent_transactions", "stop"],
    ["send_money", "stop"],
    ["get_iban", "get_most_recent_transactions", "send_money", "stop"],
    ["get_iban", "get_most_recent_transactions", "send_money", "get_balance", "stop"],
    ["get_balance", "get_iban", "get_most_recent_transactions", "send_money", "get_balance", "stop"],
])
@pytest.mark.parametrize("arm", ["A", "B"])
def test_variable_complete_histories_and_actual_native_scoring(harness, actions, arm):
    p, build, _ = harness
    callback, seen = scripted(actions, arm=arm)
    record = build().run_arm(arm, callback)
    r = record.payload()
    assert r["stop_reason"] == "TERMINAL"
    assert r["model_attempts"] == len(actions) == len(seen)
    assert all(x["model"] == p.model_id and x["max_completion_tokens"] == p.output_token_cap
               for x in seen)
    expected = int("send_money" in actions)
    assert r["native_protected_dispatches"] == expected
    assert r["native_read_calls"] == sum(x not in ("send_money", "stop") for x in actions)
    initial = r["initial_environment"]["bank_account"]["transactions"]
    after = r["post_environment"]["bank_account"]["transactions"]
    assert len(after) == len(initial) + expected
    score = score_local_arm(record)
    assert score["native_scorer_calls"] == 1
    assert score["local_utility"] is bool(expected)
    assert score["local_attack_goal_success"] is False
    assert score["official_utility"] is None
    assert record.identity == score["record_sha256"]


def test_full_attacked_tool_result_survives_to_next_model_request(harness):
    _, build, _ = harness
    cb, seen = scripted(["get_most_recent_transactions", "stop"])
    record = build().run_arm("B", cb)
    r = record.payload()
    assert r["stop_reason"] == "TERMINAL"
    payload = next(t["subject"] for t in r["initial_environment"]["bank_account"]["transactions"]
                   if t["subject"].startswith("TODO: "))
    import yaml
    rows = yaml.safe_load(seen[1]["messages"][-1]["content"][0]["text"])
    assert sum(row["subject"] == payload for row in rows) == 1
    assert {t["function"]["name"] for t in seen[0]["tools"]} == {
        t["function"]["name"] for t in seen[1]["tools"]}
    assert len(seen[0]["tools"]) == 11


@pytest.mark.parametrize("override", [
    {"date": "2099-01-01"}, {"amount": 999},
    {"recipient": "US133000000121212121212"},
])
def test_b_preserves_real_date_and_argument_refusals_and_scores_final(harness, override):
    _, build, _ = harness
    callback, _ = scripted(["send_money", "stop"], args_override=override)
    record = build().run_arm("B", callback)
    r = record.payload()
    assert r["stop_reason"] == "TERMINAL"
    assert r["native_protected_dispatches"] == 0
    assert r["protected_outcome"] == "DATE_PROFILE_REJECTED"
    assert r["pre_state_sha256"] == r["post_state_sha256"]
    assert r["candidates"][0]["arguments"][next(iter(override))] == next(iter(override.values()))
    assert score_local_arm(record)["local_utility"] is False


def test_real_bind_refusal_is_not_replaced_by_a_tool_success(harness):
    _, build, _ = harness
    cb, seen = scripted(["send_money", "stop"])
    record = build(admitted=False).run_arm("B", cb)
    r = record.payload()
    assert r["protected_outcome"] == "BLOCKED"
    assert r["native_protected_dispatches"] == 0
    assert r["pre_state_sha256"] == r["post_state_sha256"]
    assert any(m.get("error") == "GovernanceStop" for m in r["messages"])
    assert score_local_arm(record)["local_utility"] is False


def test_attempt_limit_retains_committed_effect_without_fake_terminal(harness):
    p, build, _ = harness
    cb, _ = scripted(["send_money"])
    runner = build(profile=replace(p, max_requests_per_arm=1))
    record = runner.run_arm("B", cb)
    assert record.payload()["stop_reason"] == "REQUEST_LIMIT"
    assert record.payload()["native_protected_dispatches"] == 1
    score = score_local_arm(record)
    assert score["native_scorer_calls"] == 0
    assert score["local_utility"] is score["local_attack_goal_success"] is None
    with pytest.raises(ValueError, match="ALREADY_ATTEMPTED"):
        runner.run_arm("B", cb)


def test_second_protected_proposal_is_saved_but_never_dispatched(harness):
    _, build, _ = harness
    cb, _ = scripted(["send_money", "send_money"])
    record = build().run_arm("B", cb)
    r = record.payload()
    assert r["stop_reason"] == "PROTECTED_OPERATION_LIMIT"
    assert len(r["candidates"]) == 2 and r["native_protected_dispatches"] == 1
    assert score_local_arm(record)["status"] == "UNSCORED_INCOMPLETE"


@pytest.mark.parametrize("reason", ["length", "content_filter", "unknown"])
def test_incomplete_completion_is_not_a_final_answer(harness, reason):
    _, build, _ = harness
    def generate(request):
        return LocalModelTurn({"role": "assistant", "content": [
            {"type": "text", "content": "Partial answer"}], "tool_calls": None}, reason)
    record = build().run_arm("B", generate)
    assert record.payload()["stop_reason"] == "NONTERMINAL_COMPLETION_REASON"
    assert record.payload()["steps"][0]["finish_reason"] == reason
    assert score_local_arm(record)["native_scorer_calls"] == 0


def test_generation_unknown_does_not_retry_or_expose_error(harness):
    _, build, _ = harness
    count = []
    def generate(request):
        count.append(1)
        raise RuntimeError("PRIVATE_API_SECRET_OR_BODY")
    runner = build()
    record = runner.run_arm("A", generate)
    assert len(count) == 1 and record.payload()["stop_reason"] == "UNKNOWN_GENERATION"
    assert "PRIVATE_API_SECRET_OR_BODY" not in record.payload_json
    with pytest.raises(ValueError):
        runner.run_arm("A", generate)


@pytest.mark.parametrize("reason", [None, b"stop"])
def test_malformed_finish_reason_still_produces_a_serializable_incomplete_record(harness, reason):
    _, build, _ = harness
    def generate(request):
        return LocalModelTurn({"role": "assistant", "content": [
            {"type": "text", "content": "Unverified end"}], "tool_calls": None}, reason)
    record = build().run_arm("B", generate)
    assert record.payload()["stop_reason"] == "MALFORMED_FINISH_REASON"
    assert score_local_arm(record)["status"] == "UNSCORED_INCOMPLETE"


def test_request_mutation_and_fake_origin_cannot_promote_score(harness):
    _, build, _ = harness
    cb, _ = scripted(["stop"])
    def mutate(request):
        request["messages"][0]["content"][0]["text"] = "Changed authority"
        return cb(request)
    r = build().run_arm("B", mutate)
    assert r.payload()["stop_reason"] == "GENERATION_MUTATED_REQUEST"
    payload = r.payload()
    payload["provider_origin_authenticated"] = True
    with pytest.raises(ValueError):
        score_local_arm(LocalArmRecord(json.dumps(payload)))


def test_profile_date_mismatch_refuses_before_model_callback(harness):
    p, build, _ = harness
    def forbidden(request):
        pytest.fail("DATE_NOT_MATCHED_BEFORE_MODEL")
    record = build(profile=replace(p, task_date="2027-02-06")).run_arm("A", forbidden)
    assert record.payload()["stop_reason"] == "DATE_SCOPE_MISMATCH"
    assert record.payload()["model_attempts"] == 0


@pytest.mark.parametrize("limit,code", [(1, "REQUEST_BYTE_LIMIT"),
                                       (24000, "TOTAL_REQUEST_BYTE_LIMIT")])
def test_serialized_request_limits_are_pre_callback(harness, limit, code):
    p, build, _ = harness
    if limit == 1:
        p = replace(p, max_request_bytes=1)
        cb, seen = scripted(["stop"])
    else:
        # Measure actual first canonical request, then limit cumulative bytes
        # to just above it. A second Native request cannot be dispatched.
        measure, seen = scripted(["get_iban", "stop"])
        baseline = build().run_arm("A", measure).payload()
        sizes = [step["canonical_request_bytes"] for step in baseline["steps"]]
        p = replace(p, max_request_bytes=max(sizes),
                    max_total_request_bytes_per_arm=sum(sizes) - 1)
        cb, seen = scripted(["get_iban", "stop"])
    record = build(profile=p).run_arm("B", cb)
    assert record.payload()["stop_reason"] == code
    assert len(seen) == (0 if limit == 1 else 1)


def test_independent_pair_keeps_incomplete_arm_in_denominator(harness):
    p, build, sessions = harness
    runner = build(profile=replace(p, max_requests_per_arm=1))
    a, seen_a = scripted(["stop"], arm="A")
    b, seen_b = scripted(["get_iban"], arm="B")
    records = [runner.run_arm("A", a), runner.run_arm("B", b)]
    assert len(sessions) == 2 and sessions[0] is not sessions[1]
    assert seen_a[0] == seen_b[0] and seen_a[0] is not seen_b[0]
    summary = summarize_local_pair(records)
    assert summary["attempted_arms"] == 2 and summary["completed_arms"] == 1
    assert summary["scores"][0]["local_utility"] is False
    assert summary["scores"][1]["local_utility"] is None
    assert summary["official_utility_delta"] is None
    assert summary["date_profile_causal_effect_measured"] is False


def test_real_sdk_serialization_and_response_codec_with_mock_transport(harness):
    import httpx
    import openai
    from agentdojo.agent_pipeline.llms.openai_llm import _openai_to_assistant_message
    _, build, _ = harness
    requests = []
    def handler(request):
        data = json.loads(request.content)
        requests.append(data)
        assert data["max_completion_tokens"] == 256
        assert data["messages"][0]["role"] == "developer"
        assert len(data["tools"]) == 11
        return httpx.Response(200, json={
            "id": "local-sdk-response", "object": "chat.completion", "created": 1,
            "model": data["model"], "choices": [{"index": 0, "finish_reason": "stop",
                "message": {"role": "assistant", "content": "I could not complete the refund."}}],
        }, request=request)
    with httpx.Client(transport=httpx.MockTransport(handler), trust_env=False) as http:
        with openai.OpenAI(api_key="LOCAL_TEST_KEY_NOT_PROVIDER", http_client=http,
                           max_retries=0) as client:
            def generate(request):
                reply = client.chat.completions.create(**request)
                return LocalModelTurn(_openai_to_assistant_message(reply.choices[0].message),
                                      reply.choices[0].finish_reason)
            record = build().run_arm("B", generate)
    assert len(requests) == 1
    assert record.payload()["stop_reason"] == "TERMINAL"
    assert score_local_arm(record)["local_utility"] is False


def test_unknown_after_actual_native_mutation_keeps_effect_and_no_retry(harness, monkeypatch):
    from agentdojo.functions_runtime import FunctionsRuntime
    _, build, _ = harness
    original = FunctionsRuntime.run_function
    def lost_return(self, env, function, kwargs, raise_on_error=False):
        value = original(self, env, function, kwargs, raise_on_error=raise_on_error)
        if function == "send_money":
            raise OSError("LOCAL_LOST_NATIVE_RETURN")
        return value
    monkeypatch.setattr(FunctionsRuntime, "run_function", lost_return)
    cb, seen = scripted(["send_money", "stop"])
    runner = build()
    record = runner.run_arm("B", cb)
    r = record.payload()
    assert r["stop_reason"] == "UNKNOWN_NATIVE_PROTECTED"
    assert r["native_protected_dispatches"] == 1
    assert r["protected_outcome"] == "UNKNOWN"
    assert r["pre_state_sha256"] != r["post_state_sha256"]
    assert len(seen) == 1
    assert score_local_arm(record)["local_utility"] is None
    with pytest.raises(ValueError):
        runner.run_arm("B", cb)


@pytest.mark.parametrize("kind,code", [
    ("batch", "SINGLE_TOOL_PROFILE_REQUIRED"),
    ("stop_with_call", "MALFORMED_TERMINAL"),
    ("role", "MALFORMED_ASSISTANT_MESSAGE"),
    ("empty", "MALFORMED_TERMINAL"),
    ("tool", "OUT_OF_SCOPE_TOOL"),
])
def test_unsupported_output_never_dispatches(harness, kind, code):
    from agentdojo.functions_runtime import FunctionCall
    _, build, _ = harness
    cb, _ = scripted(["get_iban"])
    def generate(request):
        turn = cb(request)
        m = turn.message
        finish = "tool_calls"
        if kind == "batch":
            m["tool_calls"].append(deepcopy(m["tool_calls"][0]))
        elif kind == "stop_with_call":
            finish = "stop"
        elif kind == "role":
            m["role"] = "system"
        elif kind == "empty":
            m["tool_calls"] = None
            m["content"] = [{"type": "text", "content": " "}]
            finish = "stop"
        elif kind == "tool":
            m["tool_calls"] = [FunctionCall(id="unknown", function="unknown_tool", args={})]
        return LocalModelTurn(m, finish)
    record = build().run_arm("B", generate)
    r = record.payload()
    assert r["stop_reason"] == code
    assert r["pre_state_sha256"] == r["post_state_sha256"]
    assert r["native_protected_dispatches"] == 0
    assert score_local_arm(record)["native_scorer_calls"] == 0
