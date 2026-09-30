from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.agentdojo_clean_ab_final_runner_v0_1 as runner

ROOT = Path(__file__).resolve().parents[1]


def test_contract_and_enrollment_remain_exact_for_current_gate():
    c = runner.contracts()
    gate = c["implementation"]["execution_gate"]
    assert gate in {"CLOSED", "OPEN"}
    cases = runner.assert_frozen_configuration(
        c,
        expected_execution_gate=gate,
    )
    assert len(cases) == 128
    assert c["implementation"]["clean_ab_executed"] is False
    assert runner.OPENAI_MAX_RETRIES == 0
    assert runner.MAX_COMPLETION_TOKENS == 1024


def test_gate_transition_validation_accepts_exact_open_state_only():
    c = runner.contracts()
    c["implementation"] = dict(c["implementation"])
    c["implementation"]["execution_gate"] = "OPEN"

    cases = runner.assert_frozen_configuration(
        c,
        expected_execution_gate="OPEN",
    )
    assert len(cases) == 128

    with pytest.raises(runner.RunnerError, match="EXECUTION_GATE_STATE_MISMATCH"):
        runner.assert_frozen_configuration(
            c,
            expected_execution_gate="CLOSED",
        )


def test_invalid_expected_gate_is_rejected():
    c = runner.contracts()
    with pytest.raises(runner.RunnerError, match="INVALID_EXPECTED_EXECUTION_GATE"):
        runner.assert_frozen_configuration(
            c,
            expected_execution_gate="ANY",
        )


def test_pinned_direct_attack_requires_suite_and_pipeline():
    from agentdojo.attacks.baseline_attacks import DirectAttack
    from agentdojo.task_suite.load_suites import get_suite

    suite = get_suite("v1.2.2", "banking")
    pipeline = SimpleNamespace(name="gpt-4.1-mini-2025-04-14-agentdojo-frozen-v0.1")
    attack = DirectAttack(suite, pipeline)

    assert attack.task_suite is suite
    assert attack.target_pipeline is pipeline


def test_budgeted_client_is_single_attempt_and_accounts_usage():
    class Base:
        def __init__(self):
            self.calls = 0

        def create(self, **kwargs):
            self.calls += 1
            details = SimpleNamespace(cached_tokens=10)
            usage = SimpleNamespace(
                prompt_tokens=100,
                completion_tokens=20,
                prompt_tokens_details=details,
            )
            return SimpleNamespace(usage=usage)

    base = Base()
    ledger = runner.BudgetLedger()
    wrapped = runner.BudgetedCompletions(base, ledger)
    wrapped.create(
        model=runner.MODEL_ID,
        temperature=0.0,
        messages=[],
        tools=[],
    )
    assert base.calls == 1
    assert ledger.calls == 1
    assert ledger.prompt_tokens == 100
    assert ledger.cached_tokens == 10
    assert ledger.completion_tokens == 20
    assert 0 < ledger.spent_usd < runner.BUDGET_USD


def test_budgeted_client_does_not_retry_provider_failure():
    class Base:
        def __init__(self):
            self.calls = 0

        def create(self, **kwargs):
            self.calls += 1
            raise RuntimeError("provider failure")

    base = Base()
    wrapped = runner.BudgetedCompletions(base, runner.BudgetLedger())
    with pytest.raises(RuntimeError, match="provider failure"):
        wrapped.create(
            model=runner.MODEL_ID,
            temperature=0.0,
            messages=[],
            tools=[],
        )
    assert base.calls == 1


def test_result_execution_requires_open_gate_and_explicit_confirmation():
    c = json.loads(
        (ROOT / "contracts/AGENTDOJO_FINAL_RUNNER_IMPLEMENTATION_v0.1.json").read_text()
    )
    assert c["execution_gate"] in {"CLOSED", "OPEN"}
    source = (ROOT / "scripts/agentdojo_clean_ab_final_runner_v0_1.py").read_text()
    assert 'if c["execution_gate"] != "OPEN":' in source
    assert 'raise RunnerError("EXECUTION_GATE_CLOSED")' in source
    assert "args.confirmation != GATE_CONFIRMATION" in source
    assert 'raise RunnerError("EXPLICIT_HUMAN_EXECUTION_CONFIRMATION_REQUIRED")' in source
    assert "max_retries=OPENAI_MAX_RETRIES" in source


def test_authority_fixture_verifies_when_crypto_available():
    pytest.importorskip("cryptography")
    assert runner.verify_authority_fixture() is True
