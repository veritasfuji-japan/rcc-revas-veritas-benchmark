"""#389 negative checks for zero-Provider real GitHub Environment gate probe."""
from __future__ import annotations
from pathlib import Path
import json
import pytest
from scripts import final128_389_task1_environment_probe_source_audit_v1 as m

@pytest.fixture
def original():
    return m.WORKFLOW.read_text(encoding="utf8")

def test_exact_manual_source_contract(original):
    result=m.validate_source(original)
    assert result["manual_dispatch_only"] is True
    assert result["preflight_before_protected_job"] is True
    assert result["protected_job_environment_name"]=="task1-real-model-pilot"
    assert result["main_only_actor_only_first_attempt_preflight"] is True
    assert result["approval_ui_not_read_or_attested"] is True
    assert result["real_provider_calls"]==0
    assert result["task1_live_execution_authorized"] is False

@pytest.mark.parametrize("before,after", [
    ("workflow_dispatch:", "push:"),
    ("workflow_dispatch:", "pull_request_target:"),
    ("  contents: read", "  contents: write"),
    ("cancel-in-progress: false", "cancel-in-progress: true"),
    ("ACKNOWLEDGE_ZERO_PROVIDER_DRY_RUN", "I_APPROVE_PAID_CALLS"),
    ("      name: task1-real-model-pilot", "      name: other-environment"),
    ("      name: task1-real-model-pilot", "      name: task4-real-provider-first-two-calls"),
    ("    needs: preflight-no-environment", "    needs: other-job"),
    ("    if: needs.preflight-no-environment.result == 'success'", "    if: always()"),
    ('test "$GITHUB_REF" = "refs/heads/main"', 'test "$GITHUB_REF" != "refs/heads/main"'),
    ('test "$GITHUB_ACTOR" = "veritasfuji-japan"', 'test "$GITHUB_ACTOR" != "veritasfuji-japan"'),
    ('test "$GITHUB_RUN_ATTEMPT" = "1"', 'test "$GITHUB_RUN_ATTEMPT" = "2"'),
    ('test "$GITHUB_REPOSITORY" = "veritasfuji-japan/rcc-revas-veritas-benchmark"',
     'test "$GITHUB_REPOSITORY" = "other/repo"'),
    ("    timeout-minutes: 5", "    timeout-minutes: 600"),
    ("    runs-on: ubuntu-24.04", "    runs-on: self-hosted"),
    ("        shell: bash", "        shell: pwsh"),
    ("    environment:\n      name: task1-real-model-pilot", "    environment:\n      name: default"),
    ("  workflow_dispatch:", "  schedule:\n    - cron: '* * * * *'\n  workflow_dispatch:"),
    ("    steps:\n      - name: Reject wrong actor, branch, rerun, event or acknowledgment",
     "    environment: task1-real-model-pilot\n    steps:\n      - name: Reject wrong actor, branch, rerun, event or acknowledgment"),
    ("    steps:\n      - name: Mark job start after GitHub Environment rules permit it",
     "    steps:\n      - uses: actions/checkout@v4\n      - name: Mark job start after GitHub Environment rules permit it"),
    ('test "$GITHUB_RUN_ATTEMPT" = "1"', 'echo "Pretend single-use passed"'),
    ("          set -euo pipefail", "          set +e"),
])
def test_tamper_fails_closed(original,before,after):
    assert before in original
    altered=original.replace(before,after,1)
    with pytest.raises(m.Denied):
        m.validate_source(altered)

@pytest.mark.parametrize("injected", [
    "\n# comment with secrets.OPENAI_API_KEY",
    "\n# gh api -X POST /repos/.../git/refs",
    "\n# curl https://api.openai.com/v1/responses",
    "\n# checkout@v4",
    "\n# repository_dispatch:",
])
def test_no_hidden_provider_or_mutating_paths_in_comments(original,injected):
    with pytest.raises(m.Denied):
        m.validate_source(original+injected)

def test_input_acknowledgment_is_not_paid_authorization(original):
    d=m.validate_source(original)
    assert d["wait_timer_runtime_observed"] is False
    assert d["required_reviewer_runtime_observed"] is False
    assert d["admin_bypass_runtime_verified"] is False
    assert d["real_single_use_issuer_verified"] is False
    assert d["hard_provider_budget_cap_verified"] is False
    assert d["native_scorer_calls"]==0
    assert d["new_utility_scores"] is None
    assert d["production_bypass_resistance_proven"] is False

def test_branch_policy_is_runtime_external_not_established_by_source(original):
    obj=m.validate_source(original)
    assert obj["preflight_no_environment_no_secret_binding"] is True
    assert obj["manual_dry_run_executed_by_this_audit"] is False
    assert obj["status"]=="SOURCE_CONTRACT_VALID_BUT_NO_LIVE_GATE_OBSERVATION"

def test_script_exposes_no_live_dispatch_entrypoint():
    src=Path(m.__file__).read_text(encoding="utf8")
    for forbidden in ("from openai import", "import openai", "requests.post(",
                      "urlopen(", "gh api -X POST", "secrets.OPENAI_API_KEY",
                      "dispatch_workflow(", "subprocess.run("):
        assert forbidden not in src

def test_new_pr_ci_has_no_environment_or_auto_manual_dispatch():
    src=Path(".github/workflows/final128-389-task1-environment-offline-audit-v1.yml").read_text()
    assert "on:\n  pull_request:" in src
    assert "workflow_dispatch:" not in src
    assert "task1-real-model-pilot" not in src
    assert "secrets.OPENAI_API_KEY" not in src
    assert "permissions:\n  contents: read" in src
    assert "persist-credentials: false" in src
