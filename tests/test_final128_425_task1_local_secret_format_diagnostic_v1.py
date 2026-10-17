"""#425 Task1 manual no-paid format diagnosis: no Provider or GitHub tag mutation."""
from __future__ import annotations

import base64
from pathlib import Path
import subprocess
import sys

import pytest

from scripts import final128_425_task1_local_secret_format_diagnostic_v1 as m


def clean_environ():
    return {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": "veritasfuji-japan/rcc-revas-veritas-benchmark",
        "GITHUB_ACTOR": "veritasfuji-japan",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_RUN_ID": "39010798949",
        "GITHUB_SHA": "7ca4fcce0bf034f9e21b5e4fbb3a581063192f60",
        "TASK1_OPENAI_API_KEY": "local_ONLY_FAKE_not_a_real_api_key",
        "TASK1_CAPTURE_AES256_KEY": base64.b64encode(bytes(range(32))).decode(),
    }


def test_425_local_diagnostic_valid_syntax_is_not_live_provider_attestation():
    status = m.diagnose(clean_environ())
    assert status == "LOCAL_SECRET_FORMATS_VALID_NOT_PROVIDER_AUTHENTICATED"
    assert status not in m.DENIED


@pytest.mark.parametrize("name,value,expected", [
    ("GITHUB_ACTIONS", "false", "RUNTIME_CONTEXT"),
    ("GITHUB_EVENT_NAME", "pull_request", "RUNTIME_CONTEXT"),
    ("GITHUB_REPOSITORY", "private-other/repo", "RUNTIME_CONTEXT"),
    ("GITHUB_ACTOR", "other-person", "RUNTIME_CONTEXT"),
    ("GITHUB_REF", "refs/heads/not-main", "RUNTIME_CONTEXT"),
    ("GITHUB_RUN_ATTEMPT", "2", "RUNTIME_CONTEXT"),
    ("GITHUB_RUN_ID", "bogus", "RUNTIME_CONTEXT"),
    ("GITHUB_SHA", "xyz", "RUNTIME_CONTEXT"),
    ("TASK1_OPENAI_API_KEY", "", "API_KEY_FORMAT"),
    ("TASK1_OPENAI_API_KEY", "short", "API_KEY_FORMAT"),
    ("TASK1_OPENAI_API_KEY", " FAKE_SECRET_VALID_LENGTH_ABC", "API_KEY_FORMAT"),
    ("TASK1_OPENAI_API_KEY", "FAKE_SECRET_VALID_LENGTH_ABC\n", "API_KEY_FORMAT"),
    ("TASK1_CAPTURE_AES256_KEY", "", "AES256_KEY_FORMAT"),
    ("TASK1_CAPTURE_AES256_KEY", "not--base64$$$$", "AES256_KEY_FORMAT"),
    ("TASK1_CAPTURE_AES256_KEY", base64.b64encode(bytes(31)).decode(), "AES256_KEY_FORMAT"),
    ("TASK1_CAPTURE_AES256_KEY", base64.b64encode(bytes(33)).decode(), "AES256_KEY_FORMAT"),
    ("TASK1_CAPTURE_AES256_KEY", base64.b64encode(bytes(32)).decode()+"\n", "AES256_KEY_FORMAT"),
])
def test_425_no_paid_diagnostic_returns_only_coarse_reason(name, value, expected):
    env = clean_environ()
    env[name] = value
    assert m.diagnose(env) == expected
    # Secret sentinel values only: numeric run attempt may overlap fixed "425".
    if name in ("TASK1_OPENAI_API_KEY", "TASK1_CAPTURE_AES256_KEY") and len(value) >= 8:
        assert value not in m.OUT_PREFIX + m.diagnose(env)

@pytest.mark.parametrize("name,expected", [
    ("TASK1_OPENAI_API_KEY", "API_KEY_FORMAT"),
    ("TASK1_CAPTURE_AES256_KEY", "AES256_KEY_FORMAT"),
    ("GITHUB_ACTOR", "RUNTIME_CONTEXT"),
    ("GITHUB_RUN_ID", "RUNTIME_CONTEXT"),
])
def test_425_missing_context_or_secret_is_fixed_only(name, expected):
    env = clean_environ()
    del env[name]
    assert m.diagnose(env) == expected


@pytest.mark.parametrize("name,secret,category", [
    ("TASK1_OPENAI_API_KEY", "FAKE PRIVATE KEY MUST NEVER PRINT \n", "API_KEY_FORMAT"),
    ("TASK1_CAPTURE_AES256_KEY", "SECRET AES VALUE MUST NEVER PRINT ***", "AES256_KEY_FORMAT"),
])
def test_425_standalone_manual_script_exits_without_secret_echo(name, secret, category):
    env = clean_environ()
    env[name] = secret
    result = subprocess.run(
        [sys.executable, "scripts/final128_425_task1_local_secret_format_diagnostic_v1.py"],
        cwd=Path(__file__).resolve().parents[1],
        env=env, text=True, capture_output=True, timeout=10,
    )
    assert result.returncode == 1
    assert result.stdout.strip() == m.OUT_PREFIX + category
    assert result.stderr == ""
    assert secret not in result.stdout + result.stderr
    assert "Traceback" not in result.stdout + result.stderr


def test_425_main_valid_path_no_api_no_tag(capsys, monkeypatch):
    monkeypatch.setattr(m, "diagnose", lambda _e: m.OK)
    assert m.main() == 0
    out = capsys.readouterr()
    assert out.out == m.OUT_PREFIX + m.OK + "\n"
    assert out.err == ""


def test_425_unknown_errors_hide_str_exception(capsys, monkeypatch):
    def abnormal(_e):
        raise RuntimeError("NEVER_PRINT_SECRET_INSIDE_EXCEPTION")
    monkeypatch.setattr(m, "diagnose", abnormal)
    assert m.main() == 1
    out = capsys.readouterr()
    assert out.out == m.OUT_PREFIX + "UNCLASSIFIED\n"
    assert out.err == ""
    assert "SECRET" not in out.out


def test_425_diagnostic_workflow_is_readonly_manual_environment_bound():
    wf = Path(
        ".github/workflows/final128-425-task1-safe-local-secrets-diagnostic-no-provider-v1.yml"
    ).read_text()
    source = Path(m.__file__).read_text()
    assert "\n  workflow_dispatch:\n" in wf
    assert "\n  push:" not in wf and "\n  pull_request:" not in wf
    assert "\npermissions:\n  contents: read\n" in wf
    assert "environment: task1-real-model-pilot" in wf
    assert "github.actor == 'veritasfuji-japan'" in wf
    assert "github.ref == 'refs/heads/main'" in wf
    assert "TASK1_OPENAI_API_KEY: ${{ secrets.TASK1_OPENAI_API_KEY }}" in wf
    assert "TASK1_CAPTURE_AES256_KEY: ${{ secrets.TASK1_CAPTURE_AES256_KEY }}" in wf
    assert "persist-credentials: false" in wf
    assert "python3 scripts/final128_425_task1_local_secret_format_diagnostic_v1.py" in wf
    for banned in ("GH_TOKEN", "contents: write", "git/refs",
                   "upload-artifact", "curl ", "gh api", "requests.", "http.client",
                   "OPENAI_BASE_URL", "--mode send", "pip install", "secrets-preflight"):
        assert banned not in wf
    for banned in ("urllib", "requests", "http.client", "openai",
                   "subprocess", "os.system", "os.popen", "exec(", "eval("):
        assert banned not in source
