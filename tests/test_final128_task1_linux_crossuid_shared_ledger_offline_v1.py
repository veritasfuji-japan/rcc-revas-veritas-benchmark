"""#450 cross-UID local mock Executor/Ledger; no real Provider or bank."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
from scripts import final128_task1_linux_crossuid_shared_ledger_offline_v1 as m

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/optimization/FINAL128_TASK1_LINUX_CROSSUID_SHARED_LEDGER_OFFLINE_V1.md"


def test_kernel_enforced_cross_uid_local_services_no_effect():
    # This integration test is REQUIRED on the repository's Ubuntu CI.
    # A temporary ROOT supervisor prepares numeric UID-owned directories then
    # drops privileges to four DISTINCT real Linux kernel UIDs. No useradd.
    assert sys.platform.startswith("linux"), "Dedicated proof requires Linux"
    command = [sys.executable, "-m",
               "scripts.final128_task1_linux_crossuid_shared_ledger_offline_v1",
               "--prove"]
    if os.geteuid() != 0:
        sudo = shutil.which("sudo")
        assert sudo is not None, "Ubuntu CI requires passwordless sudo"
        command = [sudo, "-n", "--", "/usr/bin/env", "-i",
                   "PATH=/usr/bin:/bin", f"PYTHONPATH={ROOT}",
                   "PYTHONDONTWRITEBYTECODE=1", *command]
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True,
                            text=True, timeout=100, check=False)
    assert result.returncode == 0, (
        f"Cross-UID offline proof failed: {result.stdout[-2000:]} {result.stderr[-2000:]}")
    evidence = json.loads(result.stdout)
    assert evidence["schema"] == m.SCHEMA
    assert evidence["status"] == "CROSSUID_LOCAL_MOCK_ONLY_NO_GO"
    assert evidence["paid_dispatch_authorized"] is False
    assert evidence["external_provider_calls"] == 0
    assert evidence["issue_427_closed"] is False
    assert len(evidence["cases"]) == 2
    for case in evidence["cases"]:
        assert case["distinct_kernel_uids"] == 4
        assert case["os_dac_runner_denial"] is True
        assert case["os_dac_executor_denial"] is True
        assert case["direct_ledger_peer_refused"] is True
        assert case["after_restart_A"] == "DENIED"
        assert case["real_provider_calls"] == 0
        assert case["remote_cross_host_proven"] is False
        assert case["production_iam_proven"] is False
    assert evidence["cases"][0]["runner_race"] == ["ACK", "DENIED"]
    assert evidence["cases"][0]["phase"] == "A_ACK"
    assert evidence["cases"][1]["runner_race"] == ["DENIED", "UNKNOWN"]
    assert evidence["cases"][1]["phase"] == "UNKNOWN_A"


def test_root_supervisor_is_explicitly_not_part_of_proof():
    source = Path(m.__file__).read_text(encoding="utf-8")
    assert "Root orchestrator is TRUSTED" in source
    assert len(set((m.LEDGER_UID, m.EXECUTOR_UID,
                    m.RUNNER_A_UID, m.RUNNER_B_UID))) == 4
    assert all(n > 0 for n in (m.LEDGER_UID, m.EXECUTOR_UID,
                               m.RUNNER_A_UID, m.RUNNER_B_UID))
    assert m.SNAPSHOT.is_file()


def test_no_real_provider_or_workflow_operations():
    source = Path(m.__file__).read_text(encoding="utf-8")
    for bad in ("import http.client", "api.openai.com", "from openai",
                "import requests", "workflow_dispatch", "POST /git/refs",
                "TASK1_OPENAI_API_KEY", "OPENAI_API_KEY", "import urllib"):
        assert bad not in source
    assert not hasattr(m, "send_paid_provider")
    docs = DOC.read_text(encoding="utf-8")
    for term in ("NO-GO", "Issue #427", "#449", "#448", "#423",
                 "root", "distinct Linux UIDs", "not real GitHub",
                 "no Provider", "same host"):
        assert term in docs
