#!/usr/bin/env python3
"""Pin and exercise the standalone, provider-free Task4 date profile."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts/TASK4_TRUSTED_EXECUTION_DATE_PROFILE_V1.json"
EXPECTED_CONTRACT_BLOB = "faef166fc6f4c55c3e345e9b9b50e3ff240a164f"


def blob(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    require(not os.environ.get("OPENAI_API_KEY"), "OPENAI_API_KEY_MUST_BE_EMPTY")
    require(not os.environ.get("VERITAS_DATABASE_URL"), "VERITAS_DATABASE_URL_MUST_BE_EMPTY")
    require(blob(CONTRACT) == EXPECTED_CONTRACT_BLOB, "PROFILE_CONTRACT_BLOB_MISMATCH")
    c = json.loads(CONTRACT.read_text())
    require(c["rule_of_one"] == "TASK4_TRUSTED_EXECUTION_DATE_PROFILE_V1", "PROFILE_RULE_OF_ONE_MISMATCH")
    for path, expected in c["source_blobs"].items():
        require(blob(ROOT / path) == expected, "PROFILE_SOURCE_BLOB_MISMATCH:" + path)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    junit = (args.output_dir / "task4-trusted-execution-date-profile-v1.junit.xml").resolve()
    report_path = args.output_dir / "task4-trusted-execution-date-profile-v1.json"
    # Prevent a prior report from satisfying this invocation.
    for previous in (junit, report_path):
        if previous.exists():
            previous.unlink()
    env = dict(os.environ)
    env["OPENAI_API_KEY"] = ""
    env["VERITAS_DATABASE_URL"] = ""
    env["PYTEST_ADDOPTS"] = ""
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-o", "addopts=", "tests/test_task4_trusted_execution_date_profile_v1.py", "--junitxml", str(junit)], cwd=ROOT, env=env, text=True, capture_output=True)
    print(result.stdout, end="")
    require(result.returncode == 0, "PROFILE_TEST_FAILURE:" + result.stderr)
    cases = ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases) == c["offline_proof"]["test_case_count"], "PROFILE_TEST_COUNT_MISMATCH")
    require(not any(case.find(tag) is not None for case in cases for tag in ("failure", "error", "skipped")), "PROFILE_TEST_INCOMPLETE")
    report = {
        "schema_version": "veritas.task4-trusted-execution-date-profile-report.v1",
        "rule_of_one": c["rule_of_one"],
        "profile_test_cases": len(cases),
        "failures": 0,
        "skipped": 0,
        "determination": "OFFLINE_PROFILE_PASS_WITH_EXPLICIT_HARNESS_CLOCK_AND_KEY_ASSUMPTIONS",
        "runner_integrated": False,
        "full_bind_authority_proven": False,
        "historical_task4_recovery_proven": False,
        "safe_to_relax_existing_runner_now": 0,
        "provider_execution": 0,
        "database_access": 0,
        "external_effect": 0,
        "scorer_or_gold_derived_authority": 0,
        "candidate_repair": 0,
        "v13_authorization_reuse": 0,
        "next_rule_of_one": c["next_rule_of_one"],
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("PASS_TASK4_TRUSTED_EXECUTION_DATE_PROFILE_V1")
    print("PASS_TASK4_DATE_PROFILE_SOURCE_PINS")
    print("PASS_TASK4_AUTHENTICATED_PRE_CAPTURE_DATE_CONTEXT")
    print("PASS_TASK4_PAIRING_AND_IMMUTABLE_CAPTURE")
    print("PASS_TASK4_STALE_ROLLOVER_ROLLBACK_SUBSTITUTION_REJECTION")
    print("profile_test_cases=" + str(len(cases)))
    print("safe_to_relax_existing_runner_now=0")
    print("runner_integrated=false provider_execution=0 database_access=0 external_effect=0")
    print("next_rule_of_one=" + c["next_rule_of_one"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
