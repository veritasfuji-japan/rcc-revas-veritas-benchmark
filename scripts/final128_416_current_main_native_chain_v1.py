#!/usr/bin/env python3
"""#416: reuse untouched #77 native chain against independently pinned OS main.

This copies EXACT fixture bytes to a temporary isolated profile root. Only the
fixture's INPUT manifest is chosen from a new reviewed profile. No historical
manifest, original sandbox.py, Ben sources, native verifier, or security gate is
patched or disabled. A source pin is not model performance or production proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from scripts.final128_415_native_chain_pinned_seven_mode_v1 import (
    ROOT, BEN_PIN, VERITAS_PIN as FROZEN_PIN,
    MODES, git_head, read_json, verify_fixture_files, verify_case,
    digest_bytes,
)
from scripts.final128_414_current_main_native_continuity_preflight_v1 import (
    git_blob_sha,
)

PROFILE_FILE = ROOT / "contracts/CURRENT_VERITAS_OS_MAIN_416_SOURCE_PROFILE_V1.json"
FROZEN_MANIFEST = ROOT / "contracts/CURRENT_VERITAS_CRITICAL_SOURCE_HASHES_V1.json"
EXISTING_FIXTURE = ROOT / "integration/current_veritas_uninterrupted/sandbox.py"
MAIN_PIN = "73b73a75c5605aaf779ea291436722fae52ed1a7"
STATUS = "CURRENT_OS_MAIN_COMMIT_416_PINNED_LOCAL_CHAIN_REPLAY_NOT_PRODUCTION"


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_current_profile(veritas_root: Path) -> dict:
    data = read_json(PROFILE_FILE)
    frozen = read_json(FROZEN_MANIFEST)
    require(data.get("schema_version") ==
            "veritas.current-os-main-416-independent-source-profile.v1",
            "416_PROFILE_WRONG_SCHEMA")
    require(data.get("status") == "RUN_PENDING_NOT_PROVEN",
            "416_UNAUTHORIZED_PROFILE_PROOF_PROMOTION")
    require(data.get("scope") ==
            "REVIEWED_CURRENT_MAIN_COMMIT_SEVEN_MODE_CONTROLLED_LOCAL_REPLAY_ONLY",
            "416_SCOPE_DRIFT")
    require(data.get("veritas_commit") == MAIN_PIN and
            data.get("historical_frozen_veritas_commit") == FROZEN_PIN and
            data.get("ben_canonical_commit") == BEN_PIN,
            "416_CROSS_PROFILE_PIN_MISMATCH")
    require(data.get("hash_algorithm") == "sha256",
            "416_HASH_ALGORITHM_DRIFT")
    require(data.get("critical_sources") == frozen.get("critical_sources"),
            "416_FROZEN_CORE_HASH_REWRITE")
    require(data.get("frozen_profile_changes_permitted") is False and
            data.get("external_validation") is False and
            data.get("production_authority_proven") is False and
            data.get("latest_moving_main_continuously_monitored") is False and
            data.get("new_official_utility_measured") is False and
            data.get("paid_provider_calls") == 0,
            "416_UNBOUNDED_CLAIM")
    require(data.get("fixture_source_git_blob_sha1") ==
            git_blob_sha(EXISTING_FIXTURE.read_bytes()) ==
            "db63ea47d07f75b288fd5a64108e91a6230ce6c4",
            "416_FIXTURE_SOURCE_CHANGED")
    require(git_head(veritas_root) == MAIN_PIN, "416_OS_CHECKOUT_WRONG_COMMIT")
    require(type(data["critical_sources"]) is dict
            and len(data["critical_sources"]) == 7, "416_CRITICAL_SOURCE_SHAPE")
    base = veritas_root.resolve(strict=True)
    for rel, expected in sorted(data["critical_sources"].items()):
        source = (base / rel).resolve(strict=True)
        require(source.is_relative_to(base) and source.is_file(),
                "416_SOURCE_OUTSIDE_CHECKOUT")
        require(sha256_file(source) == expected,
                "416_CURRENT_MAIN_CORE_SOURCE_DRIFT:" + rel)
    return data


def run_current(ben_root: Path, veritas_root: Path, output: Path) -> dict:
    ben_root = ben_root.resolve(strict=True)
    veritas_root = veritas_root.resolve(strict=True)
    require(git_head(ben_root.parents[1]) == BEN_PIN, "416_WRONG_BEN_CHECKOUT")
    require(not output.exists(), "416_OUTPUT_ALREADY_EXISTS")
    repo_head = git_head(ROOT)
    require(os.getenv("GITHUB_HEAD_SHA", repo_head) == repo_head,
            "416_RERUN_SOURCE_SHA_MISMATCH")
    data = verify_current_profile(veritas_root)
    env = os.environ.copy()
    for variable in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN", "GH_TOKEN",
                     "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GOOGLE_API_KEY"):
        env.pop(variable, None)
    env["BEN_CANONICAL_ROOT"] = str(ben_root)
    env["VERITAS_PIN"] = MAIN_PIN
    checked = []
    # Only new private scratch bytes are changed. The legacy fixture source is
    # copied unchanged; its code still verifies commit and critical sha256.
    with tempfile.TemporaryDirectory(prefix="final128-416-private-") as temp:
        scratch = Path(temp)
        staged = scratch / "new-reviewed-profile"
        fixture = staged / "integration/current_veritas_uninterrupted/sandbox.py"
        fixture.parent.mkdir(parents=True)
        shutil.copyfile(EXISTING_FIXTURE, fixture)
        require(fixture.read_bytes() == EXISTING_FIXTURE.read_bytes(),
                "416_STAGED_FIXTURE_NOT_BYTE_IDENTICAL")
        input_manifest = staged / "contracts/CURRENT_VERITAS_CRITICAL_SOURCE_HASHES_V1.json"
        input_manifest.parent.mkdir(parents=True)
        # Only explicitly reviewed, new commit-bound data is placed at the
        # unchanged fixture's expected manifest path in an isolated temp root.
        input_manifest.write_text(json.dumps({
            "veritas_commit": data["veritas_commit"],
            "critical_sources": data["critical_sources"],
            "hash_algorithm": data["hash_algorithm"],
            "status": "RUN_PENDING_NOT_PROVEN",
        }, sort_keys=True) + "\n", encoding="utf-8")
        for mode in MODES:
            directory = scratch / "results" / mode
            call = [
                sys.executable, str(fixture), "--veritas-root", str(veritas_root),
                "--mode", mode, "--output", str(directory),
            ]
            executed = subprocess.run(
                call, cwd=ROOT, env=env, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=240, check=False,
            )
            require(executed.returncode == 0, "416_NATIVE_FIXTURE_FAILED:" + mode)
            report = read_json(directory / "report.json")
            verify_fixture_files(directory, report)
            lines = (directory / "journal.jsonl").read_text(encoding="utf-8").splitlines()
            events = set()
            for line in lines:
                row = json.loads(line)
                require(type(row) is dict and type(row.get("event")) is str,
                        "416_INVALID_EVENT_RECORD")
                events.add(row["event"])
            matrix = directory / "continuity-matrix.json"
            continuity = read_json(matrix) if matrix.exists() else None
            result = verify_case(report, mode, events, continuity, veritas_pin=MAIN_PIN)
            checked.append(result)
    require(len(checked) == 7 and sum(x["native_apply_count"] for x in checked) == 1,
            "416_UNEXPECTED_EFFECT_TOTAL")
    summary = {
        "schema": "veritas.final128-416.current-os-main-native-chain-seven-mode.v1",
        "status": STATUS,
        "rcc_tested_checkout_sha": repo_head,
        "ben_upstream_pin": BEN_PIN,
        "veritas_tested_current_main_commit": MAIN_PIN,
        "historical_veritas_pin_not_used_as_current_proof": FROZEN_PIN,
        "source_profile_sha256": sha256_file(PROFILE_FILE),
        "unchanged_original_fixture_git_blob": data["fixture_source_git_blob_sha1"],
        "critical_source_count": len(data["critical_sources"]),
        "actual_native_fixture_processes": len(checked),
        "cases": checked,
        "positive_mock_commits": 1,
        "negative_cases": 6,
        "negative_additional_effects": 0,
        "controlled_provider_fixture_only": True,
        "real_provider_calls": 0,
        "official_agentdojo_scorer_calls": 0,
        "new_official_utility_recovery": False,
        "production_or_customer_effects": 0,
        "independent_validation": False,
        "moving_main_or_all_dependencies_certified": False,
    }
    output.mkdir(parents=True, exist_ok=False)
    report_path = output / "report.json"
    report_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    (output / "manifest.sha256").write_text(
        digest_bytes(report_path.read_bytes()) + "  report.json\n", encoding="ascii"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ben-root", type=Path, required=True)
    parser.add_argument("--veritas-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    r = run_current(args.ben_root, args.veritas_root, args.output)
    print(json.dumps({
        "status": r["status"],
        "cases": len(r["cases"]),
        "positive_mock_commits": r["positive_mock_commits"],
        "negative_cases": r["negative_cases"],
        "real_provider_calls": r["real_provider_calls"],
        "new_official_utility_recovery": r["new_official_utility_recovery"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
