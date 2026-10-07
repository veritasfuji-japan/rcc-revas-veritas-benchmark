#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import zipfile
from collections import Counter
from pathlib import Path

CONTRACT = Path("contracts/PAIRWISE_PROTECTED_CANDIDATE_REPLAY_HARNESS_V1.json")
CURRENT = Path(os.environ["CURRENT_REPLAY_RESULT"])
DISCOVERY_ZIP = Path(os.environ["DISCOVERY_REPLAY_ARTIFACT_ZIP"])

EXPECTED_CONTRACT_BLOB = "3d19e8cb1b543b78d1584392bbfcd48e849d1787"
EXPECTED_DISCOVERY_ZIP_SHA256 = "f57ac927b0d298bafb006318cf58c41c687d854b9f505a15807c9a0d0ce04de4"
EXPECTED_DISCOVERY_JSON_SHA256 = "42d06e1498a34de8796f6f92054b6225e5f7803eeb64bb8b96e936be47c11dcd"
EXPECTED_DISCOVERY_LOG_SHA256 = "3f4e3287454238fc5a1336ed42025c9a1132afd9c0aeb202dbb21d8bab58c4cd"

def git_blob(path: Path) -> str:
    return subprocess.run(
        ["git", "hash-object", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def check_result(data: dict) -> None:
    summary = data["summary"]
    rows = data["rows"]
    assert summary["status"] == "PASS_PROVIDER_FREE_PAIRWISE_REPLAY"
    assert summary["case_count_total"] == 128
    assert summary["mutation_relevant_replay_count"] == 81
    assert summary["source_selection"] == {"A": 78, "B": 3}
    assert summary["disposition_pairs"] == {
        "COMMITTED->COMMITTED": 12,
        "COMMITTED->VERITAS_BLOCKED": 69,
    }
    assert summary["provider_execution"] == 0
    assert summary["database_access"] == 0
    assert summary["scorer_or_gold_access"] == 0
    assert summary["policy_change"] == 0
    assert summary["resolver_change"] == 0

    assert len(rows) == 81
    selections = Counter()
    pairs = Counter()
    pairing_hashes = set()
    for row in rows:
        assert row["schema_version"] == "veritas.pairwise-protected-candidate-replay-row.v1"
        assert row["proposal_ordinal"] == 0
        assert len(row["immediate_pre_state_sha256"]) == 64
        assert len(row["candidate_sha256"]) == 64
        assert len(row["pairing_identity_sha256"]) == 64
        assert row["arm_A"]["pre_state_sha256"] == row["immediate_pre_state_sha256"]
        assert row["arm_B"]["pre_state_sha256"] == row["immediate_pre_state_sha256"]
        assert row["arm_A"]["candidate_sha256"] == row["candidate_sha256"]
        assert row["arm_B"]["candidate_sha256"] == row["candidate_sha256"]
        assert row["arm_A"]["error"] is None
        assert row["arm_B"]["error"] is None
        selections[row["source_arm"]] += 1
        pairs[row["arm_A"]["disposition"] + "->" + row["arm_B"]["disposition"]] += 1
        if row["pairing_identity_sha256"] in pairing_hashes:
            raise AssertionError("PAIRING_IDENTITY_DUPLICATE")
        pairing_hashes.add(row["pairing_identity_sha256"])

    assert dict(selections) == {"A": 78, "B": 3}
    assert dict(pairs) == {
        "COMMITTED->COMMITTED": 12,
        "COMMITTED->VERITAS_BLOCKED": 69,
    }

assert git_blob(CONTRACT) == EXPECTED_CONTRACT_BLOB
contract = json.loads(CONTRACT.read_text())
assert contract["status"] == "OBSERVED_REPLAY_RESULT_FROZEN"
assert contract["rule_of_one"] == "PAIRWISE_PROTECTED_CANDIDATE_REPLAY_HARNESS_V1"
assert contract["observed_result"] == {
    "discovery_run_id": 37600062157,
    "discovery_job_id": 112721969849,
    "discovery_head_sha": "1fefb8adaf74abc7e2919a4aedb0ccb83a433145",
    "artifact_id": 11472665588,
    "artifact_name": "pairwise-protected-candidate-replay-v1-37600062157",
    "artifact_zip_sha256": EXPECTED_DISCOVERY_ZIP_SHA256,
    "result_json_sha256": EXPECTED_DISCOVERY_JSON_SHA256,
    "result_log_sha256": EXPECTED_DISCOVERY_LOG_SHA256,
    "mutation_relevant_replay_count": 81,
    "source_selection": {"A": 78, "B": 3},
    "disposition_pairs": {
        "COMMITTED->COMMITTED": 12,
        "COMMITTED->VERITAS_BLOCKED": 69,
    },
    "infrastructure_errors": 0,
    "rcc_upstream_disposition_divergences": 0,
    "provider_execution": 0,
    "database_access": 0,
    "scorer_or_gold_access": 0,
}
assert contract["next_rule_of_one_if_passed"] == "CONTROLLED_GOVERNANCE_TREATMENT_DELTA_ANALYSIS_V1"

if os.environ.get("OPENAI_API_KEY"):
    raise SystemExit("OPENAI_API_KEY_MUST_BE_EMPTY")
if os.environ.get("VERITAS_DATABASE_URL"):
    raise SystemExit("VERITAS_DATABASE_URL_MUST_BE_EMPTY")

assert DISCOVERY_ZIP.is_file()
assert sha256_bytes(DISCOVERY_ZIP.read_bytes()) == EXPECTED_DISCOVERY_ZIP_SHA256
with zipfile.ZipFile(DISCOVERY_ZIP) as z:
    names = set(z.namelist())
    assert names == {
        "results/pairwise-protected-candidate-replay-v1.json",
        "results/pairwise-protected-candidate-replay-v1.log",
    }
    discovery_json_bytes = z.read("results/pairwise-protected-candidate-replay-v1.json")
    discovery_log_bytes = z.read("results/pairwise-protected-candidate-replay-v1.log")

assert sha256_bytes(discovery_json_bytes) == EXPECTED_DISCOVERY_JSON_SHA256
assert sha256_bytes(discovery_log_bytes) == EXPECTED_DISCOVERY_LOG_SHA256
discovery = json.loads(discovery_json_bytes)
check_result(discovery)

assert CURRENT.is_file()
current = json.loads(CURRENT.read_text())
check_result(current)

# Reproduction means the controlled aggregate is identical; per-row journals may
# include timestamps in VERITAS receipts and therefore are not byte-for-byte frozen.
assert current["summary"] == discovery["summary"]

print("PASS_PAIRWISE_PROTECTED_CANDIDATE_REPLAY_RESULT_FREEZE")
print("PASS_REPLAY_DISCOVERY_ARTIFACT_HASHES")
print("PASS_REPLAY_DISCOVERY_81_ROWS_RECOMPUTED")
print("PASS_REPLAY_CURRENT_RUN_REPRODUCES_AGGREGATE")
print("PASS_REPLAY_NO_INFRASTRUCTURE_ERRORS")
print("PASS_REPLAY_NO_RCC_UPSTREAM_DIVERGENCE")
print("provider_execution=0")
print("database_access=0")
print("scorer_or_gold_access=0")
print("COMMITTED_to_COMMITTED=12")
print("COMMITTED_to_VERITAS_BLOCKED=69")
print("next_rule_of_one=CONTROLLED_GOVERNANCE_TREATMENT_DELTA_ANALYSIS_V1")
