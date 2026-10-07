#!/usr/bin/env python3
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

CONTRACT = Path("contracts/PAIRWISE_PROTECTED_CANDIDATE_CONTROL_V1_1_CANONICAL_ALIGNMENT.json")
V1 = Path("scripts/pairwise_protected_candidate_control_v1.py")
V11 = Path("scripts/pairwise_protected_candidate_control_v1_1.py")

EXPECTED_CONTRACT_BLOB = "4010671ff48b65041c2e1d9c87cad577aa59b670"
EXPECTED_V1_BLOB = "daffd0308a3cd60563d00006bd899fa8ae86ebad"
EXPECTED_V11_BLOB = "be113ebc85a78a52af3c168f9256fce28d3eaf9b"
EXPECTED_RCC_MODELS_BLOB = "3fe4da0462c60184838f31b2e8dbcbb62b2f99d9"
EXPECTED_RCC_CANONICAL_BLOB = "dc672bb78bedae318b07e9098ccdb56dc9c9e14b"

def git_blob(path: Path) -> str:
    return subprocess.run(
        ["git", "hash-object", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

def git_blob_in(repo: Path, rel: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "hash-object", rel],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module

c = json.loads(CONTRACT.read_text())
assert git_blob(CONTRACT) == EXPECTED_CONTRACT_BLOB
assert git_blob(V1) == EXPECTED_V1_BLOB
assert git_blob(V11) == EXPECTED_V11_BLOB

assert c["status"] == "SUPERSEDES_V1_CANDIDATE_HASH_PAYLOAD_ONLY"
assert c["rule_of_one"] == "PAIRWISE_PROTECTED_CANDIDATE_CONTROL_V1_1_CANONICAL_ALIGNMENT"
assert c["base_main_sha"] == "751b6b1cf036cdf0d78204ea574b4f202137062d"
assert c["source_v1"]["contract_git_blob_sha"] == "f19f5e50e7a596db06770b6c3007b1e74144019a"
assert c["corrected_implementation"]["git_blob_sha"] == EXPECTED_V11_BLOB
assert c["issue"]["classification"] == "HASH_PAYLOAD_SHAPE_MISMATCH_NOT_PAIRING_LOGIC_FAILURE"
assert c["scope"]["changes_candidate_hash_payload_only"] is True
assert c["scope"]["changes_pairing_fields"] is False
assert c["scope"]["changes_policy_semantics"] is False
assert c["scope"]["changes_resolver_semantics"] is False
assert c["scope"]["provider_execution"] is False
assert c["scope"]["database_access"] is False
assert c["scope"]["final_128_execution"] is False
assert c["replay_requirement"]["v1_hash_interoperability_accepted"] is False
assert c["replay_requirement"]["v1_1_required_for_replay_harness"] is True
assert c["next_rule_of_one"] == "PAIRWISE_PROTECTED_CANDIDATE_REPLAY_HARNESS_V1"

if os.environ.get("OPENAI_API_KEY"):
    raise SystemExit("OPENAI_API_KEY_MUST_BE_EMPTY")
if os.environ.get("VERITAS_DATABASE_URL"):
    raise SystemExit("VERITAS_DATABASE_URL_MUST_BE_EMPTY")

rcc_root = Path(os.environ["RCC_ROOT"])
models_rel = "external-eval/v0.3.9/src/rveval/models.py"
canonical_rel = "external-eval/v0.3.9/src/rveval/canonical.py"
assert git_blob_in(rcc_root, models_rel) == EXPECTED_RCC_MODELS_BLOB
assert git_blob_in(rcc_root, canonical_rel) == EXPECTED_RCC_CANONICAL_BLOB

rcc_src = (rcc_root / "external-eval/v0.3.9/src").resolve()
sys.path.insert(0, str(rcc_src))
from rveval.canonical import sha_json as rcc_sha_json
from rveval.models import CandidateAction

v1 = load_module("pair_control_v1", V1)
v11 = load_module("pair_control_v11", V11)

case_id = "banking:user_task_4:injection_task_0:direct"
pre = "0" * 64
args = {
    "recipient": "GB29NWBK60161331926819",
    "amount": 10,
    "subject": "refund",
    "date": "2026-10-07",
}

actual = CandidateAction("tool_call", name="send_money", arguments=args)
actual_payload = actual.to_dict()
actual_hash = rcc_sha_json(actual_payload)

assert list(actual_payload.keys()) == [
    "kind",
    "name",
    "arguments",
    "content",
    "metadata",
]
assert actual_payload["content"] is None
assert actual_payload["metadata"] == {}

old = v1.ProtectedCandidateControl.build(
    case_id=case_id,
    proposal_ordinal=0,
    immediate_pre_state_sha256=pre,
    function="send_money",
    normalized_arguments=args,
)
new = v11.ProtectedCandidateControlV11.build(
    case_id=case_id,
    proposal_ordinal=0,
    immediate_pre_state_sha256=pre,
    function="send_money",
    normalized_arguments=args,
)

assert old.candidate_sha256 != actual_hash
assert new.candidate_sha256 == actual_hash
assert v11.sha_json(new.candidate_payload()) == actual_hash
assert new.candidate_payload() == actual_payload

new_peer = v11.ProtectedCandidateControlV11.build(
    case_id=case_id,
    proposal_ordinal=0,
    immediate_pre_state_sha256=pre,
    function="send_money",
    normalized_arguments=args,
)
pair_hash = v11.require_exact_pair(new, new_peer)
assert pair_hash == new.pairing_identity_sha256()

arm_a, arm_b = v11.fork_exact_candidate(new)
assert arm_a == actual_payload
assert arm_b == actual_payload
arm_a["arguments"]["amount"] = 999
assert arm_b["arguments"]["amount"] == 10
assert new.arguments["amount"] == 10
v11.assert_candidate_unchanged(new, arm_b)

try:
    mismatch = v11.ProtectedCandidateControlV11.build(
        case_id=case_id,
        proposal_ordinal=0,
        immediate_pre_state_sha256="1" * 64,
        function="send_money",
        normalized_arguments=args,
    )
    v11.require_exact_pair(new, mismatch)
except v11.PairingViolation:
    pass
else:
    raise AssertionError("PRESTATE_MISMATCH_MUST_FAIL_CLOSED")

assert c["corrected_hash_rule"]["canonical_profile"] == "rveval.python-finite-json.v2"
assert c["corrected_hash_rule"]["payload"] == {
    "kind": "tool_call",
    "name": "<protected function>",
    "arguments": "<Pydantic-normalized arguments>",
    "content": None,
    "metadata": {},
}

print("PASS_PAIRWISE_PROTECTED_CANDIDATE_CONTROL_V1_1_CANONICAL_ALIGNMENT")
print("PASS_V1_HASH_MISMATCH_REPRODUCED")
print("PASS_V11_HASH_EQUALS_RCC_CANDIDATEACTION_HASH")
print("PASS_RCC_CANDIDATE_PAYLOAD_SHAPE_PIN")
print("PASS_RCC_CANONICAL_PROFILE_PIN")
print("PASS_PAIRING_IDENTITY_AND_DEEP_COPY_PRESERVED")
print("PASS_PRESTATE_MISMATCH_FAIL_CLOSED")
print("provider_execution=0")
print("database_access=0")
print(f"v1_candidate_sha256={old.candidate_sha256}")
print(f"rcc_candidate_sha256={actual_hash}")
print(f"v1_1_candidate_sha256={new.candidate_sha256}")
print("next_rule_of_one=PAIRWISE_PROTECTED_CANDIDATE_REPLAY_HARNESS_V1")
