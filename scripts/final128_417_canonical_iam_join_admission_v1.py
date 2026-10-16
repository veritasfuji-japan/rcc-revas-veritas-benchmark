#!/usr/bin/env python3
"""#417: deny a false cross-repository identity join.

The reviewed #416 canonical counter fixture and #2382 IAM grant use separate
issuance and different actions/IDs. SHA-pinned observations are useful for
diagnostics but cannot delegate authority. This module NEVER creates a
permission or reports that a canonical candidate executed at IAM.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts/FINAL128_417_CANONICAL_TO_IAM_JOIN_GAP_V1.json"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_MODES = {
    "valid", "tampered", "revoked", "candidate_substitution",
    "request_id_substitution", "prestate_drift", "scorer_gold_authority",
}
STATUS = "NOT_ADMITTED_NEEDS_SOURCE_BOUND_NATIVE_ISSUER"


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError("417_" + reason)


def read_obj(blob: bytes) -> dict:
    item = json.loads(blob)
    require(type(item) is dict, "NOT_JSON_OBJECT")
    return item


def digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def read_contract(path: Path = CONTRACT) -> dict:
    contract = read_obj(path.read_bytes())
    require(contract.get("schema") ==
            "veritas.final128-417.reviewed-dual-artifact-lineage-gap.v1",
            "CONTRACT_SCHEMA_DRIFT")
    require(contract.get("status") ==
            "UNLINKED_GAP_AUDIT_ONLY_NOT_INTEGRATION_PROVEN",
            "PREMATURE_PROOF_PROMOTION")
    scope = contract.get("nonclaims")
    require(type(scope) is dict and
            scope.get("two_separate_runs_are_one_executed_intent") is False
            and scope.get("source_bound_issuer_integrated") is False
            and scope.get("production_authority_proven") is False
            and scope.get("official_final128_utility_recovered") is False
            and scope.get("paid_provider_calls") == 0,
            "PROOF_CLAIMS_DRIFT")
    required = contract.get("required_new_native_boundary")
    require(type(required) is dict and len(required) >= 9
            and all(v is True for v in required.values()),
            "NATIVE_BRIDGE_REQUIREMENTS_DOWNGRADED")
    sources = contract.get("sources")
    require(type(sources) is dict and set(sources) == {"canonical", "iam"},
            "SOURCES_SHAPE")
    for name in ("canonical", "iam"):
        value = sources[name]
        require(type(value) is dict and
                HEX64.fullmatch(str(value.get("zip_sha256", ""))) is not None
                and HEX40.fullmatch(str(value.get("source_head" if name == "canonical"
                                                 else "merged_main_sha", ""))) is not None,
                "SOURCE_PIN_INVALID")
        require(type(value.get("valid")) is dict, "SOURCE_LINEAGE_MISSING")
    require(sources["canonical"]["ben_upstream"] ==
            "1d3782d3aae5ff9c88036709c1a5642320cc53c2" and
            sources["canonical"]["reviewed_os_commit"] ==
            "73b73a75c5605aaf779ea291436722fae52ed1a7" and
            sources["iam"]["merged_main_sha"] ==
            "5af56051cdc5b88c1705f0afe876aa6ba4858371",
            "SOURCE_REFERENCE_DRIFT")
    c = sources["canonical"]["valid"]
    i = sources["iam"]["valid"]
    for field in ("original_request_digest", "candidate_hash"):
        require(HEX64.fullmatch(str(c.get(field, ""))) is not None,
                "CANONICAL_HASH_INVALID")
    require(c.get("request_id") and c.get("execution_intent_id") and
            i.get("request_id") and i.get("execution_intent_id"),
            "MISSING_JOIN_IDENTITIES")
    require(HEX64.fullmatch(str(i.get("challenge_sha256", ""))) is not None,
            "CHALLENGE_HASH_INVALID")
    return contract


def read_artifact(path: Path, expected_sha: str) -> dict[str, dict]:
    # A published SHA pins bytes; the manifest pins the JSON members.
    require(path.is_file() and not path.is_symlink(), "ARTIFACT_MISSING")
    require(digest(path.read_bytes()) == expected_sha, "ARTIFACT_ZIP_SHA_MISMATCH")
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) <= 50 and len(names) == len(set(names))
                and "manifest.sha256" in names and all(
                    "/" not in n and "\\" not in n and n not in (".", "..")
                    and n.endswith((".json", ".sha256")) for n in names),
                "ARTIFACT_MEMBER_UNSAFE")
        manifest = archive.read("manifest.sha256").decode("ascii").splitlines()
        members: dict[str, dict] = {}
        listed: set[str] = set()
        for line in manifest:
            require(len(line) >= 67 and line[64:66] == "  ",
                    "MANIFEST_FORMAT_INVALID")
            expected, listed_name = line[:64], line[66:]
            # GitHub's native OS evidence is produced by sha256sum and
            # legitimately names members "./filename.json"; ZIP members
            # themselves are safe top-level bare names. Strip ONLY one "./"
            # prefix and reject any traversal, alternate path, or alias.
            name = listed_name[2:] if listed_name.startswith("./") else listed_name
            require(HEX64.fullmatch(expected) is not None
                    and name in names and name.endswith(".json")
                    and name not in listed and
                    (listed_name == name or listed_name == "./" + name),
                    "MANIFEST_MEMBER_INVALID")
            raw = archive.read(name)
            require(len(raw) < 1024 * 1024 and digest(raw) == expected,
                    "MANIFEST_MEMBER_HASH_DRIFT")
            members[name] = read_obj(raw)
            listed.add(name)
        require(listed == set(names) - {"manifest.sha256"},
                "MANIFEST_INCOMPLETE")
        return members


def check_canonical(report: dict, contract: dict) -> dict:
    source = contract["sources"]["canonical"]
    require(report.get("schema") ==
            "veritas.final128-416.current-os-main-native-chain-seven-mode.v1",
            "CANONICAL_REPORT_SCHEMA")
    require(report.get("status") ==
            "CURRENT_OS_MAIN_COMMIT_416_PINNED_LOCAL_CHAIN_REPLAY_NOT_PRODUCTION",
            "CANONICAL_SCOPE")
    require(report.get("rcc_tested_checkout_sha") == source["source_head"]
            and report.get("veritas_tested_current_main_commit") ==
            source["reviewed_os_commit"]
            and report.get("ben_upstream_pin") == source["ben_upstream"],
            "CANONICAL_SOURCE_DRIFT")
    require(report.get("positive_mock_commits") == 1
            and report.get("negative_cases") == 6
            and report.get("negative_additional_effects") == 0
            and report.get("production_or_customer_effects") == 0
            and report.get("real_provider_calls") == 0
            and report.get("official_agentdojo_scorer_calls") == 0
            and report.get("new_official_utility_recovery") is False
            and report.get("independent_validation") is False,
            "CANONICAL_CLAIM_DRIFT")
    cases = report.get("cases")
    require(type(cases) is list and len(cases) == 7
            and {c.get("mode") for c in cases if type(c) is dict} == REQUIRED_MODES,
            "CANONICAL_SEVEN_MODE_MATRIX_MISSING")
    for c in cases:
        is_valid = c["mode"] == "valid"
        require(c.get("native_apply_count") == (1 if is_valid else 0)
                and c.get("outcome") == ("COMMITTED" if is_valid else "BLOCKED")
                and (type(c.get("native_lineage")) is dict) == is_valid,
                "CANONICAL_CASE_OUTCOME_INVALID")
    lineage = next(c["native_lineage"] for c in cases if c["mode"] == "valid")
    for key, want in source["valid"].items():
        require(lineage.get(key) == want, "CANONICAL_ORIGINAL_LINEAGE_CHANGED:" + key)
    return lineage


def check_iam(members: dict[str, dict], contract: dict) -> dict:
    source = contract["sources"]["iam"]
    need = ("native_issuer_receipt.json", "iam_reconciliation_reconcile.json",
            "verification_post_native.json", "iam_challenge_registered.json",
            "iam_challenge_consumed.json")
    require(all(key in members for key in need), "IAM_REQUIRED_EVIDENCE_MISSING")
    issuer = members[need[0]]
    rec = members[need[1]]
    post = members[need[2]]
    registered = members[need[3]]
    consumed = members[need[4]]
    for key, want in source["valid"].items():
        actual = (consumed.get("challenge_sha256") if key == "challenge_sha256"
                  else issuer.get(key))
        require(actual == want, "IAM_ORIGINAL_LINEAGE_CHANGED:" + key)
    require(issuer.get("native_signed_human_approval_verified") is True
            and issuer.get("native_authorization_consumed") is True
            and issuer.get("native_store_durable") is True
            and issuer.get("external_iam_provider_called") is False
            and issuer.get("production_claim") is False,
            "IAM_ISSUER_CLAIM_DRIFT")
    require(rec.get("effect_state_before") == "EFFECT_UNKNOWN"
            and rec.get("effect_state_after") == "CONFIRMED_EFFECT"
            and rec.get("operation_id") == issuer["consumption_id"]
            and rec.get("freshness_challenge_digest") ==
            consumed["challenge_sha256"]
            and rec.get("target_ack_signature_verified") is True
            and rec.get("durable_challenge_consumed_with_effect") is True
            and rec.get("target_post_retried") is False
            and rec.get("permit_reissued") is False
            and rec.get("production_claim") is False,
            "IAM_RECONCILIATION_CLAIM_DRIFT")
    require(registered.get("state") == "ISSUED"
            and consumed.get("state") == "CONSUMED"
            and registered.get("challenge_sha256") ==
            consumed.get("challenge_sha256"), "IAM_CHALLENGE_NOT_CONSUMED")
    require(post.get("native_postgres_consumption_rows") == 1
            and post.get("target_grants") == 1
            and post.get("real_mtls_allowed_exactly_once") is True
            and post.get("mutation_retried") is False
            and post.get("native_permit_reissued") is False
            and post.get("production_claim") is False
            and post.get("source_sha") == post.get("expected_sha") ==
            source["tested_workflow_merge_sha"],
            "IAM_EFFECT_OR_PIN_DRIFT")
    # Existing IAM issuer receipt lacks origin digest/candidate commitment.
    require("source_bound_canonical_receipt" not in issuer
            and "original_request_digest" not in issuer
            and "canonical_candidate_hash" not in issuer,
            "IAM_SOURCE_BINDING_UNREVIEWED")
    return issuer


def assess(lineage: dict, issuer: dict, *, zip_verified: bool) -> dict:
    require(lineage.get("original_request_digest")
            and lineage.get("candidate_hash")
            and lineage.get("request_id")
            and lineage.get("execution_intent_id"),
            "UPSTREAM_LINEAGE_INCOMPLETE")
    require(issuer.get("request_id") and issuer.get("execution_intent_id"),
            "DOWNSTREAM_LINEAGE_INCOMPLETE")
    # Equality alone is never an issuance proof. A new, independently
    # verified, native-issued source-binding capability is required.
    return {
        "schema": "veritas.final128-417.join-admission.v1",
        "status": STATUS,
        "result": "PASS_GAP_IDENTIFIED_NOT_CROSS_REPO_EXECUTION_PROOF",
        "canonical_and_iam_were_separate_executions": True,
        "request_id_equal": lineage["request_id"] == issuer["request_id"],
        "execution_intent_id_equal":
            lineage["execution_intent_id"] == issuer["execution_intent_id"],
        "native_issuer_proved_source_bound_original_request": False,
        "native_issuer_proved_source_bound_candidate": False,
        "same_source_bound_execution_authorized": False,
        "real_both_artifact_zip_hashes_checked_this_run": zip_verified,
        "production_proven": False,
        "final128_utility_recovered": False,
        "paid_provider_calls": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, default=CONTRACT)
    parser.add_argument("--canonical-zip", type=Path)
    parser.add_argument("--iam-zip", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    contract = read_contract(args.contract)
    paired = args.canonical_zip is not None or args.iam_zip is not None
    require(not paired or (args.canonical_zip and args.iam_zip),
            "INCOMPLETE_ARTIFACT_PAIR")
    if paired:
        canon = read_artifact(
            args.canonical_zip, contract["sources"]["canonical"]["zip_sha256"])
        iam = read_artifact(args.iam_zip, contract["sources"]["iam"]["zip_sha256"])
        lineage = check_canonical(canon["report.json"], contract)
        issuer = check_iam(iam, contract)
    else:
        # Metadata-only CI explicitly cannot claim that it fetched the ZIPs.
        lineage = contract["sources"]["canonical"]["valid"]
        issuer = contract["sources"]["iam"]["valid"]
    result = assess(lineage, issuer, zip_verified=bool(paired))
    require(result["request_id_equal"] is False
            and result["execution_intent_id_equal"] is False,
            "SNAPSHOT_EXPECTED_DISTINCT_IDS")
    require(not args.output.exists(), "OUTPUT_ALREADY_EXISTS")
    args.output.mkdir(parents=True)
    contents = json.dumps(result, sort_keys=True, indent=2) + "\n"
    (args.output / "report.json").write_text(contents, encoding="utf-8")
    (args.output / "manifest.sha256").write_text(
        digest(contents.encode("utf-8")) + "  report.json\n", encoding="ascii")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
