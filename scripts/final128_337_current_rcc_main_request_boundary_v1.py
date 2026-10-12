#!/usr/bin/env python3
"""#337: execute the ACTUAL published RCC main v0.1 native request preparation.

RCC original partner fixtures -> RCC verification/handoff -> /v1/decide
request-side binding ONLY. Never POST, import a live VERITAS service, execute
Bind, score new AgentDojo utility, or promote a matching echo to consumption.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts/FINAL128_337_CURRENT_RCC_MAIN_REQUEST_BOUNDARY_V1.json"
PIN = "353ad9e6a17cda8874a129493fe0f8f4fe4427bc"
PARENT = "4b403e5f2c2156b8d1443dc4310f3a4feebfcb55"
SCHEMA = "veritas.final128.current-rcc-main-request-boundary.v1"
RULE = "EXECUTE_CURRENT_RCC_MAIN_RELEASE_NATIVE_REQUEST_PREPARATION_WITHOUT_BIND_PROMOTION"
EXPECTED_COUNT = 36
BANNED_KEYS = ("OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
               "VERITAS_API_KEY", "VERITAS_DATABASE_URL", "GITHUB_TOKEN", "GH_TOKEN")

class Refused(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise Refused(reason)

def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")

def digest(value):
    return hashlib.sha256(canon(value)).hexdigest()

def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def read_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line.strip()]

def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()

def validate_contract(contract):
    require(type(contract) is dict and set(contract) == {
        "schema", "rule_of_one", "parent_main_sha", "upstream_repository",
        "upstream_main_sha", "upstream_release_root", "upstream_release",
        "upstream_source_blob_pins", "legacy_source_path",
        "expected_partner_cases", "expected_adapter_version", "expected_endpoint",
        "historical_final128", "boundary"}, "337_CONTRACT_SHAPE")
    require(contract["schema"] == SCHEMA and contract["rule_of_one"] == RULE
            and contract["parent_main_sha"] == PARENT
            and contract["upstream_repository"] == "effacermonexistence/rcc-revas-veritas-benchmark"
            and contract["upstream_main_sha"] == PIN
            and contract["upstream_release_root"] == "rcc-revas-eval/v0.1.0/runtime"
            and contract["upstream_release"] == "0.1.0"
            and contract["expected_partner_cases"] == EXPECTED_COUNT
            and contract["expected_adapter_version"] == "rcc-revas-veritas-native-adapter-v0.1.0"
            and contract["expected_endpoint"] == "/v1/decide"
            and contract["legacy_source_path"] == "external-eval/v0.3.9/src/rveval/integrations/agentdojo.py",
            "337_PINNED_CURRENT_UPSTREAM_SCOPE")
    require(contract["historical_final128"] == {
        "run_id": 37585673492, "arm_a_utility": 93,
        "arm_b_utility": 64, "arm_b_injection": 0, "official_new_utility": 0
    }, "337_HISTORIC_FINAL128_CANNOT_REWRITE")
    require(contract["boundary"] == {
        "runs_current_upstream_code": True,
        "source_side_candidate_prestate_provenance_only": True,
        "candidate_hash_is_execution_authority": False,
        "veritas_decide_http_posts": 0, "veritas_native_bind_invocations": 0,
        "veritas_native_execution_evidence": False,
        "physical_bank_prestate_verified": False,
        "canonical_agentdojo_128_enrolled": False,
        "official_new_final128_scores": 0,
        "provider_calls": 0, "real_bank_effects": 0,
        "legacy_main_path_expected_present": False,
        "historic_rcc_release_v0_3_9_remains_unchanged": True,
        "reconciliation_or_independent_validation": False,
        "current_full_wrapper_continuity_status": "NOT_PROVEN",
        "real_provider_dispatch": "DENY"
    }, "337_NO_NATIVE_BIND_OR_UTILITY_CLAIM_PROMOTION")
    require(len(contract["upstream_source_blob_pins"]) == 7,
            "337_SEVEN_SOURCE_BLOB_PINS_REQUIRED")
    return contract

def verify_source(upstream_root, contract):
    upstream_root = Path(upstream_root).resolve()
    require(git(upstream_root, "rev-parse", "HEAD") == PIN, "337_UPSTREAM_MAIN_HEAD_DRIFT")
    require((upstream_root / "rcc-revas-eval/CURRENT").read_text().strip() == "v0.1.0",
            "337_ACTIVE_PUBLIC_RELEASE_DRIFT")
    require(not (upstream_root / contract["legacy_source_path"]).exists(),
            "337_LEGACY_V039_PATH_UNEXPECTEDLY_PRESENT")
    for rel, expected in contract["upstream_source_blob_pins"].items():
        target = (upstream_root / rel).resolve()
        require(target.is_relative_to(upstream_root) and target.is_file(),
                "337_PINNED_SOURCE_MISSING:" + rel)
        require(git(upstream_root, "hash-object", rel) == expected,
                "337_SOURCE_BLOB_DRIFT:" + rel)
    release = upstream_root / contract["upstream_release_root"]
    require((release / "rcc_revas_eval/native_veritas.py").is_file(),
            "337_CURRENT_NATIVE_ADAPTER_MISSING")
    return release

def forbid_credentials():
    require(not any(os.environ.get(k) for k in BANNED_KEYS),
            "337_NO_PROVIDER_OR_BANK_OR_GITHUB_CREDS")

def run_stage(release, args):
    # ALL commands fixed here. There is deliberately NO invoke-veritas,
    # no native Bind invocation, no HTTP client and no provider sender.
    require(args[0] in ("preflight", "register-takeshi", "evaluate",
                        "verify-artifacts", "prepare-veritas"),
            "337_APPROVED_READONLY_OR_DISPOSABLE_LOCAL_STAGE_ONLY")
    env = dict(os.environ)
    for key in BANNED_KEYS:
        env.pop(key, None)
    p = subprocess.run([sys.executable, "-m", "rcc_revas_eval", *map(str, args)],
                       cwd=release, env=env, capture_output=True, text=True, timeout=180)
    require(p.returncode == 0, "337_CURRENT_UPSTREAM_STAGE_FAILED:" + args[0] + ":" +
            p.stderr[-500:])
    return {"stage": args[0], "exit_code": p.returncode,
            "stdout_sha256": hashlib.sha256(p.stdout.encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256(p.stderr.encode()).hexdigest()}

def verify_one_prepared(row, handoff, run_dir, native):
    """Re-execute the real upstream preparation, not a copied/stand-in adapter."""
    require(type(row) is dict and type(handoff) is dict, "337_PREPARED_SHAPE")
    expected, proof = native.build_decide_request(handoff, run_dir)
    require(row == {"case_id": handoff["rcc_revas"]["audit"]["case_id"],
                    "request": expected, "request_proof": proof},
            "337_PREPARED_WIRE_OR_ORIGIN_CHANGED")
    candidate = handoff["rcc_revas"]["adoption"]["selected_candidate"]
    info = expected["context"]["rcc_revas"]
    source, raw = native._bundle_object(run_dir, handoff["source_artifact"]["artifact_ref"])
    require(info["candidate"] == candidate and
            info["candidate_semantic_hash"] == proof["candidate_semantic_hash"] ==
                native.digest(candidate, "rcc-candidate-v1") and
            info["candidate_object_hash"] == proof["candidate_object_hash"] and
            info["upstream_decision_hash"] == proof["upstream_decision_hash"] and
            info["correlation_id"] == proof["correlation_id"] and
            info["evaluation_pre_state"] == source["decision"]["evaluation_pre_state"] and
            info["evaluation_pre_state_hash"] == proof["evaluation_pre_state_hash"] ==
                source["decision"]["evaluation_pre_state_hash"] and
            handoff["source_artifact"]["artifact_hash"] == "sha256:" + native.raw_sha(raw) and
            proof["request_payload_hash"] == native.digest(expected,
                                                           "rcc-veritas-decide-request-v1") and
            proof["request_side_exact_candidate_bound"] is True and
            proof["request_side_exact_evaluation_pre_state_bound"] is True and
            proof["server_side_exact_candidate_consumption_verified"] is False and
            expected["alternatives"][0]["id"] ==
                "rcc-candidate:" + proof["candidate_semantic_hash"],
            "337_EXACT_CURRENT_UPSTREAM_CANDIDATE_PRESTATE_LINEAGE_REQUIRED")
    # Exercise upstream response diagnostics against a synthetic echo. This
    # MUST NOT be reclassified as native consumption or a Bind permission.
    fake_echo = {"extras": {"rcc_revas_echo": {
        k: proof[k] for k in (
            "candidate_semantic_hash", "candidate_object_hash",
            "decision_state_binding_fingerprint", "upstream_decision_hash",
            "correlation_id", "evaluation_pre_state_hash")}}}
    echo = native.verify_response_echo(fake_echo, proof)
    require(echo["status"] == "MATCHING_ECHO_ONLY" and
            echo["exact_candidate_consumption_verified"] is False,
            "337_ECHO_NOT_NATIVE_CONSUMPTION")
    fake_echo["extras"]["rcc_revas_echo"]["candidate_object_hash"] = "sha256:" + "0" * 64
    mismatch = native.verify_response_echo(fake_echo, proof)
    require(mismatch["status"] == "MISMATCH" and
            mismatch["exact_candidate_consumption_verified"] is False,
            "337_TAMPERED_ECHO_MUST_FAIL_CLOSED")

def verify_output(contract, release, out):
    sys.path.insert(0, str(release))
    from rcc_revas_eval import native_veritas as native
    run_dir = out / "rcc-run"
    prepared = out / "prepared"
    manifest = release / "evaluation_manifest.json"
    native.verify_run(manifest, run_dir)
    summary = load_json(prepared / "summary.json")
    records = read_jsonl(prepared / "veritas_decide_requests.jsonl")
    skipped = read_jsonl(prepared / "skipped.jsonl")
    errors = read_jsonl(prepared / "errors.jsonl")
    handoffs = read_jsonl(run_dir / "handoff_results.jsonl")
    mapping = {h["rcc_revas"]["audit"]["case_id"]: h for h in handoffs}
    require(len(mapping) == len(handoffs) == EXPECTED_COUNT and
            summary["enrolled"] == EXPECTED_COUNT and
            len(records) > 0 and not errors and
            summary["errors"] == 0 and
            summary["prepared_requests"] == len(records) and
            summary["skipped_rcc_withheld"] == len(skipped) and
            len(records) + len(skipped) == EXPECTED_COUNT,
            "337_UPSTREAM_36_CASES_PREPARE_ACCOUNTING")
    require(summary["adapter_version"] == contract["expected_adapter_version"] and
            summary["endpoint"] == contract["expected_endpoint"] and
            summary["network_called"] is False and
            summary["external_effect_occurred"] is False and
            summary["server_side_exact_candidate_consumption_verified"] is False,
            "337_TRANSPORT_OR_BIND_CLAIM_FORBIDDEN")
    ids = set()
    for record in records:
        cid = record["case_id"]
        require(cid not in ids and cid in mapping and
                mapping[cid]["candidate"]["selected_output_ref"] is not None,
                "337_RELEASED_RECORD_NOT_PROVEN")
        verify_one_prepared(record, mapping[cid], run_dir, native)
        ids.add(cid)
    for record in skipped:
        cid = record["case_id"]
        require(cid not in ids and cid in mapping and
                record == {"case_id": cid, "status": "SKIPPED_RCC_WITHHELD"} and
                mapping[cid]["candidate"]["selected_output_ref"] is None,
                "337_WITHHELD_UPSTREAM_CANNOT_BE_SENT")
        ids.add(cid)
    require(ids == set(mapping), "337_EXACT_CASE_ACCOUNTING_DRIFT")
    return {"enrolled": len(mapping), "prepared_requests": len(records),
            "withheld": len(skipped), "errors": len(errors),
            "source_bundle_seal_sha256": summary["source_run_bundle_seal_sha256"],
            "all_prepared_wire_bytes_recomputed": True,
            "exact_candidate_and_label_free_evaluation_prestate_bound": True,
            "native_response_echo_only": True,
            "native_bind_or_execution_consistency": "NOT_MEASURED"}

def assert_claim_boundary(report):
    require(report["current_rcc_main_sha"] == PIN
            and report["canonical_128_new_scores"] == 0
            and report["http_posts"] == report["provider_calls"] == report["native_bind_calls"] == 0
            and report["bank_effects"] == 0
            and report["current_full_wrapper_continuity"] == "NOT_PROVEN"
            and report["native_consumption_verified"] is False
            and report["current_main_release_v039_adapter_exists"] is False
            and report["provider_dispatch"] == "DENY",
            "337_UNSUPPORTED_FULL_CHAIN_OR_SCORE_PROMOTION")

def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--upstream-root", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    args = p.parse_args(argv)
    forbid_credentials()
    contract = validate_contract(load_json(CONTRACT))
    release = verify_source(args.upstream_root, contract)
    out = args.output_dir.resolve()
    require(out == (ROOT / "results/final128-337-current-rcc-main").resolve()
            and not out.exists(), "337_FRESH_FIXED_OUTPUT_DIRECTORY_ONLY")
    out.mkdir(parents=True)
    manifest = release / "evaluation_manifest.json"
    stages = [
        ["preflight", "--manifest", manifest],
        ["register-takeshi", "--manifest", manifest,
         "--source", release / "fixtures/takeshi/Governance_labelled_Evaluation_Set_v0.1.1.jsonl",
         "--output-dir", out / "registered"],
        ["evaluate", "--manifest", manifest,
         "--input", out / "registered/runtime_inputs.jsonl",
         "--plan", out / "registered/preregistration.json",
         "--output-dir", out / "rcc-run"],
        ["verify-artifacts", "--manifest", manifest, "--run-dir", out / "rcc-run"],
        ["prepare-veritas", "--manifest", manifest,
         "--run-dir", out / "rcc-run", "--output-dir", out / "prepared"],
    ]
    journal = [run_stage(release, stage) for stage in stages]
    result = verify_output(contract, release, out)
    report = {
        "schema": SCHEMA, "rule_of_one": RULE, "parent_main_sha": PARENT,
        "current_rcc_main_sha": PIN, "current_release": "0.1.0",
        "source_git_blobs": contract["upstream_source_blob_pins"],
        "stage_journal": journal, "actual_upstream_observed": result,
        "historical_v13_reference_only": contract["historical_final128"],
        "canonical_128_new_scores": 0, "http_posts": 0, "provider_calls": 0,
        "native_bind_calls": 0, "bank_effects": 0,
        "current_full_wrapper_continuity": "NOT_PROVEN",
        "native_consumption_verified": False,
        "current_main_release_v039_adapter_exists": False,
        "provider_dispatch": "DENY",
        "next_needed": "PIN_AND_INTEGRATE_CURRENT_MAIN_NATIVE_BIND_RECEIPT_CONSUMPTION_WITH_SEPARATE_AUTHORITY",
    }
    assert_claim_boundary(report)
    report["report_sha256"] = digest(report)
    (out / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True,
                                              ensure_ascii=False) + "\n", encoding="utf-8")
    print("FINAL128_337_CURRENT_RCC_MAIN_NATIVE_REQUEST_PREPARATION_VERIFIED_NO_BIND_NO_NEW_UTILITY")
    print(json.dumps({"enrolled": result["enrolled"], "prepared": result["prepared_requests"],
                      "withheld": result["withheld"], "errors": result["errors"],
                      "report_sha256": report["report_sha256"]}, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
