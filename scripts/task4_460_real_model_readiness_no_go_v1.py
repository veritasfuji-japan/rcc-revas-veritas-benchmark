#!/usr/bin/env python3
"""Task4 #460: read-only real-model gap report. Never authorizes Provider dispatch."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts/TASK4_460_REAL_MODEL_READINESS_NO_GO_V1.json"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
GATES = tuple("R" + str(n) for n in range(1, 9))
PRODUCTION = ("P1", "P2", "P3")
CREDENTIAL_ENV = ("OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                  "OPENAI_BASE_URL", "GH_TOKEN", "GITHUB_TOKEN",
                  "TASK4_323_APPROVAL_PHRASE", "TASK4_460_PAID_APPROVAL",
                  "VERITAS_DATABASE_URL")
PINNED_FILES = frozenset((
    "task4_323_single_arm_trajectory_v1.py",
    "task4_frozen_provider_transport_date_context_binding_v1.py",
    "task4_323_single_arm_scorer_v1.py",
    "scripts/task4_455_research_native_sender_hard_nogo_v1.py",
    "scripts/task4_457_local_response_aead_v1.py",
    "scripts/task4_458_local_broker_once_ciphertext_v1.py",
    "scripts/task4_459_native_broker_custody_join_v1.py",
    "scripts/final128_344_native_terminal_measurement_admission_v1.py",
))


class Refused(ValueError):
    pass


def need(ok, reason):
    if ok is not True:
        raise Refused(reason)


def strict_pairs(items):
    out = {}
    for k, v in items:
        need(k not in out, "460_DUPLICATE_JSON_KEY")
        out[k] = v
    return out


def load_contract():
    return json.loads(CONTRACT.read_text(encoding="utf-8"),
                      object_pairs_hook=strict_pairs)


def validate(c):
    need(type(c) is dict and set(c) == {
        "schema", "baseline_commit", "case_id", "model_candidate",
        "frozen_agentdojo", "frozen_rcc", "frozen_veritas",
        "frozen_prestate_sha256", "frozen_attack_sha256", "source_blob_pins",
        "research_gates", "production_gates", "planning_limits_not_consent",
        "nonclaims"}, "460_EXACT_CONTRACT_REQUIRED")
    need(c["schema"] == "task4.real-model-readiness-contract.v1"
         and c["baseline_commit"] == "8e595a88338cb62f5bddf7adf7e023445b711a59"
         and c["case_id"] == "banking:user_task_4:injection_task_0:direct"
         and c["model_candidate"] == "gpt-4.1-mini-2025-04-14"
         and c["frozen_agentdojo"] == "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b"
         and c["frozen_rcc"] == "1d3782d3aae5ff9c88036709c1a5642320cc53c2"
         and c["frozen_veritas"] == "a1d66aef02262cf8a913295270c3aafd159c6adb"
         and c["frozen_prestate_sha256"] == "8b653f253d3b2b033ad2baebc938bb66cb09719be8b488a470e7e82d25abbe14"
         and c["frozen_attack_sha256"] == "0d5011fb8b275e313c83da127698f19a77095d44e82a81b4d5804046c3cb61a9",
         "460_SOURCE_TRIAL_OR_BENCHMARK_PIN_DRIFT")
    p = c["source_blob_pins"]
    need(type(p) is dict and set(p) == PINNED_FILES
         and all(type(v) is str and HEX40.fullmatch(v) for v in p.values()),
         "460_SOURCE_PIN_SHAPE_REQUIRED")
    for key, ids in (("research_gates", GATES), ("production_gates", PRODUCTION)):
        rows = c[key]
        need(type(rows) is list and len(rows) == len(ids)
             and all(type(v) is dict and set(v) == {"id", "state", "why"}
                     and v["id"] == id_ and v["state"] == "NOT_ATTESTED"
                     and type(v["why"]) is str and len(v["why"]) >= 20
                     for v, id_ in zip(rows, ids)),
             "460_GATES_MUST_REMAIN_UNATTESTED")
    need(c["planning_limits_not_consent"] == {
        "posts_per_arm": 5, "posts_total": 10,
        "completion_tokens_per_call": 256,
        "estimate_usd": 0.044096, "estimate_not_hard_cap": True},
        "460_BUDGET_IS_ONLY_UNAPPROVED_PLANNING")
    need(c["nonclaims"] == {
        "real_provider_dispatch": "DENY",
        "fresh_owner_paid_consent": False,
        "genuine_task4_utility": "UNSCORED",
        "genuine_injection_outcome": "UNSCORED",
        "new_genuine_utility_recoveries": 0,
        "cross_runner_cas_proven": False,
        "external_validation": False}, "460_NO_PROVEN_OR_DISPATCH_PROMOTION")


def source_fingerprint_check(c, root=ROOT):
    root = Path(root).resolve(strict=True)
    records = []
    for rel, expected in c["source_blob_pins"].items():
        p = root / rel
        need(not p.is_symlink() and p.is_file()
             and p.resolve(strict=True).is_relative_to(root),
             "460_SOURCE_MISSING_SYMLINK_OR_OUT_OF_ROOT")
        b = p.read_bytes()
        git_sha = hashlib.sha1(b"blob " + str(len(b)).encode() + b"\0" + b).hexdigest()
        need(bool(b) and git_sha == expected,
             "460_FROZEN_SOURCE_CHANGED_REQUIRES_REVIEW")
        records.append({"path": rel, "git_blob": git_sha,
                        "sha256": hashlib.sha256(b).hexdigest()})
    return records


def classify_distinct_offline_reports(pre, local):
    """Shape check only; caller-provided reports/hashes do not authenticate Providers."""
    need(type(pre) is dict and type(local) is dict, "460_TWO_REPORT_OBJECTS_REQUIRED")
    need(pre.get("rule_of_one") == "TASK4_455_NATIVE_SDK_RESEARCH_SENDER_WIRE_HARD_NO_GO_V1"
         and pre.get("status") == "OFFLINE_NATIVE_SDK_PREWIRE_READY_LIVE_UNAUTHORIZED"
         and pre.get("case_id") == "banking:user_task_4:injection_task_0:direct"
         and pre.get("actual_provider_calls") == 0
         and pre.get("fresh_paid_permission") is False
         and pre.get("new_true_model_utility_recoveries") == 0
         and pre.get("new_live_provider_dispatch") == "DENY",
         "460_PREWIRE_CANNOT_HAVE_PROVIDER_OUTPUT")
    arms = pre.get("arms")
    need(type(arms) is list and len(arms) == 2
         and [a.get("arm") for a in arms if type(a) is dict] == ["A", "B"]
         and all(a.get("provider_calls") == 0
                 and a.get("real_provider_send_enabled") is False
                 and a.get("native_scorer_calls") == 0
                 and a.get("real_issuer_date_attested") is False
                 for a in arms), "460_PREWIRE_ONLY_ARM_BOUNDARY")
    need(local.get("rule_of_one") == "TASK4_459_SINGLE_LOCAL_NATIVE_SOURCE_BROKER_ENCRYPTED_CUSTODY_JOIN_NO_PROVIDER_V1"
         and local.get("source") == "LOCAL_SCRIPTED_OPENAI_SDK_MOCK_NOT_REAL_LLM"
         and local.get("case_id") == pre["case_id"]
         and local.get("paired_arm_sources") == ["A", "B"]
         and local.get("native_model_requests_captured") == 8
         and local.get("encrypted_broker_slots_recovered_after_restart") == 8
         and local.get("source_native_terminals") == 2
         and local.get("source_detached_native_scorer_calls") == 2
         and local.get("real_provider_posts") == 0
         and local.get("new_genuine_utility") == 0
         and local.get("provider_authenticated") is False
         and local.get("off_runner_custody_proven") is False
         and local.get("independent_cross_runner_cas_proven") is False
         and local.get("real_execution_date_authority_proven") is False
         and local.get("live_dispatch") == "DENY",
         "460_SCRIPTED_NATIVE_CANNOT_BE_GENUINE")
    receipts = local.get("hash_only_receipts")
    need(type(receipts) is list and len(receipts) == 8
         and all(type(r) is dict and set(r) == {
              "arm", "ordinal", "request_sha256", "response_sha256",
              "ciphertext_sha256", "broker_receipt_sha256"}
              and all(type(r[k]) is str and HEX64.fullmatch(r[k])
                      for k in ("request_sha256", "response_sha256",
                                "ciphertext_sha256", "broker_receipt_sha256"))
              for r in receipts)
         and Counter((r["arm"], r["ordinal"]) for r in receipts)
         == Counter((a, n) for a in ("A", "B") for n in range(4)),
         "460_EIGHT_DISTINCT_LOCAL_RECEIPTS_REQUIRED")
    return {"classification": "SEPARATE_OFFLINE_EVIDENCE_NOT_GENUINE_SAME_RUN",
            "genuine_utility": None, "genuine_injection": None,
            "native_score": "UNSCORED", "real_provider_dispatch": "DENY"}


def readiness(root=ROOT, c=None):
    need(not any(os.environ.get(k) for k in CREDENTIAL_ENV),
         "460_LIVE_OR_CREDENTIAL_CONTEXT_REFUSED")
    c = load_contract() if c is None else c
    validate(c)
    sources = source_fingerprint_check(c, root)
    return {"schema": "task4.readiness-gap-report.v1",
            "baseline_commit": c["baseline_commit"],
            "case_id": c["case_id"], "model_candidate": c["model_candidate"],
            "source_pins_checked": sources,
            "research_gates_not_attested": [g["id"] for g in c["research_gates"]],
            "production_gates_not_attested": [g["id"] for g in c["production_gates"]],
            "actual_provider_posts": 0, "fresh_owner_paid_consent": False,
            "true_utility": None, "true_injection": None,
            "score_status": "UNSCORED",
            "real_provider_dispatch": "DENY",
            "same_run_real_A_B_native_terminal_proven": False,
            "status": "TASK4_REAL_MODEL_MEASUREMENT_NOT_READY_HARD_NO_GO"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = readiness()
    dest = (ROOT / args.output).resolve()
    need(dest.is_relative_to(ROOT) and not dest.exists(),
         "460_CREATE_ONLY_REPORT_INSIDE_REPOSITORY")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8")
    print("TASK4_460_READINESS_8_GAPS_NO_PROVIDER_NO_FAKE_UTILITY")


if __name__ == "__main__":
    main()
