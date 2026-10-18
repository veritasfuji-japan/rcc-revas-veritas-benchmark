"""Task4 #454: offline native-scored A/B evidence admission, NEVER Provider dispatch.

Only joins the *existing* #323 and #363 local SDK/MockTransport audits.
It is NOT a new model inference, issuer, cost approval, or deployed sender.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHA = "0123456789abcdef"
CASE = "banking:user_task_4:injection_task_0:direct"
RULE = "TASK4_454_RESEARCH_PRESEND_OFFLINE_NATIVE_SCORER_REUSE_NO_LIVE_V1"
BLOCKED = (
    "OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "OPENAI_BASE_URL", "TASK4_454_LIVE_APPROVAL",
)


class Refused(ValueError):
    pass


def need(ok: bool, reason: str):
    if not ok:
        raise Refused(reason)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def exact_sha(value: object) -> bool:
    return (type(value) is str and len(value) == 64
            and all(x in SHA for x in value))


def ensure_research_only(env=None):
    env = os.environ if env is None else env
    need(not any(env.get(k) for k in BLOCKED), "454_SECRET_OR_LIVE_CONTEXT_FORBIDDEN")


def audit(native: object, lineage: object, *, native_bytes: bytes, lineage_bytes: bytes):
    need(type(native) is dict and type(lineage) is dict, "454_EXACT_TWO_AUDITS")
    need(native.get("source_case") == CASE and
         native.get("two_independent_scripted_first_request_roots") == 2 and
         native.get("real_sdk_local_interceptions") == 8 and
         native.get("native_arm_executions") == 2 and
         native.get("postonly_native_scorer_calls") == 2 and
         native.get("shadow_native_arm_executions") == 0 and
         native.get("new_real_provider_posts") == 0 and
         native.get("new_genuine_model_generations") == 0 and
         native.get("new_final128_cases") == 0 and
         native.get("external_bank_effects") == 0 and
         native.get("independent_prod_execution_authority") is False and
         native.get("real_provider_dispatch") == "DENY" and
         native.get("historical_provider_consent_spent") is True,
         "454_NATIVE_MUST_BE_SCRIPTED_COMPLETE_DENY_LIVE")
    need(lineage.get("scope") ==
         "FULL_OFFLINE_SCRIPTED_SDK_NATIVE_SCORER_LINEAGE_NOT_REAL_MODEL" and
         lineage.get("verified_model_shaped_requests") == 8 and
         lineage.get("native_terminal_histories") == 2 and
         lineage.get("postonly_native_scorer_bindings") == 2 and
         lineage.get("real_provider_calls") == 0 and
         lineage.get("real_final128_case_scores") == 0 and
         lineage.get("external_effects") == 0 and
         lineage.get("real_model_independence_proven") is False and
         lineage.get("live_provider_dispatch") == "DENY",
         "454_NATIVE_WIRE_LINEAGE_MUST_BE_SCRIPTED_ONLY")
    a = native.get("selected_source_arms")
    b = lineage.get("sources")
    need(type(a) is dict and set(a) == {"A", "B"} and
         type(b) is list and len(b) == 2 and
         [x.get("arm") for x in b if type(x) is dict] == ["A", "B"],
         "454_TWO_DISTINCT_SOURCE_ARM_A_B_REQUIRED")
    for row in b:
        arm = row["arm"]
        origin = a[arm]
        need(type(origin) is dict and
             origin.get("native_dispatches") == 1 and
             origin.get("native_scorer_invocations") == 1 and
             origin.get("shadow_arms") == 0 and
             origin.get("real_model_generations") == 0 and
             origin.get("dev_only_native_utility") is True and
             origin.get("dev_only_attack_goal_success") is False and
             row.get("real_provider_calls") == 0 and
             row.get("native_to_sdk_turns_verified") == 4 and
             type(row.get("wire_request_hashes")) is list and
             len(row["wire_request_hashes"]) == 4 and
             all(exact_sha(v) for v in row["wire_request_hashes"]) and
             origin.get("first_request_sha256") == row["wire_request_hashes"][0] and
             origin.get("native_terminal_history_sha256") ==
                 row.get("native_terminal_history_sha256") and
             origin.get("native_post_state_sha256") ==
                 row.get("scored_post_state_sha256") and
             origin.get("scorer_result_sha256") ==
                 row.get("scorer_result_sha256") and
             all(exact_sha(row.get(k)) for k in (
                 "terminal_assistant_sha256", "native_terminal_history_sha256",
                 "scored_post_state_sha256", "scorer_result_sha256")),
             "454_CROSS_AUDIT_ARM_OR_SCORER_PROVENANCE_MISMATCH")
    need(b[0]["wire_request_hashes"][0] == b[1]["wire_request_hashes"][0] and
         b[0]["native_terminal_history_sha256"] !=
             b[1]["native_terminal_history_sha256"] and
         a["A"].get("first_response_id") != a["B"].get("first_response_id"),
         "454_A_B_INDEPENDENT_SCRIPTED_ORIGIN_REQUIREMENT")
    return {
        "rule_of_one": RULE,
        "classification": "OFFLINE_RESEARCH_PRESEND_ONLY_NOT_APPROVED",
        "case_id": CASE,
        "arm_sources": ["A", "B"],
        "reused_original_native_test": "TASK4_323",
        "reused_original_native_lineage_audit": "TASK4_363",
        "native_audit_sha256": sha256(native_bytes),
        "lineage_audit_sha256": sha256(lineage_bytes),
        "scripted_arms_native_scored": 2,
        "scripted_sdk_requests": 8,
        "genuine_model_generations": 0,
        "genuine_terminal_model_responses": 0,
        "new_canonical_utility_recoveries": 0,
        "real_provider_attempts": 0,
        "external_banking_effects": 0,
        "model_snapshot_account_available": "NOT_ATTESTED",
        "monthly_project_limit_from_owner_screenshot": "USD_1_LIMIT_ENFORCED_NOT_PER_RUN_HARD_STOP",
        "protected_environment_from_owner_screenshot": "MAIN_ONLY_NO_SECRETS_NO_REVIEWER",
        "provider_credential_read": "DENY",
        "fresh_owner_paid_approval": "NOT_GIVEN",
        "independent_production_authority": "NOT_PROVEN",
        "live_provider_dispatch": "DENY",
        "issue_321": "OPEN_NO_GO",
        "issue_427": "OPEN_NO_GO",
    }


def main():
    ap = argparse.ArgumentParser(description="Offline joins #323/#363 reports ONLY")
    ap.add_argument("--native", required=True)
    ap.add_argument("--lineage", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    ensure_research_only()
    paths = [(ROOT / x).resolve() for x in
             (args.native, args.lineage, args.output)]
    need(all(x.is_relative_to(ROOT) for x in paths) and
         len(set(paths)) == 3 and
         all(x.is_file() for x in paths[:2]),
         "454_ONLY_EXISTING_REPOSITORY_LOCAL_AUDIT_INPUTS")
    nb, lb = [x.read_bytes() for x in paths[:2]]
    need(len(nb) <= 500_000 and len(lb) <= 500_000,
         "454_BOUNDED_LOCAL_AUDIT_INPUTS")
    report = audit(json.loads(nb), json.loads(lb),
                   native_bytes=nb, lineage_bytes=lb)
    paths[2].parent.mkdir(parents=True, exist_ok=True)
    need(not paths[2].exists(), "454_NEVER_OVERWRITE_RESEARCH_EVIDENCE")
    paths[2].write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("TASK4_454_SCRIPTED_NATIVE_A_B_SOURCE_SCORER_JOIN_PASS_PROVIDER_DENY")


if __name__ == "__main__":
    main()
