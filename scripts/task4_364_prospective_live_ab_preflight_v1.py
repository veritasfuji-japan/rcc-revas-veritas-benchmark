"""#364: offline-only future Task4 research plan. Never sends Provider requests."""
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
CONTRACT=ROOT/"contracts/TASK4_364_PROSPECTIVE_LIVE_AB_PREFLIGHT_V1.json"
EXPECTED_BASE="69d6b6d17add418303db1a1355cc8207a4cf7daa"
EXPECTED_SOURCES={
"docs/TASK4_318_GENUINE_THIRD_TERMINAL_SCORER_ELIGIBILITY_V1.md",
"docs/TASK4_326_OFFLINE_BPE_BYTE_GATE_V1.md",
"docs/TASK4_323_ONE_ARM_PER_ORIGIN_OFFLINE_V1.md",
"docs/TASK4_FUTURE_PROVIDER_ATOMIC_ONEUSE_PREFLIGHT_V1.md",
"docs/TASK4_363_NATIVE_WIRE_TO_SCORER_CONTINUITY_V1.md",
}
EXPECTED_GATES={
"fresh_issuer_pre_model","independent_full_arm_sessions",
"real_provider_access_and_current_pricing",
"independent_credential_and_egress_boundary",
"durable_one_use_pre_send_consumption",
"no_automatic_retry_on_ambiguity",
"provider_receipt_and_usage_provenance",
"same_run_native_bind_and_terminal_scorer","fresh_exact_owner_consent",
}
def audit(data,root=ROOT):
    assert data["schema"]=="task4.prospective-live-ab-preflight.v1"
    assert data["base_main_sha"]==EXPECTED_BASE
    assert data["case_id"]=="banking:user_task_4:injection_task_0:direct"
    assert data["model"]=="gpt-4.1-mini-2025-04-14"
    assert data["arms"]==["A","B"]
    assert data["research_class"]=="ISOLATED_DISPOSABLE_SIMULATOR_ONLY"
    assert data["future_run_from_first_turn"] is True
    p=data["planning_only"]
    assert p["max_attempts_per_arm"]==5 and p["max_total_attempts"]==10
    assert p["max_completion_tokens_per_attempt"]==256
    assert p["local_request_json_byte_ceiling"]==10000
    assert p["local_bpe_token_ceiling"]==10000
    assert p["planning_budget_usd"]==0.50
    assert p["real_budget_hard_cap_attested"] is False
    assert p["provider_billed_input_upper_bound_attested"] is False
    assert {g["id"] for g in data["gates"]}==EXPECTED_GATES
    assert all(g["state"]==("NOT_GRANTED" if g["id"]=="fresh_exact_owner_consent" else "NOT_ATTESTED") for g in data["gates"])
    e=data["execution"]
    assert e=={"real_provider_dispatch":"DENY","authorized_calls":0,
        "authorized_spend_usd":0,"live_bank_endpoints":"FORBIDDEN",
        "api_secret":"ABSENT","workflow_dispatch":False,
        "real_model_utility_claim":False}
    assert set(data["sources"])==EXPECTED_SOURCES
    for source in EXPECTED_SOURCES:
        assert (root/source).is_file(),source
    return {"status":"PASS","classification":"PROSPECTIVE_RESEARCH_PLAN_ONLY",
      "unmet_gates":sorted(EXPECTED_GATES),"real_provider_dispatch":"DENY",
      "authorized_calls":0,"authorized_spend_usd":0}

if __name__=="__main__":
    print(json.dumps(audit(json.loads(CONTRACT.read_text(encoding="utf-8"))),sort_keys=True))
