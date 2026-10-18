"""#454 safety: reuse existing native proof, deny model and cost promotion."""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import pytest

from scripts import task4_454_research_admission_offline_v1 as m

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/task4-454-research-only-offline-native-admission.yml"


def hash_for(s):
    return hashlib.sha256(s.encode()).hexdigest()


def local_pair():
    arms = {}
    wires = []
    for arm in "AB":
        first = hash_for("same-first-wire")
        end = hash_for(arm + "-terminal")
        score = hash_for(arm + "-score")
        state = hash_for(arm + "-poststate")
        arms[arm] = {
            "native_dispatches": 1, "native_scorer_invocations": 1,
            "shadow_arms": 0, "real_model_generations": 0,
            "dev_only_native_utility": True,
            "dev_only_attack_goal_success": False,
            "first_response_id": arm + "-LOCAL_FAKE_ONLY",
            "first_request_sha256": first,
            "native_terminal_history_sha256": end,
            "native_post_state_sha256": state,
            "scorer_result_sha256": score,
        }
        wires.append({
            "arm": arm,
            "wire_request_hashes": [first] + [hash_for(arm + str(i)) for i in range(3)],
            "real_provider_calls": 0,
            "native_to_sdk_turns_verified": 4,
            "terminal_assistant_sha256": hash_for(arm + "-assistant"),
            "native_terminal_history_sha256": end,
            "scored_post_state_sha256": state,
            "scorer_result_sha256": score,
        })
    native = {
        "source_case": m.CASE,
        "two_independent_scripted_first_request_roots": 2,
        "real_sdk_local_interceptions": 8,
        "native_arm_executions": 2,
        "postonly_native_scorer_calls": 2,
        "shadow_native_arm_executions": 0,
        "new_real_provider_posts": 0,
        "new_genuine_model_generations": 0,
        "new_final128_cases": 0,
        "external_bank_effects": 0,
        "independent_prod_execution_authority": False,
        "real_provider_dispatch": "DENY",
        "historical_provider_consent_spent": True,
        "selected_source_arms": arms,
    }
    lineage = {
        "scope": "FULL_OFFLINE_SCRIPTED_SDK_NATIVE_SCORER_LINEAGE_NOT_REAL_MODEL",
        "verified_model_shaped_requests": 8,
        "native_terminal_histories": 2,
        "postonly_native_scorer_bindings": 2,
        "real_provider_calls": 0,
        "real_final128_case_scores": 0,
        "external_effects": 0,
        "real_model_independence_proven": False,
        "live_provider_dispatch": "DENY",
        "sources": wires,
    }
    return native, lineage


def test_local_structural_contract_never_promotes_real_provider():
    native, lineage = local_pair()
    report = m.audit(native, lineage, native_bytes=b"local-fake-323",
                     lineage_bytes=b"local-fake-363")
    assert report["scripted_arms_native_scored"] == 2
    assert report["genuine_model_generations"] == 0
    assert report["genuine_terminal_model_responses"] == 0
    assert report["new_canonical_utility_recoveries"] == 0
    assert report["real_provider_attempts"] == 0
    assert report["fresh_owner_paid_approval"] == "NOT_GIVEN"
    assert report["live_provider_dispatch"] == "DENY"
    assert report["model_snapshot_account_available"] == "NOT_ATTESTED"


@pytest.mark.parametrize("target,key,value", [
    ("native", "new_real_provider_posts", 1),
    ("native", "new_genuine_model_generations", 2),
    ("native", "real_provider_dispatch", "ALLOW"),
    ("native", "historical_provider_consent_spent", False),
    ("native", "new_final128_cases", 1),
    ("native", "independent_prod_execution_authority", True),
    ("native", "postonly_native_scorer_calls", 3),
    ("native", "source_case", "banking:other"),
    ("lineage", "real_provider_calls", 1),
    ("lineage", "real_model_independence_proven", True),
    ("lineage", "live_provider_dispatch", "ALLOW"),
    ("lineage", "native_terminal_histories", 1),
    ("lineage", "postonly_native_scorer_bindings", 0),
])
def test_promotions_refused(target, key, value):
    n, l = local_pair()
    (n if target == "native" else l)[key] = value
    with pytest.raises(m.Refused):
        m.audit(n, l, native_bytes=b"fake", lineage_bytes=b"fake")


@pytest.mark.parametrize("mutation", [
    "swapped_arm", "reused_first_response_id", "changed_first_request",
    "scorer_splice", "terminal_splice", "poststate_splice", "shadow",
    "missing_terminal", "changed_provider_call", "forged_utility",
])
def test_cross_origin_and_scorer_mismatch_refused(mutation):
    n, l = local_pair()
    a = n["selected_source_arms"]["A"]
    b = l["sources"]
    if mutation == "swapped_arm":
        b[0]["arm"] = "B"
    elif mutation == "reused_first_response_id":
        n["selected_source_arms"]["B"]["first_response_id"] = a["first_response_id"]
    elif mutation == "changed_first_request":
        b[1]["wire_request_hashes"][0] = hash_for("forged")
    elif mutation == "scorer_splice":
        a["scorer_result_sha256"] = hash_for("forged")
    elif mutation == "terminal_splice":
        a["native_terminal_history_sha256"] = hash_for("forged")
    elif mutation == "poststate_splice":
        a["native_post_state_sha256"] = hash_for("forged")
    elif mutation == "shadow":
        a["shadow_arms"] = 1
    elif mutation == "missing_terminal":
        b[0]["terminal_assistant_sha256"] = None
    elif mutation == "changed_provider_call":
        b[0]["real_provider_calls"] = 1
    elif mutation == "forged_utility":
        a["dev_only_native_utility"] = False
    with pytest.raises(m.Refused):
        m.audit(n, l, native_bytes=b"fake", lineage_bytes=b"fake")


@pytest.mark.parametrize("key", list(m.BLOCKED))
def test_secret_or_live_signal_always_denies(key):
    with pytest.raises(m.Refused, match="SECRET_OR_LIVE_CONTEXT"):
        m.ensure_research_only({key: "NON_SECRET_SENTINEL"})
    m.ensure_research_only({})


def test_exact_research_workflow_no_live_provider_entrypoints():
    s = WORKFLOW.read_text()
    assert "  pull_request:" in s
    assert "\n  workflow_dispatch:" not in s
    assert "\n  push:" not in s
    assert "\n  schedule:" not in s
    assert "\n  pull_request_target:" not in s
    assert "  contents: read" in s
    assert "  actions: read" in s
    assert "contents: write" not in s
    assert "id-token: write" not in s
    assert "environment:" not in s
    assert "secrets." not in s
    assert "api.openai.com" not in s
    assert "gh workflow run" not in s
    assert "curl " not in s
    assert "persist-credentials: false" in s
    for key in ("OPENAI_API_KEY", "TASK4_OPENAI_API_KEY",
                "ANTHROPIC_API_KEY", "OPENAI_BASE_URL"):
        assert key + ': ""' in s
    assert "tests/test_task4_323_one_arm_native_offline_v1.py" in s
    assert "scripts/task4_323_one_arm_audit_v1.py" in s
    assert "scripts/task4_363_native_wire_lineage_audit_v1.py" in s
    assert "scripts/task4_454_research_admission_offline_v1.py" in s


def test_no_network_sender_code_in_454():
    s = Path(m.__file__).read_text()
    for forbidden in (
        "HTTPSConnection(", "httpx.post(", "requests.post(",
        "AsyncOpenAI(", "OpenAI(", "secrets.", "workflow_dispatch"):
        assert forbidden not in s
