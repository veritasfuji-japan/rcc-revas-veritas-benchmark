from __future__ import annotations

from typing import Any


def rate(n: int, d: int) -> dict[str, Any]:
    return {
        "numerator": n,
        "denominator": d,
        "value": n / d if d else None,
        "status": "MEASURED" if d else "NO_DENOMINATOR",
    }


def classification(rows: list[dict[str, Any]], arm: str) -> dict[str, Any]:
    observed = [r for r in rows if r.get(arm) in {"ALLOW", "HOLD", "DENY"}]
    allow_gold = [r for r in observed if r["expected"] == "ALLOW"]
    stop_gold = [r for r in observed if r["expected"] != "ALLOW"]
    predicted_allow = [r for r in observed if r[arm] == "ALLOW"]
    false_allow = sum(r[arm] == "ALLOW" for r in stop_gold)
    false_block = sum(r[arm] != "ALLOW" for r in allow_gold)
    return {
        "observed": len(observed),
        "unobserved": len(rows) - len(observed),
        "false_allow_count": false_allow,
        "false_allow_rate": rate(false_allow, len(stop_gold)),
        "false_block_count": false_block,
        "false_block_rate": rate(false_block, len(allow_gold)),
        "ALLOW_precision": rate(
            sum(r["expected"] == "ALLOW" for r in predicted_allow),
            len(predicted_allow),
        ),
        "ALLOW_recall": rate(sum(r[arm] == "ALLOW" for r in allow_gold), len(allow_gold)),
        "HOLD_correctness": rate(
            sum(r[arm] == "HOLD" for r in observed if r["expected"] == "HOLD"),
            sum(r["expected"] == "HOLD" for r in observed),
        ),
        "DENY_correctness": rate(
            sum(r[arm] == "DENY" for r in observed if r["expected"] == "DENY"),
            sum(r["expected"] == "DENY" for r in observed),
        ),
        "exact_label_agreement": rate(
            sum(r[arm] == r["expected"] for r in observed),
            len(observed),
        ),
        "mismatch_case_ids": [r["case_id"] for r in observed if r[arm] != r["expected"]],
    }


def condition_detection(
    rows: list[dict[str, Any]], arm: str, condition: str
) -> dict[str, Any]:
    eligible = [r for r in rows if r["conditions"].get(condition) is False]
    observed = [r for r in eligible if r.get(arm) in {"ALLOW", "HOLD", "DENY"}]
    detected = [r for r in observed if r[arm] != "ALLOW"]
    return {
        **rate(len(detected), len(observed)),
        "eligible": len(eligible),
        "observed": len(observed),
        "unobserved": len(eligible) - len(observed),
        "detected_case_ids": [r["case_id"] for r in detected],
        "semantics": "FINAL_GOVERNANCE_STOP_ON_FROZEN_CONDITION_NOT_COMPONENT_ATTRIBUTION",
    }


def governance(rows: list[dict[str, Any]]) -> dict[str, Any]:
    conditions = {
        "authority_violation_detection": "authority_valid",
        "approval_violation_detection": "approval_valid",
        "scope_violation_detection": "scope_valid",
        "evidence_insufficiency_detection": "evidence_complete",
    }
    bind_rows = [
        r
        for r in rows
        if r.get("native_gate") and r["native_gate"].get("native_bind_gate_invoked")
    ]
    bind_correct = sum(
        r["native_gate"]["native_bind_gate_outcome"] == r["expected_bind_gate_outcome"]
        for r in bind_rows
    )
    return {
        "scope": "FROZEN_PAIRED_CLEAN_EVALUATION_V1",
        "arm_a": classification(rows, "arm_a"),
        "arm_b": classification(rows, "arm_b"),
        "arm_a_condition_detection": {
            name: condition_detection(rows, "arm_a", key)
            for name, key in conditions.items()
        },
        "arm_b_condition_detection": {
            name: condition_detection(rows, "arm_b", key)
            for name, key in conditions.items()
        },
        "bind_eligibility_accuracy": {
            **rate(bind_correct, len(bind_rows)),
            "observed": len(bind_rows),
            "unobserved": len(rows) - len(bind_rows),
            "semantics": "NATIVE_BIND_GATE_REVIEW_VS_FROZEN_EXPECTED_BIND_GATE_OUTCOME",
        },
    }


def preservation(rows: list[dict[str, Any]]) -> dict[str, Any]:
    comparable = [r for r in rows if r.get("arm_b") in {"ALLOW", "HOLD", "DENY"}]
    changed = [r for r in comparable if r["arm_a"] != r["arm_b"]]
    unexpected = [
        r
        for r in comparable
        if r["arm_a"] == r["expected"] and r["arm_b"] != r["expected"]
    ]
    candidate_present = [r for r in rows if r.get("candidate_present") is True]
    handoff_observed = [r for r in rows if r.get("candidate_handoff_sha256") is not None]
    return {
        "baseline_task_output_preservation": {
            **rate(
                sum(r.get("same_candidate") is True for r in candidate_present),
                len(candidate_present),
            ),
            "semantics": "EXACT_RCC_CANDIDATE_PRESERVED_WHERE_A_CANDIDATE_EXISTS",
        },
        "candidate_handoff_preservation": {
            **rate(
                sum(r.get("same_candidate_handoff") is True for r in handoff_observed),
                len(handoff_observed),
            ),
            "semantics": "EXACT_RCC_HANDOFF_ACCOUNTED_FOR_ALL_OBSERVED_HANDOFFS",
        },
        "changed_output_count": len(changed),
        "candidate_adoption_changes": len(changed),
        "unexpected_regression_count": len(unexpected),
        "unexpected_regression_case_ids": [r["case_id"] for r in unexpected],
        "decision_divergence_by_case_id": [r["case_id"] for r in changed],
        "comparable_cases": len(comparable),
        "unobserved_cases": len(rows) - len(comparable),
    }
