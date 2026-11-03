"""Offline classifier for research proposals; NEVER an authorization decision."""
import json
import re
from pathlib import Path

SCHEMA = "veritas.authority-recovery-review.v1"
STATUS = "REVIEW_ONLY_NO_AUTHORITY_NO_POLICY_ACTIVATION_NO_PROVIDER"
ENV = "disposable_in_memory_agentdojo_only_no_real_bank_endpoint_or_funds"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def review(proposal, *, expected_case=None):
    failures = []
    def require(condition, code):
        if not condition:
            failures.append(code)

    if not isinstance(proposal, dict):
        return {"status": "FAIL", "failures": ["INVALID_DOCUMENT"], "execution_authority": False}
    require(proposal.get("schema") == SCHEMA, "UNKNOWN_SCHEMA")
    require(proposal.get("status") == STATUS, "NOT_REVIEW_ONLY")
    require(proposal.get("environment") == ENV, "UNSAFE_ENVIRONMENT")
    require(proposal.get("legacy_profile_unchanged") is True, "LEGACY_POLICY_CHANGE")
    require(proposal.get("proposed_date_is_not_issued_or_authorized") is True, "DATE_AUTHORITY_PROMOTION")
    require(proposal.get("new_evidence_source_may_not_be_tool_payload_model_or_scorer") is True, "UNTRUSTED_ISSUER")
    require(proposal.get("new_condition_must_be_named_and_shared_by_B_and_engine") is True, "UNMATCHED_CONDITION")
    cases = proposal.get("cases")
    require(isinstance(cases, list) and bool(cases), "MISSING_CASES")
    if isinstance(cases, list):
        ids = set()
        for idx, case in enumerate(cases):
            if not isinstance(case, dict):
                failures.append(f"INVALID_CASE:{idx}")
                continue
            cid = case.get("case_id")
            if not isinstance(cid, str) or not cid:
                failures.append(f"MISSING_CASE_ID:{idx}")
            elif cid in ids:
                failures.append(f"DUPLICATE_CASE:{idx}")
            else:
                ids.add(cid)
            for key in ("original_request_sha256", "original_injected_prestate_sha256"):
                val = case.get(key)
                require(isinstance(val, str) and HEX64.fullmatch(val) is not None, f"INVALID_HASH:{idx}:{key}")
        if expected_case is not None:
            require(isinstance(expected_case, dict) and expected_case in cases, "CASE_PRESTATE_OR_REQUEST_MISMATCH")
    return {
        "status": "FAIL" if failures else "RESEARCH_PROPOSAL_FORMAT_VALID",
        "failures": failures, "execution_authority": False,
        "issuer_provenance": "UNVERIFIED", "bind": "UNVERIFIED",
        "current_validity": "UNVERIFIED", "single_use": "UNVERIFIED",
        "external_effect": "UNVERIFIED",
    }


def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("proposal", type=Path)
    p.add_argument("--report", type=Path)
    args = p.parse_args()
    result = review(json.loads(args.proposal.read_text(encoding="utf-8")))
    output = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.report:
        args.report.write_text(output, encoding="utf-8")
    print(output, end="")
    raise SystemExit(result["status"] == "FAIL")


if __name__ == "__main__":
    main()
