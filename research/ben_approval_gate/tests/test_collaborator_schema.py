"""Synthetic compatibility checks matching fields in the collaborator's 2026-11-01
RESEARCH_APPROVAL_PROPOSAL.json. No private cases or hashes are committed.
"""
import unittest
from research.ben_approval_gate.approval_gate import review, SCHEMA, STATUS, ENV


def representative():
    return {
        "schema": SCHEMA,
        "created_at_utc": "2026-11-01T19:05:06.266185+00:00",
        "status": STATUS,
        "legacy_profile_unchanged": True,
        "legacy_N_score_reference": 72,
        "new_condition_must_be_named_and_shared_by_B_and_engine": True,
        "pure_feedback_or_legacy_104_recovery_claim_allowed": False,
        "new_evidence_source_may_not_be_tool_payload_model_or_scorer": True,
        "environment": ENV,
        "proposed_execution_date": "2026-11-01",
        "proposed_date_is_not_issued_or_authorized": True,
        "date_only_scope_count": 32,
        "new_invoice_policy_scope_count": 8,
        "task12_and_task14_legacy_refusals_retained": 16,
        "benchmark_denominator_retained": 128,
        "planning_arithmetic_only_not_a_score_or_prediction": {
            "legacy_reference": 72, "maximum_new_scope_cases": 40, "sum": 112,
        },
        "cases": [{
            "case_id": "banking:user_task_0:injection_task_0:direct",
            "original_request_sha256": "1" * 64,
            "original_injected_prestate_sha256": "2" * 64,
        }],
    }


class CollaboratorSchemaTests(unittest.TestCase):
    def test_representative_format_not_authority(self):
        result = review(representative())
        self.assertEqual(result["status"], "RESEARCH_PROPOSAL_FORMAT_VALID")
        self.assertFalse(result["execution_authority"])
        for field in ("issuer_provenance", "bind", "current_validity", "single_use", "external_effect"):
            self.assertEqual(result[field], "UNVERIFIED")

    def test_proposed_date_never_becomes_issued_authority(self):
        proposal = representative()
        proposal["proposed_date_is_not_issued_or_authorized"] = False
        self.assertIn("DATE_AUTHORITY_PROMOTION", review(proposal)["failures"])

    def test_case_request_and_prestate_binding(self):
        proposal = representative()
        expected = dict(proposal["cases"][0])
        self.assertEqual(review(proposal, expected_case=expected)["status"], "RESEARCH_PROPOSAL_FORMAT_VALID")
        expected["original_injected_prestate_sha256"] = "3" * 64
        self.assertIn("CASE_PRESTATE_OR_REQUEST_MISMATCH", review(proposal, expected_case=expected)["failures"])


if __name__ == "__main__":
    unittest.main()
