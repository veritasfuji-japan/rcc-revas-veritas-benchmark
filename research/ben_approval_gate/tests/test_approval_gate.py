import copy
import unittest
from research.ben_approval_gate.approval_gate import review, SCHEMA, STATUS, ENV


def sample():
    return {
        "schema": SCHEMA, "status": STATUS, "environment": ENV,
        "legacy_profile_unchanged": True,
        "proposed_date_is_not_issued_or_authorized": True,
        "new_evidence_source_may_not_be_tool_payload_model_or_scorer": True,
        "new_condition_must_be_named_and_shared_by_B_and_engine": True,
        "cases": [{"case_id": "synthetic-001", "original_request_sha256": "a" * 64,
                   "original_injected_prestate_sha256": "b" * 64}],
    }


class GateTests(unittest.TestCase):
    def test_research_only(self):
        result = review(sample())
        self.assertEqual(result["status"], "RESEARCH_PROPOSAL_FORMAT_VALID")
        self.assertFalse(result["execution_authority"])
        self.assertEqual(result["issuer_provenance"], "UNVERIFIED")

    def test_mutations(self):
        for key, val in [("schema", "bad"), ("status", "APPROVED"),
                         ("environment", "real_bank"), ("legacy_profile_unchanged", False),
                         ("proposed_date_is_not_issued_or_authorized", False),
                         ("new_evidence_source_may_not_be_tool_payload_model_or_scorer", False),
                         ("new_condition_must_be_named_and_shared_by_B_and_engine", False)]:
            with self.subTest(key=key):
                doc = sample()
                doc[key] = val
                self.assertEqual(review(doc)["status"], "FAIL")

    def test_hash_and_prestate_mismatch(self):
        doc = sample()
        expected = copy.deepcopy(doc["cases"][0])
        doc["cases"][0]["original_request_sha256"] = "c" * 64
        self.assertEqual(review(doc, expected_case=expected)["status"], "FAIL")
        doc["cases"][0]["original_request_sha256"] = "bad"
        self.assertEqual(review(doc)["status"], "FAIL")

    def test_duplicate_and_malformed_id(self):
        doc = sample()
        doc["cases"].append(copy.deepcopy(doc["cases"][0]))
        self.assertEqual(review(doc)["status"], "FAIL")
        doc = sample()
        doc["cases"][0]["case_id"] = []
        self.assertEqual(review(doc)["status"], "FAIL")

    def test_malformed_input(self):
        for val in (None, [], "x", {"cases": [None]}):
            self.assertEqual(review(val)["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
