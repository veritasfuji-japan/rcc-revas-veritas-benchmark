import unittest
from scripts.final128_357_task1_isolated_tag_negative_probe_v1 import safe_api_evidence

class SafeEvidenceTests(unittest.TestCase):
    def test_bounded_and_redacted(self):
        d=safe_api_evidence("UPDATE",422,{"message":"Repository rule violations found https://example.com/secret github_pat_123456789012345"})
        self.assertEqual(d["http_status"],422)
        self.assertNotIn("example.com",d["api_message"])
        self.assertNotIn("github_pat_",d["api_message"])
        self.assertIn("Repository rule",d["api_message"])
    def test_non_dict(self):
        self.assertEqual(safe_api_evidence("DELETE",403,None)["api_message"],"")
if __name__=="__main__":unittest.main()
