"""Offline, zero-network regression tests for Task1 singleton Ruleset visibility diagnostic."""
import unittest

from scripts import final128_task1_ruleset_get_only_diagnostic_v1 as probe


def valid_detail():
    return {
        "conditions": {"ref_name": {"include": [probe.TAG], "exclude": []}},
        "rules": [{"type": "deletion"}, {"type": "update"},
                  {"type": "non_fast_forward"}],
        "bypass_actors": [],
    }


def listed(identifier=probe.RULESET_ID):
    return {"id": identifier, "target": "tag", "enforcement": "active"}


def run_case(collection=None, details=None, ref_status=404, list_status=200):
    if collection is None:
        collection = [listed()]
    if details is None:
        details = {probe.RULESET_ID: valid_detail()}
    calls, output = [], []

    def fake_get(path):
        calls.append(path)
        if path == probe.REF_PATH:
            return ref_status, None
        if path == probe.LIST_PATH:
            return list_status, collection
        identifier = int(path.split("/")[-1])
        return details.get(identifier, (200, None)) if isinstance(
            details.get(identifier), tuple
        ) else (200, details.get(identifier))

    result = probe.inspect(fake_get, emit=output.append)
    return result, output, calls


class TestRulesetGetOnlyDiagnostic(unittest.TestCase):
    def test_expected_active_exact_ruleset_matches(self):
        ok, output, calls = run_case()
        self.assertTrue(ok)
        self.assertIn(probe.PREFIX + "ORIGINAL_PREDICATE_MATCH_COUNT_1", output)
        self.assertIn(probe.PREFIX + "EXPECTED_DETAIL_EXACT_MATCH_YES", output)
        self.assertEqual(calls, [probe.REF_PATH, probe.LIST_PATH,
                                 "rulesets/" + str(probe.RULESET_ID)])

    def test_missing_bypass_field_never_passes(self):
        detail = valid_detail()
        del detail["bypass_actors"]
        ok, output, _ = run_case(details={probe.RULESET_ID: detail})
        self.assertFalse(ok)
        self.assertIn(probe.PREFIX + "EXPECTED_DETAIL_BYPASS_IS_EMPTY_LIST_NO", output)
        self.assertIn(probe.PREFIX + "ORIGINAL_PREDICATE_MATCH_COUNT_0", output)

    def test_other_ruleset_duplicate_not_accepted(self):
        detail = valid_detail()
        ok, output, _ = run_case(
            collection=[listed(), listed(24921426)],
            details={probe.RULESET_ID: detail, 24921426: detail},
        )
        self.assertFalse(ok)
        self.assertIn(probe.PREFIX + "ORIGINAL_PREDICATE_MATCH_COUNT_2", output)

    def test_missing_expected_list_item_not_accepted(self):
        ok, output, _ = run_case(collection=[])
        self.assertFalse(ok)
        self.assertIn(probe.PREFIX + "EXPECTED_ACTIVE_TAG_LISTED_NO", output)

    def test_unreadable_detail_fails_without_exception_details(self):
        ok, output, _ = run_case(details={probe.RULESET_ID: (403, None)})
        self.assertFalse(ok)
        self.assertIn(probe.PREFIX + "EXPECTED_DETAIL_HTTP_403", output)
        self.assertIn(probe.PREFIX + "STOP_DETAIL_UNREADABLE", output)

    def test_existing_tag_stops_before_ruleset_requests(self):
        ok, output, calls = run_case(ref_status=200)
        self.assertFalse(ok)
        self.assertEqual(calls, [probe.REF_PATH])
        self.assertIn(probe.PREFIX + "STOP_REF_NOT_CONFIRMED_ABSENT", output)

    def test_unreadable_ruleset_collection_stops(self):
        ok, output, calls = run_case(list_status=403)
        self.assertFalse(ok)
        self.assertEqual(calls, [probe.REF_PATH, probe.LIST_PATH])
        self.assertIn(probe.PREFIX + "STOP_LIST_UNREADABLE", output)

    def test_creation_rule_disqualifies(self):
        detail = valid_detail()
        detail["rules"].append({"type": "creation"})
        ok, _, _ = run_case(details={probe.RULESET_ID: detail})
        self.assertFalse(ok)

    def test_only_known_static_http_labels(self):
        self.assertEqual(probe.status_label(403), "403")
        self.assertEqual(probe.status_label(418), "OTHER")


if __name__ == "__main__":
    unittest.main()
